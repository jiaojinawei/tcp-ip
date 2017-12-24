/*
 *	Generic address resolution entity
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Alexey Kuznetsov	<kuznet@ms2.inr.ac.ru>
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 *	Fixes:
 *	Vitaly E. Lavrov	releasing NULL neighbor in neigh_add.
 *	Harald Welte		Add neighbour cache statistics like rtstat
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif
#include <linux/times.h>
#include <net/neighbour.h>
#include <net/dst.h>
#include <net/sock.h>
#include <net/netevent.h>
#include <net/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/random.h>
#include <linux/string.h>

#define NEIGH_DEBUG 1

#define NEIGH_PRINTK(x...) printk(x)
#define NEIGH_NOPRINTK(x...) do { ; } while(0)
#define NEIGH_PRINTK0 NEIGH_PRINTK
#define NEIGH_PRINTK1 NEIGH_NOPRINTK
#define NEIGH_PRINTK2 NEIGH_NOPRINTK

#if NEIGH_DEBUG >= 1
#undef NEIGH_PRINTK1
#define NEIGH_PRINTK1 NEIGH_PRINTK
#endif
#if NEIGH_DEBUG >= 2
#undef NEIGH_PRINTK2
#define NEIGH_PRINTK2 NEIGH_PRINTK
#endif

#define PNEIGH_HASHMASK		0xF

static void neigh_timer_handler(unsigned long arg);
#ifdef CONFIG_ARPD
static void neigh_app_notify(struct neighbour *n);
#endif
static int pneigh_ifdown(struct neigh_table *tbl, struct net_device *dev);
void neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev);

static struct neigh_table *neigh_tables;
#ifdef CONFIG_PROC_FS
static struct file_operations neigh_stat_seq_fops;
#endif

/*
   Neighbour hash table buckets are protected with rwlock tbl->lock.

   - All the scans/updates to hash buckets MUST be made under this lock.
   - NOTHING clever should be made under this lock: no callbacks
     to protocol backends, no attempts to send something to network.
     It will result in deadlocks, if backend/driver wants to use neighbour
     cache.
   - If the entry requires some non-trivial actions, increase
     its reference count and release table lock.

   Neighbour entries are protected:
   - with reference count.
   - with rwlock neigh->lock

   Reference count prevents destruction.

   neigh->lock mainly serializes ll address data and its validity state.
   However, the same lock is used to protect another entry fields:
    - timer
    - resolution queue

   Again, nothing clever shall be made under neigh->lock,
   the most complicated procedure, which we allow is dev->hard_header.
   It is supposed, that dev->hard_header is simplistic and does
   not make callbacks to neighbour tables.

   The last lock is neigh_tbl_lock. It is pure SMP lock, protecting
   list of neighbour tables. This list is used only in process context,
 */

static DEFINE_RWLOCK(neigh_tbl_lock);

static int neigh_blackhole(struct sk_buff *skb)
{
	kfree_skb(skb);
	return -ENETDOWN;
}

/*
 * It is random distribution in the interval (1/2)*base...(3/2)*base.
 * It corresponds to default IPv6 settings and is not overridable,
 * because it is really reasonable choice.
 */

unsigned long neigh_rand_reach_time(unsigned long base)
{
	return (base ? (net_random() % base) + (base >> 1) : 0);
}


static int neigh_forced_gc(struct neigh_table *tbl)
{
	int shrunk = 0;
	int i;

	NEIGH_CACHE_STAT_INC(tbl, forced_gc_runs);

	write_lock_bh(&tbl->lock);
	/* 遍历hash桶 */
	for (i = 0; i <= tbl->hash_mask; i++) {
		struct neighbour *n, **np;

		np = &tbl->hash_buckets[i];
		while ((n = *np) != NULL) {
			/* Neighbour record may be discarded if:
			 * - nobody refers to it.
			 * - it is not permanent
			 */
			write_lock(&n->lock);
			if (atomic_read(&n->refcnt) == 1 &&
			    !(n->nud_state & NUD_PERMANENT)) {
				*np	= n->next;
				n->dead = 1;
				shrunk	= 1;
				write_unlock(&n->lock);
				neigh_release(n);
				continue;
			}
			write_unlock(&n->lock);
			np = &n->next;
		}
	}

	tbl->last_flush = jiffies;

	write_unlock_bh(&tbl->lock);

	return shrunk;
}

static int neigh_del_timer(struct neighbour *n)
{
	if ((n->nud_state & NUD_IN_TIMER) &&
	    del_timer(&n->timer)) {
		neigh_release(n);
		return 1;
	}
	return 0;
}

static void pneigh_queue_purge(struct sk_buff_head *list)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(list)) != NULL) {
		dev_put(skb->dev);
		kfree_skb(skb);
	}
}
/* 清洗设备的邻居表项 */
static void neigh_flush_dev(struct neigh_table *tbl, struct net_device *dev)
{
	int i;
	/* 遍历hash表 */
	for (i = 0; i <= tbl->hash_mask; i++) {
		/* 获取链表头 */
		struct neighbour *n, **np = &tbl->hash_buckets[i];
		/* 遍历链表的每一个成员 */
		while ((n = *np) != NULL) {
			if (dev && n->dev != dev) {
				np = &n->next;
				continue;
			}
			/* 只处理该设备的表项 */
			*np = n->next;
			write_lock(&n->lock);
			neigh_del_timer(n);/* 删除定时器 */
			n->dead = 1;/* 设置删除标志 */
			/* 判断引用计数是否为0 */
			if (atomic_read(&n->refcnt) != 1) {
				/* The most unpleasant situation.
				   We must destroy neighbour entry,
				   but someone still uses it.

				   The destroy will be delayed until
				   the last user releases us, but
				   we must kill timers etc. and move
				   it to safe state.
				   * 引用计数如果不为0
				 */
				skb_queue_purge(&n->arp_queue);/* 删除所有的待发送报文 */
				n->output = neigh_blackhole;/* 设置其输出函数为黑洞 */
				if (n->nud_state & NUD_VALID)
					n->nud_state = NUD_NOARP;/* 改变其状态为不需要arp */
				else
					n->nud_state = NUD_NONE;
				NEIGH_PRINTK2("neigh %p is stray.\n", n);
			}
			write_unlock(&n->lock);
			neigh_release(n);/* 释放邻居表项 */
		}
	}
}

void neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev)
{
	write_lock_bh(&tbl->lock);
	neigh_flush_dev(tbl, dev);
	write_unlock_bh(&tbl->lock);
}

/* 响应接口掉电函数 */
int neigh_ifdown(struct neigh_table *tbl, struct net_device *dev)
{
	write_lock_bh(&tbl->lock);
	neigh_flush_dev(tbl, dev);
	pneigh_ifdown(tbl, dev);
	write_unlock_bh(&tbl->lock);
	/* 删除代理定时器 */
	del_timer_sync(&tbl->proxy_timer);
	/* 清理代理报文队列 */
	pneigh_queue_purge(&tbl->proxy_queue);
	return 0;
}
/* 分配一个表项 */
static struct neighbour *neigh_alloc(struct neigh_table *tbl)
{
	struct neighbour *n = NULL;
	unsigned long now = jiffies;
	int entries;

	entries = atomic_inc_return(&tbl->entries) - 1;/* 获取已经存在的表项个数，并且增加当前的个数统计 */
	/* 当表项大于最高阈值时，进行强制回收，或者大于2级阈值且超过了5秒 */
	if (entries >= tbl->gc_thresh3 ||
	    (entries >= tbl->gc_thresh2 &&
	     time_after(now, tbl->last_flush + 5 * HZ))) {
		if (!neigh_forced_gc(tbl) &&
		    entries >= tbl->gc_thresh3)
			goto out_entries;
	}
	/* 分配一个表项 */
	n = kmem_cache_alloc(tbl->kmem_cachep, GFP_ATOMIC);
	if (!n)
		goto out_entries;
	/* 清零 */
	memset(n, 0, tbl->entry_size);
	/* 初始化报文发送队列 */
	skb_queue_head_init(&n->arp_queue);
	/* 初始化读写锁 */
	rwlock_init(&n->lock);
	/* 更新时间 */
	n->updated	  = n->used = now;
	n->nud_state	  = NUD_NONE;
	/* 此时的输出函数为黑洞，即删除 */
	n->output	  = neigh_blackhole;
	/* 指向表的参数 */
	n->parms	  = neigh_parms_clone(&tbl->parms);
	init_timer(&n->timer);
	/* 初始化定时器处理函数 */
	n->timer.function = neigh_timer_handler;
	n->timer.data	  = (unsigned long)n;

	NEIGH_CACHE_STAT_INC(tbl, allocs);
	n->tbl		  = tbl;
	atomic_set(&n->refcnt, 1);
	/* 设置其为等待删除标志 */
	n->dead		  = 1;
out:
	return n;

out_entries:
	atomic_dec(&tbl->entries);
	goto out;
}

static struct neighbour **neigh_hash_alloc(unsigned int entries)
{
	unsigned long size = entries * sizeof(struct neighbour *);
	struct neighbour **ret;

	if (size <= PAGE_SIZE) {
		ret = kzalloc(size, GFP_ATOMIC);
	} else {
		ret = (struct neighbour **)
		      __get_free_pages(GFP_ATOMIC|__GFP_ZERO, get_order(size));
	}
	return ret;
}

static void neigh_hash_free(struct neighbour **hash, unsigned int entries)
{
	unsigned long size = entries * sizeof(struct neighbour *);

	if (size <= PAGE_SIZE)
		kfree(hash);
	else
		free_pages((unsigned long)hash, get_order(size));
}
/* hash桶进行扩容 */
static void neigh_hash_grow(struct neigh_table *tbl, unsigned long new_entries)
{
	struct neighbour **new_hash, **old_hash;
	unsigned int i, new_hash_mask, old_entries;

	NEIGH_CACHE_STAT_INC(tbl, hash_grows);

	BUG_ON(new_entries & (new_entries - 1));
	/* 分配新的hash桶个数 */
	new_hash = neigh_hash_alloc(new_entries);
	if (!new_hash)
		return;
	/* 原来的个数，需要进行拷贝 */
	old_entries = tbl->hash_mask + 1;
	new_hash_mask = new_entries - 1;
	old_hash = tbl->hash_buckets;

	get_random_bytes(&tbl->hash_rnd, sizeof(tbl->hash_rnd));
	/* 遍历老的hash表项 */
	for (i = 0; i < old_entries; i++) {
		struct neighbour *n, *next;

		for (n = old_hash[i]; n; n = next) {
			/* 根据三层地址进行hash */
			unsigned int hash_val = tbl->hash(n->primary_key, n->dev);
			/* 获取新的hash值，挂入hash表 */
			hash_val &= new_hash_mask;
			next = n->next;

			n->next = new_hash[hash_val];
			new_hash[hash_val] = n;
		}
	}
	tbl->hash_buckets = new_hash;
	tbl->hash_mask = new_hash_mask;
	/* 释放老的hash表 */
	neigh_hash_free(old_hash, old_entries);
}

struct neighbour *neigh_lookup(struct neigh_table *tbl, const void *pkey,
			       struct net_device *dev)
{
	struct neighbour *n;
	int key_len = tbl->key_len;
	u32 hash_val = tbl->hash(pkey, dev);
	
	NEIGH_CACHE_STAT_INC(tbl, lookups);

	read_lock_bh(&tbl->lock);
	for (n = tbl->hash_buckets[hash_val & tbl->hash_mask]; n; n = n->next) {
		if (dev == n->dev && !memcmp(n->primary_key, pkey, key_len)) {
			neigh_hold(n);
			NEIGH_CACHE_STAT_INC(tbl, hits);
			break;
		}
	}
	read_unlock_bh(&tbl->lock);
	return n;
}

struct neighbour *neigh_lookup_nodev(struct neigh_table *tbl, const void *pkey)
{
	struct neighbour *n;
	int key_len = tbl->key_len;
	u32 hash_val = tbl->hash(pkey, NULL);

	NEIGH_CACHE_STAT_INC(tbl, lookups);

	read_lock_bh(&tbl->lock);
	for (n = tbl->hash_buckets[hash_val & tbl->hash_mask]; n; n = n->next) {
		if (!memcmp(n->primary_key, pkey, key_len)) {
			neigh_hold(n);
			NEIGH_CACHE_STAT_INC(tbl, hits);
			break;
		}
	}
	read_unlock_bh(&tbl->lock);
	return n;
}
/* 创建邻居表项 */
struct neighbour *neigh_create(struct neigh_table *tbl, const void *pkey,
			       struct net_device *dev)
{
	u32 hash_val;
	int key_len = tbl->key_len;/* 获取key长度 */
	int error;
	struct neighbour *n1, *rc, *n = neigh_alloc(tbl);/* 分配一个表项 */

	if (!n) {
		rc = ERR_PTR(-ENOBUFS);
		goto out;
	}
	/* 将三层地址拷贝到数组中 */
	memcpy(n->primary_key, pkey, key_len);
	n->dev = dev;/* 表项所属设备 */
	dev_hold(dev);

	/* Protocol specific setup. 调用构建函数进行构建 */
	if (tbl->constructor &&	(error = tbl->constructor(n)) < 0) {
		rc = ERR_PTR(error);
		goto out_neigh_release;
	}

	/* Device specific setup. */
	if (n->parms->neigh_setup &&
	    (error = n->parms->neigh_setup(n)) < 0) {
		rc = ERR_PTR(error);
		goto out_neigh_release;
	}
	/* 设置表项的确认超时时间 */
	n->confirmed = jiffies - (n->parms->base_reachable_time << 1);

	write_lock_bh(&tbl->lock);/* 获取表锁 */

	/* 表项数大于hash桶数，则进行扩充，采用的是一个桶保存一个表 */
	if (atomic_read(&tbl->entries) > (tbl->hash_mask + 1))
		/* hash桶扩大一倍 */
		neigh_hash_grow(tbl, (tbl->hash_mask + 1) << 1);

	hash_val = tbl->hash(pkey, dev) & tbl->hash_mask;

	if (n->parms->dead) {
		rc = ERR_PTR(-EINVAL);
		goto out_tbl_unlock;
	}
	/* 遍历该hash表下的所有表项 */
	for (n1 = tbl->hash_buckets[hash_val]; n1; n1 = n1->next) {
		/* 查找设备相同，并且目的三层第一也相同的 */
		if (dev == n1->dev && !memcmp(n1->primary_key, pkey, key_len)) {
			neigh_hold(n1);/* 增加其引用计数即可 */
			rc = n1;
			goto out_tbl_unlock;
		}
	}
	/* 将新的表项插入头部 */
	n->next = tbl->hash_buckets[hash_val];
	tbl->hash_buckets[hash_val] = n;
	n->dead = 0;/* 设置非删除标志 */
	neigh_hold(n);/* 增加引用计数 */
	write_unlock_bh(&tbl->lock);
	NEIGH_PRINTK2("neigh %p is created.\n", n);
	rc = n;
out:
	return rc;
out_tbl_unlock:
	write_unlock_bh(&tbl->lock);
out_neigh_release:
	neigh_release(n);
	goto out;
}

struct pneigh_entry * pneigh_lookup(struct neigh_table *tbl, const void *pkey,
				    struct net_device *dev, int creat)
{
	struct pneigh_entry *n;
	int key_len = tbl->key_len;
	u32 hash_val = *(u32 *)(pkey + key_len - 4);

	hash_val ^= (hash_val >> 16);
	hash_val ^= hash_val >> 8;
	hash_val ^= hash_val >> 4;
	hash_val &= PNEIGH_HASHMASK;

	read_lock_bh(&tbl->lock);

	for (n = tbl->phash_buckets[hash_val]; n; n = n->next) {
		if (!memcmp(n->key, pkey, key_len) &&
		    (n->dev == dev || !n->dev)) {
			read_unlock_bh(&tbl->lock);
			goto out;
		}
	}
	read_unlock_bh(&tbl->lock);
	n = NULL;
	if (!creat)
		goto out;

	n = kmalloc(sizeof(*n) + key_len, GFP_KERNEL);
	if (!n)
		goto out;

	memcpy(n->key, pkey, key_len);
	n->dev = dev;
	if (dev)
		dev_hold(dev);

	if (tbl->pconstructor && tbl->pconstructor(n)) {
		if (dev)
			dev_put(dev);
		kfree(n);
		n = NULL;
		goto out;
	}

	write_lock_bh(&tbl->lock);
	n->next = tbl->phash_buckets[hash_val];
	tbl->phash_buckets[hash_val] = n;
	write_unlock_bh(&tbl->lock);
out:
	return n;
}


int pneigh_delete(struct neigh_table *tbl, const void *pkey,
		  struct net_device *dev)
{
	struct pneigh_entry *n, **np;
	int key_len = tbl->key_len;
	u32 hash_val = *(u32 *)(pkey + key_len - 4);

	hash_val ^= (hash_val >> 16);
	hash_val ^= hash_val >> 8;
	hash_val ^= hash_val >> 4;
	hash_val &= PNEIGH_HASHMASK;

	write_lock_bh(&tbl->lock);
	for (np = &tbl->phash_buckets[hash_val]; (n = *np) != NULL;
	     np = &n->next) {
		if (!memcmp(n->key, pkey, key_len) && n->dev == dev) {
			*np = n->next;
			write_unlock_bh(&tbl->lock);
			if (tbl->pdestructor)
				tbl->pdestructor(n);
			if (n->dev)
				dev_put(n->dev);
			kfree(n);
			return 0;
		}
	}
	write_unlock_bh(&tbl->lock);
	return -ENOENT;
}

static int pneigh_ifdown(struct neigh_table *tbl, struct net_device *dev)
{
	struct pneigh_entry *n, **np;
	u32 h;

	for (h = 0; h <= PNEIGH_HASHMASK; h++) {
		np = &tbl->phash_buckets[h];
		while ((n = *np) != NULL) {
			if (!dev || n->dev == dev) {
				*np = n->next;
				if (tbl->pdestructor)
					tbl->pdestructor(n);
				if (n->dev)
					dev_put(n->dev);
				kfree(n);
				continue;
			}
			np = &n->next;
		}
	}
	return -ENOENT;
}


/*
 *	neighbour must already be out of the table;
 *
 */
void neigh_destroy(struct neighbour *neigh)
{
	struct hh_cache *hh;

	NEIGH_CACHE_STAT_INC(neigh->tbl, destroys);

	if (!neigh->dead) {
		printk(KERN_WARNING
		       "Destroying alive neighbour %p\n", neigh);
		dump_stack();
		return;
	}

	if (neigh_del_timer(neigh))
		printk(KERN_WARNING "Impossible event.\n");

	while ((hh = neigh->hh) != NULL) {
		neigh->hh = hh->hh_next;
		hh->hh_next = NULL;

		write_seqlock_bh(&hh->hh_lock);
		hh->hh_output = neigh_blackhole;
		write_sequnlock_bh(&hh->hh_lock);
		if (atomic_dec_and_test(&hh->hh_refcnt))
			kfree(hh);
	}

	if (neigh->parms->neigh_destructor)
		(neigh->parms->neigh_destructor)(neigh);

	skb_queue_purge(&neigh->arp_queue);

	dev_put(neigh->dev);
	neigh_parms_put(neigh->parms);

	NEIGH_PRINTK2("neigh %p is destroyed.\n", neigh);

	atomic_dec(&neigh->tbl->entries);
	kmem_cache_free(neigh->tbl->kmem_cachep, neigh);
}

/* Neighbour state is suspicious;
   disable fast path.

   Called with write_locked neigh.
   邻居状态是可疑的，进行可疑处理
 */
static void neigh_suspect(struct neighbour *neigh)
{
	struct hh_cache *hh;

	NEIGH_PRINTK2("neigh %p is suspected.\n", neigh);

	neigh->output = neigh->ops->output;

	for (hh = neigh->hh; hh; hh = hh->hh_next)
		hh->hh_output = neigh->ops->output;
}

/* Neighbour state is OK;
   enable fast path.

   Called with write_locked neigh.
 */
static void neigh_connect(struct neighbour *neigh)
{
	struct hh_cache *hh;

	NEIGH_PRINTK2("neigh %p is connected.\n", neigh);

	neigh->output = neigh->ops->connected_output;

	for (hh = neigh->hh; hh; hh = hh->hh_next)
		hh->hh_output = neigh->ops->hh_output;
}
/* 邻居定时器周期处理函数，一般是1秒，可以通过改代码改变 */
static void neigh_periodic_timer(unsigned long arg)
{
	struct neigh_table *tbl = (struct neigh_table *)arg;/* 强制类型转换获得邻居表描述控制块 */
	struct neighbour *n, **np;
	unsigned long expire, now = jiffies;/* 获取当前时间 */

	NEIGH_CACHE_STAT_INC(tbl, periodic_gc_runs);/* 统计邻居表运行次数 */

	write_lock(&tbl->lock);/* 获取邻居表写锁 */

	/*
	 *	periodically recompute ReachableTime from random function
	 * 周期性重新计算到达时间，是一个随机值
	 */

	if (time_after(now, tbl->last_rand + 300 * HZ)) {
		struct neigh_parms *p;
		tbl->last_rand = now;
		for (p = &tbl->parms; p; p = p->next)
			p->reachable_time =
				neigh_rand_reach_time(p->base_reachable_time);
	}
	/* 获取本次回收的桶 */
	np = &tbl->hash_buckets[tbl->hash_chain_gc];
	/* 下次回收的桶 */
	tbl->hash_chain_gc = ((tbl->hash_chain_gc + 1) & tbl->hash_mask);
	/* 遍历hash链表 */
	while ((n = *np) != NULL) {
		unsigned int state;

		write_lock(&n->lock);/* 获取邻居表项写锁 */

		state = n->nud_state;/* 获取其状态 */
		/* 如果该表项是永久有效的，即用户已经配置了硬件地址，或者存在定时器 */
		if (state & (NUD_PERMANENT | NUD_IN_TIMER)) {
			write_unlock(&n->lock);/* 不处理这类邻居表项 */
			goto next_elt;
		}
		/*  */
		if (time_before(n->used, n->confirmed))
			n->used = n->confirmed;

		if (atomic_read(&n->refcnt) == 1 &&
		    (state == NUD_FAILED ||
		     time_after(now, n->used + n->parms->gc_staletime))) {
			*np = n->next;
			n->dead = 1;
			write_unlock(&n->lock);
			/* 释放该邻居表项 */
			neigh_release(n);
			continue;
		}
		write_unlock(&n->lock);

next_elt:
		np = &n->next;
	}

 	/* Cycle through all hash buckets every base_reachable_time/2 ticks.
 	 * ARP entry timeouts range from 1/2 base_reachable_time to 3/2
 	 * base_reachable_time.
	 */
	expire = tbl->parms.base_reachable_time >> 1;
	expire /= (tbl->hash_mask + 1);
	if (!expire)
		expire = 1;

 	mod_timer(&tbl->gc_timer, now + expire);

	write_unlock(&tbl->lock);
}

static __inline__ int neigh_max_probes(struct neighbour *n)
{
	struct neigh_parms *p = n->parms;
	return (n->nud_state & NUD_PROBE ?
		p->ucast_probes :
		p->ucast_probes + p->app_probes + p->mcast_probes);
}

static inline void neigh_add_timer(struct neighbour *n, unsigned long when)
{
	if (unlikely(mod_timer(&n->timer, when))) {
		printk("NEIGH: BUG, double timer add, state is %x\n",
		       n->nud_state);
		dump_stack();
	}
}

/* Called when a timer expires for a neighbour entry. */
/* 邻居表项定时器超时处理函数 */
static void neigh_timer_handler(unsigned long arg)
{
	unsigned long now, next;
	struct neighbour *neigh = (struct neighbour *)arg;/* 获取邻居表项的控制块 */
	unsigned state;
	int notify = 0;

	write_lock(&neigh->lock);/* 获取写锁 */

	state = neigh->nud_state;/* 获取该表项的状态 */
	now = jiffies;/* 获取当前时间 */
	next = now + HZ;/* 下次超时时间为1秒 */

	if (!(state & NUD_IN_TIMER)) {/* 不存在定时器，则说明有问题 */
#ifndef CONFIG_SMP
		printk(KERN_WARNING "neigh: timer & !nud_in_timer\n");
#endif
		goto out;
	}

	/* 如果是已经得到并且可以使用的非静态表项 */
	if (state & NUD_REACHABLE) {
		if (time_before_eq(now, 
				   neigh->confirmed + neigh->parms->reachable_time)) {
			NEIGH_PRINTK2("neigh %p is still alive.\n", neigh);
			next = neigh->confirmed + neigh->parms->reachable_time;
			/* 确认时间未超时，不改变状态，定时器改为下一次确认时间超时时间 */
		} else if (time_before_eq(now,
					  neigh->used + neigh->parms->delay_probe_time)) {
					  /* 确认时间超时，但是闲置时间未超时，改变状态为NUD_DELAY */
			NEIGH_PRINTK2("neigh %p is delayed.\n", neigh);
			neigh->nud_state = NUD_DELAY;/* 状态改变 */
			neigh->updated = jiffies;/* 记录状态改变时间 */
			neigh_suspect(neigh);/* 时间改为下次闲置时间 */
			next = now + neigh->parms->delay_probe_time;
		} else {/* 都超时的话，直接改为NUD_STALE */
			NEIGH_PRINTK2("neigh %p is suspected.\n", neigh);
			neigh->nud_state = NUD_STALE;
			neigh->updated = jiffies;
			neigh_suspect(neigh);
			notify = 1;
		}
	} else if (state & NUD_DELAY) {
		if (time_before_eq(now, 
				   neigh->confirmed + neigh->parms->delay_probe_time)) {
				   /* 延迟状态，但是却没有超时确认时间 */
			NEIGH_PRINTK2("neigh %p is now reachable.\n", neigh);
			neigh->nud_state = NUD_REACHABLE;
			neigh->updated = jiffies;
			/* 可达状态选用连接发送函数 */
			neigh_connect(neigh);
			notify = 1;
			/* 等待确认超时 */
			next = neigh->confirmed + neigh->parms->reachable_time;
		} else {
			/* 确认时间超时，设置探测超时时间 */
			NEIGH_PRINTK2("neigh %p is probed.\n", neigh);
			neigh->nud_state = NUD_PROBE;
			neigh->updated = jiffies;
			atomic_set(&neigh->probes, 0);
			next = now + neigh->parms->retrans_time;
		}
	} else {
		/* NUD_PROBE|NUD_INCOMPLETE 这两个状态继续发送*/
		next = now + neigh->parms->retrans_time;
	}

	/* 判断是否发送超过上限 */
	if ((neigh->nud_state & (NUD_INCOMPLETE | NUD_PROBE)) &&
	    atomic_read(&neigh->probes) >= neigh_max_probes(neigh)) {
		struct sk_buff *skb;
		/* 状态改为failed */
		neigh->nud_state = NUD_FAILED;
		neigh->updated = jiffies;
		notify = 1;
		NEIGH_CACHE_STAT_INC(neigh->tbl, res_failed);
		NEIGH_PRINTK2("neigh %p is failed.\n", neigh);

		/* It is very thin place. report_unreachable is very complicated
		   routine. Particularly, it can hit the same neighbour entry!

		   So that, we try to be accurate and avoid dead loop. --ANK
		 * 邻居表项失效后
		 */
		while (neigh->nud_state == NUD_FAILED &&
		       (skb = __skb_dequeue(&neigh->arp_queue)) != NULL) {
			write_unlock(&neigh->lock);
			/* 向三层发送错误报文，对于arp来说发送icmp不可达错误报文 */
			neigh->ops->error_report(neigh, skb);
			write_lock(&neigh->lock);
		}
		skb_queue_purge(&neigh->arp_queue);
	}
	/* 更新定时器 */
	if (neigh->nud_state & NUD_IN_TIMER) {
		if (time_before(next, jiffies + HZ/2))
			next = jiffies + HZ/2;
		if (!mod_timer(&neigh->timer, next))
			/* 成功，增加引用计数 */
			neigh_hold(neigh);
	}
	if (neigh->nud_state & (NUD_INCOMPLETE | NUD_PROBE)) {
		struct sk_buff *skb = skb_peek(&neigh->arp_queue);
		/* keep skb alive even if arp_queue overflows */
		if (skb)
			skb_get(skb);
		write_unlock(&neigh->lock);
		neigh->ops->solicit(neigh, skb);
		atomic_inc(&neigh->probes);
		if (skb)
			kfree_skb(skb);
	} else {
out:
		write_unlock(&neigh->lock);
	}
	/* 状态改变发送通知 */
	if (notify)
		call_netevent_notifiers(NETEVENT_NEIGH_UPDATE, neigh);

#ifdef CONFIG_ARPD
	if (notify && neigh->parms->app_probes)
		neigh_app_notify(neigh);
#endif
	/* 释放失败态的表项 */
	neigh_release(neigh);
}
/* 用于检测邻居表是否有效 */
int __neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	int rc;
	unsigned long now;

	write_lock_bh(&neigh->lock);

	rc = 0;
	/* 这几个状态可以直接发送 */
	if (neigh->nud_state & (NUD_CONNECTED | NUD_DELAY | NUD_PROBE))
		goto out_unlock_bh;

	now = jiffies;
	
	if (!(neigh->nud_state & (NUD_STALE | NUD_INCOMPLETE))) {
		if (neigh->parms->mcast_probes + neigh->parms->app_probes) {
			atomic_set(&neigh->probes, neigh->parms->ucast_probes);
			neigh->nud_state     = NUD_INCOMPLETE;
			neigh->updated = jiffies;
			neigh_hold(neigh);
			neigh_add_timer(neigh, now + 1);
		} else {
			neigh->nud_state = NUD_FAILED;
			neigh->updated = jiffies;
			write_unlock_bh(&neigh->lock);

			if (skb)
				kfree_skb(skb);
			return 1;
		}
	} else if (neigh->nud_state & NUD_STALE) {/* 这种情况下，发送报文后进入delay状态 */
		NEIGH_PRINTK2("neigh %p is delayed.\n", neigh);
		neigh_hold(neigh);
		neigh->nud_state = NUD_DELAY;
		neigh->updated = jiffies;
		neigh_add_timer(neigh,
				jiffies + neigh->parms->delay_probe_time);
	}

	if (neigh->nud_state == NUD_INCOMPLETE) {
		if (skb) {
			/* 队列满了，直接删除 */
			if (skb_queue_len(&neigh->arp_queue) >=
			    neigh->parms->queue_len) {
				struct sk_buff *buff;
				buff = neigh->arp_queue.next;
				__skb_unlink(buff, &neigh->arp_queue);
				kfree_skb(buff);
			}
			/* 还没有收到回应的话，加入到队尾部 */
			__skb_queue_tail(&neigh->arp_queue, skb);
		}
		rc = 1;
	}
out_unlock_bh:
	write_unlock_bh(&neigh->lock);
	return rc;
}

static void neigh_update_hhs(struct neighbour *neigh)
{
	struct hh_cache *hh;
	void (*update)(struct hh_cache*, struct net_device*, unsigned char *) =
		neigh->dev->header_cache_update;

	if (update) {
		for (hh = neigh->hh; hh; hh = hh->hh_next) {
			write_seqlock_bh(&hh->hh_lock);
			update(hh, neigh->dev, neigh->ha);
			write_sequnlock_bh(&hh->hh_lock);
		}
	}
}



/* Generic update routine.
   -- lladdr is new lladdr or NULL, if it is not supplied.
   -- new    is new state.
   -- flags
	NEIGH_UPDATE_F_OVERRIDE allows to override existing lladdr,
				if it is different.
	NEIGH_UPDATE_F_WEAK_OVERRIDE will suspect existing "connected"
				lladdr instead of overriding it 
				if it is different.
				It also allows to retain current state
				if lladdr is unchanged.
	NEIGH_UPDATE_F_ADMIN	means that the change is administrative.

	NEIGH_UPDATE_F_OVERRIDE_ISROUTER allows to override existing 
				NTF_ROUTER flag.
	NEIGH_UPDATE_F_ISROUTER	indicates if the neighbour is known as
				a router.

   Caller MUST hold reference count on the entry.
 */

int neigh_update(struct neighbour *neigh, const u8 *lladdr, u8 new,
		 u32 flags)
{
	u8 old;
	int err;
	int notify = 0;
	struct net_device *dev;
	int update_isrouter = 0;

	write_lock_bh(&neigh->lock);

	dev    = neigh->dev;/* 获取表项对应的设备 */
	old    = neigh->nud_state;/* 获取表项状态 */
	err    = -EPERM;
	/* 如果表项是NUD_NOARP|NUD_PERMANENT,则必须设置了管理标志 */
	if (!(flags & NEIGH_UPDATE_F_ADMIN) && 
	    (old & (NUD_NOARP | NUD_PERMANENT)))
		goto out;
	/* 如果需要设置的标志是不有效表项 */
	if (!(new & NUD_VALID)) {
		/* 删除定时器 */
		neigh_del_timer(neigh);
		if (old & NUD_CONNECTED)
			neigh_suspect(neigh);/* 改变输出函数为out_put */
		neigh->nud_state = new;/* 设置新的状态 */
		err = 0;
		notify = old & NUD_VALID;
		goto out;
	}

	/* Compare new lladdr with cached one */
	if (!dev->addr_len) {
		/* First case: device needs no address. */
		lladdr = neigh->ha;
	} else if (lladdr) {
		/* The second case: if something is already cached
		   and a new address is proposed:
		   - compare new & old
		   - if they are different, check override flag
		 */
		if ((old & NUD_VALID) && 
		    !memcmp(lladdr, neigh->ha, dev->addr_len))
			lladdr = neigh->ha;
	} else {
		/* No address is supplied; if we know something,
		   use it, otherwise discard the request.
		 */
		err = -EINVAL;
		if (!(old & NUD_VALID))
			goto out;
		lladdr = neigh->ha;
	}

	/* 如果新的状态是链接的，则更确认时间为当前时间 */
	if (new & NUD_CONNECTED)
		neigh->confirmed = jiffies;
	neigh->updated = jiffies;

	/* If entry was valid and address is not changed,
	   do not change entry state, if new one is STALE.
	 */
	err = 0;
	update_isrouter = flags & NEIGH_UPDATE_F_OVERRIDE_ISROUTER;
	if (old & NUD_VALID) {
		if (lladdr != neigh->ha && !(flags & NEIGH_UPDATE_F_OVERRIDE)) {
			update_isrouter = 0;
			if ((flags & NEIGH_UPDATE_F_WEAK_OVERRIDE) &&
			    (old & NUD_CONNECTED)) {
				lladdr = neigh->ha;
				new = NUD_STALE;
			} else
				goto out;
		} else {
			if (lladdr == neigh->ha && new == NUD_STALE &&
			    ((flags & NEIGH_UPDATE_F_WEAK_OVERRIDE) ||
			     (old & NUD_CONNECTED))
			    )
				new = old;
		}
	}

	if (new != old) {
		neigh_del_timer(neigh);/* 删除老的定时器 */
		if (new & NUD_IN_TIMER) {
			neigh_hold(neigh);/* 增加引用计数 */
			neigh_add_timer(neigh, (jiffies + 
						((new & NUD_REACHABLE) ? 
						 neigh->parms->reachable_time :
						 0)));/* 更新定时器 */
		}
		neigh->nud_state = new;
	}
	/* 更新设备的硬件地址 */
	if (lladdr != neigh->ha) {
		memcpy(&neigh->ha, lladdr, dev->addr_len);
		neigh_update_hhs(neigh);
		if (!(new & NUD_CONNECTED))
			neigh->confirmed = jiffies -
				      (neigh->parms->base_reachable_time << 1);
		notify = 1;
	}
	if (new == old)
		goto out;
	if (new & NUD_CONNECTED)
		neigh_connect(neigh);
	else
		neigh_suspect(neigh);
	if (!(old & NUD_VALID)) {
		struct sk_buff *skb;

		/* Again: avoid dead loop if something went wrong */

		while (neigh->nud_state & NUD_VALID &&
		       (skb = __skb_dequeue(&neigh->arp_queue)) != NULL) {
			struct neighbour *n1 = neigh;
			write_unlock_bh(&neigh->lock);
			/* On shaper/eql skb->dst->neighbour != neigh :( */
			if (skb->dst && skb->dst->neighbour)
				n1 = skb->dst->neighbour;
			n1->output(skb);
			write_lock_bh(&neigh->lock);
		}
		skb_queue_purge(&neigh->arp_queue);
	}
out:
	if (update_isrouter) {
		neigh->flags = (flags & NEIGH_UPDATE_F_ISROUTER) ?
			(neigh->flags | NTF_ROUTER) :
			(neigh->flags & ~NTF_ROUTER);
	}
	write_unlock_bh(&neigh->lock);

	if (notify)
		call_netevent_notifiers(NETEVENT_NEIGH_UPDATE, neigh);
#ifdef CONFIG_ARPD
	if (notify && neigh->parms->app_probes)
		neigh_app_notify(neigh);
#endif
	return err;
}

struct neighbour *neigh_event_ns(struct neigh_table *tbl,
				 u8 *lladdr, void *saddr,
				 struct net_device *dev)
{
	struct neighbour *neigh = __neigh_lookup(tbl, saddr, dev,
						 lladdr || !dev->addr_len);
	if (neigh)
		neigh_update(neigh, lladdr, NUD_STALE, 
			     NEIGH_UPDATE_F_OVERRIDE);
	return neigh;
}
/* 建立二层首部缓存 */
static void neigh_hh_init(struct neighbour *n, struct dst_entry *dst,
			  __be16 protocol)
{
	struct hh_cache	*hh;
	struct net_device *dev = dst->dev;

	for (hh = n->hh; hh; hh = hh->hh_next)
		if (hh->hh_type == protocol)
			break;

	if (!hh && (hh = kzalloc(sizeof(*hh), GFP_ATOMIC)) != NULL) {
		seqlock_init(&hh->hh_lock);
		hh->hh_type = protocol;
		atomic_set(&hh->hh_refcnt, 0);
		hh->hh_next = NULL;
		if (dev->hard_header_cache(n, hh)) {
			kfree(hh);
			hh = NULL;
		} else {
			atomic_inc(&hh->hh_refcnt);
			hh->hh_next = n->hh;
			n->hh	    = hh;
			if (n->nud_state & NUD_CONNECTED)
				hh->hh_output = n->ops->hh_output;
			else
				hh->hh_output = n->ops->output;
		}
	}
	if (hh)	{
		atomic_inc(&hh->hh_refcnt);
		dst->hh = hh;
	}
}

/* This function can be used in contexts, where only old dev_queue_xmit
   worked, f.e. if you want to override normal output path (eql, shaper),
   but resolution is not made yet.
 */

int neigh_compat_output(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;

	__skb_pull(skb, skb->nh.raw - skb->data);

	if (dev->hard_header &&
	    dev->hard_header(skb, dev, ntohs(skb->protocol), NULL, NULL,
		    	     skb->len) < 0 &&
	    dev->rebuild_header(skb))
		return 0;

	return dev_queue_xmit(skb);
}

/* Slow and careful. */
/* 慢速发送函数 */
int neigh_resolve_output(struct sk_buff *skb)
{
	struct dst_entry *dst = skb->dst;
	struct neighbour *neigh;
	int rc = 0;
	/* 目的路由为空，或者路由的邻居表项为空，直接丢弃 */
	if (!dst || !(neigh = dst->neighbour))
		goto discard;
	/* 报文的长度偏移掉二层头部 */
	__skb_pull(skb, skb->nh.raw - skb->data);

	if (!neigh_event_send(neigh, skb)) {
		int err;
		struct net_device *dev = neigh->dev;
		/* 如果设备支持hard_header_cache，并且其路由缓存中的二层缓存为空，则为其建立二层首部缓存 */
		if (dev->hard_header_cache && !dst->hh) {
			write_lock_bh(&neigh->lock);
			if (!dst->hh)/* 建立二层首部缓存 */
				neigh_hh_init(neigh, dst, dst->ops->protocol);
			/* 在报文中添加二层首部 */
			err = dev->hard_header(skb, dev, ntohs(skb->protocol),
					       neigh->ha, NULL, skb->len);
			write_unlock_bh(&neigh->lock);
		} else {
			read_lock_bh(&neigh->lock);
			err = dev->hard_header(skb, dev, ntohs(skb->protocol),
					       neigh->ha, NULL, skb->len);
			read_unlock_bh(&neigh->lock);
		}
		/* 调用输出函数进行输出 */
		if (err >= 0)
			rc = neigh->ops->queue_xmit(skb);
		else
			goto out_kfree_skb;
	}
out:
	return rc;
discard:
	NEIGH_PRINTK1("neigh_resolve_output: dst=%p neigh=%p\n",
		      dst, dst ? dst->neighbour : NULL);
out_kfree_skb:
	rc = -EINVAL;
	kfree_skb(skb);
	goto out;
}

/* As fast as possible without hh cache */

int neigh_connected_output(struct sk_buff *skb)
{
	int err;
	struct dst_entry *dst = skb->dst;
	struct neighbour *neigh = dst->neighbour;
	struct net_device *dev = neigh->dev;

	__skb_pull(skb, skb->nh.raw - skb->data);

	read_lock_bh(&neigh->lock);
	err = dev->hard_header(skb, dev, ntohs(skb->protocol),
			       neigh->ha, NULL, skb->len);
	read_unlock_bh(&neigh->lock);
	if (err >= 0)
		err = neigh->ops->queue_xmit(skb);
	else {
		err = -EINVAL;
		kfree_skb(skb);
	}
	return err;
}
/* 代理邻居处理 */
static void neigh_proxy_process(unsigned long arg)
{
	struct neigh_table *tbl = (struct neigh_table *)arg;
	long sched_next = 0;
	unsigned long now = jiffies;
	struct sk_buff *skb;

	spin_lock(&tbl->proxy_queue.lock);

	skb = tbl->proxy_queue.next;
	/* 循环处理所有的报文 */
	while (skb != (struct sk_buff *)&tbl->proxy_queue) {
		struct sk_buff *back = skb;
		/* 计算 */
		long tdif = NEIGH_CB(back)->sched_next - now;

		skb = skb->next;
		if (tdif <= 0) {
			struct net_device *dev = back->dev;
			__skb_unlink(back, &tbl->proxy_queue);
			if (tbl->proxy_redo && netif_running(dev))
				tbl->proxy_redo(back);
			else
				kfree_skb(back);

			dev_put(dev);
		} else if (!sched_next || tdif < sched_next)
			sched_next = tdif;
	}
	del_timer(&tbl->proxy_timer);
	if (sched_next)
		mod_timer(&tbl->proxy_timer, jiffies + sched_next);
	spin_unlock(&tbl->proxy_queue.lock);
}
/* 代理邻居报文入队列 */
void pneigh_enqueue(struct neigh_table *tbl, struct neigh_parms *p,
		    struct sk_buff *skb)
{
	unsigned long now = jiffies;
	unsigned long sched_next = now + (net_random() % p->proxy_delay);

	/* 请求个数大于允许的个数，立即删除 */
	if (tbl->proxy_queue.qlen > p->proxy_qlen) {
		kfree_skb(skb);
		return;
	}
	/* 设置其下一次调度时间 */
	NEIGH_CB(skb)->sched_next = sched_next;
	NEIGH_CB(skb)->flags |= LOCALLY_ENQUEUED;

	spin_lock(&tbl->proxy_queue.lock);
	if (del_timer(&tbl->proxy_timer)) {
		if (time_before(tbl->proxy_timer.expires, sched_next))
			sched_next = tbl->proxy_timer.expires;
	}
	dst_release(skb->dst);
	skb->dst = NULL;
	dev_hold(skb->dev);
	__skb_queue_tail(&tbl->proxy_queue, skb);
	mod_timer(&tbl->proxy_timer, sched_next);
	spin_unlock(&tbl->proxy_queue.lock);
}


struct neigh_parms *neigh_parms_alloc(struct net_device *dev,
				      struct neigh_table *tbl)
{
	struct neigh_parms *p = kmemdup(&tbl->parms, sizeof(*p), GFP_KERNEL);

	if (p) {
		p->tbl		  = tbl;
		atomic_set(&p->refcnt, 1);
		INIT_RCU_HEAD(&p->rcu_head);
		p->reachable_time =
				neigh_rand_reach_time(p->base_reachable_time);
		if (dev) {
			if (dev->neigh_setup && dev->neigh_setup(dev, p)) {
				kfree(p);
				return NULL;
			}

			dev_hold(dev);
			p->dev = dev;
		}
		p->sysctl_table = NULL;
		write_lock_bh(&tbl->lock);
		p->next		= tbl->parms.next;
		tbl->parms.next = p;
		write_unlock_bh(&tbl->lock);
	}
	return p;
}

static void neigh_rcu_free_parms(struct rcu_head *head)
{
	struct neigh_parms *parms =
		container_of(head, struct neigh_parms, rcu_head);

	neigh_parms_put(parms);
}

void neigh_parms_release(struct neigh_table *tbl, struct neigh_parms *parms)
{
	struct neigh_parms **p;

	if (!parms || parms == &tbl->parms)
		return;
	write_lock_bh(&tbl->lock);
	for (p = &tbl->parms.next; *p; p = &(*p)->next) {
		if (*p == parms) {
			*p = parms->next;
			parms->dead = 1;
			write_unlock_bh(&tbl->lock);
			if (parms->dev)
				dev_put(parms->dev);
			call_rcu(&parms->rcu_head, neigh_rcu_free_parms);
			return;
		}
	}
	write_unlock_bh(&tbl->lock);
	NEIGH_PRINTK1("neigh_parms_release: not found\n");
}

void neigh_parms_destroy(struct neigh_parms *parms)
{
	kfree(parms);
}

void neigh_table_init_no_netlink(struct neigh_table *tbl)
{
	unsigned long now = jiffies;
	unsigned long phsize;
	/* 设置该邻居表的引用计数为1 */
	atomic_set(&tbl->parms.refcnt, 1);
	/* 初始化邻居表的rcu，采用的是rcu进行保护 */
	INIT_RCU_HEAD(&tbl->parms.rcu_head);
	tbl->parms.reachable_time =
			  neigh_rand_reach_time(tbl->parms.base_reachable_time);
	/* 构建邻居表项cache */
	if (!tbl->kmem_cachep)
		tbl->kmem_cachep =
			kmem_cache_create(tbl->id, tbl->entry_size, 0,
					  SLAB_HWCACHE_ALIGN|SLAB_PANIC,
					  NULL, NULL);
	/* 分配邻居表的统计信息每cpu结构体 */
	tbl->stats = alloc_percpu(struct neigh_statistics);
	if (!tbl->stats)
		panic("cannot create neighbour cache statistics");
	
#ifdef CONFIG_PROC_FS
	tbl->pde = create_proc_entry(tbl->id, 0, proc_net_stat);
	if (!tbl->pde) 
		panic("cannot create neighbour proc dir entry");
	tbl->pde->proc_fops = &neigh_stat_seq_fops;
	tbl->pde->data = tbl;
#endif
	/* hash桶的掩码为1，那么总共有1+1两个桶 */
	tbl->hash_mask = 1;
    /* 分配邻居表的hash桶 */
	tbl->hash_buckets = neigh_hash_alloc(tbl->hash_mask + 1);
	/* 分配代理邻居表hash桶 */
	phsize = (PNEIGH_HASHMASK + 1) * sizeof(struct pneigh_entry *);
	tbl->phash_buckets = kzalloc(phsize, GFP_KERNEL);

	if (!tbl->hash_buckets || !tbl->phash_buckets)
		panic("cannot allocate neighbour cache hashes");

	get_random_bytes(&tbl->hash_rnd, sizeof(tbl->hash_rnd));
	/* 初始化多写者的读写自旋锁，用于写者之间的互斥 */
	rwlock_init(&tbl->lock);
	/* 初始化垃圾回收定时器 */
	init_timer(&tbl->gc_timer);
	/* 回收的参数 */
	tbl->gc_timer.data     = (unsigned long)tbl;
	/* 回收函数 */
	tbl->gc_timer.function = neigh_periodic_timer;
	/* 超时时间为1秒 */
	tbl->gc_timer.expires  = now + 1;
	/* 启动定时器 */
	add_timer(&tbl->gc_timer);
	/* 初始化代理定时器 */
	init_timer(&tbl->proxy_timer);
	tbl->proxy_timer.data	  = (unsigned long)tbl;
	tbl->proxy_timer.function = neigh_proxy_process;
	skb_queue_head_init(&tbl->proxy_queue);

	tbl->last_flush = now;
	tbl->last_rand	= now + tbl->parms.reachable_time * 20;
}
/* 邻居表初始化 */
void neigh_table_init(struct neigh_table *tbl)
{
	struct neigh_table *tmp;
	/* 邻居表初始化 */
	neigh_table_init_no_netlink(tbl);
	/* 获取全局邻居表写锁 */
	write_lock(&neigh_tbl_lock);
	/* 遍历邻居表链表 */
	for (tmp = neigh_tables; tmp; tmp = tmp->next) {
		/* 判断同一协议族的邻居表是否已经存在,仅仅是做告警使用 */
		if (tmp->family == tbl->family)
			break;
	}
	/* 将邻居表插在开头 */
	tbl->next	= neigh_tables;
	neigh_tables	= tbl;
	/* 替换新的链表头 */
	write_unlock(&neigh_tbl_lock);

	if (unlikely(tmp)) {
		printk(KERN_ERR "NEIGH: Registering multiple tables for "
		       "family %d\n", tbl->family);
		dump_stack();
	}
}

int neigh_table_clear(struct neigh_table *tbl)
{
	struct neigh_table **tp;

	/* It is not clean... Fix it to unload IPv6 module safely */
	del_timer_sync(&tbl->gc_timer);
	del_timer_sync(&tbl->proxy_timer);
	pneigh_queue_purge(&tbl->proxy_queue);
	neigh_ifdown(tbl, NULL);
	if (atomic_read(&tbl->entries))
		printk(KERN_CRIT "neighbour leakage\n");
	write_lock(&neigh_tbl_lock);
	for (tp = &neigh_tables; *tp; tp = &(*tp)->next) {
		if (*tp == tbl) {
			*tp = tbl->next;
			break;
		}
	}
	write_unlock(&neigh_tbl_lock);

	neigh_hash_free(tbl->hash_buckets, tbl->hash_mask + 1);
	tbl->hash_buckets = NULL;

	kfree(tbl->phash_buckets);
	tbl->phash_buckets = NULL;

	free_percpu(tbl->stats);
	tbl->stats = NULL;

	return 0;
}

int neigh_delete(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	struct ndmsg *ndm;
	struct nlattr *dst_attr;
	struct neigh_table *tbl;
	struct net_device *dev = NULL;
	int err = -EINVAL;

	if (nlmsg_len(nlh) < sizeof(*ndm))
		goto out;

	dst_attr = nlmsg_find_attr(nlh, sizeof(*ndm), NDA_DST);
	if (dst_attr == NULL)
		goto out;

	ndm = nlmsg_data(nlh);
	if (ndm->ndm_ifindex) {
		dev = dev_get_by_index(ndm->ndm_ifindex);
		if (dev == NULL) {
			err = -ENODEV;
			goto out;
		}
	}

	read_lock(&neigh_tbl_lock);
	for (tbl = neigh_tables; tbl; tbl = tbl->next) {
		struct neighbour *neigh;

		if (tbl->family != ndm->ndm_family)
			continue;
		read_unlock(&neigh_tbl_lock);

		if (nla_len(dst_attr) < tbl->key_len)
			goto out_dev_put;

		if (ndm->ndm_flags & NTF_PROXY) {
			err = pneigh_delete(tbl, nla_data(dst_attr), dev);
			goto out_dev_put;
		}

		if (dev == NULL)
			goto out_dev_put;

		neigh = neigh_lookup(tbl, nla_data(dst_attr), dev);
		if (neigh == NULL) {
			err = -ENOENT;
			goto out_dev_put;
		}

		err = neigh_update(neigh, NULL, NUD_FAILED,
				   NEIGH_UPDATE_F_OVERRIDE |
				   NEIGH_UPDATE_F_ADMIN);
		neigh_release(neigh);
		goto out_dev_put;
	}
	read_unlock(&neigh_tbl_lock);
	err = -EAFNOSUPPORT;

out_dev_put:
	if (dev)
		dev_put(dev);
out:
	return err;
}

/* 添加邻居表项函数 */
int neigh_add(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	struct ndmsg *ndm;
	struct nlattr *tb[NDA_MAX+1];
	struct neigh_table *tbl;
	struct net_device *dev = NULL;
	int err;
	/* 解析邻居表项的netlink消息 */
	err = nlmsg_parse(nlh, sizeof(*ndm), tb, NDA_MAX, NULL);
	if (err < 0)
		goto out;

	err = -EINVAL;
	if (tb[NDA_DST] == NULL)
		goto out;

	ndm = nlmsg_data(nlh);
	/* 获取设备索引 */
	if (ndm->ndm_ifindex) {
		/* 根据设备索引获取设备描述控制块 */
		dev = dev_get_by_index(ndm->ndm_ifindex);
		if (dev == NULL) {
			err = -ENODEV;
			goto out;
		}
		/* 获取硬件地址 */
		if (tb[NDA_LLADDR] && nla_len(tb[NDA_LLADDR]) < dev->addr_len)
			goto out_dev_put;
	}

	read_lock(&neigh_tbl_lock);
	/* 查找邻居表 */
	for (tbl = neigh_tables; tbl; tbl = tbl->next) {
		int flags = NEIGH_UPDATE_F_ADMIN | NEIGH_UPDATE_F_OVERRIDE;
		struct neighbour *neigh;
		void *dst, *lladdr;
		/* 查看家族是否相等 */
		if (tbl->family != ndm->ndm_family)
			continue;
		read_unlock(&neigh_tbl_lock);
		/* 校验三层地址长度 */
		if (nla_len(tb[NDA_DST]) < tbl->key_len)
			goto out_dev_put;
		/* 获取三层地址 */
		dst = nla_data(tb[NDA_DST]);
		/* 获取链路层地址 */
		lladdr = tb[NDA_LLADDR] ? nla_data(tb[NDA_LLADDR]) : NULL;

		/* 是否是邻居代理 */
		if (ndm->ndm_flags & NTF_PROXY) {/* 查找代理 */
			struct pneigh_entry *pn;

			err = -ENOBUFS;
			pn = pneigh_lookup(tbl, dst, dev, 1);
			if (pn) {
				pn->flags = ndm->ndm_flags;
				err = 0;
			}
			goto out_dev_put;
		}

		if (dev == NULL)/* 不存在指定的设备 */
			goto out_dev_put;
		/* 查找邻居表项 */
		neigh = neigh_lookup(tbl, dst, dev);
		if (neigh == NULL) {/* 没找到 */
			if (!(nlh->nlmsg_flags & NLM_F_CREATE)) {/* 是否是获取 */
				err = -ENOENT;
				goto out_dev_put;
			}
			/* 创建邻居表项 */
			neigh = __neigh_lookup_errno(tbl, dst, dev);
			if (IS_ERR(neigh)) {
				err = PTR_ERR(neigh);
				goto out_dev_put;
			}
		} else {
			if (nlh->nlmsg_flags & NLM_F_EXCL) {
				err = -EEXIST;
				neigh_release(neigh);
				goto out_dev_put;
			}

			if (!(nlh->nlmsg_flags & NLM_F_REPLACE))
				flags &= ~NEIGH_UPDATE_F_OVERRIDE;
		}
		/* 更新邻居表项 */
		err = neigh_update(neigh, lladdr, ndm->ndm_state, flags);
		neigh_release(neigh);
		goto out_dev_put;
	}

	read_unlock(&neigh_tbl_lock);
	err = -EAFNOSUPPORT;

out_dev_put:
	if (dev)
		dev_put(dev);
out:
	return err;
}

static int neightbl_fill_parms(struct sk_buff *skb, struct neigh_parms *parms)
{
	struct nlattr *nest;

	nest = nla_nest_start(skb, NDTA_PARMS);
	if (nest == NULL)
		return -ENOBUFS;

	if (parms->dev)
		NLA_PUT_U32(skb, NDTPA_IFINDEX, parms->dev->ifindex);

	NLA_PUT_U32(skb, NDTPA_REFCNT, atomic_read(&parms->refcnt));
	NLA_PUT_U32(skb, NDTPA_QUEUE_LEN, parms->queue_len);
	NLA_PUT_U32(skb, NDTPA_PROXY_QLEN, parms->proxy_qlen);
	NLA_PUT_U32(skb, NDTPA_APP_PROBES, parms->app_probes);
	NLA_PUT_U32(skb, NDTPA_UCAST_PROBES, parms->ucast_probes);
	NLA_PUT_U32(skb, NDTPA_MCAST_PROBES, parms->mcast_probes);
	NLA_PUT_MSECS(skb, NDTPA_REACHABLE_TIME, parms->reachable_time);
	NLA_PUT_MSECS(skb, NDTPA_BASE_REACHABLE_TIME,
		      parms->base_reachable_time);
	NLA_PUT_MSECS(skb, NDTPA_GC_STALETIME, parms->gc_staletime);
	NLA_PUT_MSECS(skb, NDTPA_DELAY_PROBE_TIME, parms->delay_probe_time);
	NLA_PUT_MSECS(skb, NDTPA_RETRANS_TIME, parms->retrans_time);
	NLA_PUT_MSECS(skb, NDTPA_ANYCAST_DELAY, parms->anycast_delay);
	NLA_PUT_MSECS(skb, NDTPA_PROXY_DELAY, parms->proxy_delay);
	NLA_PUT_MSECS(skb, NDTPA_LOCKTIME, parms->locktime);

	return nla_nest_end(skb, nest);

nla_put_failure:
	return nla_nest_cancel(skb, nest);
}

static int neightbl_fill_info(struct sk_buff *skb, struct neigh_table *tbl,
			      u32 pid, u32 seq, int type, int flags)
{
	struct nlmsghdr *nlh;
	struct ndtmsg *ndtmsg;

	nlh = nlmsg_put(skb, pid, seq, type, sizeof(*ndtmsg), flags);
	if (nlh == NULL)
		return -ENOBUFS;

	ndtmsg = nlmsg_data(nlh);

	read_lock_bh(&tbl->lock);
	ndtmsg->ndtm_family = tbl->family;
	ndtmsg->ndtm_pad1   = 0;
	ndtmsg->ndtm_pad2   = 0;

	NLA_PUT_STRING(skb, NDTA_NAME, tbl->id);
	NLA_PUT_MSECS(skb, NDTA_GC_INTERVAL, tbl->gc_interval);
	NLA_PUT_U32(skb, NDTA_THRESH1, tbl->gc_thresh1);
	NLA_PUT_U32(skb, NDTA_THRESH2, tbl->gc_thresh2);
	NLA_PUT_U32(skb, NDTA_THRESH3, tbl->gc_thresh3);

	{
		unsigned long now = jiffies;
		unsigned int flush_delta = now - tbl->last_flush;
		unsigned int rand_delta = now - tbl->last_rand;

		struct ndt_config ndc = {
			.ndtc_key_len		= tbl->key_len,
			.ndtc_entry_size	= tbl->entry_size,
			.ndtc_entries		= atomic_read(&tbl->entries),
			.ndtc_last_flush	= jiffies_to_msecs(flush_delta),
			.ndtc_last_rand		= jiffies_to_msecs(rand_delta),
			.ndtc_hash_rnd		= tbl->hash_rnd,
			.ndtc_hash_mask		= tbl->hash_mask,
			.ndtc_hash_chain_gc	= tbl->hash_chain_gc,
			.ndtc_proxy_qlen	= tbl->proxy_queue.qlen,
		};

		NLA_PUT(skb, NDTA_CONFIG, sizeof(ndc), &ndc);
	}

	{
		int cpu;
		struct ndt_stats ndst;

		memset(&ndst, 0, sizeof(ndst));

		for_each_possible_cpu(cpu) {
			struct neigh_statistics	*st;

			st = per_cpu_ptr(tbl->stats, cpu);
			ndst.ndts_allocs		+= st->allocs;
			ndst.ndts_destroys		+= st->destroys;
			ndst.ndts_hash_grows		+= st->hash_grows;
			ndst.ndts_res_failed		+= st->res_failed;
			ndst.ndts_lookups		+= st->lookups;
			ndst.ndts_hits			+= st->hits;
			ndst.ndts_rcv_probes_mcast	+= st->rcv_probes_mcast;
			ndst.ndts_rcv_probes_ucast	+= st->rcv_probes_ucast;
			ndst.ndts_periodic_gc_runs	+= st->periodic_gc_runs;
			ndst.ndts_forced_gc_runs	+= st->forced_gc_runs;
		}

		NLA_PUT(skb, NDTA_STATS, sizeof(ndst), &ndst);
	}

	BUG_ON(tbl->parms.dev);
	if (neightbl_fill_parms(skb, &tbl->parms) < 0)
		goto nla_put_failure;

	read_unlock_bh(&tbl->lock);
	return nlmsg_end(skb, nlh);

nla_put_failure:
	read_unlock_bh(&tbl->lock);
	return nlmsg_cancel(skb, nlh);
}

static int neightbl_fill_param_info(struct sk_buff *skb,
				    struct neigh_table *tbl,
				    struct neigh_parms *parms,
				    u32 pid, u32 seq, int type,
				    unsigned int flags)
{
	struct ndtmsg *ndtmsg;
	struct nlmsghdr *nlh;

	nlh = nlmsg_put(skb, pid, seq, type, sizeof(*ndtmsg), flags);
	if (nlh == NULL)
		return -ENOBUFS;

	ndtmsg = nlmsg_data(nlh);

	read_lock_bh(&tbl->lock);
	ndtmsg->ndtm_family = tbl->family;
	ndtmsg->ndtm_pad1   = 0;
	ndtmsg->ndtm_pad2   = 0;

	if (nla_put_string(skb, NDTA_NAME, tbl->id) < 0 ||
	    neightbl_fill_parms(skb, parms) < 0)
		goto errout;

	read_unlock_bh(&tbl->lock);
	return nlmsg_end(skb, nlh);
errout:
	read_unlock_bh(&tbl->lock);
	return nlmsg_cancel(skb, nlh);
}
 
static inline struct neigh_parms *lookup_neigh_params(struct neigh_table *tbl,
						      int ifindex)
{
	struct neigh_parms *p;
	
	for (p = &tbl->parms; p; p = p->next)
		if ((p->dev && p->dev->ifindex == ifindex) ||
		    (!p->dev && !ifindex))
			return p;

	return NULL;
}

static struct nla_policy nl_neightbl_policy[NDTA_MAX+1] __read_mostly = {
	[NDTA_NAME]		= { .type = NLA_STRING },
	[NDTA_THRESH1]		= { .type = NLA_U32 },
	[NDTA_THRESH2]		= { .type = NLA_U32 },
	[NDTA_THRESH3]		= { .type = NLA_U32 },
	[NDTA_GC_INTERVAL]	= { .type = NLA_U64 },
	[NDTA_PARMS]		= { .type = NLA_NESTED },
};

static struct nla_policy nl_ntbl_parm_policy[NDTPA_MAX+1] __read_mostly = {
	[NDTPA_IFINDEX]			= { .type = NLA_U32 },
	[NDTPA_QUEUE_LEN]		= { .type = NLA_U32 },
	[NDTPA_PROXY_QLEN]		= { .type = NLA_U32 },
	[NDTPA_APP_PROBES]		= { .type = NLA_U32 },
	[NDTPA_UCAST_PROBES]		= { .type = NLA_U32 },
	[NDTPA_MCAST_PROBES]		= { .type = NLA_U32 },
	[NDTPA_BASE_REACHABLE_TIME]	= { .type = NLA_U64 },
	[NDTPA_GC_STALETIME]		= { .type = NLA_U64 },
	[NDTPA_DELAY_PROBE_TIME]	= { .type = NLA_U64 },
	[NDTPA_RETRANS_TIME]		= { .type = NLA_U64 },
	[NDTPA_ANYCAST_DELAY]		= { .type = NLA_U64 },
	[NDTPA_PROXY_DELAY]		= { .type = NLA_U64 },
	[NDTPA_LOCKTIME]		= { .type = NLA_U64 },
};

int neightbl_set(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	struct neigh_table *tbl;
	struct ndtmsg *ndtmsg;
	struct nlattr *tb[NDTA_MAX+1];
	int err;

	err = nlmsg_parse(nlh, sizeof(*ndtmsg), tb, NDTA_MAX,
			  nl_neightbl_policy);
	if (err < 0)
		goto errout;

	if (tb[NDTA_NAME] == NULL) {
		err = -EINVAL;
		goto errout;
	}

	ndtmsg = nlmsg_data(nlh);
	read_lock(&neigh_tbl_lock);
	for (tbl = neigh_tables; tbl; tbl = tbl->next) {
		if (ndtmsg->ndtm_family && tbl->family != ndtmsg->ndtm_family)
			continue;

		if (nla_strcmp(tb[NDTA_NAME], tbl->id) == 0)
			break;
	}

	if (tbl == NULL) {
		err = -ENOENT;
		goto errout_locked;
	}

	/* 
	 * We acquire tbl->lock to be nice to the periodic timers and
	 * make sure they always see a consistent set of values.
	 */
	write_lock_bh(&tbl->lock);

	if (tb[NDTA_PARMS]) {
		struct nlattr *tbp[NDTPA_MAX+1];
		struct neigh_parms *p;
		int i, ifindex = 0;

		err = nla_parse_nested(tbp, NDTPA_MAX, tb[NDTA_PARMS],
				       nl_ntbl_parm_policy);
		if (err < 0)
			goto errout_tbl_lock;

		if (tbp[NDTPA_IFINDEX])
			ifindex = nla_get_u32(tbp[NDTPA_IFINDEX]);

		p = lookup_neigh_params(tbl, ifindex);
		if (p == NULL) {
			err = -ENOENT;
			goto errout_tbl_lock;
		}

		for (i = 1; i <= NDTPA_MAX; i++) {
			if (tbp[i] == NULL)
				continue;

			switch (i) {
			case NDTPA_QUEUE_LEN:
				p->queue_len = nla_get_u32(tbp[i]);
				break;
			case NDTPA_PROXY_QLEN:
				p->proxy_qlen = nla_get_u32(tbp[i]);
				break;
			case NDTPA_APP_PROBES:
				p->app_probes = nla_get_u32(tbp[i]);
				break;
			case NDTPA_UCAST_PROBES:
				p->ucast_probes = nla_get_u32(tbp[i]);
				break;
			case NDTPA_MCAST_PROBES:
				p->mcast_probes = nla_get_u32(tbp[i]);
				break;
			case NDTPA_BASE_REACHABLE_TIME:
				p->base_reachable_time = nla_get_msecs(tbp[i]);
				break;
			case NDTPA_GC_STALETIME:
				p->gc_staletime = nla_get_msecs(tbp[i]);
				break;
			case NDTPA_DELAY_PROBE_TIME:
				p->delay_probe_time = nla_get_msecs(tbp[i]);
				break;
			case NDTPA_RETRANS_TIME:
				p->retrans_time = nla_get_msecs(tbp[i]);
				break;
			case NDTPA_ANYCAST_DELAY:
				p->anycast_delay = nla_get_msecs(tbp[i]);
				break;
			case NDTPA_PROXY_DELAY:
				p->proxy_delay = nla_get_msecs(tbp[i]);
				break;
			case NDTPA_LOCKTIME:
				p->locktime = nla_get_msecs(tbp[i]);
				break;
			}
		}
	}

	if (tb[NDTA_THRESH1])
		tbl->gc_thresh1 = nla_get_u32(tb[NDTA_THRESH1]);

	if (tb[NDTA_THRESH2])
		tbl->gc_thresh2 = nla_get_u32(tb[NDTA_THRESH2]);

	if (tb[NDTA_THRESH3])
		tbl->gc_thresh3 = nla_get_u32(tb[NDTA_THRESH3]);

	if (tb[NDTA_GC_INTERVAL])
		tbl->gc_interval = nla_get_msecs(tb[NDTA_GC_INTERVAL]);

	err = 0;

errout_tbl_lock:
	write_unlock_bh(&tbl->lock);
errout_locked:
	read_unlock(&neigh_tbl_lock);
errout:
	return err;
}

int neightbl_dump_info(struct sk_buff *skb, struct netlink_callback *cb)
{
	int family, tidx, nidx = 0;
	int tbl_skip = cb->args[0];
	int neigh_skip = cb->args[1];
	struct neigh_table *tbl;

	family = ((struct rtgenmsg *) nlmsg_data(cb->nlh))->rtgen_family;

	read_lock(&neigh_tbl_lock);
	for (tbl = neigh_tables, tidx = 0; tbl; tbl = tbl->next, tidx++) {
		struct neigh_parms *p;

		if (tidx < tbl_skip || (family && tbl->family != family))
			continue;

		if (neightbl_fill_info(skb, tbl, NETLINK_CB(cb->skb).pid,
				       cb->nlh->nlmsg_seq, RTM_NEWNEIGHTBL,
				       NLM_F_MULTI) <= 0)
			break;

		for (nidx = 0, p = tbl->parms.next; p; p = p->next, nidx++) {
			if (nidx < neigh_skip)
				continue;

			if (neightbl_fill_param_info(skb, tbl, p,
						     NETLINK_CB(cb->skb).pid,
						     cb->nlh->nlmsg_seq,
						     RTM_NEWNEIGHTBL,
						     NLM_F_MULTI) <= 0)
				goto out;
		}

		neigh_skip = 0;
	}
out:
	read_unlock(&neigh_tbl_lock);
	cb->args[0] = tidx;
	cb->args[1] = nidx;

	return skb->len;
}

static int neigh_fill_info(struct sk_buff *skb, struct neighbour *neigh,
			   u32 pid, u32 seq, int type, unsigned int flags)
{
	unsigned long now = jiffies;
	struct nda_cacheinfo ci;
	struct nlmsghdr *nlh;
	struct ndmsg *ndm;

	nlh = nlmsg_put(skb, pid, seq, type, sizeof(*ndm), flags);
	if (nlh == NULL)
		return -ENOBUFS;

	ndm = nlmsg_data(nlh);
	ndm->ndm_family	 = neigh->ops->family;
	ndm->ndm_pad1    = 0;
	ndm->ndm_pad2    = 0;
	ndm->ndm_flags	 = neigh->flags;
	ndm->ndm_type	 = neigh->type;
	ndm->ndm_ifindex = neigh->dev->ifindex;

	NLA_PUT(skb, NDA_DST, neigh->tbl->key_len, neigh->primary_key);

	read_lock_bh(&neigh->lock);
	ndm->ndm_state	 = neigh->nud_state;
	if ((neigh->nud_state & NUD_VALID) &&
	    nla_put(skb, NDA_LLADDR, neigh->dev->addr_len, neigh->ha) < 0) {
		read_unlock_bh(&neigh->lock);
		goto nla_put_failure;
	}

	ci.ndm_used	 = now - neigh->used;
	ci.ndm_confirmed = now - neigh->confirmed;
	ci.ndm_updated	 = now - neigh->updated;
	ci.ndm_refcnt	 = atomic_read(&neigh->refcnt) - 1;
	read_unlock_bh(&neigh->lock);

	NLA_PUT_U32(skb, NDA_PROBES, atomic_read(&neigh->probes));
	NLA_PUT(skb, NDA_CACHEINFO, sizeof(ci), &ci);

	return nlmsg_end(skb, nlh);

nla_put_failure:
	return nlmsg_cancel(skb, nlh);
}


static int neigh_dump_table(struct neigh_table *tbl, struct sk_buff *skb,
			    struct netlink_callback *cb)
{
	struct neighbour *n;
	int rc, h, s_h = cb->args[1];
	int idx, s_idx = idx = cb->args[2];

	read_lock_bh(&tbl->lock);
	for (h = 0; h <= tbl->hash_mask; h++) {
		if (h < s_h)
			continue;
		if (h > s_h)
			s_idx = 0;
		for (n = tbl->hash_buckets[h], idx = 0; n; n = n->next, idx++) {
			if (idx < s_idx)
				continue;
			if (neigh_fill_info(skb, n, NETLINK_CB(cb->skb).pid,
					    cb->nlh->nlmsg_seq,
					    RTM_NEWNEIGH,
					    NLM_F_MULTI) <= 0) {
				read_unlock_bh(&tbl->lock);
				rc = -1;
				goto out;
			}
		}
	}
	read_unlock_bh(&tbl->lock);
	rc = skb->len;
out:
	cb->args[1] = h;
	cb->args[2] = idx;
	return rc;
}

int neigh_dump_info(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct neigh_table *tbl;
	int t, family, s_t;

	read_lock(&neigh_tbl_lock);
	family = ((struct rtgenmsg *) nlmsg_data(cb->nlh))->rtgen_family;
	s_t = cb->args[0];

	for (tbl = neigh_tables, t = 0; tbl; tbl = tbl->next, t++) {
		if (t < s_t || (family && tbl->family != family))
			continue;
		if (t > s_t)
			memset(&cb->args[1], 0, sizeof(cb->args) -
						sizeof(cb->args[0]));
		if (neigh_dump_table(tbl, skb, cb) < 0)
			break;
	}
	read_unlock(&neigh_tbl_lock);

	cb->args[0] = t;
	return skb->len;
}

void neigh_for_each(struct neigh_table *tbl, void (*cb)(struct neighbour *, void *), void *cookie)
{
	int chain;

	read_lock_bh(&tbl->lock);
	for (chain = 0; chain <= tbl->hash_mask; chain++) {
		struct neighbour *n;

		for (n = tbl->hash_buckets[chain]; n; n = n->next)
			cb(n, cookie);
	}
	read_unlock_bh(&tbl->lock);
}
EXPORT_SYMBOL(neigh_for_each);

/* The tbl->lock must be held as a writer and BH disabled. */
void __neigh_for_each_release(struct neigh_table *tbl,
			      int (*cb)(struct neighbour *))
{
	int chain;

	for (chain = 0; chain <= tbl->hash_mask; chain++) {
		struct neighbour *n, **np;

		np = &tbl->hash_buckets[chain];
		while ((n = *np) != NULL) {
			int release;

			write_lock(&n->lock);
			release = cb(n);
			if (release) {
				*np = n->next;
				n->dead = 1;
			} else
				np = &n->next;
			write_unlock(&n->lock);
			if (release)
				neigh_release(n);
		}
	}
}
EXPORT_SYMBOL(__neigh_for_each_release);

#ifdef CONFIG_PROC_FS

static struct neighbour *neigh_get_first(struct seq_file *seq)
{
	struct neigh_seq_state *state = seq->private;
	struct neigh_table *tbl = state->tbl;
	struct neighbour *n = NULL;
	int bucket = state->bucket;

	state->flags &= ~NEIGH_SEQ_IS_PNEIGH;
	for (bucket = 0; bucket <= tbl->hash_mask; bucket++) {
		n = tbl->hash_buckets[bucket];

		while (n) {
			if (state->neigh_sub_iter) {
				loff_t fakep = 0;
				void *v;

				v = state->neigh_sub_iter(state, n, &fakep);
				if (!v)
					goto next;
			}
			if (!(state->flags & NEIGH_SEQ_SKIP_NOARP))
				break;
			if (n->nud_state & ~NUD_NOARP)
				break;
		next:
			n = n->next;
		}

		if (n)
			break;
	}
	state->bucket = bucket;

	return n;
}

static struct neighbour *neigh_get_next(struct seq_file *seq,
					struct neighbour *n,
					loff_t *pos)
{
	struct neigh_seq_state *state = seq->private;
	struct neigh_table *tbl = state->tbl;

	if (state->neigh_sub_iter) {
		void *v = state->neigh_sub_iter(state, n, pos);
		if (v)
			return n;
	}
	n = n->next;

	while (1) {
		while (n) {
			if (state->neigh_sub_iter) {
				void *v = state->neigh_sub_iter(state, n, pos);
				if (v)
					return n;
				goto next;
			}
			if (!(state->flags & NEIGH_SEQ_SKIP_NOARP))
				break;

			if (n->nud_state & ~NUD_NOARP)
				break;
		next:
			n = n->next;
		}

		if (n)
			break;

		if (++state->bucket > tbl->hash_mask)
			break;

		n = tbl->hash_buckets[state->bucket];
	}

	if (n && pos)
		--(*pos);
	return n;
}

static struct neighbour *neigh_get_idx(struct seq_file *seq, loff_t *pos)
{
	struct neighbour *n = neigh_get_first(seq);

	if (n) {
		while (*pos) {
			n = neigh_get_next(seq, n, pos);
			if (!n)
				break;
		}
	}
	return *pos ? NULL : n;
}

static struct pneigh_entry *pneigh_get_first(struct seq_file *seq)
{
	struct neigh_seq_state *state = seq->private;
	struct neigh_table *tbl = state->tbl;
	struct pneigh_entry *pn = NULL;
	int bucket = state->bucket;

	state->flags |= NEIGH_SEQ_IS_PNEIGH;
	for (bucket = 0; bucket <= PNEIGH_HASHMASK; bucket++) {
		pn = tbl->phash_buckets[bucket];
		if (pn)
			break;
	}
	state->bucket = bucket;

	return pn;
}

static struct pneigh_entry *pneigh_get_next(struct seq_file *seq,
					    struct pneigh_entry *pn,
					    loff_t *pos)
{
	struct neigh_seq_state *state = seq->private;
	struct neigh_table *tbl = state->tbl;

	pn = pn->next;
	while (!pn) {
		if (++state->bucket > PNEIGH_HASHMASK)
			break;
		pn = tbl->phash_buckets[state->bucket];
		if (pn)
			break;
	}

	if (pn && pos)
		--(*pos);

	return pn;
}

static struct pneigh_entry *pneigh_get_idx(struct seq_file *seq, loff_t *pos)
{
	struct pneigh_entry *pn = pneigh_get_first(seq);

	if (pn) {
		while (*pos) {
			pn = pneigh_get_next(seq, pn, pos);
			if (!pn)
				break;
		}
	}
	return *pos ? NULL : pn;
}

static void *neigh_get_idx_any(struct seq_file *seq, loff_t *pos)
{
	struct neigh_seq_state *state = seq->private;
	void *rc;

	rc = neigh_get_idx(seq, pos);
	if (!rc && !(state->flags & NEIGH_SEQ_NEIGH_ONLY))
		rc = pneigh_get_idx(seq, pos);

	return rc;
}

void *neigh_seq_start(struct seq_file *seq, loff_t *pos, struct neigh_table *tbl, unsigned int neigh_seq_flags)
{
	struct neigh_seq_state *state = seq->private;
	loff_t pos_minus_one;

	state->tbl = tbl;
	state->bucket = 0;
	state->flags = (neigh_seq_flags & ~NEIGH_SEQ_IS_PNEIGH);

	read_lock_bh(&tbl->lock);

	pos_minus_one = *pos - 1;
	return *pos ? neigh_get_idx_any(seq, &pos_minus_one) : SEQ_START_TOKEN;
}
EXPORT_SYMBOL(neigh_seq_start);

void *neigh_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct neigh_seq_state *state;
	void *rc;

	if (v == SEQ_START_TOKEN) {
		rc = neigh_get_idx(seq, pos);
		goto out;
	}

	state = seq->private;
	if (!(state->flags & NEIGH_SEQ_IS_PNEIGH)) {
		rc = neigh_get_next(seq, v, NULL);
		if (rc)
			goto out;
		if (!(state->flags & NEIGH_SEQ_NEIGH_ONLY))
			rc = pneigh_get_first(seq);
	} else {
		BUG_ON(state->flags & NEIGH_SEQ_NEIGH_ONLY);
		rc = pneigh_get_next(seq, v, NULL);
	}
out:
	++(*pos);
	return rc;
}
EXPORT_SYMBOL(neigh_seq_next);

void neigh_seq_stop(struct seq_file *seq, void *v)
{
	struct neigh_seq_state *state = seq->private;
	struct neigh_table *tbl = state->tbl;

	read_unlock_bh(&tbl->lock);
}
EXPORT_SYMBOL(neigh_seq_stop);

/* statistics via seq_file */

static void *neigh_stat_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct proc_dir_entry *pde = seq->private;
	struct neigh_table *tbl = pde->data;
	int cpu;

	if (*pos == 0)
		return SEQ_START_TOKEN;
	
	for (cpu = *pos-1; cpu < NR_CPUS; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu+1;
		return per_cpu_ptr(tbl->stats, cpu);
	}
	return NULL;
}

static void *neigh_stat_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct proc_dir_entry *pde = seq->private;
	struct neigh_table *tbl = pde->data;
	int cpu;

	for (cpu = *pos; cpu < NR_CPUS; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu+1;
		return per_cpu_ptr(tbl->stats, cpu);
	}
	return NULL;
}

static void neigh_stat_seq_stop(struct seq_file *seq, void *v)
{

}

static int neigh_stat_seq_show(struct seq_file *seq, void *v)
{
	struct proc_dir_entry *pde = seq->private;
	struct neigh_table *tbl = pde->data;
	struct neigh_statistics *st = v;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "entries  allocs destroys hash_grows  lookups hits  res_failed  rcv_probes_mcast rcv_probes_ucast  periodic_gc_runs forced_gc_runs\n");
		return 0;
	}

	seq_printf(seq, "%08x  %08lx %08lx %08lx  %08lx %08lx  %08lx  "
			"%08lx %08lx  %08lx %08lx\n",
		   atomic_read(&tbl->entries),

		   st->allocs,
		   st->destroys,
		   st->hash_grows,

		   st->lookups,
		   st->hits,

		   st->res_failed,

		   st->rcv_probes_mcast,
		   st->rcv_probes_ucast,

		   st->periodic_gc_runs,
		   st->forced_gc_runs
		   );

	return 0;
}

static struct seq_operations neigh_stat_seq_ops = {
	.start	= neigh_stat_seq_start,
	.next	= neigh_stat_seq_next,
	.stop	= neigh_stat_seq_stop,
	.show	= neigh_stat_seq_show,
};

static int neigh_stat_seq_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &neigh_stat_seq_ops);

	if (!ret) {
		struct seq_file *sf = file->private_data;
		sf->private = PDE(inode);
	}
	return ret;
};

static struct file_operations neigh_stat_seq_fops = {
	.owner	 = THIS_MODULE,
	.open 	 = neigh_stat_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

#endif /* CONFIG_PROC_FS */

#ifdef CONFIG_ARPD
static inline size_t neigh_nlmsg_size(void)
{
	return NLMSG_ALIGN(sizeof(struct ndmsg))
	       + nla_total_size(MAX_ADDR_LEN) /* NDA_DST */
	       + nla_total_size(MAX_ADDR_LEN) /* NDA_LLADDR */
	       + nla_total_size(sizeof(struct nda_cacheinfo))
	       + nla_total_size(4); /* NDA_PROBES */
}

static void __neigh_notify(struct neighbour *n, int type, int flags)
{
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = nlmsg_new(neigh_nlmsg_size(), GFP_ATOMIC);
	if (skb == NULL)
		goto errout;

	err = neigh_fill_info(skb, n, 0, 0, type, flags);
	/* failure implies BUG in neigh_nlmsg_size() */
	BUG_ON(err < 0);

	err = rtnl_notify(skb, 0, RTNLGRP_NEIGH, NULL, GFP_ATOMIC);
errout:
	if (err < 0)
		rtnl_set_sk_err(RTNLGRP_NEIGH, err);
}

void neigh_app_ns(struct neighbour *n)
{
	__neigh_notify(n, RTM_GETNEIGH, NLM_F_REQUEST);
}

static void neigh_app_notify(struct neighbour *n)
{
	__neigh_notify(n, RTM_NEWNEIGH, 0);
}

#endif /* CONFIG_ARPD */

#ifdef CONFIG_SYSCTL

static struct neigh_sysctl_table {
	struct ctl_table_header *sysctl_header;
	ctl_table		neigh_vars[__NET_NEIGH_MAX];
	ctl_table		neigh_dev[2];
	ctl_table		neigh_neigh_dir[2];
	ctl_table		neigh_proto_dir[2];
	ctl_table		neigh_root_dir[2];
} neigh_sysctl_template __read_mostly = {
	.neigh_vars = {
		{
			.ctl_name	= NET_NEIGH_MCAST_SOLICIT,
			.procname	= "mcast_solicit",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_UCAST_SOLICIT,
			.procname	= "ucast_solicit",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_APP_SOLICIT,
			.procname	= "app_solicit",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_RETRANS_TIME,
			.procname	= "retrans_time",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_userhz_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_REACHABLE_TIME,
			.procname	= "base_reachable_time",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_jiffies,
			.strategy	= &sysctl_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_DELAY_PROBE_TIME,
			.procname	= "delay_first_probe_time",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_jiffies,
			.strategy	= &sysctl_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_GC_STALE_TIME,
			.procname	= "gc_stale_time",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_jiffies,
			.strategy	= &sysctl_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_UNRES_QLEN,
			.procname	= "unres_qlen",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_PROXY_QLEN,
			.procname	= "proxy_qlen",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_ANYCAST_DELAY,
			.procname	= "anycast_delay",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_userhz_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_PROXY_DELAY,
			.procname	= "proxy_delay",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_userhz_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_LOCKTIME,
			.procname	= "locktime",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_userhz_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_GC_INTERVAL,
			.procname	= "gc_interval",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_jiffies,
			.strategy	= &sysctl_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_GC_THRESH1,
			.procname	= "gc_thresh1",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_GC_THRESH2,
			.procname	= "gc_thresh2",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_GC_THRESH3,
			.procname	= "gc_thresh3",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_RETRANS_TIME_MS,
			.procname	= "retrans_time_ms",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_ms_jiffies,
			.strategy	= &sysctl_ms_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_REACHABLE_TIME_MS,
			.procname	= "base_reachable_time_ms",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_ms_jiffies,
			.strategy	= &sysctl_ms_jiffies,
		},
	},
	.neigh_dev = {
		{
			.ctl_name	= NET_PROTO_CONF_DEFAULT,
			.procname	= "default",
			.mode		= 0555,
		},
	},
	.neigh_neigh_dir = {
		{
			.procname	= "neigh",
			.mode		= 0555,
		},
	},
	.neigh_proto_dir = {
		{
			.mode		= 0555,
		},
	},
	.neigh_root_dir = {
		{
			.ctl_name	= CTL_NET,
			.procname	= "net",
			.mode		= 0555,
		},
	},
};

int neigh_sysctl_register(struct net_device *dev, struct neigh_parms *p,
			  int p_id, int pdev_id, char *p_name, 
			  proc_handler *handler, ctl_handler *strategy)
{
	struct neigh_sysctl_table *t = kmemdup(&neigh_sysctl_template,
					       sizeof(*t), GFP_KERNEL);
	const char *dev_name_source = NULL;
	char *dev_name = NULL;
	int err = 0;

	if (!t)
		return -ENOBUFS;
	t->neigh_vars[0].data  = &p->mcast_probes;
	t->neigh_vars[1].data  = &p->ucast_probes;
	t->neigh_vars[2].data  = &p->app_probes;
	t->neigh_vars[3].data  = &p->retrans_time;
	t->neigh_vars[4].data  = &p->base_reachable_time;
	t->neigh_vars[5].data  = &p->delay_probe_time;
	t->neigh_vars[6].data  = &p->gc_staletime;
	t->neigh_vars[7].data  = &p->queue_len;
	t->neigh_vars[8].data  = &p->proxy_qlen;
	t->neigh_vars[9].data  = &p->anycast_delay;
	t->neigh_vars[10].data = &p->proxy_delay;
	t->neigh_vars[11].data = &p->locktime;

	if (dev) {
		dev_name_source = dev->name;
		t->neigh_dev[0].ctl_name = dev->ifindex;
		t->neigh_vars[12].procname = NULL;
		t->neigh_vars[13].procname = NULL;
		t->neigh_vars[14].procname = NULL;
		t->neigh_vars[15].procname = NULL;
	} else {
 		dev_name_source = t->neigh_dev[0].procname;
		t->neigh_vars[12].data = (int *)(p + 1);
		t->neigh_vars[13].data = (int *)(p + 1) + 1;
		t->neigh_vars[14].data = (int *)(p + 1) + 2;
		t->neigh_vars[15].data = (int *)(p + 1) + 3;
	}

	t->neigh_vars[16].data  = &p->retrans_time;
	t->neigh_vars[17].data  = &p->base_reachable_time;

	if (handler || strategy) {
		/* RetransTime */
		t->neigh_vars[3].proc_handler = handler;
		t->neigh_vars[3].strategy = strategy;
		t->neigh_vars[3].extra1 = dev;
		/* ReachableTime */
		t->neigh_vars[4].proc_handler = handler;
		t->neigh_vars[4].strategy = strategy;
		t->neigh_vars[4].extra1 = dev;
		/* RetransTime (in milliseconds)*/
		t->neigh_vars[16].proc_handler = handler;
		t->neigh_vars[16].strategy = strategy;
		t->neigh_vars[16].extra1 = dev;
		/* ReachableTime (in milliseconds) */
		t->neigh_vars[17].proc_handler = handler;
		t->neigh_vars[17].strategy = strategy;
		t->neigh_vars[17].extra1 = dev;
	}

	dev_name = kstrdup(dev_name_source, GFP_KERNEL);
	if (!dev_name) {
		err = -ENOBUFS;
		goto free;
	}

 	t->neigh_dev[0].procname = dev_name;

	t->neigh_neigh_dir[0].ctl_name = pdev_id;

	t->neigh_proto_dir[0].procname = p_name;
	t->neigh_proto_dir[0].ctl_name = p_id;

	t->neigh_dev[0].child	       = t->neigh_vars;
	t->neigh_neigh_dir[0].child    = t->neigh_dev;
	t->neigh_proto_dir[0].child    = t->neigh_neigh_dir;
	t->neigh_root_dir[0].child     = t->neigh_proto_dir;

	t->sysctl_header = register_sysctl_table(t->neigh_root_dir, 0);
	if (!t->sysctl_header) {
		err = -ENOBUFS;
		goto free_procname;
	}
	p->sysctl_table = t;
	return 0;

	/* error path */
 free_procname:
	kfree(dev_name);
 free:
	kfree(t);

	return err;
}

void neigh_sysctl_unregister(struct neigh_parms *p)
{
	if (p->sysctl_table) {
		struct neigh_sysctl_table *t = p->sysctl_table;
		p->sysctl_table = NULL;
		unregister_sysctl_table(t->sysctl_header);
		kfree(t->neigh_dev[0].procname);
		kfree(t);
	}
}

#endif	/* CONFIG_SYSCTL */

EXPORT_SYMBOL(__neigh_event_send);
EXPORT_SYMBOL(neigh_changeaddr);
EXPORT_SYMBOL(neigh_compat_output);
EXPORT_SYMBOL(neigh_connected_output);
EXPORT_SYMBOL(neigh_create);
EXPORT_SYMBOL(neigh_delete);
EXPORT_SYMBOL(neigh_destroy);
EXPORT_SYMBOL(neigh_dump_info);
EXPORT_SYMBOL(neigh_event_ns);
EXPORT_SYMBOL(neigh_ifdown);
EXPORT_SYMBOL(neigh_lookup);
EXPORT_SYMBOL(neigh_lookup_nodev);
EXPORT_SYMBOL(neigh_parms_alloc);
EXPORT_SYMBOL(neigh_parms_release);
EXPORT_SYMBOL(neigh_rand_reach_time);
EXPORT_SYMBOL(neigh_resolve_output);
EXPORT_SYMBOL(neigh_table_clear);
EXPORT_SYMBOL(neigh_table_init);
EXPORT_SYMBOL(neigh_table_init_no_netlink);
EXPORT_SYMBOL(neigh_update);
EXPORT_SYMBOL(pneigh_enqueue);
EXPORT_SYMBOL(pneigh_lookup);

#ifdef CONFIG_ARPD
EXPORT_SYMBOL(neigh_app_ns);
#endif
#ifdef CONFIG_SYSCTL
EXPORT_SYMBOL(neigh_sysctl_register);
EXPORT_SYMBOL(neigh_sysctl_unregister);
#endif
