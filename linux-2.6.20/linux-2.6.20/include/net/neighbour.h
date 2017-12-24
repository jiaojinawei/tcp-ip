#ifndef _NET_NEIGHBOUR_H
#define _NET_NEIGHBOUR_H

#include <linux/neighbour.h>

/*
 *	Generic neighbour manipulation
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Alexey Kuznetsov	<kuznet@ms2.inr.ac.ru>
 *
 * 	Changes:
 *
 *	Harald Welte:		<laforge@gnumonks.org>
 *		- Add neighbour cache statistics like rtstat
 */

#include <asm/atomic.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>

#include <linux/err.h>
#include <linux/sysctl.h>
/* 定时器状态，该状态下存在定时器 */
#define NUD_IN_TIMER	(NUD_INCOMPLETE|NUD_REACHABLE|NUD_DELAY|NUD_PROBE)
/* 有效表项 */
#define NUD_VALID	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE|NUD_PROBE|NUD_STALE|NUD_DELAY)
/* 已经连接状态，在改状态下可以直接将报文发给该邻居 */
#define NUD_CONNECTED	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE)

struct neighbour;

struct neigh_parms
{
	struct net_device *dev;
	struct neigh_parms *next;
	int	(*neigh_setup)(struct neighbour *);
	void	(*neigh_destructor)(struct neighbour *);
	struct neigh_table *tbl;

	void	*sysctl_table;

	int dead;
	atomic_t refcnt;/* 邻居表的引用计数 */
	struct rcu_head rcu_head;/* 保护邻居表的rcu锁 */

	int	base_reachable_time;
	int	retrans_time;
	int	gc_staletime;
	int	reachable_time;
	int	delay_probe_time;

	int	queue_len;
	int	ucast_probes;
	int	app_probes;
	int	mcast_probes;
	int	anycast_delay;
	int	proxy_delay;
	int	proxy_qlen;
	int	locktime;
};
/* 邻居表统计信息，使用时申明为每cpu变量 */
struct neigh_statistics
{
	unsigned long allocs;		/* number of allocated neighs */
	unsigned long destroys;		/* number of destroyed neighs */
	unsigned long hash_grows;	/* number of hash resizes */

	unsigned long res_failed;	/* nomber of failed resolutions */

	unsigned long lookups;		/* number of lookups */
	unsigned long hits;		/* number of hits (among lookups) */

	unsigned long rcv_probes_mcast;	/* number of received mcast ipv6 */
	unsigned long rcv_probes_ucast; /* number of received ucast ipv6 */

	unsigned long periodic_gc_runs;	/* number of periodic GC runs 周期垃圾回收函数运行次数 */
	unsigned long forced_gc_runs;	/* number of forced GC runs 强制垃圾回收函数运行次数*/
};

#define NEIGH_CACHE_STAT_INC(tbl, field)				\
	do {								\
		preempt_disable();					\
		(per_cpu_ptr((tbl)->stats, smp_processor_id())->field)++; \
		preempt_enable();					\
	} while (0)
/* 邻居子系统描述控制块 */
struct neighbour
{
	struct neighbour	*next;/* 所有邻居表项形成一条单链表 */
	struct neigh_table	*tbl; /* 指向其所属邻居表 */
	struct neigh_parms	*parms;/* 指向了所属邻居表的参数 */
	struct net_device		*dev;/* 指向的网络设备 */
	unsigned long		used;/* 上次使用时间 */
	unsigned long		confirmed;/* 最近一次确认可达性时间，一般收到邻居的报文 */
	unsigned long		updated;/* 邻居状态发生变化时更新 */
	__u8			flags;
	__u8			nud_state;/* 邻居表项状态 */
	__u8			type;
	__u8			dead;/* 生存标志，当该值为1时，表示该表项正在被删除 */
	atomic_t		probes;/* 尝试发送请求报文，但未能得到应答的次数 */
	rwlock_t		lock;/* 读写锁 */
	unsigned char		ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))];/* 表项硬件地址 */
	struct hh_cache		*hh;
	atomic_t		refcnt;/* 引用计数 */
	int			(*output)(struct sk_buff *skb);/* 报文输出函数 */
	struct sk_buff_head	arp_queue;/* 当邻居表项处于无效状态时，用来缓存需要输出报文队列 */
	struct timer_list	timer;/* 邻居定时器 */
	struct neigh_ops	*ops;/* 邻居操作函数 */
	u8			primary_key[0];/* 三层地址，动态分配的，一般对于ipv4来说是4个字节 */
};

struct neigh_ops
{
	int			family;/* 所属家族 */	
	/* 发送请求报文函数。当第一次发送报文时，会先将报文缓存到arp_queue中，然后调用该函数发送报文 */
	void			(*solicit)(struct neighbour *, struct sk_buff*);
	/* 当邻居表项缓存着未发送的报文，而该邻居表项不可达时，会调用该函数给三层发送一个
	报告错误报文，arp是发送一个icmp不可达差错报文 */
	void			(*error_report)(struct neighbour *, struct sk_buff*);
	/* 最通用的输出函数 */
	int			(*output)(struct sk_buff*);
	/* 可达输出报文 */
	int			(*connected_output)(struct sk_buff*);
	/* 缓存了二层头后，调用该函数输出 */
	int			(*hh_output)(struct sk_buff*);
	/* 准备好二层头报文后调用该函数输出 */
	int			(*queue_xmit)(struct sk_buff*);
};

struct pneigh_entry
{
	struct pneigh_entry	*next;
	struct net_device		*dev;
	u8			flags;
	u8			key[0];
};

/*
 *	neighbour table manipulation
 */

/* 邻居表操作控制块 */
struct neigh_table
{
	struct neigh_table	*next;/* 指向下一个邻居表 */
	int			family;/* 协议族 */
	int			entry_size;/* 邻居表项的大小 */
	int			key_len;/* 三层地址长度 */
	__u32			(*hash)(const void *pkey, const struct net_device *);/* 将key进行hash的函数 */
	int			(*constructor)(struct neighbour *);
	int			(*pconstructor)(struct pneigh_entry *);
	void			(*pdestructor)(struct pneigh_entry *);
	void			(*proxy_redo)(struct sk_buff *skb);
	char			*id;/* 邻居表项的cache名字，对于arp来说就是arp_cache */
	struct neigh_parms	parms;/* 邻居参数，不同设备的参数不同 */
	/* HACK. gc_* shoul follow parms without a gap! */
	int			gc_interval;/* 垃圾回收时间 */
	int			gc_thresh1;/* 1级阈值，小于该值，不进行垃圾回收 */
	int			gc_thresh2;/* 2级阈值，大于该阈值时，新建的邻居表项如果超过5秒未刷新的话，删除 */
	int			gc_thresh3;/* 3级阈值，大于该值，每次新建表项必须进行强制删除 */
	unsigned long		last_flush;/* 上次垃圾清洗时间 */
	struct timer_list 	gc_timer;/* 垃圾回收定时器 */
	struct timer_list 	proxy_timer;/* 代理arp定时器 */
	struct sk_buff_head	proxy_queue;/* 对于收到的代理的arp请求，缓存到该链表中，在定时器中处理 */
	atomic_t		entries;/* 表项数目 */
	rwlock_t		lock;/* 保护锁 */
	unsigned long		last_rand;/* 用于记录邻居表中neigh_parms最近一次更新时间 */
	struct kmem_cache		*kmem_cachep;/* 邻居表cache */
	struct neigh_statistics	*stats;/* 邻居表统计信息 */
	struct neighbour	**hash_buckets;/* 邻居表hash桶 */
	unsigned int		hash_mask;/* hash桶掩码 */
	__u32			hash_rnd;/* 用于计算hash的随机值，避免攻击 */
	unsigned int		hash_chain_gc;/* 保存下一次将进行垃圾回收的桶的序列号 */
	struct pneigh_entry	**phash_buckets;/* 代理邻居hash表桶 */
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry	*pde;
#endif
};

/* flags for neigh_update() */
#define NEIGH_UPDATE_F_OVERRIDE			0x00000001
#define NEIGH_UPDATE_F_WEAK_OVERRIDE		0x00000002
#define NEIGH_UPDATE_F_OVERRIDE_ISROUTER	0x00000004
#define NEIGH_UPDATE_F_ISROUTER			0x40000000
#define NEIGH_UPDATE_F_ADMIN			0x80000000

extern void			neigh_table_init(struct neigh_table *tbl);
extern void			neigh_table_init_no_netlink(struct neigh_table *tbl);
extern int			neigh_table_clear(struct neigh_table *tbl);
extern struct neighbour *	neigh_lookup(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern struct neighbour *	neigh_lookup_nodev(struct neigh_table *tbl,
						   const void *pkey);
extern struct neighbour *	neigh_create(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern void			neigh_destroy(struct neighbour *neigh);
extern int			__neigh_event_send(struct neighbour *neigh, struct sk_buff *skb);
extern int			neigh_update(struct neighbour *neigh, const u8 *lladdr, u8 new, 
					     u32 flags);
extern void			neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_ifdown(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_resolve_output(struct sk_buff *skb);
extern int			neigh_connected_output(struct sk_buff *skb);
extern int			neigh_compat_output(struct sk_buff *skb);
extern struct neighbour 	*neigh_event_ns(struct neigh_table *tbl,
						u8 *lladdr, void *saddr,
						struct net_device *dev);

extern struct neigh_parms	*neigh_parms_alloc(struct net_device *dev, struct neigh_table *tbl);
extern void			neigh_parms_release(struct neigh_table *tbl, struct neigh_parms *parms);
extern void			neigh_parms_destroy(struct neigh_parms *parms);
extern unsigned long		neigh_rand_reach_time(unsigned long base);

extern void			pneigh_enqueue(struct neigh_table *tbl, struct neigh_parms *p,
					       struct sk_buff *skb);
extern struct pneigh_entry	*pneigh_lookup(struct neigh_table *tbl, const void *key, struct net_device *dev, int creat);
extern int			pneigh_delete(struct neigh_table *tbl, const void *key, struct net_device *dev);

struct netlink_callback;
struct nlmsghdr;
extern int neigh_dump_info(struct sk_buff *skb, struct netlink_callback *cb);
extern int neigh_add(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg);
extern int neigh_delete(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg);
extern void neigh_app_ns(struct neighbour *n);

extern int neightbl_dump_info(struct sk_buff *skb, struct netlink_callback *cb);
extern int neightbl_set(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg);

extern void neigh_for_each(struct neigh_table *tbl, void (*cb)(struct neighbour *, void *), void *cookie);
extern void __neigh_for_each_release(struct neigh_table *tbl, int (*cb)(struct neighbour *));
extern void pneigh_for_each(struct neigh_table *tbl, void (*cb)(struct pneigh_entry *));

struct neigh_seq_state {
	struct neigh_table *tbl;
	void *(*neigh_sub_iter)(struct neigh_seq_state *state,
				struct neighbour *n, loff_t *pos);
	unsigned int bucket;
	unsigned int flags;
#define NEIGH_SEQ_NEIGH_ONLY	0x00000001
#define NEIGH_SEQ_IS_PNEIGH	0x00000002
#define NEIGH_SEQ_SKIP_NOARP	0x00000004
};
extern void *neigh_seq_start(struct seq_file *, loff_t *, struct neigh_table *, unsigned int);
extern void *neigh_seq_next(struct seq_file *, void *, loff_t *);
extern void neigh_seq_stop(struct seq_file *, void *);

extern int			neigh_sysctl_register(struct net_device *dev, 
						      struct neigh_parms *p,
						      int p_id, int pdev_id,
						      char *p_name,
						      proc_handler *proc_handler,
						      ctl_handler *strategy);
extern void			neigh_sysctl_unregister(struct neigh_parms *p);

static inline void __neigh_parms_put(struct neigh_parms *parms)
{
	atomic_dec(&parms->refcnt);
}

static inline void neigh_parms_put(struct neigh_parms *parms)
{
	if (atomic_dec_and_test(&parms->refcnt))
		neigh_parms_destroy(parms);
}

static inline struct neigh_parms *neigh_parms_clone(struct neigh_parms *parms)
{
	atomic_inc(&parms->refcnt);
	return parms;
}

/*
 *	Neighbour references
 */

static inline void neigh_release(struct neighbour *neigh)
{
	if (atomic_dec_and_test(&neigh->refcnt))
		neigh_destroy(neigh);
}

static inline struct neighbour * neigh_clone(struct neighbour *neigh)
{
	if (neigh)
		atomic_inc(&neigh->refcnt);
	return neigh;
}

#define neigh_hold(n)	atomic_inc(&(n)->refcnt)

static inline void neigh_confirm(struct neighbour *neigh)
{
	if (neigh)
		neigh->confirmed = jiffies;
}

static inline int neigh_is_connected(struct neighbour *neigh)
{
	return neigh->nud_state&NUD_CONNECTED;
}

static inline int neigh_is_valid(struct neighbour *neigh)
{
	return neigh->nud_state&NUD_VALID;
}

static inline int neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	neigh->used = jiffies;
	/* 如果不处于这几个状态，继续深度检测 */
	if (!(neigh->nud_state&(NUD_CONNECTED|NUD_DELAY|NUD_PROBE)))
		return __neigh_event_send(neigh, skb);
	return 0;
}

static inline int neigh_hh_output(struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned seq;
	int hh_len;

	do {
		int hh_alen;

		seq = read_seqbegin(&hh->hh_lock);
		hh_len = hh->hh_len;
		hh_alen = HH_DATA_ALIGN(hh_len);
		memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
	} while (read_seqretry(&hh->hh_lock, seq));

	skb_push(skb, hh_len);
	return hh->hh_output(skb);
}

static inline struct neighbour *
__neigh_lookup(struct neigh_table *tbl, const void *pkey, struct net_device *dev, int creat)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n || !creat)
		return n;

	n = neigh_create(tbl, pkey, dev);
	return IS_ERR(n) ? NULL : n;
}

static inline struct neighbour *
__neigh_lookup_errno(struct neigh_table *tbl, const void *pkey,
  struct net_device *dev)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n)
		return n;

	return neigh_create(tbl, pkey, dev);
}
/* 邻居表私有数据 */
struct neighbour_cb {
	unsigned long sched_next;
	unsigned int flags;
};

#define LOCALLY_ENQUEUED 0x1

#define NEIGH_CB(skb)	((struct neighbour_cb *)(skb)->cb)

#endif
