#ifndef __NET_SCHED_GENERIC_H
#define __NET_SCHED_GENERIC_H

#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <net/gen_stats.h>

struct Qdisc_ops;
struct qdisc_walker;
struct tcf_walker;
struct module;
/* 队列速率统计描述控制块 */
struct qdisc_rate_table
{
	struct tc_ratespec rate;
	u32		data[256];
	struct qdisc_rate_table *next;
	int		refcnt;/* 引用计数 */
};

struct Qdisc
{
	int 			(*enqueue)(struct sk_buff *skb, struct Qdisc *dev);/* 入队函数 */
	struct sk_buff *	(*dequeue)(struct Qdisc *dev);/* 出队函数 */
	unsigned		flags;
#define TCQ_F_BUILTIN	1
#define TCQ_F_THROTTLED	2/* 扼杀，表明已经超过了限制，不在收包 */
#define TCQ_F_INGRESS	4
	int			padded;/* 填充字节数 */
	struct Qdisc_ops	*ops;/* 队列操作函数 */
	u32			handle;/* 规程句柄((parent)&TC_H_MAJ_MASK) */
	u32			parent;/* 与上面句柄一起使用，用于查找父规程 */
	atomic_t		refcnt;/* 引用计数 */
	struct sk_buff_head	q;/* 报文队列 */
	struct net_device	*dev;/* 队列所属设备 */
	struct list_head	list;/* 将所有队列穿起来 */

	struct gnet_stats_basic	bstats;/* 网络统计 */
	struct gnet_stats_queue	qstats;/* 队列统计 */
	struct gnet_stats_rate_est	rate_est;/* 速率评估 */
	spinlock_t		*stats_lock;/* 统计信息锁 */
	struct rcu_head 	q_rcu;/* 该规程的rcu保护结构体 */
	int			(*reshape_fail)(struct sk_buff *skb,
					struct Qdisc *q);/* 整形 */

	/* This field is deprecated, but it is still used by CBQ
	 * and it will live until better solution will be invented.
	 */
	struct Qdisc		*__parent;/* 父规则 */
};

struct Qdisc_class_ops
{
	/* Child qdisc manipulation */
	int			(*graft)(struct Qdisc *, unsigned long cl,
					struct Qdisc *, struct Qdisc **);
	struct Qdisc *		(*leaf)(struct Qdisc *, unsigned long cl);
	void			(*qlen_notify)(struct Qdisc *, unsigned long);

	/* Class manipulation routines */
	unsigned long		(*get)(struct Qdisc *, u32 classid);
	void			(*put)(struct Qdisc *, unsigned long);
	int			(*change)(struct Qdisc *, u32, u32,
					struct rtattr **, unsigned long *);
	int			(*delete)(struct Qdisc *, unsigned long);
	void			(*walk)(struct Qdisc *, struct qdisc_walker * arg);

	/* Filter manipulation */
	struct tcf_proto **	(*tcf_chain)(struct Qdisc *, unsigned long);
	unsigned long		(*bind_tcf)(struct Qdisc *, unsigned long,
					u32 classid);
	void			(*unbind_tcf)(struct Qdisc *, unsigned long);

	/* rtnetlink specific */
	int			(*dump)(struct Qdisc *, unsigned long,
					struct sk_buff *skb, struct tcmsg*);
	int			(*dump_stats)(struct Qdisc *, unsigned long,
					struct gnet_dump *);
};

struct Qdisc_ops
{
	struct Qdisc_ops	*next;/* 所有规程操作结构体链入到一个链表中 */
	struct Qdisc_class_ops	*cl_ops;/* 规程操作的类，规程如果不是一个最后的队列的话，需要操作该类 */
	char			id[IFNAMSIZ];
	int			priv_size;/* 规程中私有信息的大小 */

	int 			(*enqueue)(struct sk_buff *, struct Qdisc *);
	struct sk_buff *	(*dequeue)(struct Qdisc *);
	int 			(*requeue)(struct sk_buff *, struct Qdisc *);
	unsigned int		(*drop)(struct Qdisc *);

	int			(*init)(struct Qdisc *, struct rtattr *arg);
	void			(*reset)(struct Qdisc *);
	void			(*destroy)(struct Qdisc *);
	int			(*change)(struct Qdisc *, struct rtattr *arg);

	int			(*dump)(struct Qdisc *, struct sk_buff *);
	int			(*dump_stats)(struct Qdisc *, struct gnet_dump *);

	struct module		*owner;
};


struct tcf_result
{
	unsigned long	class;
	u32		classid;
};

struct tcf_proto_ops
{
	struct tcf_proto_ops	*next;
	char			kind[IFNAMSIZ];

	int			(*classify)(struct sk_buff*, struct tcf_proto*,
					struct tcf_result *);
	int			(*init)(struct tcf_proto*);
	void			(*destroy)(struct tcf_proto*);

	unsigned long		(*get)(struct tcf_proto*, u32 handle);
	void			(*put)(struct tcf_proto*, unsigned long);
	int			(*change)(struct tcf_proto*, unsigned long,
					u32 handle, struct rtattr **,
					unsigned long *);
	int			(*delete)(struct tcf_proto*, unsigned long);
	void			(*walk)(struct tcf_proto*, struct tcf_walker *arg);

	/* rtnetlink specific */
	int			(*dump)(struct tcf_proto*, unsigned long,
					struct sk_buff *skb, struct tcmsg*);

	struct module		*owner;
};

struct tcf_proto
{
	/* Fast access part */
	struct tcf_proto	*next;
	void			*root;
	int			(*classify)(struct sk_buff*, struct tcf_proto*,
					struct tcf_result *);
	__be16			protocol;

	/* All the rest */
	u32			prio;
	u32			classid;
	struct Qdisc		*q;
	void			*data;
	struct tcf_proto_ops	*ops;
};


extern void qdisc_lock_tree(struct net_device *dev);
extern void qdisc_unlock_tree(struct net_device *dev);

#define sch_tree_lock(q)	qdisc_lock_tree((q)->dev)
#define sch_tree_unlock(q)	qdisc_unlock_tree((q)->dev)
#define tcf_tree_lock(tp)	qdisc_lock_tree((tp)->q->dev)
#define tcf_tree_unlock(tp)	qdisc_unlock_tree((tp)->q->dev)

extern struct Qdisc noop_qdisc;
extern struct Qdisc_ops noop_qdisc_ops;

extern void dev_init_scheduler(struct net_device *dev);
extern void dev_shutdown(struct net_device *dev);
extern void dev_activate(struct net_device *dev);
extern void dev_deactivate(struct net_device *dev);
extern void qdisc_reset(struct Qdisc *qdisc);
extern void qdisc_destroy(struct Qdisc *qdisc);
extern void qdisc_tree_decrease_qlen(struct Qdisc *qdisc, unsigned int n);
extern struct Qdisc *qdisc_alloc(struct net_device *dev, struct Qdisc_ops *ops);
extern struct Qdisc *qdisc_create_dflt(struct net_device *dev,
				       struct Qdisc_ops *ops, u32 parentid);

static inline void
tcf_destroy(struct tcf_proto *tp)
{
	tp->ops->destroy(tp);
	module_put(tp->ops->owner);
	kfree(tp);
}

static inline int __qdisc_enqueue_tail(struct sk_buff *skb, struct Qdisc *sch,
				       struct sk_buff_head *list)
{
	__skb_queue_tail(list, skb);
	sch->qstats.backlog += skb->len;
	sch->bstats.bytes += skb->len;
	sch->bstats.packets++;

	return NET_XMIT_SUCCESS;
}

static inline int qdisc_enqueue_tail(struct sk_buff *skb, struct Qdisc *sch)
{
	return __qdisc_enqueue_tail(skb, sch, &sch->q);
}

static inline struct sk_buff *__qdisc_dequeue_head(struct Qdisc *sch,
						   struct sk_buff_head *list)
{
	struct sk_buff *skb = __skb_dequeue(list);

	if (likely(skb != NULL))
		sch->qstats.backlog -= skb->len;/* 减去 */

	return skb;
}

static inline struct sk_buff *qdisc_dequeue_head(struct Qdisc *sch)
{
	return __qdisc_dequeue_head(sch, &sch->q);
}

static inline struct sk_buff *__qdisc_dequeue_tail(struct Qdisc *sch,
						   struct sk_buff_head *list)
{
	struct sk_buff *skb = __skb_dequeue_tail(list);

	if (likely(skb != NULL))
		sch->qstats.backlog -= skb->len;

	return skb;
}

static inline struct sk_buff *qdisc_dequeue_tail(struct Qdisc *sch)
{
	return __qdisc_dequeue_tail(sch, &sch->q);
}

static inline int __qdisc_requeue(struct sk_buff *skb, struct Qdisc *sch,
				  struct sk_buff_head *list)
{
	__skb_queue_head(list, skb);
	sch->qstats.backlog += skb->len;
	sch->qstats.requeues++;/* 重入队列统计 */

	return NET_XMIT_SUCCESS;
}

static inline int qdisc_requeue(struct sk_buff *skb, struct Qdisc *sch)
{
	return __qdisc_requeue(skb, sch, &sch->q);
}

static inline void __qdisc_reset_queue(struct Qdisc *sch,
				       struct sk_buff_head *list)
{
	/*
	 * We do not know the backlog in bytes of this list, it
	 * is up to the caller to correct it
	 * 清空队列的所有报文并将其删除释放其内存
	 */
	skb_queue_purge(list);
}

static inline void qdisc_reset_queue(struct Qdisc *sch)
{
	__qdisc_reset_queue(sch, &sch->q);
	sch->qstats.backlog = 0;
}
/* 出队报文丢弃 */
static inline unsigned int __qdisc_queue_drop(struct Qdisc *sch,
					      struct sk_buff_head *list)
{
	struct sk_buff *skb = __qdisc_dequeue_tail(sch, list);

	if (likely(skb != NULL)) {
		unsigned int len = skb->len;
		kfree_skb(skb);
		return len;
	}

	return 0;
}

static inline unsigned int qdisc_queue_drop(struct Qdisc *sch)
{
	return __qdisc_queue_drop(sch, &sch->q);
}

static inline int qdisc_drop(struct sk_buff *skb, struct Qdisc *sch)
{
	kfree_skb(skb);
	sch->qstats.drops++;

	return NET_XMIT_DROP;
}

static inline int qdisc_reshape_fail(struct sk_buff *skb, struct Qdisc *sch)
{
	sch->qstats.drops++;

#ifdef CONFIG_NET_CLS_POLICE
	if (sch->reshape_fail == NULL || sch->reshape_fail(skb, sch))
		goto drop;

	return NET_XMIT_SUCCESS;

drop:
#endif
	kfree_skb(skb);
	return NET_XMIT_DROP;
}

#endif
