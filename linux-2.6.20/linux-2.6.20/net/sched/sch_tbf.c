/*
 * net/sched/sch_tbf.c	Token Bucket Filter queue.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *		Dmitry Torokhov <dtor@mail.ru> - allow attaching inner qdiscs -
 *						 original idea by Martin Devera
 *
 */

#include <linux/module.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/notifier.h>
#include <net/ip.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/pkt_sched.h>


/*	Simple Token Bucket Filter.
	=======================================

	SOURCE.
	-------

	None.

	Description.
	------------

	A data flow obeys TBF with rate R and depth B, if for any
	time interval t_i...t_f the number of transmitted bits
	does not exceed B + R*(t_f-t_i).

	Packetized version of this definition:
	The sequence of packets of sizes s_i served at moments t_i
	obeys TBF, if for any i<=k:

	s_i+....+s_k <= B + R*(t_k - t_i)

	Algorithm.
	----------

	Let N(t_i) be B/R initially and N(t) grow continuously with time as:

	N(t+delta) = min{B/R, N(t) + delta}

	If the first packet in queue has length S, it may be
	transmitted only at the time t_* when S/R <= N(t_*),
	and in this case N(t) jumps:

	N(t_* + 0) = N(t_* - 0) - S/R.



	Actually, QoS requires two TBF to be applied to a data stream.
	One of them controls steady state burst size, another
	one with rate P (peak rate) and depth M (equal to link MTU)
	limits bursts at a smaller time scale.

	It is easy to see that P>R, and B>M. If P is infinity, this double
	TBF is equivalent to a single one.

	When TBF works in reshaping mode, latency is estimated as:

	lat = max ((L-B)/R, (L-M)/P)


	NOTES.
	------

	If TBF throttles, it starts a watchdog timer, which will wake it up
	when it is ready to transmit.
	Note that the minimal timer resolution is 1/HZ.
	If no new packets arrive during this period,
	or if the device is not awaken by EOI for some previous packet,
	TBF can stop its activity for 1/HZ.


	This means, that with depth B, the maximal rate is

	R_crit = B*HZ

	F.e. for 10Mbit ethernet and HZ=100 the minimal allowed B is ~10Kbytes.

	Note that the peak rate TBF is much more tough: with MTU 1500
	P_crit = 150Kbytes/sec. So, if you need greater peak
	rates, use alpha with HZ=1000 :-)

	With classful TBF, limit is just kept for backwards compatibility.
	It is passed to the default bfifo qdisc - if the inner qdisc is
	changed the limit is not effective anymore.
*/
/* 令牌桶队列的私有数据 */
struct tbf_sched_data
{
/* Parameters */
	u32		limit;		/* Maximal length of backlog: bytes 最大允许积压的字节数 */
	u32		buffer;		/* Token bucket depth/rate: MUST BE >= MTU/B 桶中最大允许的字节令牌个数，与tokens对应 */
	u32		mtu;		/* 桶中允许的最大包令牌数与ptokens对应 */
	u32		max_size;   /* 单个报文最大字节值 */
	struct qdisc_rate_table	*R_tab;/* 字节速率限制 */
	struct qdisc_rate_table	*P_tab;

/* Variables */
	long	tokens;			/* Current number of B tokens 当前字节令牌数目 */
	long	ptokens;		/* Current number of P tokens 当前报文令牌数目 */
	psched_time_t	t_c;		/* Time check-point */
	struct timer_list wd_timer;	/* Watchdog timer 看门狗定时器 */
	struct Qdisc	*qdisc;		/* Inner qdisc, default - bfifo queue 其所属规程，默认使用bfifo规程 */
};

#define L2T(q,L)   ((q)->R_tab->data[(L)>>(q)->R_tab->rate.cell_log])/* 将报文长度转化为需要的字节令牌数 */
#define L2T_P(q,L) ((q)->P_tab->data[(L)>>(q)->P_tab->rate.cell_log])/* 将报文长度转化为需要的包令牌数 */
/* 令牌桶过滤入队列 */
static int tbf_enqueue(struct sk_buff *skb, struct Qdisc* sch)
{
	struct tbf_sched_data *q = qdisc_priv(sch);
	int ret;

	if (skb->len > q->max_size) {/* 如果报文过长的话，直接丢弃报文 */
		sch->qstats.drops++;
#ifdef CONFIG_NET_CLS_POLICE
		if (sch->reshape_fail == NULL || sch->reshape_fail(skb, sch))
#endif
			kfree_skb(skb);

		return NET_XMIT_DROP;
	}

	if ((ret = q->qdisc->enqueue(skb, q->qdisc)) != 0) {
		sch->qstats.drops++;
		return ret;
	}

	sch->q.qlen++;/* 队列中长度加加 */
	sch->bstats.bytes += skb->len;/* 字节加加 */
	sch->bstats.packets++;/* 报文处理个数加加 */
	return 0;
}
/* 令牌桶重入队列 */
static int tbf_requeue(struct sk_buff *skb, struct Qdisc* sch)
{
	struct tbf_sched_data *q = qdisc_priv(sch);
	int ret;

	if ((ret = q->qdisc->ops->requeue(skb, q->qdisc)) == 0) {/* 进行重入队 */
		sch->q.qlen++;/* 入队统计 */
		sch->qstats.requeues++;
	}

	return ret;
}
/* 报文丢弃函数 */
static unsigned int tbf_drop(struct Qdisc* sch)
{
	struct tbf_sched_data *q = qdisc_priv(sch);
	unsigned int len = 0;

	if (q->qdisc->ops->drop && (len = q->qdisc->ops->drop(q->qdisc)) != 0) {
		sch->q.qlen--;
		sch->qstats.drops++;
	}
	return len;
}

static void tbf_watchdog(unsigned long arg)
{
	struct Qdisc *sch = (struct Qdisc*)arg;

	sch->flags &= ~TCQ_F_THROTTLED;
	netif_schedule(sch->dev);
}
/* 出队函数 */
static struct sk_buff *tbf_dequeue(struct Qdisc* sch)
{
	struct tbf_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;

	skb = q->qdisc->dequeue(q->qdisc);/* 从队列中取包 */

	if (skb) {/* 发送报文 */
		psched_time_t now;
		long toks, delay;
		long ptoks = 0;
		unsigned int len = skb->len;

		PSCHED_GET_TIME(now);/* 获取当前时间，将其转化为秒 */

		toks = PSCHED_TDIFF_SAFE(now, q->t_c, q->buffer);/* 计算需要增加的令牌数目 */

		if (q->P_tab) {/* 处理包令牌 */
			ptoks = toks + q->ptokens;/* 计算总的令牌数 */
			if (ptoks > (long)q->mtu)/* 如果大于桶中的可以存在的上限，则设置为桶的上限 */
				ptoks = q->mtu;
			ptoks -= L2T_P(q, len);/* 将报文长度转化为需要的包令牌数，从总数中减掉 */
		}

		/* 处理字节令牌 */
		toks += q->tokens;
		if (toks > (long)q->buffer)
			toks = q->buffer;
		toks -= L2T(q, len);/* 将报文长度转化为需要的字节令牌数，从总数中减掉 */

		if ((toks|ptoks) >= 0) {/* 报文限速或者字节限速只要有一个没有超过则认为是可以通过 */
			q->t_c = now;/* 更新发送时间 */
			q->tokens = toks;/* 记录新的字节令牌个数 */
			q->ptokens = ptoks;/* 记录新的报文令牌个数 */
			sch->q.qlen--;/* 队列长度减掉1 */
			sch->flags &= ~TCQ_F_THROTTLED;/* 去掉扼杀标志 */
			return skb;
		}
		
		delay = PSCHED_US2JIFFIE(max_t(long, -toks, -ptoks));/* 将微秒转化成jiffies */

		if (delay == 0)
			delay = 1;

		mod_timer(&q->wd_timer, jiffies+delay);/* 设置延迟定时器 */

		/* Maybe we have a shorter packet in the queue,
		   which can be sent now. It sounds cool,
		   but, however, this is wrong in principle.
		   We MUST NOT reorder packets under these circumstances.

		   可能在某种环境下有一个短包可以发送出去，听起来很棒，但是某些情况下可能会坏事，因为我们改变了报文的顺序。

		   Really, if we split the flow into independent
		   subflows, it would be a very good solution.
		   This is the main idea of all FQ algorithms
		   (cf. CSZ, HPFQ, HFSC)
		 */

		if (q->qdisc->ops->requeue(skb, q->qdisc) != NET_XMIT_SUCCESS) {/* 入队，如果入队不成功，减小队列长度 */
			/* When requeue fails skb is dropped */
			qdisc_tree_decrease_qlen(q->qdisc, 1);/* 规程树递归减掉1，主要是祖先规程，本规程已经减掉了1 */
			sch->qstats.drops++;/* 增加失败统计 */
		}

		sch->flags |= TCQ_F_THROTTLED;/* 设置扼杀标志，表明队列已经满了，不在收包 */
		sch->qstats.overlimits++;/* 溢出统计加加 */
	}
	return NULL;
}

static void tbf_reset(struct Qdisc* sch)
{
	struct tbf_sched_data *q = qdisc_priv(sch);

	qdisc_reset(q->qdisc);/* 复位规程 */
	sch->q.qlen = 0;/* 报文个数为0 */
	PSCHED_GET_TIME(q->t_c);/* 初始化时间为当前时间 */
	q->tokens = q->buffer;/* 还原字节令牌数 */
	q->ptokens = q->mtu;/* 还原包令牌数 */
	sch->flags &= ~TCQ_F_THROTTLED;/* 可以收包 */
	del_timer(&q->wd_timer);/* 删除定时器 */
}
/* 为主规程sch创建一个tbf子规程 */
static struct Qdisc *tbf_create_dflt_qdisc(struct Qdisc *sch, u32 limit)
{
	struct Qdisc *q;
        struct rtattr *rta;
	int ret;
	/* 分配一个tbf规程，默认规程的操作函数为bfifo_qdisc_ops */
	q = qdisc_create_dflt(sch->dev, &bfifo_qdisc_ops,
			      TC_H_MAKE(sch->handle, 1));
	if (q) {
		rta = kmalloc(RTA_LENGTH(sizeof(struct tc_fifo_qopt)), GFP_KERNEL);
		if (rta) {
			rta->rta_type = RTM_NEWQDISC;
			rta->rta_len = RTA_LENGTH(sizeof(struct tc_fifo_qopt)); 
			((struct tc_fifo_qopt *)RTA_DATA(rta))->limit = limit;

			ret = q->ops->change(q, rta);
			kfree(rta);

			if (ret == 0)
				return q;
		}
		qdisc_destroy(q);
	}

	return NULL;
}
/* 创建一个tbf规程 */
static int tbf_change(struct Qdisc* sch, struct rtattr *opt)
{
	int err = -EINVAL;
	struct tbf_sched_data *q = qdisc_priv(sch);
	struct rtattr *tb[TCA_TBF_PTAB];
	struct tc_tbf_qopt *qopt;
	struct qdisc_rate_table *rtab = NULL;
	struct qdisc_rate_table *ptab = NULL;
	struct Qdisc *child = NULL;
	int max_size,n;

	if (rtattr_parse_nested(tb, TCA_TBF_PTAB, opt) ||
	    tb[TCA_TBF_PARMS-1] == NULL ||
	    RTA_PAYLOAD(tb[TCA_TBF_PARMS-1]) < sizeof(*qopt))
		goto done;

	qopt = RTA_DATA(tb[TCA_TBF_PARMS-1]);
	rtab = qdisc_get_rtab(&qopt->rate, tb[TCA_TBF_RTAB-1]);
	if (rtab == NULL)
		goto done;

	if (qopt->peakrate.rate) {
		if (qopt->peakrate.rate > qopt->rate.rate)
			ptab = qdisc_get_rtab(&qopt->peakrate, tb[TCA_TBF_PTAB-1]);
		if (ptab == NULL)
			goto done;
	}

	for (n = 0; n < 256; n++)
		if (rtab->data[n] > qopt->buffer) break;
	max_size = (n << qopt->rate.cell_log)-1;
	if (ptab) {
		int size;

		for (n = 0; n < 256; n++)
			if (ptab->data[n] > qopt->mtu) break;
		size = (n << qopt->peakrate.cell_log)-1;
		if (size < max_size) max_size = size;
	}
	if (max_size < 0)
		goto done;

	if (qopt->limit > 0) {
		if ((child = tbf_create_dflt_qdisc(sch, qopt->limit)) == NULL)
			goto done;
	}

	sch_tree_lock(sch);
	if (child) {
		qdisc_tree_decrease_qlen(q->qdisc, q->qdisc->q.qlen);
		qdisc_destroy(xchg(&q->qdisc, child));
	}
	q->limit = qopt->limit;
	q->mtu = qopt->mtu;
	q->max_size = max_size;
	q->buffer = qopt->buffer;
	q->tokens = q->buffer;
	q->ptokens = q->mtu;
	rtab = xchg(&q->R_tab, rtab);
	ptab = xchg(&q->P_tab, ptab);
	sch_tree_unlock(sch);
	err = 0;
done:
	if (rtab)
		qdisc_put_rtab(rtab);
	if (ptab)
		qdisc_put_rtab(ptab);
	return err;
}
/* 令牌桶过滤初始化函数 */
static int tbf_init(struct Qdisc* sch, struct rtattr *opt)
{
	struct tbf_sched_data *q = qdisc_priv(sch);/* 获取令牌桶的私有数据 */

	if (opt == NULL)
		return -EINVAL;

	PSCHED_GET_TIME(q->t_c);
	init_timer(&q->wd_timer);/* 初始化看门狗定时器 */
	q->wd_timer.function = tbf_watchdog;/* 看门狗超时函数 */
	q->wd_timer.data = (unsigned long)sch;

	q->qdisc = &noop_qdisc;

	return tbf_change(sch, opt);
}

static void tbf_destroy(struct Qdisc *sch)
{
	struct tbf_sched_data *q = qdisc_priv(sch);

	del_timer(&q->wd_timer);

	if (q->P_tab)
		qdisc_put_rtab(q->P_tab);
	if (q->R_tab)
		qdisc_put_rtab(q->R_tab);

	qdisc_destroy(q->qdisc);
}

static int tbf_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct tbf_sched_data *q = qdisc_priv(sch);
	unsigned char	 *b = skb->tail;
	struct rtattr *rta;
	struct tc_tbf_qopt opt;

	rta = (struct rtattr*)b;
	RTA_PUT(skb, TCA_OPTIONS, 0, NULL);

	opt.limit = q->limit;
	opt.rate = q->R_tab->rate;
	if (q->P_tab)
		opt.peakrate = q->P_tab->rate;
	else
		memset(&opt.peakrate, 0, sizeof(opt.peakrate));
	opt.mtu = q->mtu;
	opt.buffer = q->buffer;
	RTA_PUT(skb, TCA_TBF_PARMS, sizeof(opt), &opt);
	rta->rta_len = skb->tail - b;

	return skb->len;

rtattr_failure:
	skb_trim(skb, b - skb->data);
	return -1;
}

static int tbf_dump_class(struct Qdisc *sch, unsigned long cl,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	struct tbf_sched_data *q = qdisc_priv(sch);

	if (cl != 1) 	/* only one class */
		return -ENOENT;

	tcm->tcm_handle |= TC_H_MIN(1);
	tcm->tcm_info = q->qdisc->handle;

	return 0;
}

static int tbf_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		     struct Qdisc **old)
{
	struct tbf_sched_data *q = qdisc_priv(sch);

	if (new == NULL)
		new = &noop_qdisc;

	sch_tree_lock(sch);
	*old = xchg(&q->qdisc, new);
	qdisc_tree_decrease_qlen(*old, (*old)->q.qlen);
	qdisc_reset(*old);
	sch_tree_unlock(sch);

	return 0;
}

static struct Qdisc *tbf_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct tbf_sched_data *q = qdisc_priv(sch);
	return q->qdisc;
}

static unsigned long tbf_get(struct Qdisc *sch, u32 classid)
{
	return 1;
}

static void tbf_put(struct Qdisc *sch, unsigned long arg)
{
}

static int tbf_change_class(struct Qdisc *sch, u32 classid, u32 parentid, 
			    struct rtattr **tca, unsigned long *arg)
{
	return -ENOSYS;
}

static int tbf_delete(struct Qdisc *sch, unsigned long arg)
{
	return -ENOSYS;
}

static void tbf_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
	if (!walker->stop) {
		if (walker->count >= walker->skip)
			if (walker->fn(sch, 1, walker) < 0) {
				walker->stop = 1;
				return;
			}
		walker->count++;
	}
}

static struct tcf_proto **tbf_find_tcf(struct Qdisc *sch, unsigned long cl)
{
	return NULL;
}

static struct Qdisc_class_ops tbf_class_ops =
{
	.graft		=	tbf_graft,
	.leaf		=	tbf_leaf,
	.get		=	tbf_get,
	.put		=	tbf_put,
	.change		=	tbf_change_class,
	.delete		=	tbf_delete,
	.walk		=	tbf_walk,
	.tcf_chain	=	tbf_find_tcf,
	.dump		=	tbf_dump_class,
};

static struct Qdisc_ops tbf_qdisc_ops = {
	.next		=	NULL,
	.cl_ops		=	&tbf_class_ops,
	.id		=	"tbf",
	.priv_size	=	sizeof(struct tbf_sched_data),
	.enqueue	=	tbf_enqueue,
	.dequeue	=	tbf_dequeue,
	.requeue	=	tbf_requeue,
	.drop		=	tbf_drop,
	.init		=	tbf_init,
	.reset		=	tbf_reset,
	.destroy	=	tbf_destroy,
	.change		=	tbf_change,
	.dump		=	tbf_dump,
	.owner		=	THIS_MODULE,
};

static int __init tbf_module_init(void)
{
	return register_qdisc(&tbf_qdisc_ops);
}

static void __exit tbf_module_exit(void)
{
	unregister_qdisc(&tbf_qdisc_ops);
}
module_init(tbf_module_init)
module_exit(tbf_module_exit)
MODULE_LICENSE("GPL");
