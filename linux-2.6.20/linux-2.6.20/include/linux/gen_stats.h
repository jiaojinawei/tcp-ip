#ifndef __LINUX_GEN_STATS_H
#define __LINUX_GEN_STATS_H

#include <linux/types.h>

enum {
	TCA_STATS_UNSPEC,
	TCA_STATS_BASIC,
	TCA_STATS_RATE_EST,
	TCA_STATS_QUEUE,
	TCA_STATS_APP,
	__TCA_STATS_MAX,
};
#define TCA_STATS_MAX (__TCA_STATS_MAX - 1)

/**
 * struct gnet_stats_basic - byte/packet throughput statistics
 * @bytes: number of seen bytes
 * @packets: number of seen packets
 */
struct gnet_stats_basic
{
	__u64	bytes;/* 总共处理的字节数，与backlog不同，backlog表示积压的字节数 */
	__u32	packets;/* 总共处理的报文数 */
};

/**
 * struct gnet_stats_rate_est - rate estimator
 * @bps: current byte rate
 * @pps: current packet rate
 */
struct gnet_stats_rate_est
{
	__u32	bps;
	__u32	pps;
};

/**
 * struct gnet_stats_queue - queuing statistics
 * @qlen: queue length
 * @backlog: backlog size of queue
 * @drops: number of dropped packets
 * @requeues: number of requeues
 * @overlimits: number of enqueues over the limit
 */
struct gnet_stats_queue
{
	__u32	qlen;/* 当前队列报文数 */
	__u32	backlog;/* 当前队列的字节数，积压的报文个数 */
	__u32	drops;/* 丢弃的报文个数 */
	__u32	requeues;/* 重入队列统计(出队后发送不成功，只能重入队列尾部) */
	__u32	overlimits;/* 队列中报文的个数超过限制的次数 */
};

/**
 * struct gnet_estimator - rate estimator configuration
 * @interval: sampling period
 * @ewma_log: the log of measurement window weight
 */
struct gnet_estimator
{
	signed char	interval;
	unsigned char	ewma_log;
};


#endif /* __LINUX_GEN_STATS_H */
