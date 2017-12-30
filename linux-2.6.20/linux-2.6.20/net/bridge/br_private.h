/*
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_private.h,v 1.7 2001/12/24 00:59:55 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#ifndef _BR_PRIVATE_H
#define _BR_PRIVATE_H

#include <linux/netdevice.h>
#include <linux/miscdevice.h>
#include <linux/if_bridge.h>

#define BR_HASH_BITS 8
#define BR_HASH_SIZE (1 << BR_HASH_BITS)

#define BR_HOLD_TIME (1*HZ)

#define BR_PORT_BITS	10
#define BR_MAX_PORTS	(1<<BR_PORT_BITS)

#define BR_PORT_DEBOUNCE (HZ/10)

#define BR_VERSION	"2.2"

typedef struct bridge_id bridge_id;
typedef struct mac_addr mac_addr;
typedef __u16 port_id;

/* 网桥id，由两部分组成，共8个字节，两个字节的优先级，6个字节的mac地址 */
struct bridge_id
{
	unsigned char	prio[2];
	unsigned char	addr[6];
};

struct mac_addr
{
	unsigned char	addr[6];
};

struct net_bridge_fdb_entry
{
	struct hlist_node		hlist;/* 链接到hash表中 */
	struct net_bridge_port		*dst;/* 目的桥端口 */

	struct rcu_head			rcu;/* rcu保护 */
	atomic_t			use_count;/* 使用计数 */
	unsigned long			ageing_timer;/* 老化时间 */
	mac_addr			    addr;/* mac地址 */
	unsigned char			is_local;/* 是否是本地地址 */
	unsigned char			is_static;/* 是否是静态地址 */
};

struct net_bridge_port
{
	struct net_bridge		*br;
	struct net_device		*dev;
	struct list_head		list;

	/* STP */
	u8				priority;/* 端口的优先级 */
	u8				state;/* 端口的状态 */
	u16				port_no;/* 端口编号 */
	unsigned char			topology_change_ack;
	unsigned char			config_pending;
	port_id				port_id;/* 该端口的端口id */
	port_id				designated_port;/* 网桥的指定端口 */
	bridge_id			designated_root;
	bridge_id			designated_bridge;
	u32				path_cost;/* 路径开销 */
	u32				designated_cost;/* 指定端口的路径开销 */

	struct timer_list		forward_delay_timer;/* 转发延迟定时器 */
	struct timer_list		hold_timer;/* 持续定时器 */
	struct timer_list		message_age_timer;/* 老化时间定时器 */
	struct kobject			kobj;
	struct delayed_work		carrier_check;
	struct rcu_head			rcu;
};

/* 网桥设备描述控制块 */
struct net_bridge
{
	spinlock_t			lock;/* 锁 */
	struct list_head		port_list;/* 桥端口链表 */
	struct net_device		*dev;/* 指向其所属的二层网络设备描述控制块 */
	struct net_device_stats		statistics;/* 统计信息 */
	spinlock_t			hash_lock;/* hash锁 */
	struct hlist_head		hash[BR_HASH_SIZE];/* 转发表项hash表 */
	struct list_head		age_list;/* 老化队列 */
	unsigned long			feature_mask;/* 特性掩码 */

	/* STP */
	bridge_id			designated_root;/* 根网桥id */
	bridge_id			bridge_id;/* 网桥id */
	u32				root_path_cost;
	unsigned long			max_age;
	unsigned long			hello_time;
	unsigned long			forward_delay;
	unsigned long			bridge_max_age;
	unsigned long			ageing_time;
	unsigned long			bridge_hello_time;
	unsigned long			bridge_forward_delay;

	u8				group_addr[ETH_ALEN];
	u16				root_port;/* 网桥的根端口，对于非根桥，需要将离根桥最近的端口设置为根端口 */
	unsigned char			stp_enabled;/* 是否是能生成树协议 */
	unsigned char			topology_change;/* top是否改变 */
	unsigned char			topology_change_detected;/* top改变是否被检测到 */

	struct timer_list		hello_timer;/* 心跳定时器 */
	struct timer_list		tcn_timer;/*  */
	struct timer_list		topology_change_timer;/* top改变定时器 */
	struct timer_list		gc_timer;/* 垃圾回收定时器 */
	struct kobject			ifobj;
};

extern struct notifier_block br_device_notifier;
extern const u8 br_group_address[ETH_ALEN];

/* called under bridge lock */
/* 判断该网桥是不是根网桥，通过比较网桥id与指定根网桥id决定的 */
static inline int br_is_root_bridge(const struct net_bridge *br)
{
	return !memcmp(&br->bridge_id, &br->designated_root, 8);
}


/* br_device.c */
extern void br_dev_setup(struct net_device *dev);
extern int br_dev_xmit(struct sk_buff *skb, struct net_device *dev);

/* br_fdb.c */
extern void br_fdb_init(void);
extern void br_fdb_fini(void);
extern void br_fdb_changeaddr(struct net_bridge_port *p,
			      const unsigned char *newaddr);
extern void br_fdb_cleanup(unsigned long arg);
extern void br_fdb_delete_by_port(struct net_bridge *br,
				  const struct net_bridge_port *p, int do_all);
extern struct net_bridge_fdb_entry *__br_fdb_get(struct net_bridge *br,
						 const unsigned char *addr);
extern struct net_bridge_fdb_entry *br_fdb_get(struct net_bridge *br,
					       unsigned char *addr);
extern void br_fdb_put(struct net_bridge_fdb_entry *ent);
extern int br_fdb_fillbuf(struct net_bridge *br, void *buf, 
			  unsigned long count, unsigned long off);
extern int br_fdb_insert(struct net_bridge *br,
			 struct net_bridge_port *source,
			 const unsigned char *addr);
extern void br_fdb_update(struct net_bridge *br,
			  struct net_bridge_port *source,
			  const unsigned char *addr);

/* br_forward.c */
extern void br_deliver(const struct net_bridge_port *to,
		struct sk_buff *skb);
extern int br_dev_queue_push_xmit(struct sk_buff *skb);
extern void br_forward(const struct net_bridge_port *to,
		struct sk_buff *skb);
extern int br_forward_finish(struct sk_buff *skb);
extern void br_flood_deliver(struct net_bridge *br,
		      struct sk_buff *skb,
		      int clone);
extern void br_flood_forward(struct net_bridge *br,
		      struct sk_buff *skb,
		      int clone);

/* br_if.c */
extern int br_add_bridge(const char *name);
extern int br_del_bridge(const char *name);
extern void br_cleanup_bridges(void);
extern int br_add_if(struct net_bridge *br,
	      struct net_device *dev);
extern int br_del_if(struct net_bridge *br,
	      struct net_device *dev);
extern int br_min_mtu(const struct net_bridge *br);
extern void br_features_recompute(struct net_bridge *br);

/* br_input.c */
extern int br_handle_frame_finish(struct sk_buff *skb);
extern int br_handle_frame(struct net_bridge_port *p, struct sk_buff **pskb);

/* br_ioctl.c */
extern int br_dev_ioctl(struct net_device *dev, struct ifreq *rq, int cmd);
extern int br_ioctl_deviceless_stub(unsigned int cmd, void __user *arg);

/* br_netfilter.c */
#ifdef CONFIG_BRIDGE_NETFILTER
extern int br_netfilter_init(void);
extern void br_netfilter_fini(void);
#else
#define br_netfilter_init()	(0)
#define br_netfilter_fini()	do { } while(0)
#endif

/* br_stp.c */
extern void br_log_state(const struct net_bridge_port *p);
extern struct net_bridge_port *br_get_port(struct net_bridge *br,
				    	   u16 port_no);
extern void br_init_port(struct net_bridge_port *p);
extern void br_become_designated_port(struct net_bridge_port *p);

/* br_stp_if.c */
extern void br_stp_enable_bridge(struct net_bridge *br);
extern void br_stp_disable_bridge(struct net_bridge *br);
extern void br_stp_enable_port(struct net_bridge_port *p);
extern void br_stp_disable_port(struct net_bridge_port *p);
extern void br_stp_recalculate_bridge_id(struct net_bridge *br);
extern void br_stp_change_bridge_id(struct net_bridge *br, const unsigned char *a);
extern void br_stp_set_bridge_priority(struct net_bridge *br,
				       u16 newprio);
extern void br_stp_set_port_priority(struct net_bridge_port *p,
				     u8 newprio);
extern void br_stp_set_path_cost(struct net_bridge_port *p,
				 u32 path_cost);
extern ssize_t br_show_bridge_id(char *buf, const struct bridge_id *id);

/* br_stp_bpdu.c */
extern int br_stp_rcv(struct sk_buff *skb, struct net_device *dev,
		      struct packet_type *pt, struct net_device *orig_dev);

/* br_stp_timer.c */
extern void br_stp_timer_init(struct net_bridge *br);
extern void br_stp_port_timer_init(struct net_bridge_port *p);
extern unsigned long br_timer_value(const struct timer_list *timer);

/* br.c */
extern struct net_bridge_fdb_entry *(*br_fdb_get_hook)(struct net_bridge *br,
						       unsigned char *addr);
extern void (*br_fdb_put_hook)(struct net_bridge_fdb_entry *ent);


/* br_netlink.c */
extern void br_netlink_init(void);
extern void br_netlink_fini(void);
extern void br_ifinfo_notify(int event, struct net_bridge_port *port);

#ifdef CONFIG_SYSFS
/* br_sysfs_if.c */
extern struct sysfs_ops brport_sysfs_ops;
extern int br_sysfs_addif(struct net_bridge_port *p);

/* br_sysfs_br.c */
extern int br_sysfs_addbr(struct net_device *dev);
extern void br_sysfs_delbr(struct net_device *dev);

#else

#define br_sysfs_addif(p)	(0)
#define br_sysfs_addbr(dev)	(0)
#define br_sysfs_delbr(dev)	do { } while(0)
#endif /* CONFIG_SYSFS */

#endif
