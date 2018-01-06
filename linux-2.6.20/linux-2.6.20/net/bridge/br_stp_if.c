/*
 *	Spanning tree protocol; interface code
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_stp_if.c,v 1.4 2001/04/14 21:14:39 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/smp_lock.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>

#include "br_private.h"
#include "br_private_stp.h"


/* Port id is composed of priority and port number.
 * NB: least significant bits of priority are dropped to
 *     make room for more ports.
 */
static inline port_id br_make_port_id(__u8 priority, __u16 port_no)
{
	return ((u16)priority << BR_PORT_BITS) 
		| (port_no & ((1<<BR_PORT_BITS)-1));
}

/* called under bridge lock */
/* 端口初始化的时候默认字节是指定端口 */
void br_init_port(struct net_bridge_port *p)
{
	p->port_id = br_make_port_id(p->priority, p->port_no);
	br_become_designated_port(p);/* 初始化时默认是指定端口 */
	p->state = BR_STATE_BLOCKING;
	p->topology_change_ack = 0;
	p->config_pending = 0;
}

/* called under bridge lock */
void br_stp_enable_bridge(struct net_bridge *br)
{
	struct net_bridge_port *p;

	spin_lock_bh(&br->lock);
	mod_timer(&br->hello_timer, jiffies + br->hello_time);
	mod_timer(&br->gc_timer, jiffies + HZ/10);
	
	br_config_bpdu_generation(br);

	list_for_each_entry(p, &br->port_list, list) {
		if ((p->dev->flags & IFF_UP) && netif_carrier_ok(p->dev))
			br_stp_enable_port(p);

	}
	spin_unlock_bh(&br->lock);
}

/* NO locks held */
/* 禁止桥的生成树功能 */
void br_stp_disable_bridge(struct net_bridge *br)
{
	struct net_bridge_port *p;

	spin_lock_bh(&br->lock);
	list_for_each_entry(p, &br->port_list, list) {
		if (p->state != BR_STATE_DISABLED)
			br_stp_disable_port(p);

	}

	br->topology_change = 0;
	br->topology_change_detected = 0;
	spin_unlock_bh(&br->lock);

	del_timer_sync(&br->hello_timer);
	del_timer_sync(&br->topology_change_timer);
	del_timer_sync(&br->tcn_timer);
	del_timer_sync(&br->gc_timer);
}

/* called under bridge lock */
/* 是能该端口的生成树协议 */
void br_stp_enable_port(struct net_bridge_port *p)
{
	br_init_port(p);
	br_ifinfo_notify(RTM_NEWLINK, p);
	br_port_state_selection(p->br);
}

/* called under bridge lock */
/* 禁止端口的生成树功能 */
void br_stp_disable_port(struct net_bridge_port *p)
{
	struct net_bridge *br;
	int wasroot;

	br = p->br;
	printk(KERN_INFO "%s: port %i(%s) entering %s state\n",
	       br->dev->name, p->port_no, p->dev->name, "disabled");

	br_ifinfo_notify(RTM_DELLINK, p);
	/* 获取桥是否为根桥 */
	wasroot = br_is_root_bridge(br);
	/* 进行指定端口选举 */
	br_become_designated_port(p);
	/* 设置其端口为禁止状态 */
	p->state = BR_STATE_DISABLED;
	p->topology_change_ack = 0;
	p->config_pending = 0;
	/* 删除端口的定时器 */
	del_timer(&p->message_age_timer);
	del_timer(&p->forward_delay_timer);
	del_timer(&p->hold_timer);
	/* 删除所有该端口的端口转发表项，不删除静态的fdb表项 */
	br_fdb_delete_by_port(br, p, 0);
	/* 更新网桥配置--进行根端口选举，指定端口选举 */
	br_configuration_update(br);

	br_port_state_selection(br);

	if (br_is_root_bridge(br) && !wasroot)/* 根桥改变，重新选举根桥 */
		br_become_root_bridge(br);
}

/* called under bridge lock */
void br_stp_change_bridge_id(struct net_bridge *br, const unsigned char *addr)
{
	unsigned char oldaddr[6];
	struct net_bridge_port *p;
	int wasroot;

	wasroot = br_is_root_bridge(br);

	memcpy(oldaddr, br->bridge_id.addr, ETH_ALEN);
	memcpy(br->bridge_id.addr, addr, ETH_ALEN);
	memcpy(br->dev->dev_addr, addr, ETH_ALEN);

	list_for_each_entry(p, &br->port_list, list) {
		if (!compare_ether_addr(p->designated_bridge.addr, oldaddr))
			memcpy(p->designated_bridge.addr, addr, ETH_ALEN);

		if (!compare_ether_addr(p->designated_root.addr, oldaddr))
			memcpy(p->designated_root.addr, addr, ETH_ALEN);

	}

	br_configuration_update(br);
	br_port_state_selection(br);
	if (br_is_root_bridge(br) && !wasroot)
		br_become_root_bridge(br);
}

static const unsigned char br_mac_zero[6];

/* called under bridge lock */
/* 重新计算桥id */
void br_stp_recalculate_bridge_id(struct net_bridge *br)
{
	const unsigned char *addr = br_mac_zero;
	struct net_bridge_port *p;

	list_for_each_entry(p, &br->port_list, list) {
		if (addr == br_mac_zero ||
		    memcmp(p->dev->dev_addr, addr, ETH_ALEN) < 0)
			addr = p->dev->dev_addr;

	}

	if (compare_ether_addr(br->bridge_id.addr, addr))
		br_stp_change_bridge_id(br, addr);
}

/* called under bridge lock */
/* 设置网桥的优先级 */
void br_stp_set_bridge_priority(struct net_bridge *br, u16 newprio)
{
	struct net_bridge_port *p;
	int wasroot;

	wasroot = br_is_root_bridge(br);/* 判断该网桥是否为根网桥 */

	list_for_each_entry(p, &br->port_list, list) {/* 遍历网桥端口 */
		if (p->state != BR_STATE_DISABLED &&/* 只处理指定端口和非禁止状态的端口 */
		    br_is_designated_port(p)) {
		    /* 如果该端口是指定端口的话，重新设置该端口所属网桥的网桥id */
			p->designated_bridge.prio[0] = (newprio >> 8) & 0xFF;
			p->designated_bridge.prio[1] = newprio & 0xFF;
		}

	}
	/* 修改该网桥的网桥id */
	br->bridge_id.prio[0] = (newprio >> 8) & 0xFF;
	br->bridge_id.prio[1] = newprio & 0xFF;
	br_configuration_update(br);
	br_port_state_selection(br);
	if (br_is_root_bridge(br) && !wasroot)
		br_become_root_bridge(br);/* 进行根桥的重新选举 */
}

/* called under bridge lock */
/* 设置端口的优先级 */
void br_stp_set_port_priority(struct net_bridge_port *p, u8 newprio)
{
	port_id new_port_id = br_make_port_id(newprio, p->port_no);

	if (br_is_designated_port(p))/* 只有该端口是指定端口，才需要改变其所属的指定端口变量为自身 */
		p->designated_port = new_port_id;/**/

	p->port_id = new_port_id;
	p->priority = newprio;
	if (!memcmp(&p->br->bridge_id, &p->designated_bridge, 8) &&
	    p->port_id < p->designated_port) {/* 满足条件，成为新的指定端口 */
		br_become_designated_port(p);
		br_port_state_selection(p->br);
	}
}

/* called under bridge lock */
/* 设置路径开销 */
void br_stp_set_path_cost(struct net_bridge_port *p, u32 path_cost)
{
	p->path_cost = path_cost;/* 经过该端口的路径开销，根据端口的带宽相关，带宽越大，开销越小 */
	br_configuration_update(p->br);/* 改变端口的开销后，需要进行根端口的重新选举和指定端口的重新选举 */
	br_port_state_selection(p->br);/* 端口状态的重新改变 */
}
/* 显示网桥id，共八个字节 */
ssize_t br_show_bridge_id(char *buf, const struct bridge_id *id)
{
	return sprintf(buf, "%.2x%.2x.%.2x%.2x%.2x%.2x%.2x%.2x\n",
	       id->prio[0], id->prio[1],
	       id->addr[0], id->addr[1], id->addr[2],
	       id->addr[3], id->addr[4], id->addr[5]);
}
