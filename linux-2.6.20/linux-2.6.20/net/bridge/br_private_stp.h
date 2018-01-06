/*
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_private_stp.h,v 1.3 2001/02/05 06:03:47 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#ifndef _BR_PRIVATE_STP_H
#define _BR_PRIVATE_STP_H

#define BPDU_TYPE_CONFIG 0
#define BPDU_TYPE_TCN 0x80

/* 生成树协议数据报 */
struct br_config_bpdu
{
	unsigned	topology_change:1;/* top改变标识 */
	unsigned	topology_change_ack:1;/* top改变会赢标识 */
	bridge_id	root;/* 根网桥id，用于汇聚后的网桥网络中，所有配置BPDU中的该字段应该具有相同值(同vlan中)，该值分为网桥优先级和mac地址组合 */
	int		root_path_cost;/* 通往根网桥的所有链路的累积开销 */
	bridge_id	bridge_id;/* 创建当前BPDU的网桥id */
	port_id		port_id;/* 发送端口id  */
	int		message_age;/* 记录根网桥生成当前的BPDU起源信息所消耗的时间 */
	int		max_age;/* 保存BPDU配置信息的最长时间，也反映了top变化通知过程中的网桥表的生存时间情况 */
	int		hello_time;/* 心跳时间 */
	int		forward_delay;/* 用于在listening和learning状态的时间，也反映了拓扑变化通知过程中的时间情况 */
};

/* called under bridge lock */
/* 判断端口是否为指定端口，通过比较端口的id和指定端口id是否相等决定 */
static inline int br_is_designated_port(const struct net_bridge_port *p)
{
	return !memcmp(&p->designated_bridge, &p->br->bridge_id, 8) &&
		(p->designated_port == p->port_id);
}


/* br_stp.c */
extern void br_become_root_bridge(struct net_bridge *br);
extern void br_config_bpdu_generation(struct net_bridge *);
extern void br_configuration_update(struct net_bridge *);
extern void br_port_state_selection(struct net_bridge *);
extern void br_received_config_bpdu(struct net_bridge_port *p, struct br_config_bpdu *bpdu);
extern void br_received_tcn_bpdu(struct net_bridge_port *p);
extern void br_transmit_config(struct net_bridge_port *p);
extern void br_transmit_tcn(struct net_bridge *br);
extern void br_topology_change_detection(struct net_bridge *br);

/* br_stp_bpdu.c */
extern void br_send_config_bpdu(struct net_bridge_port *, struct br_config_bpdu *);
extern void br_send_tcn_bpdu(struct net_bridge_port *);

#endif
