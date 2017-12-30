/*
 *	Handle incoming frames
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_input.c,v 1.10 2001/12/24 04:50:20 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_bridge.h>
#include "br_private.h"

/* Bridge group multicast address 802.1d (pg 51). */
const u8 br_group_address[ETH_ALEN] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };

/* 处理上送本机协议栈的报文，该报文中会进行local-in业务节点的处理 */
static void br_pass_frame_up(struct net_bridge *br, struct sk_buff *skb)
{
	struct net_device *indev;

	br->statistics.rx_packets++;/* 处理报文个数统计 */
	br->statistics.rx_bytes += skb->len;/* 处理字节统计 */

	indev = skb->dev;/* 获取输入设备 */
	skb->dev = br->dev;/* 网桥设备 */

	NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, indev, NULL,
		netif_receive_skb);
}

/* note: already called with rcu_read_lock (preempt_disabled) */
/* 输入路由前报文的hook节点处理 */
int br_handle_frame_finish(struct sk_buff *skb)
{
	const unsigned char *dest = eth_hdr(skb)->h_dest;
	struct net_bridge_port *p = rcu_dereference(skb->dev->br_port);
	struct net_bridge *br;
	struct net_bridge_fdb_entry *dst;
	int passedup = 0;

	if (!p || p->state == BR_STATE_DISABLED)
		goto drop;

	/* insert into forwarding database after filtering to avoid spoofing */
	br = p->br;/* 获取端口所属网桥 */
	br_fdb_update(br, p, eth_hdr(skb)->h_source);/* 进行源mac地址学习 */

	if (p->state == BR_STATE_LEARNING)/* 如果端口的状态是学习状态，直接丢弃报文 */
		goto drop;

	if (br->dev->flags & IFF_PROMISC) {/* 如果端口设置了混杂模型 */
		struct sk_buff *skb2;

		skb2 = skb_clone(skb, GFP_ATOMIC);/* 将报文进行拷贝 */
		if (skb2 != NULL) {
			passedup = 1;
			br_pass_frame_up(br, skb2);
		}
	}

	if (is_multicast_ether_addr(dest)) {/* 如果报文是组播地址 */
		br->statistics.multicast++;/* 组播地址报文统计 */
		br_flood_forward(br, skb, !passedup);/* 将该报文进行泛洪 */
		if (!passedup)
			br_pass_frame_up(br, skb);
		goto out;
	}

	dst = __br_fdb_get(br, dest);/* 获取fdb表项 */
	if (dst != NULL && dst->is_local) {/* 如果报文的目的地址是上送本机协议栈 */
		if (!passedup)
			br_pass_frame_up(br, skb);/* 上送本机协议栈 */
		else
			kfree_skb(skb);
		goto out;
	}

    /* 非上送本机协议栈的报文，直接进行转发 */
	if (dst != NULL) {
		br_forward(dst->dst, skb);
		goto out;
	}

	/* 对于未知目的mac地址的报文直接进行泛洪 */
	br_flood_forward(br, skb, 0);

out:
	return 0;
drop:
	kfree_skb(skb);
	goto out;
}

/* note: already called with rcu_read_lock (preempt_disabled) */
static int br_handle_local_finish(struct sk_buff *skb)
{
	struct net_bridge_port *p = rcu_dereference(skb->dev->br_port);

	if (p && p->state != BR_STATE_DISABLED)
		br_fdb_update(p->br, p, eth_hdr(skb)->h_source);

	return 0;	 /* process further */
}

/* Does address match the link local multicast address.
 * 01:80:c2:00:00:0X
 */
static inline int is_link_local(const unsigned char *dest)
{
	return memcmp(dest, br_group_address, 5) == 0 && (dest[5] & 0xf0) == 0;
}

/*
 * Called via br_handle_frame_hook.
 * Return 0 if *pskb should be processed furthur
 *	  1 if *pskb is handled
 * note: already called with rcu_read_lock (preempt_disabled) 
 * 桥协议输入报文处理函数
 */
int br_handle_frame(struct net_bridge_port *p,/* 输入的网桥端口描述控制块 */
                           struct sk_buff **pskb)/* 输入的报文的指针的指针 */
{
	struct sk_buff *skb = *pskb;/* 获取报文 */
	const unsigned char *dest = eth_hdr(skb)->h_dest;/* 获取报文的目的mac地址 */

	if (!is_valid_ether_addr(eth_hdr(skb)->h_source))/* 查看报文的源mac地址是否合法 */
		goto err;

	if (unlikely(is_link_local(dest))) {/* 查看该协议报文是否为stp生成树报文，如果是的话，设置其标记为本机  */
		skb->pkt_type = PACKET_HOST;
		return NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, skb->dev,/* 处理上送本机的报文，处理local-in hook节点 */
			       NULL, br_handle_local_finish) != 0;
	}

	/* 如果当前端口的状态处于转发或者是学习阶段的话，进行报文的处理 */
	if (p->state == BR_STATE_FORWARDING || p->state == BR_STATE_LEARNING) {
		if (br_should_route_hook) {
			if (br_should_route_hook(pskb)) 
				return 0;
			skb = *pskb;
			dest = eth_hdr(skb)->h_dest;/* 获取报文的目的地址 */
		}

		if (!compare_ether_addr(p->br->dev->dev_addr, dest))/* 如果目的mac地址与该端口一致，说明报文是上送给本机的 */
			skb->pkt_type = PACKET_HOST;/* 设置报文的，目的mac地址是本机 */

		NF_HOOK(PF_BRIDGE, NF_BR_PRE_ROUTING, skb, skb->dev, NULL,
			br_handle_frame_finish);/* 进行路由前处理 */
		return 1;
	}

err:
	kfree_skb(skb);
	return 1;
}
