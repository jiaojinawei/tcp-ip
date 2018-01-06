/*
 *	Spanning tree protocol; generic parts
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_stp.c,v 1.4 2000/06/19 10:13:35 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *  ************************************************************
 *  1.指定端口(Designated Port selection)
 *	如果一个交换机在超过MaxAge时间在根端口收不到hello报文，那么他会尝试在该交换机上选出一个新的根端口，如果选不出，那么说明该交换机已经很可能
 * 	和根交换机测地失去了联系，那么它应该宣称自己是根，重新开启一次根选举。实际上是在blocking状态的端口中选举新的根端口，因为既然处于blocking状态
 *	那么说明它和商誉存在环路，此时可以将它闭合即可。


 * 	          |--------|0：指定端口                              0:根端口     |--------|
 *			  |root sw |--------------------链路1---------------------|    SW1   |
 *            |--------|                                              |--------|
 *         指定端口   |                                               指定端口   |
 *	               |                                                      |
 *                 |                                                      |
 *                 |                                                      |
 *	               |                                                      |
 *                 |                                                      |
 *                 |                                                      |
 *	               |                                                      |
 *                 |                                                      |
 *     0:根端口       |                                              0:根端口|
 * 	          |--------|1：blocking端口                       1:指定端口     |--------|
 *			  |   SW3  |--------------------链路4---------------------|    SW4   |
 *            |--------|                                              |--------|
 *
 * 1.如果链路1和交换机1之间有一个hub之类的供电器，即使其与根交换机之间的链路断开了，交换机1也检测不到链路断开，而是MaxAge超时。
 * 
 */
#include <linux/kernel.h>
#include <linux/smp_lock.h>

#include "br_private.h"
#include "br_private_stp.h"

/* since time values in bpdu are in jiffies and then scaled (1/256)
 * before sending, make sure that is at least one.
 */
#define MESSAGE_AGE_INCR	((HZ < 256) ? 1 : (HZ/256))

static const char *br_port_state_names[] = {
	[BR_STATE_DISABLED] = "disabled", 
	[BR_STATE_LISTENING] = "listening",
	[BR_STATE_LEARNING] = "learning", 
	[BR_STATE_FORWARDING] = "forwarding", 
	[BR_STATE_BLOCKING] = "blocking",
};
/* 网桥打印桥的状态信息 */
void br_log_state(const struct net_bridge_port *p)
{
	pr_info("%s: port %d(%s) entering %s state\n",
		p->br->dev->name, p->port_no, p->dev->name, 
		br_port_state_names[p->state]);

}

/* called under bridge lock */
/* 根据网桥的端口编号获取其端口的，描述控制块 */
struct net_bridge_port *br_get_port(struct net_bridge *br, u16 port_no)
{
	struct net_bridge_port *p;

	list_for_each_entry_rcu(p, &br->port_list, list) {
		if (p->port_no == port_no)
			return p;
	}

	return NULL;
}

/* called under bridge lock */
/* 非根桥需要选择一个离根桥最近的端口成为根端口 */
/* 选举根端口判断 */
static int br_should_become_root_port(const struct net_bridge_port *p, 
				      u16 root_port)
{
	struct net_bridge *br;
	struct net_bridge_port *rp;
	int t;

	br = p->br;
	if (p->state == BR_STATE_DISABLED ||/* 1.不能是禁止端口。不能是指定端口，指定端口是下行的 */
	    br_is_designated_port(p))
		return 0;

	if (memcmp(&br->bridge_id, &p->designated_root, 8) <= 0)/* 根桥不参与根端口选举的，因为根桥不需要根端口 */
		return 0;

	if (!root_port)
		return 1;

	rp = br_get_port(br, root_port);/* 获取候选的根端口的描述控制块 */
	
	/* 比较两者之间的指定根网桥id是否相同 */
	t = memcmp(&p->designated_root, &rp->designated_root, 8);
	if (t < 0)/* 选择其根网桥id更小的一个 */
		return 1;
	else if (t > 0)/* 大于0的话，不行 */
		return 0;
	/* 四步判断：
	 *    生成树算法就是利用上述四个参数在判断，判断过程总是相同的：
     * 1、确定最小路径开销；
     * 2、确定根桥，桥ID最小的（即把包中的桥ID，同自己以前记录的那个最小的桥ID相比，机器加电时，总是以自己的桥ID为根桥ID）的为根桥；
     * 3、确定最小发送方ID；
     * 4、确定最小的端口ID：
	 */

	if (p->designated_cost + p->path_cost <
	    rp->designated_cost + rp->path_cost)/* 比较距离根网桥的路径消耗，选择小的 */
		return 1;
	else if (p->designated_cost + p->path_cost >
		 rp->designated_cost + rp->path_cost)
		return 0;

	t = memcmp(&p->designated_bridge, &rp->designated_bridge, 8);/* 比较指定网桥 */
	if (t < 0)
		return 1;
	else if (t > 0)
		return 0;

	if (p->designated_port < rp->designated_port)
		return 1;
	else if (p->designated_port > rp->designated_port)
		return 0;

	if (p->port_id < rp->port_id)
		return 1;

	return 0;
}

/* called under bridge lock */
/* 选举根端口 */
static void br_root_selection(struct net_bridge *br)
{
	struct net_bridge_port *p;
	u16 root_port = 0;

	/* 它逐个遍历桥的每一个所属端口，找出一个符合条件的，保存下来，再用下一个来与之做比较，用变量root_port来标志 */
	list_for_each_entry(p, &br->port_list, list) {
		/* 判断该端口是否可以成为根端口 */
		if (br_should_become_root_port(p, root_port))
			root_port = p->port_no;

	}

	br->root_port = root_port;/* 根端口 */

	if (!root_port) {/* 找完了还没找到根端口，则认为自己是根桥 */
		br->designated_root = br->bridge_id;/* 断定自己是根桥 */
		br->root_path_cost = 0;/* 设置到根桥的开销为0，自己到自己当然为0 */
	} else {
		p = br_get_port(br, root_port);/* 获取端口描述控制块 */
		br->designated_root = p->designated_root;/* 该端口的根桥为整个设备的根桥 */
		br->root_path_cost = p->designated_cost + p->path_cost;
	}
}

/* called under bridge lock */
/* 转换成根网桥 */
void br_become_root_bridge(struct net_bridge *br)
{
	br->max_age = br->bridge_max_age;
	br->hello_time = br->bridge_hello_time;
	br->forward_delay = br->bridge_forward_delay;
	br_topology_change_detection(br);/* 进行top变化检测 */
	del_timer(&br->tcn_timer);

	if (br->dev->flags & IFF_UP) {
		br_config_bpdu_generation(br);
		mod_timer(&br->hello_timer, jiffies + br->hello_time);
	}
}

/* called under bridge lock */
void br_transmit_config(struct net_bridge_port *p)
{
	struct br_config_bpdu bpdu;
	struct net_bridge *br;


	if (timer_pending(&p->hold_timer)) {
		p->config_pending = 1;
		return;
	}

	br = p->br;

	bpdu.topology_change = br->topology_change;
	bpdu.topology_change_ack = p->topology_change_ack;
	bpdu.root = br->designated_root;
	bpdu.root_path_cost = br->root_path_cost;
	bpdu.bridge_id = br->bridge_id;
	bpdu.port_id = p->port_id;
	if (br_is_root_bridge(br))
		bpdu.message_age = 0;
	else {
		struct net_bridge_port *root
			= br_get_port(br, br->root_port);
		bpdu.message_age = br->max_age
			- (root->message_age_timer.expires - jiffies)
			+ MESSAGE_AGE_INCR;
	}
	bpdu.max_age = br->max_age;
	bpdu.hello_time = br->hello_time;
	bpdu.forward_delay = br->forward_delay;

	if (bpdu.message_age < br->max_age) {
		br_send_config_bpdu(p, &bpdu);
		p->topology_change_ack = 0;
		p->config_pending = 0;
		mod_timer(&p->hold_timer, jiffies + BR_HOLD_TIME);
	}
}

/* called under bridge lock */
static inline void br_record_config_information(struct net_bridge_port *p, 
						const struct br_config_bpdu *bpdu)
{
	p->designated_root = bpdu->root;//指定的根网桥的网桥ID
	p->designated_cost = bpdu->root_path_cost;//指定的到根桥的链路花销
	p->designated_bridge = bpdu->bridge_id;//指定的发送当前BPDU包的网桥的ID
	p->designated_port = bpdu->port_id;//指定的发送当前BPDU包的网桥的端口的ID

	mod_timer(&p->message_age_timer, jiffies 
		  + (p->br->max_age - bpdu->message_age));/* 设置这些信息保存的时间，定时器超时，重新选举 */
}

/* called under bridge lock */
static inline void br_record_config_timeout_values(struct net_bridge *br, 
					    const struct br_config_bpdu *bpdu)
{
	br->max_age = bpdu->max_age;
	br->hello_time = bpdu->hello_time;
	br->forward_delay = bpdu->forward_delay;
	br->topology_change = bpdu->topology_change;
}

/* called under bridge lock */
/* 发送tcn报文 */
void br_transmit_tcn(struct net_bridge *br)
{
	br_send_tcn_bpdu(br_get_port(br, br->root_port));
}

/* called under bridge lock */
static int br_should_become_designated_port(const struct net_bridge_port *p)
{
	struct net_bridge *br;
	int t;

	br = p->br;
	if (br_is_designated_port(p))/* 如果端口已经是指定端口，直接返回true */
		return 1;
	/* 1.比较指定的根网桥id，如果一样的话，返回true */
	if (memcmp(&p->designated_root, &br->designated_root, 8))
		return 1;
	/* 2.比较到根网桥的路径开销 */
	if (br->root_path_cost < p->designated_cost)
		return 1;
	else if (br->root_path_cost > p->designated_cost)
		return 0;
    /* 比较网桥id与与发送该bpdu的 */
	t = memcmp(&br->bridge_id, &p->designated_bridge, 8);
	if (t < 0)
		return 1;
	else if (t > 0)
		return 0;

	if (p->port_id < p->designated_port)
		return 1;

	return 0;
}

/* called under bridge lock */
static void br_designated_port_selection(struct net_bridge *br)
{
	struct net_bridge_port *p;

	/*进行指定端口选择*/
	list_for_each_entry(p, &br->port_list, list) {
		if (p->state != BR_STATE_DISABLED &&
		    br_should_become_designated_port(p))
			br_become_designated_port(p);

	}
}

/* called under bridge lock */
/* 网桥需要在收到每一个每一个BPDU时调用该函数 */
static int br_supersedes_port_info(struct net_bridge_port *p, struct br_config_bpdu *bpdu)
{
	int t;

	t = memcmp(&bpdu->root, &p->designated_root, 8);/* 判断该BPDU是否来自根网桥，或者其网桥id比根网桥还低 */
	if (t < 0)/* 更高优先级的网桥id */
		return 1;
	else if (t > 0)
		return 0;

	/* 1.到跟网桥的开销与其指定设备到跟网桥的开销 */
	if (bpdu->root_path_cost < p->designated_cost)
		return 1;
	else if (bpdu->root_path_cost > p->designated_cost)
		return 0;
	/* 2.网桥id */
	t = memcmp(&bpdu->bridge_id, &p->designated_bridge, 8);
	if (t < 0)
		return 1;
	else if (t > 0)
		return 0;
	/* 3.比较网桥id与当前网桥的网桥id */
	if (memcmp(&bpdu->bridge_id, &p->br->bridge_id, 8))
		return 1;
	/* 4.比较端口id与指定端口 */
	if (bpdu->port_id <= p->designated_port)
		return 1;

	return 0;
}

/* called under bridge lock */
static inline void br_topology_change_acknowledged(struct net_bridge *br)
{
	br->topology_change_detected = 0;
	del_timer(&br->tcn_timer);
}

/* called under bridge lock */
/* top变化检测函数 */
void br_topology_change_detection(struct net_bridge *br)
{
	int isroot = br_is_root_bridge(br);/* 判断是否为跟网桥 */

	pr_info("%s: topology change detected, %s\n", br->dev->name,
		isroot ? "propagating" : "sending tcn bpdu");

	if (isroot) {/* 如果该网桥是根网桥 */
		br->topology_change = 1;/* 设置top改变标识 */
		mod_timer(&br->topology_change_timer, jiffies
			  + br->bridge_forward_delay + br->bridge_max_age);
	} else if (!br->topology_change_detected) {
		br_transmit_tcn(br);/* 非根网桥 */
		mod_timer(&br->tcn_timer, jiffies + br->bridge_hello_time);
	}

	br->topology_change_detected = 1;/* 已经发送top改变 */
}

/* called under bridge lock */
void br_config_bpdu_generation(struct net_bridge *br)
{
	struct net_bridge_port *p;

	list_for_each_entry(p, &br->port_list, list) {
		if (p->state != BR_STATE_DISABLED &&
		    br_is_designated_port(p))
			br_transmit_config(p);
	}
}

/* called under bridge lock */
static inline void br_reply(struct net_bridge_port *p)
{
	br_transmit_config(p);
}

/* called under bridge lock */
/* 进行根桥和根端口选举 */
void br_configuration_update(struct net_bridge *br)
{
	br_root_selection(br);/* 选举根端口--选举不出来则认为该网桥为根网桥 */
	br_designated_port_selection(br);/* 指定端口选举 */
}

/* called under bridge lock */
/* 端口变成指定端口 */
void br_become_designated_port(struct net_bridge_port *p)
{
	struct net_bridge *br;

	br = p->br;
	p->designated_root = br->designated_root;/* 根桥继承其所属的网桥的根桥 */
	p->designated_cost = br->root_path_cost;/* 继承其网桥的路径消耗 */
	p->designated_bridge = br->bridge_id;/* 指定网桥即为其所属网桥 */
	p->designated_port = p->port_id;/* 指定端口即为其自己本身体 */
}


/* called under bridge lock */
static void br_make_blocking(struct net_bridge_port *p)
{
	if (p->state != BR_STATE_DISABLED &&
	    p->state != BR_STATE_BLOCKING) {
		if (p->state == BR_STATE_FORWARDING ||
		    p->state == BR_STATE_LEARNING)
			br_topology_change_detection(p->br);

		p->state = BR_STATE_BLOCKING;
		br_log_state(p);
		del_timer(&p->forward_delay_timer);
	}
}

/* called under bridge lock */
/* 将一个端口变成转发状   态  		    */
static void br_make_forwarding(struct net_bridge_port *p)
{
	if (p->state == BR_STATE_BLOCKING) {
		if (p->br->stp_enabled) {
			p->state = BR_STATE_LISTENING;
		} else {
			p->state = BR_STATE_LEARNING;
		}
		br_log_state(p);
		mod_timer(&p->forward_delay_timer, jiffies + p->br->forward_delay);	}
}

/* called under bridge lock */
void br_port_state_selection(struct net_bridge *br)
{
	struct net_bridge_port *p;

	list_for_each_entry(p, &br->port_list, list) {/* 遍历每一个端口 */
		if (p->state != BR_STATE_DISABLED) {/* 如果端口不是静止的 */
			if (p->port_no == br->root_port) {/* 端口是根端口 */
				p->config_pending = 0;
				p->topology_change_ack = 0;
				br_make_forwarding(p);
			} else if (br_is_designated_port(p)) {
				del_timer(&p->message_age_timer);
				br_make_forwarding(p);
			} else {
				p->config_pending = 0;
				p->topology_change_ack = 0;
				br_make_blocking(p);
			}
		}

	}
}

/* called under bridge lock */
static inline void br_topology_change_acknowledge(struct net_bridge_port *p)
{
	p->topology_change_ack = 1;
	br_transmit_config(p);
}

/* called under bridge lock */
/* 收到bpdu报文的处理函数 */
void br_received_config_bpdu(struct net_bridge_port *p, struct br_config_bpdu *bpdu)
{
	struct net_bridge *br;
	int was_root;
 
	br = p->br;
	was_root = br_is_root_bridge(br);/* 获取网桥是否为根网桥 */

	if (br_supersedes_port_info(p, bpdu)) {
		/* 需要改变 */
		br_record_config_information(p, bpdu);/* 重新记录配置信息，启动信息老化定时器 */
		br_configuration_update(br);/* 进行根桥和根端口的选举 */
		br_port_state_selection(br);

		if (!br_is_root_bridge(br) && was_root) {/* 如果当前网桥原来是根网桥，现在不是了，则通知top改变 */
			del_timer(&br->hello_timer);
			if (br->topology_change_detected) {
				del_timer(&br->topology_change_timer);
				br_transmit_tcn(br);

				mod_timer(&br->tcn_timer, 
					  jiffies + br->bridge_hello_time);
			}
		}

		if (p->port_no == br->root_port) {
			br_record_config_timeout_values(br, bpdu);
			br_config_bpdu_generation(br);
			if (bpdu->topology_change_ack)
				br_topology_change_acknowledged(br);
		}
	} else if (br_is_designated_port(p)) {		
		br_reply(p);		
	}
}

/* called under bridge lock */
/* 接收网桥生成树改变通知报文 */
void br_received_tcn_bpdu(struct net_bridge_port *p)
{
	/* 判断该端口是不是指定端口，只有指定端口才能接收 */
	if (br_is_designated_port(p)) {
		pr_info("%s: received tcn bpdu on port %i(%s)\n",
		       p->br->dev->name, p->port_no, p->dev->name);

		br_topology_change_detection(p->br);
		br_topology_change_acknowledge(p);
	}
}
