/* IP tables module for matching the value of the TTL 
 *
 * ipt_ttl.c,v 1.5 2000/11/13 11:16:08 laforge Exp
 *
 * (C) 2000,2001 by Harald Welte <laforge@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>

#include <linux/netfilter_ipv4/ipt_ttl.h>
#include <linux/netfilter_ipv4/ip_tables.h>

MODULE_AUTHOR("Harald Welte <laforge@netfilter.org>");
MODULE_DESCRIPTION("IP tables TTL matching module");
MODULE_LICENSE("GPL");

static int match(const struct sk_buff *skb,
		 const struct net_device *in, const struct net_device *out,
		 const struct xt_match *match, const void *matchinfo,
		 int offset, unsigned int protoff, int *hotdrop)
{
	const struct ipt_ttl_info *info = matchinfo;

	switch (info->mode) {
		case IPT_TTL_EQ:
			return (skb->nh.iph->ttl == info->ttl);
			break;
		case IPT_TTL_NE:
			return (!(skb->nh.iph->ttl == info->ttl));
			break;
		case IPT_TTL_LT:
			return (skb->nh.iph->ttl < info->ttl);
			break;
		case IPT_TTL_GT:
			return (skb->nh.iph->ttl > info->ttl);
			break;
		default:
			printk(KERN_WARNING "ipt_ttl: unknown mode %d\n", 
				info->mode);
			return 0;
	}

	return 0;
}

static struct ipt_match ttl_match = {
	.name		= "ttl",
	.match		= match,
	.matchsize	= sizeof(struct ipt_ttl_info),
	.me		= THIS_MODULE,
};

static int __init ipt_ttl_init(void)
{
	return ipt_register_match(&ttl_match);
}

static void __exit ipt_ttl_fini(void)
{
	ipt_unregister_match(&ttl_match);

}

module_init(ipt_ttl_init);
module_exit(ipt_ttl_fini);
