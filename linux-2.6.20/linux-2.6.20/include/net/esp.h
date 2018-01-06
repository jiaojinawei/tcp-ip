#ifndef _NET_ESP_H
#define _NET_ESP_H

#include <linux/crypto.h>
#include <net/xfrm.h>
#include <asm/scatterlist.h>

#define ESP_NUM_FAST_SG		4

struct esp_data
{
	struct scatterlist		sgbuf[ESP_NUM_FAST_SG];

	/* Confidentiality */
	/* 加密使用的相关数据 */
	struct {
		u8			*key;		/* Key 密钥 */
		int			key_len;	/* Key length 密钥长度 */
		int			padlen;		/* 0..255 填充长度 */
		/* ivlen is offset from enc_data, where encrypted data start.
		 * It is logically different of crypto_tfm_alg_ivsize(tfm).
		 * We assume that it is either zero (no ivec), or
		 * >= crypto_tfm_alg_ivsize(tfm). */
		int			ivlen;/* 初始化向量长度 */
		int			ivinitted;/* 初始化向量是否已经初始化标志 */
		u8			*ivec;		/* ivec buffer 初始化向量*/
		struct crypto_blkcipher	*tfm;		/* crypto handle加密句柄 */
	} conf;

	/* Integrity. It is active when icv_full_len != 0 */
	/* 认证使用相关数据结构 */
	struct {
		u8			*key;		/* Key 密钥 */
		int			key_len;	/* Length of the key 密钥长度 */
		u8			*work_icv;/* 初始化向量 */
		int			icv_full_len;/* 初始化向量全长 */
		int			icv_trunc_len;/* 初始化向量截断长度 */
		void			(*icv)(struct esp_data*,/* 初始化向量更新函数 */
		                               struct sk_buff *skb,
		                               int offset, int len, u8 *icv);
		struct crypto_hash	*tfm;/* hash算法 */
	} auth;
};

extern int skb_to_sgvec(struct sk_buff *skb, struct scatterlist *sg, int offset, int len);
extern int skb_cow_data(struct sk_buff *skb, int tailbits, struct sk_buff **trailer);
extern void *pskb_put(struct sk_buff *skb, struct sk_buff *tail, int len);

static inline int esp_mac_digest(struct esp_data *esp, struct sk_buff *skb,
				 int offset, int len)
{
	struct hash_desc desc;
	int err;

	desc.tfm = esp->auth.tfm;/* 获取hash算法描述控制块 */
	desc.flags = 0;

	err = crypto_hash_init(&desc);
	if (unlikely(err))
		return err;
	err = skb_icv_walk(skb, &desc, offset, len, crypto_hash_update);
	if (unlikely(err))
		return err;
	return crypto_hash_final(&desc, esp->auth.work_icv);/* hash计算结束 */
}

#endif
