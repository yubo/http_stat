/*
 * This is a module which is used to replace http .
 * 
 * Yu Bo <yubo@yubo.org>
 * 2015-02-16
 * 
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/gfp.h>
#include <linux/ctype.h>

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <net/dst.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <asm/unaligned.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_tcpudp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_nat_helper.h>

#include "http_stat_ctl.h"

struct http_session_table {
	spinlock_t  lock;
	struct hlist_head  head[HTTP_SESSION_HASH_SIZE];
};

struct http_session_key {
	uint32_t client_ip;
	uint16_t client_port;
	uint16_t res;
};

struct http_session {
	struct hlist_node hnode;
	atomic_t __refcnt;
	struct http_session_key key;
	uint32_t flags;
	uint32_t proxy_tsval;
	uint32_t jiff;			/*last access jiffies*/
}____cacheline_aligned_in_smp;

static int gc_timer_hash_index = 0;
static struct timer_list gc_timer;
static struct http_session_table *http_sess_table;

static void dump_skb(const struct sk_buff *skb, const struct net_device *in,
	const struct net_device *out)
{
	struct iphdr *iph;
	struct tcphdr *th;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	int i, llen, dlen;
	const unsigned char *pos;
	const int line_len = 16;
	char buff[1024-32];
	char *p;

	iph = ip_hdr(skb);

	p = buff;
	if (iph->protocol != IPPROTO_TCP){
		p += snprintf(p, sizeof(buff) - (p - buff), "%s: protocal not tcp [%d]\n", __FUNCTION__, iph->protocol);
		printk(KERN_DEBUG "%s", buff);
		return;
	}
	th = (struct tcphdr *) ((char*)iph + iph->ihl*4);
	dlen = ntohs(iph->tot_len) - iph->ihl * 4 - th->doff * 4;

	if (th->source == htons(80) || th->dest == htons(80) ||
		th->source == htons(8193) || th->dest == htons(8193)) {
		p += snprintf(p, sizeof(buff) - (p - buff),
			"%s:%lu skb len/datalen:%d/%d, dlen:%d %pI4:%u(%s)-->%pI4:%u(%s), seq:%x, ack:%x, next seq:%x\n\t[",
			__FUNCTION__, jiffies, skb->len, skb->data_len, dlen,
			&iph->saddr, ntohs(th->source), in  ? in->name  : "NULL",
			&iph->daddr, ntohs(th->dest),   out ? out->name : "NULL",
			ntohl(th->seq), ntohl(th->ack_seq), ntohl(th->seq)+(dlen > 0 ? dlen : 1) );
		if(th->fin) p += snprintf(p, sizeof(buff) - (p - buff), "F");
		if(th->syn) p += snprintf(p, sizeof(buff) - (p - buff), "S");
		if(th->rst) p += snprintf(p, sizeof(buff) - (p - buff), "R");
		if(th->ack) p += snprintf(p, sizeof(buff) - (p - buff), ".");
		if(th->psh) p += snprintf(p, sizeof(buff) - (p - buff), "P");
		if(th->urg) p += snprintf(p, sizeof(buff) - (p - buff), "U");
		if(th->ece) p += snprintf(p, sizeof(buff) - (p - buff), "E");
		if(th->cwr) p += snprintf(p, sizeof(buff) - (p - buff), "C");

		p += snprintf(p, sizeof(buff) - (p - buff), "] window[%04x] ", th->window);
		ct = nf_ct_get(skb, &ctinfo);
		if (ct){
			if((ct->status & IPS_NAT_MASK) == IPS_SRC_NAT)
				p += snprintf(p, sizeof(buff) - (p - buff), " [SNAT] ");
			if((ct->status & IPS_NAT_MASK) == IPS_DST_NAT)
				p += snprintf(p, sizeof(buff) - (p - buff), " [DNAT] ");
		}
		printk(KERN_DEBUG "%s\n", buff);
		p = buff;
		if(dlen >= HTTP_MIN_LEN && skb->data_len == 0) {
			dlen = dlen > line_len * 4 ? line_len * 4 : dlen;
			pos = (char *)th + th->doff * 4;
			while (dlen) {
				llen = dlen > line_len ? line_len : dlen;
				p += snprintf(p, sizeof(buff) - (p - buff), "    ");
				for (i = 0; i < llen; i++)
					p += snprintf(p, sizeof(buff) - (p - buff), " %02x", pos[i]);
				for (i = llen; i < line_len; i++)
					p += snprintf(p, sizeof(buff) - (p - buff), "   ");
				p += snprintf(p, sizeof(buff) - (p - buff), "   ");
				for (i = 0; i < llen; i++) {
					if (isprint(pos[i]))
						p += snprintf(p, sizeof(buff) - (p - buff), "%c", pos[i]);
					else
						p += snprintf(p, sizeof(buff) - (p - buff), "*");
				}
				for (i = llen; i < line_len; i++)
					p += snprintf(p, sizeof(buff) - (p - buff), " ");
				printk(KERN_DEBUG "%s\n", buff);
				p = buff;
				pos += llen;
				dlen -= llen;
			}
		}
	}
}


uint32_t http_session_hash(struct http_session_key *key)
{
	uint32_t hash = key->client_ip + key->client_port + (key->client_port >> 1);

	return (hash % HTTP_SESSION_HASH_MASK);
}

int http_session_cmp(struct http_session_key *key1, struct http_session_key *key2)
{
	return memcmp(key1, key2, sizeof(struct http_session_key));
}

struct http_session* __http_session_search(struct http_session_key *key)
{
	struct hlist_node *pos;
	struct http_session *http_sess;
	uint32_t hash = http_session_hash(key);
	struct hlist_head *head = &http_sess_table->head[hash];

	hlist_for_each_entry(http_sess, pos, head, hnode) {
		//DEBUG_PRINT(KERN_DEBUG "%s:  hash:%d, head:%p, http_sess:%p, pos:%p\n",
		//	__func__, hash, head, http_sess, pos);
		if (http_session_cmp(&http_sess->key, key) == 0) {
		//	DEBUG_PRINT(KERN_DEBUG "%s: [FIND %pI4:%u] hash:%d, head:%p, http_sess:%p, pos:%p\n",
		//		__func__, &key->client_ip, ntohs(key->client_port), hash, head, http_sess, pos);
			return http_sess;
		}
	}
	return NULL;
}

int __http_session_insert(struct http_session *http_sess)
{
	uint32_t hash = http_session_hash(&http_sess->key);
	struct hlist_head *head = &http_sess_table->head[hash];
	//DEBUG_PRINT(KERN_DEBUG "%s:  hash:%d, head:%p, http_sess:%p\n",
	//	__func__, hash, head, http_sess);
	hlist_add_head(&http_sess->hnode, head);

	return 0;
}

void __http_session_del(struct http_session *http_sess)
{
	hlist_del(&http_sess->hnode);
	return;
}

void __http_session_free(struct http_session *http_sess)
{
	kfree(http_sess);
}


void put_http_session(struct http_session *http_sess)
{
	http_sess->jiff = jiffies;
	return atomic_dec(&http_sess->__refcnt);
}

void get_http_session(struct http_session *http_sess)
{
	return atomic_inc(&http_sess->__refcnt);
}

struct http_session* http_session_search(struct http_session_key *key)
{
	struct http_session* http_sess;
	HTTP_SESS_TABLE_LOCK();
	http_sess = __http_session_search(key);
	if (http_sess)
		get_http_session(http_sess);
	HTTP_SESS_TABLE_UNLOCK();

	return http_sess;
}

struct http_session* http_session_create(struct http_session_key *key)
{
	struct http_session* http_sess;

	http_sess = kzalloc(sizeof(struct http_session), GFP_ATOMIC);
	if (http_sess == NULL) {
		printk(KERN_INFO "%s: zalloc failed key:%p, client: %pI4,%u\n",
			__func__, key, &key->client_ip, key->client_port);
		return NULL;
	}
	memcpy(&http_sess->key, key, sizeof(struct http_session_key));
	atomic_set((&http_sess->__refcnt), 1);


	HTTP_SESS_TABLE_LOCK();
	if (__http_session_search(&http_sess->key)) {
		HTTP_SESS_TABLE_UNLOCK();
		printk(KERN_INFO "%s: duplicated key:%p, client: %pI4,%u\n",
			__func__, key, &key->client_ip, ntohs(key->client_port));
		kfree(http_sess);
		http_sess = NULL;
	} else {
		__http_session_insert(http_sess);
		HTTP_SESS_TABLE_UNLOCK();
	}

	return http_sess;
}

struct http_session* http_session_del(struct http_session_key *key)
{
	struct http_session* http_sess;

	HTTP_SESS_TABLE_LOCK();
	http_sess = __http_session_search(key);
	if (http_sess)
		__http_session_del(http_sess);
	HTTP_SESS_TABLE_UNLOCK();

	return http_sess;
}

static struct config * search_stat(char *response) 
{
	uint32_t *resp;
	resp = (uint32_t *)response;
	
	DEBUG_PRINT("request[%s]\n", response);

	// http://tools.ietf.org/html/rfc2616
	// HTTP/(0.9)|(1.0)|(1.1) 404
	if(resp[0] != *(uint32_t *)"HTTP"){
		DEBUG_PRINT("not match ^HTTP\n");
		return NULL;
	}
	
	if(resp[1] == *(uint32_t *)"/0.9" || resp[1] == *(uint32_t *)"/1.0"
			|| resp[1] == *(uint32_t *)"/1.1"){
		return config_search(resp[2]);
	}
	DEBUG_PRINT("not match ^HTTP/x.x \n");
	return NULL;
}

static unsigned int ipv4_http_stat_post_hook(unsigned int hooknum,
	struct sk_buff *skb, const struct net_device *in,
	const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	int ret = NF_ACCEPT;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct iphdr *iph;
	struct tcphdr *th, _tcph;
	struct http_session_key key;
	struct http_session *session;
	int dir, dlen = 0;
	char * data = NULL;
	struct config *stat;
	char *resp, _resp[13];
	
	ct = nf_ct_get(skb, &ctinfo);
	if (ct == NULL){
		return NF_ACCEPT;
	}

	if (nf_is_loopback_packet(skb))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	/* Relocate data pointer */
	//th = (struct tcphdr *) ((char*)iph + iph->ihl*4);
	th = skb_header_pointer(skb, iph->ihl*4,
				sizeof(_tcph), &_tcph);
	if (th == NULL)
		return NF_ACCEPT;


	dir = CTINFO2DIR(ctinfo);

	if(dir == IP_CT_DIR_REPLY){
		if (th->source == htons(80)) {
			DUMP_SKB(skb, in, out);

			if (th->syn && th->ack){
				key.client_ip = iph->daddr;
				key.client_port = th->dest;
				key.res = 0;
				session = http_session_create(&key);
				if (session == NULL){
					DEBUG_PRINT(KERN_DEBUG "create seession fail!!!, NF_ACCEPT\n");
					goto out;
				}				
				DEBUG_PRINT(KERN_DEBUG "create seession success!!!\n");
				goto put_session;
			}

			key.client_ip = iph->daddr;
			key.client_port = th->dest;
			key.res = 0;
			session = http_session_search(&key);
			if (session == NULL){
				DEBUG_PRINT(KERN_DEBUG "seession found, NF_ACCEPT\n");
				goto out;
			}
			DEBUG_PRINT(KERN_DEBUG "seession founded\n");

//			if(th->psh){
				if(session->flags & HTTP_STAT_F_SKIP){
					DEBUG_PRINT(KERN_DEBUG "[HTTP_STAT_F_SKIP]skip this skb\n");
					goto put_session;
				}
					
				dlen = ntohs(iph->tot_len) - iph->ihl * 4 - th->doff * 4;
				data = (char *)th + th->doff * 4;

				if(session->flags & HTTP_STAT_F_MODI){
					DEBUG_PRINT(KERN_DEBUG "[HTTP_STAT_F_MODI]empty this skb\n");
					if(!nf_nat_mangle_tcp_packet(skb, ct, ctinfo, 
												0, dlen, NULL, 0)){
						DEBUG_PRINT(KERN_DEBUG "nf_nat_mangle_tcp_packet fail!!\n");
						session->flags |= HTTP_STAT_F_SKIP;
						ret = NF_DROP;
					}
					goto put_session;
				}

				if(dlen < HTTP_MIN_LEN){
					/* after SYN/ACK , recv ACK */
					goto put_session;
				}

				// if skb->data_len > 0
				resp = skb_header_pointer(skb, iph->ihl*4 + th->doff*4, sizeof(_resp), _resp);
				if(resp == NULL){
					DEBUG_PRINT(KERN_DEBUG" can't get response \n");
					goto put_session;
				}
				resp[12] = '\0';

				if((stat = search_stat(resp))){
					DEBUG_PRINT(KERN_DEBUG "hit HTTP/1.1%4s, modify this skb\n", (char *)&stat->code);
					
					if(!nf_nat_mangle_tcp_packet(skb, ct, ctinfo, 
												0, dlen, stat->content, strlen(stat->content))){
						DEBUG_PRINT(KERN_DEBUG "nf_nat_mangle_tcp_packet fail!!\n");
						ret = NF_DROP;
						goto put_session;
					}
					session->flags |= HTTP_STAT_F_MODI;
					goto put_session;
				}else{
					DEBUG_PRINT(KERN_DEBUG "not hit and clean this session data->len[%d]\n", skb->data_len);
					goto del_seesion;
				}
//			}
			goto put_session;
		}	
	}else{
		// 1.2.1.3:2233 -> 1.2.1.4:80
		if ( th->dest == htons(80) 
	//			&& (ct->status & IPS_NAT_MASK) == IPS_SRC_NAT // local in no need this
				&& !(ct->status & IPS_DYING))  
		{
			key.client_ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
			key.client_port = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port;
			key.res = 0;
			session = http_session_search(&key);

			DUMP_SKB(skb, in, out);

			if (session){
				goto put_session;
			}else{
				goto out;
			}
		}	
	}

out:
	return ret;

put_session:
	if((session->flags & HTTP_STAT_F_MODI)
			&& ct && test_bit(IPS_SEQ_ADJUST_BIT, &ct->status) 
			&& (ctinfo != IP_CT_RELATED + IP_CT_IS_REPLY)){
		if(nf_nat_seq_adjust_hook(skb, ct, ctinfo) != 1){
			PERF_DEBUG("nf_nat_seq_adjust_hook fail\n");
		}else{
			PERF_DEBUG("nf_nat_seq_adjust_hook success\n");
		}
	}
		
	put_http_session(session);
	return ret;
	
del_seesion:
	put_http_session(session);
	
	HTTP_SESS_TABLE_LOCK();
	__http_session_del(session);
	HTTP_SESS_TABLE_UNLOCK();
	__http_session_free(session);
	PERF_DEBUG("%s, end fake END at:%lu;", __FUNCTION__, (jiffies));
	return ret;

}

static struct nf_hook_ops ipv4_http_stat_ops[] __read_mostly = {
	{
		.hook           = ipv4_http_stat_post_hook,
		.owner          = THIS_MODULE,
		.pf             = NFPROTO_IPV4,
		.hooknum        = NF_INET_POST_ROUTING, //todo why not locatout?
		.priority       = NF_IP_PRI_CONNTRACK_CONFIRM,
	},
	{
		.hook           = ipv4_http_stat_post_hook,
		.owner          = THIS_MODULE,
		.pf             = NFPROTO_IPV4,
		.hooknum        = NF_INET_LOCAL_IN, //todo why not locatout?
		.priority       = NF_IP_PRI_CONNTRACK_CONFIRM,
	},
};


void gc_timer_callback(unsigned long data)
{
	int i;
	struct hlist_node *pos;
	struct hlist_node *n;
	struct http_session *http_sess;
	struct hlist_head *head;

	for (i=0; i<HTTP_SESSION_STEP_SIZE; i++) {
		head = &http_sess_table->head[gc_timer_hash_index];
		HTTP_SESS_TABLE_LOCK();
		hlist_for_each_entry_safe(http_sess, pos, n, head, hnode) {
			if (time_after(jiffies, http_sess->jiff + HTTP_SESSION_TIMEOUT)
					&& atomic_read(&http_sess->__refcnt) == 0) {
				__http_session_del(http_sess);
				__http_session_free(http_sess);
			}
		}
		HTTP_SESS_TABLE_UNLOCK();

		gc_timer_hash_index++;
		gc_timer_hash_index &= HTTP_SESSION_HASH_MASK;
	}
	mod_timer(&gc_timer, jiffies + GC_TIMER_INTERVAL);

	return;
}

static int __init http_stat_init(void)
{
	int i = 0;
	int err = 0;

	if((err = http_stat_ctl_init())){
		goto err_ctl_init;
	}

	http_sess_table = kzalloc(sizeof(struct http_session_table), GFP_ATOMIC);
	if (NULL == http_sess_table) {
		err = -ENOMEM;
		goto err_malloc;
	}

	spin_lock_init(&http_sess_table->lock);
	for (i = 0; i < HTTP_SESSION_HASH_SIZE; i++) {
		INIT_HLIST_HEAD(&http_sess_table->head[i]);
	}

	err = nf_register_hooks(ipv4_http_stat_ops,
			ARRAY_SIZE(ipv4_http_stat_ops));
	if (err < 0) {
		printk(KERN_ERR"%s, register nf_hooks error!\n", __FUNCTION__);
		goto err_hook;
	}


	setup_timer(&gc_timer, gc_timer_callback, 0);
	mod_timer(&gc_timer, jiffies + GC_TIMER_INTERVAL);
	printk("%s, succeed!\n", __FUNCTION__);
	return 0;

err_hook:
	kfree(http_sess_table);
err_malloc:
err_ctl_init:
	return err;
}

static void __exit http_stat_exit(void)
{
	int i;
	int ret;
	struct hlist_node *pos;
	struct hlist_node *n;
	struct http_session *http_sess;
	struct hlist_head *head;

	nf_unregister_hooks(ipv4_http_stat_ops, ARRAY_SIZE(ipv4_http_stat_ops));
	
	ret = del_timer_sync(&gc_timer);
	if (ret)
		printk("Timer is still in use...\n");

	HTTP_SESS_TABLE_LOCK();
	for (i=0; i<HTTP_SESSION_HASH_SIZE; i++) {
		head = &http_sess_table->head[i];
		hlist_for_each_entry_safe(http_sess, pos, n, head, hnode) {
			__http_session_del(http_sess);
			__http_session_free(http_sess);
		}
	}
	HTTP_SESS_TABLE_UNLOCK();
	kfree(http_sess_table);
	http_stat_ctl_exit();
}

module_init(http_stat_init);
module_exit(http_stat_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yu Bo <yubo@xiaomi.com>");
MODULE_DESCRIPTION("http stat replace");
