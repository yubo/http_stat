/*  
 *  http_stat.c
 *  yubo@yubo.org
 *  2015-02-16
 */
#if (PAGE_SIZE < 4096)
#error "http_stat needs at least a PAGE_SIZE of 4096"
#endif

//#define __HTTP_ERROR_DISABLE_TS__
#define __HTTP_ERROR_DEBUG__

#define HTTP_STAT_F_SKIP		0x00000001  /* http stat flags */
#define HTTP_STAT_F_MODI		0x00000002	/* Modified */
#define HTTP_MIN_LEN			18
#define HTTP_SESSION_HASH_SIZE	1024
#define HTTP_SESSION_STEP_SIZE	256
#define HTTP_SESSION_HASH_MASK	(HTTP_SESSION_HASH_SIZE - 1)
#define GC_TIMER_INTERVAL		msecs_to_jiffies(1000)	/* 1s */
#define HTTP_SESSION_TIMEOUT	msecs_to_jiffies(5000)	/* 5s */
#define CONFIG_HASH_SIZE		1024
#define CONFIG_HASH_MASK		(CONFIG_HASH_SIZE - 1)
#define CONFIG_PATH_SIZE		256
#define PROCFS_MAX_SIZE    		CONFIG_PATH_SIZE
#define PROC_FILENAME	   		"confdir"
#define PROC_DIRNAME	   		"http_stat"

#define HTTP_SESS_TABLE_LOCK()		spin_lock_bh(&http_sess_table->lock)
#define HTTP_SESS_TABLE_UNLOCK()	spin_unlock_bh(&http_sess_table->lock)
#define CONFIG_TABLE_LOCK()			spin_lock_bh(&conf_table->lock)
#define CONFIG_TABLE_UNLOCK()		spin_unlock_bh(&conf_table->lock)

#ifdef __HTTP_ERROR_DEBUG__
#define DEBUG_PRINT(fmt, a...) printk("%s:%d " fmt, __func__, __LINE__, ##a)
#define DUMP_SKB(skb, in, out) dump_skb(skb, in, out)
#else
#define DEBUG_PRINT(fmt, a...) do { } while(0)
#define DUMP_SKB(skb, in, out) do { } while(0)
#endif

#ifdef __PERF_DEBUG__
#define PERF_DEBUG(fmt, a...) \
    do { \
        struct timeval tv;\
        printk(fmt, ##a); \
        do_gettimeofday(&tv);\
        printk(" timeval(%dsec, %dusec)\n", tv.tv_sec, tv.tv_usec); \
    }while(0)
#else
#define PERF_DEBUG(fmt, a...) do { } while(0)
#endif


struct config_table {
	spinlock_t  lock;
	char dirname[CONFIG_PATH_SIZE];
	struct hlist_head  head[CONFIG_HASH_SIZE];
};

struct config {
	struct hlist_node hnode;
	atomic_t __refcnt;
	char filename[CONFIG_PATH_SIZE];
	uint32_t code;
	char *content;
}____cacheline_aligned_in_smp;

#ifndef __HTTP_STAT_CTL_MODULE__
int http_stat_ctl_init(void);
void http_stat_ctl_exit(void);
struct config* config_search(uint32_t key);
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
/* Packet is received from loopback */
static inline bool nf_is_loopback_packet(const struct sk_buff *skb)
{
	return skb->dev && skb->dev->flags & IFF_LOOPBACK;
}
#endif


