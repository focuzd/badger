#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include "../include/common.h"

#define WINDOW_SIZE 1000000000
#define NSEC_PER_SEC 1000000000ULL

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u16);
    __type(value, __u8);
} drop_dports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u16);
    __type(value, __u8);
} drop_sports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 64);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} src_block SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rate_window);
} dst_budget SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, struct token_bucket);
} src_buckets SEC(".maps");

static __always_inline int count_and_return(int action)
{
    __u64 *count;
    __u32 key;
    if (action == XDP_PASS)
        key = PASSED;
    else if (action == XDP_DROP)
        key = DROPPED;
    else
        return XDP_PASS;

    count = bpf_map_lookup_elem(&stats, &key);
    if (count)
        (*count)++;

    return action;
}

SEC("xdp")
int xdp_count_and_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long) ctx->data;
    void *data_end = (void *)(long) ctx->data_end;

    __u32 stats_key = SEEN;
    __u64 *count = bpf_map_lookup_elem(&stats, &stats_key);
    if (count)
        (*count)++;

    __u32 bkey = 0;
    __u32 cfg_key = CFG_DST_BUDGET;
    __u64 *dbudget = bpf_map_lookup_elem(&config, &cfg_key);
    if (dbudget && *dbudget != 0) {
        struct rate_window *win = bpf_map_lookup_elem(&dst_budget, &bkey);
        if (win) {
            __u64 now = bpf_ktime_get_ns();
            __u64 old_start = win->start_ns;
            if (now - old_start > WINDOW_SIZE) {
                if (__sync_val_compare_and_swap(&win->start_ns, old_start, now) == old_start)
                    win->count = 0;
            }
            __u64 old_count = __sync_fetch_and_add(&win->count, 1);
            if (old_count + 1 > *dbudget) 
                return count_and_return(XDP_DROP);
        }
    }

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return count_and_return(XDP_PASS);

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return count_and_return(XDP_PASS);

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return count_and_return(XDP_PASS);

    if (iph->ihl * 4 < sizeof(struct iphdr) || (void *)iph + iph->ihl * 4 > data_end) 
        return count_and_return(XDP_PASS);
    //iph->ihl is 4 bits in first byte of iph, so no byte reordering required

    struct lpm_key lkey = {
        .prefixlen = 32,
        .addr = iph->saddr
    };

    if (bpf_map_lookup_elem(&src_block, &lkey))
        return count_and_return(XDP_DROP);
    
    cfg_key = CFG_SRC_BURST;
    __u64 *src_burst = bpf_map_lookup_elem(&config, &cfg_key);
    cfg_key = CFG_SRC_RATE;
    __u64 *src_rate = bpf_map_lookup_elem(&config, &cfg_key);
    
    // TODO: work on a version with atomics
    if (src_burst && src_rate && (*src_burst != 0) && (*src_rate != 0)) {
        __u64 burst = *src_burst;
        __u64 rate = *src_rate;
        __u64 now = bpf_ktime_get_ns();
        __u32 skey = iph->saddr;

        struct token_bucket *b = bpf_map_lookup_elem(&src_buckets, &skey);
        
        if (b) {
            __u64 elapsed = now - b->last_ns;
            __u64 fill_ns = burst * NSEC_PER_SEC / rate;

            if (elapsed >= fill_ns) {
                b->tokens = burst;
                b->token_fraction = 0;
            } else {
                __u64 acc = elapsed * rate + b->token_fraction;
                __u64 tokens = b->tokens + acc / NSEC_PER_SEC;

                if (tokens > burst) {
                    b->tokens = burst;
                    b->token_fraction = 0;
                } else {
                    b->tokens = tokens;
                    b->token_fraction = acc % NSEC_PER_SEC;
                }
            }

            b->last_ns = now;
            if (b->tokens == 0)
                return count_and_return(XDP_DROP);
            b->tokens--;
            
        } else {
            struct token_bucket nb = {
                .tokens = *src_burst - 1,
                .last_ns = bpf_ktime_get_ns(),
                .token_fraction = 0
            };

            bpf_map_update_elem(&src_buckets, &skey, &nb, BPF_NOEXIST);
        }
    }

    // same goes for iph->protocol
    if (iph->protocol != IPPROTO_UDP)
        return count_and_return(XDP_PASS);

    struct udphdr *udph = (void *)iph + iph->ihl * 4;
    if ((void *)(udph + 1) > data_end)
        return count_and_return(XDP_PASS);

    if (bpf_map_lookup_elem(&drop_dports, &udph->dest) || bpf_map_lookup_elem(&drop_sports, &udph->source))
        return count_and_return(XDP_DROP);
    
    return count_and_return(XDP_PASS);
}
