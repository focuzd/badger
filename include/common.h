#ifndef COMMON_H
#define COMMON_H

#include <linux/types.h>

struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct rate_window {
    __u64 start_ns;
    __u64 count;
};

struct token_bucket {
    __u64 tokens;
    __u64 last_ns;
    __u64 token_fraction;
};

struct sample {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u16 len;
    __u16 tcp_flags;
    __u8 protocol;
    __u8 verdict;
};

enum {
    SEEN,
    PASSED,
    DROPPED
};

enum {
    CFG_DST_BUDGET,
    CFG_SRC_RATE,
    CFG_SRC_BURST,
    CFG_SAMPLE_RATE,
};

#endif
