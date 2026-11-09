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

enum {
    SEEN,
    PASSED,
    DROPPED
};

enum {
    CFG_DST_BUDGET,
    CFG_SRC_RATE,
    CFG_SRC_BURST,
};

#endif
