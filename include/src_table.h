#ifndef SRC_TABLE_H
#define SRC_TABLE_H

#include <linux/types.h>

#define SRC_TABLE_BITS 12
#define SRC_TABLE_CAP (1u << SRC_TABLE_BITS)
#define SRC_TABLE_MAX_FILL (SRC_TABLE_CAP * 3/4)

struct src_entry {
    __u32 addr;
    __u32 count;
};

struct src_table {
    struct src_entry slots[SRC_TABLE_CAP];
    __u32 used[SRC_TABLE_CAP];
    __u32 n_used;
    __u32 total;
    __u32 overflow;
    struct src_entry top;
};

void src_table_reset(struct src_table *t);
void src_table_add(struct src_table *t, __u32 addr);
static inline struct src_entry src_table_top(const struct src_table *t)
{
    return t->top;
}

#endif 