#include "../include/src_table.h"

static inline __u32 slot_of(__u32 addr)
{
    return (__u32)(addr * 2654435761u) >> (32 - SRC_TABLE_BITS);
}

void src_table_reset(struct src_table *t) 
{
    for (__u32 i = 0; i < t->n_used; i++)
        t->slots[t->used[i]].count = 0;

    t->n_used = 0;
    t->total = 0;
    t->overflow = 0;
    t->top.addr = 0;
    t->top.count = 0;
}

void src_table_add(struct src_table *t, __u32 addr) 
{
    __u32 i = slot_of(addr);

    while (t->slots[i].count != 0 && t->slots[i].addr != addr)
        i = (i + 1) & (SRC_TABLE_CAP - 1);

    if (t->slots[i].count == 0) {
        if (t->n_used >= SRC_TABLE_MAX_FILL) {
            t->overflow++;
            t->total++;
            return;
        }

        t->slots[i].addr = addr;
        t->used[t->n_used++] = i;
    }

    t->slots[i].count++;
    t->total++;

    if (t->slots[i].count > t->top.count)
        t->top = t->slots[i];
}