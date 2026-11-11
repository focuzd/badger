#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../include/common.h"
#include "../include/maps.h"

#define PORT_COUNT 65536
#define NSEC_PER_SEC 1000000000ULL
#define MAX_SRC 2048

struct src_freq {
    __u32 src;
    __u64 freq;
};

struct window {
    __u64 start_ns;
    __u64 seen_pkts;
    __u64 sport_count[PORT_COUNT];
    __u64 dport_count[PORT_COUNT];
    struct src_freq src_count[MAX_SRC];
    int stats_fd;
};

__u16 top_port(__u64 freq[]) 
{
    __u16 max_idx = 0;
    for (int i = 0; i < PORT_COUNT; i++)
        if (freq[i] > freq[max_idx])
            max_idx = i;

    return max_idx;
}

struct src_freq top_src (struct src_freq counts[])
{
    int i = 0;
    struct src_freq top = counts[0];
    while (counts[i].src != 0) {
        if (counts[i].freq > top.freq)
            top = counts[i];
        i++;
    }

    return top;
}


int handle_sample(void *ctx, void *data, size_t size) {
    struct sample *s = data;
    struct window *win = ctx;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    __u64 now = (__u64)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
    if (now - win->start_ns >= NSEC_PER_SEC) {
        printf("(%llu)\n", now);
        __u64 seen_now = read_percpu_u64(win->stats_fd, SEEN);
        printf("packet rate: %llu/sec\n", seen_now - win->seen_pkts);

        __u16 top_dport = top_port(win->dport_count);
        __u16 top_sport = top_port(win->sport_count);
        struct src_freq src_top = top_src(win->src_count);
        printf("Top destination port: %hu : %llu\n",
            ntohs(top_dport), win->dport_count[top_dport]);
        printf("Top source port: %hu : %llu\n",
            ntohs(top_sport), win->sport_count[top_sport]);
        char buf[INET_ADDRSTRLEN];
        struct in_addr a = {.s_addr = src_top.src};
        inet_ntop(AF_INET, &a, buf, sizeof(buf));
        printf("Top src address: %s : %llu\n", buf, src_top.freq);
        
        win->start_ns = now;
        win->seen_pkts = seen_now;
        memset(&win->dport_count, 0, sizeof(win->dport_count));
        memset(&win->sport_count, 0, sizeof(win->sport_count));
        memset(&win->src_count, 0, sizeof(win->src_count));
    }

    win->sport_count[s->sport]++;
    win->dport_count[s->dport]++;

    for (int i = 0; i < MAX_SRC; i++) {
        if (win->src_count[i].src == 0) {
            win->src_count[i].src = s->saddr;
            win->src_count[i].freq++;
            break;
        } else if (win->src_count[i].src == s->saddr) {
            win->src_count[i].freq++;
            break;
        }
    }

    return 0;
}

int main(void) {
    struct window state = {};
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    state.start_ns = (__u64)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
    state.stats_fd = find_map_fd("stats");
    state.seen_pkts = read_percpu_u64(state.stats_fd, SEEN);
    int map_fd = find_map_fd("samples");
    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_sample, &state, NULL); 

    while(1) 
        ring_buffer__poll(rb, 1000);
}