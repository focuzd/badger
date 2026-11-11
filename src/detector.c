#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../include/common.h"
#include "../include/maps.h"

#define NSEC_PER_SEC 1000000000ULL
#define POLL_MS 100
#define CONFIRM_TICKS 3
#define MIN_SAMPLES 100
#define DEFAULT_THRESHOLD_PPS 10000
#define FALLBACK_BUDGET_PPS 2000

#define PORT_SHARE_PCT 20
#define SRC_SHARE_PCT 30
#define SYN_SHARE_PCT 60

#define SRC_SLOTS 4096
#define SRC_MAX_FILL 3072

#define TCP_SYN 0x02
#define TCP_ACK 0x10

__u16 amplifier_ports[] = {53, 123, 389, 1900, 11211, 19, 161};

struct src_entry {
    __u32 addr;
    __u32 count;
};

// everything sampled in the current tick, cleared every second
struct tick_tally {
    __u32 samples;
    __u32 syn;
    __u32 udp_sport[65536];
    __u32 udp_dport[65536];
    struct src_entry srcs[SRC_SLOTS];
    __u32 n_srcs;
    struct src_entry top_src;
};

struct detector {
    int stats_fd, config_fd, dports_fd, sports_fd, src_fd;
    __u64 threshold_pps;
    __u64 prev_seen, prev_passed, prev_dropped;
    __u64 tick_start_ns;
    __u64 attack_start_ns;
    int breach_ticks;
    int n_installed;
    bool confirmed;
    bool rules_this_attack;
};

struct tick_tally tally;
volatile sig_atomic_t running = 1;

__u64 now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

void log_prefix(void)
{
    struct timespec ts;
    struct tm tm;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    printf("[%02d:%02d:%02d.%03ld] ", tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000);
}

void on_signal(int sig)
{
    running = 0;
}

bool is_amplifier(__u16 port)
{
    for (int i = 0; i < sizeof(amplifier_ports) / sizeof(amplifier_ports[0]); i++)
        if (amplifier_ports[i] == port)
            return true;
    return false;
}

__u32 share(__u32 count)
{
    if (tally.samples == 0)
        return 0;
    return (__u64)count * 100 / tally.samples;
}

// open addressing hash table, only the top source is needed in the end
void add_src(__u32 addr)
{
    __u32 i = (addr * 2654435761u) >> 20;

    while (tally.srcs[i].count != 0 && tally.srcs[i].addr != addr)
        i = (i + 1) % SRC_SLOTS;

    if (tally.srcs[i].count == 0) {
        if (tally.n_srcs >= SRC_MAX_FILL)
            return;
        tally.srcs[i].addr = addr;
        tally.n_srcs++;
    }

    tally.srcs[i].count++;
    if (tally.srcs[i].count > tally.top_src.count)
        tally.top_src = tally.srcs[i];
}

int handle_sample(void *ctx, void *data, size_t size)
{
    struct sample *s = data;
    __u16 flags = s->tcp_flags & (TCP_SYN | TCP_ACK);

    if (s->verdict != XDP_PASS)
        return 0;

    tally.samples++;
    if (s->protocol == IPPROTO_UDP) {
        tally.udp_sport[s->sport]++;
        tally.udp_dport[s->dport]++;
    } else if (s->protocol == IPPROTO_TCP) {
        if (flags == TCP_SYN)
            tally.syn++;
        else if (flags == TCP_ACK)
            add_src(s->saddr);
    }

    return 0;
}

// returns 1 only if the rule was not already in the map
int install_rule(struct detector *d, int fd, void *key)
{
    __u8 value = 0x01;

    if (bpf_map_update_elem(fd, key, &value, BPF_NOEXIST) != 0) {
        if (errno != EEXIST) {
            fprintf(stderr, "Err: failed to install rule ");
            perror("");
        }
        return 0;
    }

    d->n_installed++;
    return 1;
}

int choose_and_install(struct detector *d, __u64 now)
{
    __u32 min_count = tally.samples * PORT_SHARE_PCT / 100;
    double secs = (double)(now - d->attack_start_ns) / NSEC_PER_SEC;
    struct lpm_key lkey;
    struct in_addr addr;
    int changed = 0;
    __u16 port;

    for (__u32 p = 0; p < 65536; p++) {
        port = p;

        if (tally.udp_sport[p] >= min_count && is_amplifier(ntohs(port))
                && install_rule(d, d->sports_fd, &port)) {
            log_prefix();
            printf("rule: sport udp %hu (reflection), share %u%%, %.1f s after start\n",
                    ntohs(port), share(tally.udp_sport[p]), secs);
            changed++;
        }

        if (tally.udp_dport[p] >= min_count && install_rule(d, d->dports_fd, &port)) {
            log_prefix();
            printf("rule: dport udp %hu, share %u%%, %.1f s after start\n",
                    ntohs(port), share(tally.udp_dport[p]), secs);
            changed++;
        }
    }

    if (share(tally.top_src.count) >= SRC_SHARE_PCT) {
        lkey.prefixlen = 32;
        lkey.addr = tally.top_src.addr;
        if (install_rule(d, d->src_fd, &lkey)) {
            addr.s_addr = lkey.addr;
            log_prefix();
            printf("rule: src %s/32, share %u%%, %.1f s after start\n",
                    inet_ntoa(addr), share(tally.top_src.count), secs);
            changed++;
        }
    }

    if (changed)
        return changed;

    // no signature found, fall back to limiting everything unless a budget is already set
    __u32 ckey = CFG_DST_BUDGET;
    __u64 budget;
    if (bpf_map_lookup_elem(d->config_fd, &ckey, &budget) != 0) {
        fprintf(stderr, "Err: failed to read dst-budget ");
        perror("");
        return 0;
    }
    if (budget != 0)
        return 0;

    budget = FALLBACK_BUDGET_PPS;
    if (bpf_map_update_elem(d->config_fd, &ckey, &budget, BPF_ANY) != 0) {
        fprintf(stderr, "Err: failed to set dst-budget ");
        perror("");
        return 0;
    }

    log_prefix();
    printf("rule: dst-budget %d pps (%s), %.1f s after start\n", FALLBACK_BUDGET_PPS,
            share(tally.syn) >= SYN_SHARE_PCT ? "syn flood" : "no signature", secs);
    return 1;
}

void print_tick(__u64 seen_pps, __u64 passed_pps, __u64 dropped_pps)
{
    __u32 best = 0, best_port = 0;
    struct in_addr addr;

    log_prefix();
    printf("seen %7llu  passed %7llu  dropped %7llu pps | samples %4u",
            seen_pps, passed_pps, dropped_pps, tally.samples);

    for (__u32 p = 0; p < 65536; p++) {
        if (tally.udp_dport[p] > best) {
            best = tally.udp_dport[p];
            best_port = p;
        }
    }
    if (best)
        printf(" | top udp dport %hu (%u%%)", ntohs(best_port), share(best));

    if (tally.top_src.count) {
        addr.s_addr = tally.top_src.addr;
        printf(" | top tcp src %s (%u%%)", inet_ntoa(addr), share(tally.top_src.count));
    }
    printf("\n");
}

void tick(struct detector *d, __u64 now)
{
    __u64 seen = read_percpu_u64(d->stats_fd, SEEN);
    __u64 passed = read_percpu_u64(d->stats_fd, PASSED);
    __u64 dropped = read_percpu_u64(d->stats_fd, DROPPED);
    double secs = (double)(now - d->tick_start_ns) / NSEC_PER_SEC;
    __u64 seen_pps = (seen - d->prev_seen) / secs;
    __u64 passed_pps = (passed - d->prev_passed) / secs;
    __u64 dropped_pps = (dropped - d->prev_dropped) / secs;

    d->prev_seen = seen;
    d->prev_passed = passed;
    d->prev_dropped = dropped;

    print_tick(seen_pps, passed_pps, dropped_pps);

    if (passed_pps <= d->threshold_pps) {
        if (d->attack_start_ns) {
            log_prefix();
            if (d->rules_this_attack)
                printf("mitigated: passed back under %llu pps, %.1f s after attack start (seen still %llu pps)\n",
                        d->threshold_pps, (double)(now - d->attack_start_ns) / NSEC_PER_SEC, seen_pps);
            else if (d->confirmed)
                printf("breach ended, no new rules were installed\n");
            else
                printf("breach ended before confirmation, nothing installed\n");
        }
        d->breach_ticks = 0;
        d->attack_start_ns = 0;
        d->confirmed = false;
        d->rules_this_attack = false;
        return;
    }

    if (d->attack_start_ns == 0) {
        d->attack_start_ns = d->tick_start_ns;
        log_prefix();
        printf("breach: passed %llu pps > %llu, confirming for %d s\n",
                passed_pps, d->threshold_pps, CONFIRM_TICKS);
    }

    d->breach_ticks++;
    if (d->breach_ticks < CONFIRM_TICKS)
        return;
    d->breach_ticks = 0;
    d->confirmed = true;

    if (tally.samples < MIN_SAMPLES) {
        log_prefix();
        printf("confirmed, but only %u passed samples (< %d), raise the sample rate\n",
                tally.samples, MIN_SAMPLES);
    } else if (choose_and_install(d, now)) {
        d->rules_this_attack = true;
    } else {
        log_prefix();
        printf("confirmed, but every applicable rule is already in place\n");
    }
}

int main(int argc, char *argv[])
{
    struct detector d;
    memset(&d, 0, sizeof(d));
    d.threshold_pps = DEFAULT_THRESHOLD_PPS;

    if (argc > 1) {
        char *end;
        d.threshold_pps = strtoull(argv[1], &end, 10);
        if (*end != '\0' || d.threshold_pps == 0) {
            fprintf(stderr, "Usage: %s [threshold_pps]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    // keep output line buffered when piped to a file
    setvbuf(stdout, NULL, _IOLBF, 0);

    d.stats_fd = find_map_fd("stats");
    d.config_fd = find_map_fd("config");
    d.dports_fd = find_map_fd("drop_dports");
    d.sports_fd = find_map_fd("drop_sports");
    d.src_fd = find_map_fd("src_block");

    struct ring_buffer *rb = ring_buffer__new(find_map_fd("samples"), handle_sample, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Err: failed to create ring buffer ");
        perror("");
        exit(EXIT_FAILURE);
    }

    d.prev_seen = read_percpu_u64(d.stats_fd, SEEN);
    d.prev_passed = read_percpu_u64(d.stats_fd, PASSED);
    d.prev_dropped = read_percpu_u64(d.stats_fd, DROPPED);
    d.tick_start_ns = now_ns();

    log_prefix();
    printf("detector started, threshold %llu pps, confirm %d s\n", d.threshold_pps, CONFIRM_TICKS);

    while (running) {
        int err = ring_buffer__poll(rb, POLL_MS);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Err: ring buffer poll failed: %s\n", strerror(-err));
            break;
        }

        __u64 now = now_ns();
        if (now - d.tick_start_ns >= NSEC_PER_SEC) {
            tick(&d, now);
            memset(&tally, 0, sizeof(tally));
            d.tick_start_ns = now;
        }
    }

    log_prefix();
    printf("stopping, installed %d rule(s) this run, see ctl list for what is still active\n", d.n_installed);
    ring_buffer__free(rb);
    return 0;
}
