#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../include/common.h"
#include "../include/maps.h"
#include "../include/src_table.h"

#define NSEC_PER_SEC          1000000000ULL
#define TICK_NS               NSEC_PER_SEC
#define POLL_MS               100
#define CONFIRM_TICKS         3
#define MIN_SAMPLES           100
#define DEFAULT_THRESHOLD_PPS 10000
#define FALLBACK_BUDGET_PPS   2000

#define PORT_SHARE_PCT        20
#define SRC_SHARE_PCT         30
#define SYN_SHARE_PCT         60

#define MAX_CANDIDATES        4
#define MAX_INSTALLED         64

#define PORT_COUNT            65536
#define TCP_FLAG_SYN          0x02
#define TCP_FLAG_ACK          0x10

static const __u16 amplifier_ports[] = { 53, 123, 389, 1900, 11211, 19, 161 };

struct tick_tally {
    __u32 samples;
    __u32 udp;
    __u32 tcp;
    __u32 syn;
    __u32 udp_sport[PORT_COUNT];
    __u32 udp_dport[PORT_COUNT];
    struct src_table tcp_src;
};

enum phase { PHASE_IDLE, PHASE_CONFIRMING };

struct installed_rule {
    char kind;
    __u32 value;
};

struct detector {
    int stats_fd, config_fd, dports_fd, sports_fd, src_fd;

    __u64 threshold_pps;

    __u64 prev_seen, prev_passed, prev_dropped;
    __u64 tick_start_ns;

    enum phase phase;
    int breach_ticks;
    __u64 attack_start_ns;
    bool rules_this_attack;
    bool budget_on;

    struct installed_rule installed[MAX_INSTALLED];
    int n_installed;
};

static struct tick_tally tally;
static volatile sig_atomic_t running = 1;

static __u64 mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

static void log_prefix(void)
{
    struct timespec ts;
    struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    printf("[%02d:%02d:%02d.%03ld] ", tm.tm_hour, tm.tm_min, tm.tm_sec,
           ts.tv_nsec / 1000000);
}

static void on_signal(int sig)
{
    (void)sig;
    running = 0;
}

static const char *ip_str(__u32 addr_net, char *buf)
{
    struct in_addr a = { .s_addr = addr_net };
    return inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN);
}

static bool is_amplifier(__u16 port_host)
{
    for (size_t i = 0; i < sizeof(amplifier_ports) / sizeof(amplifier_ports[0]); i++)
        if (amplifier_ports[i] == port_host)
            return true;
    return false;
}

static __u32 share_pct(__u32 count, __u32 total)
{
    return total ? (__u32)((__u64)count * 100 / total) : 0;
}

static void tally_reset(struct tick_tally *t)
{
    t->samples = t->udp = t->tcp = t->syn = 0;
    memset(t->udp_sport, 0, sizeof(t->udp_sport));
    memset(t->udp_dport, 0, sizeof(t->udp_dport));
    src_table_reset(&t->tcp_src);
}

static int handle_sample(void *ctx, void *data, size_t size)
{
    struct tick_tally *t = ctx;
    const struct sample *s = data;

    if (size < sizeof(*s))
        return 0;
    if (s->verdict != XDP_PASS)
        return 0;

    t->samples++;

    if (s->protocol == IPPROTO_UDP) {
        t->udp++;
        t->udp_sport[s->sport]++;
        t->udp_dport[s->dport]++;
    } else if (s->protocol == IPPROTO_TCP) {
        bool syn = s->tcp_flags & TCP_FLAG_SYN;
        bool ack = s->tcp_flags & TCP_FLAG_ACK;

        t->tcp++;
        if (syn && !ack)
            t->syn++;
        if (ack && !syn)
            src_table_add(&t->tcp_src, s->saddr);
    }
    return 0;
}

static int collect_ports(const __u32 counts[PORT_COUNT], __u32 min_count,
                         __u16 out_port_net[MAX_CANDIDATES],
                         __u32 out_count[MAX_CANDIDATES])
{
    int n = 0;

    if (min_count == 0)
        min_count = 1;

    for (__u32 p = 0; p < PORT_COUNT; p++) {
        __u32 c = counts[p];
        if (c < min_count)
            continue;

        int pos = n < MAX_CANDIDATES ? n : MAX_CANDIDATES - 1;
        if (n == MAX_CANDIDATES && c <= out_count[pos])
            continue;
        while (pos > 0 && out_count[pos - 1] < c) {
            out_port_net[pos] = out_port_net[pos - 1];
            out_count[pos] = out_count[pos - 1];
            pos--;
        }
        out_port_net[pos] = (__u16)p;
        out_count[pos] = c;
        if (n < MAX_CANDIDATES)
            n++;
    }
    return n;
}

static bool already_installed(struct detector *d, char kind, __u32 value)
{
    for (int i = 0; i < d->n_installed; i++)
        if (d->installed[i].kind == kind && d->installed[i].value == value)
            return true;
    return false;
}

static void record_installed(struct detector *d, char kind, __u32 value)
{
    if (d->n_installed < MAX_INSTALLED)
        d->installed[d->n_installed++] =
            (struct installed_rule){ .kind = kind, .value = value };
}

static bool install_port_rule(struct detector *d, int fd, char kind, __u16 port_net)
{
    __u16 key = port_net;
    __u8 one = 1;

    if (already_installed(d, kind, port_net))
        return false;

    if (bpf_map_update_elem(fd, &key, &one, BPF_ANY) != 0) {
        log_prefix();
        printf("ERROR installing %s rule udp %u: %s\n",
               kind == 'd' ? "dport" : "sport", ntohs(port_net), strerror(errno));
        return false;
    }
    record_installed(d, kind, port_net);
    return true;
}

static bool install_src_rule(struct detector *d, __u32 addr_net)
{
    struct lpm_key key = { .prefixlen = 32, .addr = addr_net };
    __u8 one = 1;
    char buf[INET_ADDRSTRLEN];

    if (already_installed(d, 'a', addr_net))
        return false;

    if (bpf_map_update_elem(d->src_fd, &key, &one, BPF_ANY) != 0) {
        log_prefix();
        printf("ERROR installing src rule %s/32: %s\n",
               ip_str(addr_net, buf), strerror(errno));
        return false;
    }
    record_installed(d, 'a', addr_net);
    return true;
}

static bool set_dst_budget(struct detector *d, __u64 pps)
{
    __u32 key = CFG_DST_BUDGET;

    if (bpf_map_update_elem(d->config_fd, &key, &pps, BPF_ANY) != 0) {
        log_prefix();
        printf("ERROR setting dst-budget: %s\n", strerror(errno));
        return false;
    }
    d->budget_on = pps != 0;
    return true;
}

static void log_installed(struct detector *d, __u64 now, const char *what,
                          __u32 count, __u32 total)
{
    log_prefix();
    printf("RULE %-28s share %3u%%  time-to-mitigate %.1f s\n", what,
           share_pct(count, total),
           (double)(now - d->attack_start_ns) / NSEC_PER_SEC);
}

static int choose_and_install(struct detector *d, const struct tick_tally *t, __u64 now)
{
    __u16 ports[MAX_CANDIDATES];
    __u32 counts[MAX_CANDIDATES];
    char what[64], buf[INET_ADDRSTRLEN];
    int changed = 0;
    __u32 min_port = (__u32)((__u64)t->samples * PORT_SHARE_PCT / 100);
    int n;

    n = collect_ports(t->udp_sport, min_port, ports, counts);
    for (int i = 0; i < n; i++) {
        __u16 port = ntohs(ports[i]);
        if (!is_amplifier(port))
            continue;
        if (install_port_rule(d, d->sports_fd, 's', ports[i])) {
            snprintf(what, sizeof(what), "sport udp %u (reflection)", port);
            log_installed(d, now, what, counts[i], t->samples);
            changed++;
        }
    }

    n = collect_ports(t->udp_dport, min_port, ports, counts);
    for (int i = 0; i < n; i++) {
        __u16 port = ntohs(ports[i]);
        if (install_port_rule(d, d->dports_fd, 'd', ports[i])) {
            snprintf(what, sizeof(what), "dport udp %u", port);
            log_installed(d, now, what, counts[i], t->samples);
            changed++;
        }
    }

    struct src_entry top = src_table_top(&t->tcp_src);
    if (top.count && share_pct(top.count, t->samples) >= SRC_SHARE_PCT) {
        if (install_src_rule(d, top.addr)) {
            snprintf(what, sizeof(what), "src %s/32", ip_str(top.addr, buf));
            log_installed(d, now, what, top.count, t->samples);
            changed++;
        }
    }

    if (changed)
        return changed;

    bool syn_flood = share_pct(t->syn, t->samples) >= SYN_SHARE_PCT;

    if (!d->budget_on && set_dst_budget(d, FALLBACK_BUDGET_PPS)) {
        snprintf(what, sizeof(what), "dst-budget %u pps (%s)", FALLBACK_BUDGET_PPS,
                 syn_flood ? "SYN flood" : "no signature");
        log_installed(d, now, what, syn_flood ? t->syn : t->samples, t->samples);
        changed++;
    }
    return changed;
}

static void print_tick(const struct tick_tally *t, __u64 seen_pps,
                       __u64 passed_pps, __u64 dropped_pps)
{
    char buf[INET_ADDRSTRLEN];

    log_prefix();
    printf("seen %7llu  passed %7llu  dropped %7llu pps | samples %4u",
           (unsigned long long)seen_pps, (unsigned long long)passed_pps,
           (unsigned long long)dropped_pps, t->samples);

    __u32 best = 0, best_port = 0;
    for (__u32 p = 0; p < PORT_COUNT; p++)
        if (t->udp_dport[p] > best) {
            best = t->udp_dport[p];
            best_port = p;
        }
    if (best)
        printf(" | top udp dport %u (%u%%)", ntohs((__u16)best_port),
               share_pct(best, t->samples));

    struct src_entry top = src_table_top(&t->tcp_src);
    if (top.count)
        printf(" | top tcp src %s (%u%%)", ip_str(top.addr, buf),
               share_pct(top.count, t->samples));
    printf("\n");
}

static void tick(struct detector *d, __u64 now)
{
    __u64 seen = read_percpu_u64(d->stats_fd, SEEN);
    __u64 passed = read_percpu_u64(d->stats_fd, PASSED);
    __u64 dropped = read_percpu_u64(d->stats_fd, DROPPED);

    double secs = (double)(now - d->tick_start_ns) / NSEC_PER_SEC;
    __u64 seen_pps = (__u64)((seen - d->prev_seen) / secs);
    __u64 passed_pps = (__u64)((passed - d->prev_passed) / secs);
    __u64 dropped_pps = (__u64)((dropped - d->prev_dropped) / secs);

    d->prev_seen = seen;
    d->prev_passed = passed;
    d->prev_dropped = dropped;

    print_tick(&tally, seen_pps, passed_pps, dropped_pps);

    bool breach = passed_pps > d->threshold_pps;

    if (!breach) {
        if (d->attack_start_ns) {
            log_prefix();
            if (d->rules_this_attack)
                printf("MITIGATED: passed back under %llu pps, %.1f s after attack start "
                       "(seen still %llu pps)\n",
                       (unsigned long long)d->threshold_pps,
                       (double)(now - d->attack_start_ns) / NSEC_PER_SEC,
                       (unsigned long long)seen_pps);
            else
                printf("breach ended before confirmation, nothing installed\n");
        }
        d->phase = PHASE_IDLE;
        d->breach_ticks = 0;
        d->attack_start_ns = 0;
        d->rules_this_attack = false;
        return;
    }

    if (d->phase == PHASE_IDLE) {
        d->phase = PHASE_CONFIRMING;
        d->breach_ticks = 0;
        if (!d->attack_start_ns)
            d->attack_start_ns = d->tick_start_ns;
        log_prefix();
        printf("BREACH: passed %llu pps > %llu, confirming for %d s\n",
               (unsigned long long)passed_pps, (unsigned long long)d->threshold_pps,
               CONFIRM_TICKS);
    }

    d->breach_ticks++;
    if (d->breach_ticks < CONFIRM_TICKS)
        return;

    if (tally.samples < MIN_SAMPLES) {
        log_prefix();
        printf("confirmed, but only %u passed samples (< %d); raise the sample rate\n",
               tally.samples, MIN_SAMPLES);
    } else if (choose_and_install(d, &tally, now) > 0) {
        d->rules_this_attack = true;
    } else {
        log_prefix();
        printf("confirmed, but every applicable rule is already in place\n");
    }

    d->breach_ticks = 0;
}

int main(int argc, char **argv)
{
    struct detector d = { .threshold_pps = DEFAULT_THRESHOLD_PPS };

    if (argc > 1) {
        char *end;
        unsigned long long v = strtoull(argv[1], &end, 10);
        if (*end != '\0' || v == 0) {
            fprintf(stderr, "usage: %s [threshold_pps]\n", argv[0]);
            return 1;
        }
        d.threshold_pps = v;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    setvbuf(stdout, NULL, _IOLBF, 0);

    d.stats_fd = find_map_fd("stats");
    d.config_fd = find_map_fd("config");
    d.dports_fd = find_map_fd("drop_dports");
    d.sports_fd = find_map_fd("drop_sports");
    d.src_fd = find_map_fd("src_block");
    int samples_fd = find_map_fd("samples");

    struct ring_buffer *rb = ring_buffer__new(samples_fd, handle_sample, &tally, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new failed: %s\n", strerror(errno));
        return 1;
    }

    tally_reset(&tally);
    d.prev_seen = read_percpu_u64(d.stats_fd, SEEN);
    d.prev_passed = read_percpu_u64(d.stats_fd, PASSED);
    d.prev_dropped = read_percpu_u64(d.stats_fd, DROPPED);
    d.tick_start_ns = mono_ns();

    log_prefix();
    printf("detector started, threshold %llu pps, confirm %d s\n",
           (unsigned long long)d.threshold_pps, CONFIRM_TICKS);

    while (running) {
        int err = ring_buffer__poll(rb, POLL_MS);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll: %s\n", strerror(-err));
            break;
        }

        __u64 now = mono_ns();
        if (now - d.tick_start_ns >= TICK_NS) {
            tick(&d, now);
            tally_reset(&tally);
            d.tick_start_ns = now;
        }
    }

    log_prefix();
    printf("stopping; %d rule(s) installed this run remain (remove with ctl)\n",
           d.n_installed);
    ring_buffer__free(rb);
    return 0;
}