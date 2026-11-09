#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <stddef.h>
#include <stdio.h>

#include "../include/common.h"
#include "../include/maps.h"

struct state {
    __u64 start_ns;
};

int handle_sample(void *ctx, void *data, size_t size) {
    struct sample *s = data;
    char buf[INET_ADDRSTRLEN];
    struct in_addr a = { .s_addr = s->saddr };
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    printf("source ip: %s\n", buf);
    
    a.s_addr = s->daddr;
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    printf("dest ip: %s\n", buf);

    printf("source port: %hu\n", ntohs(s->sport));
    printf("dest port: %hu\n", ntohs(s->dport));
    printf("packet length: %hu\n", ntohs(s->len));
}

int main(void) {
    int map_fd = find_map_fd("samples");
    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_sample, NULL, NULL); 

    while(true) 
        ring_buffer__poll(rb, 1000);
}