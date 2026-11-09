#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/common.h"
#include "../include/maps.h"

int find_map_fd(const char *name)
{
    __u32 start_id = 0, next_id, len;
    int fd;
    struct bpf_map_info info;
    int ret = -1;

    while(bpf_map_get_next_id(start_id, &next_id) == 0) {
        fd = bpf_map_get_fd_by_id(next_id);
        if (fd < 0) {
            fprintf(stderr, "Err: can't get map fd id: %u ", next_id);
            perror("");
            exit(EXIT_FAILURE);
        }
        
        memset(&info, 0, sizeof(info));
        len = sizeof(info);

        if (bpf_map_get_info_by_fd(fd, &info, &len) != 0) {
            close(fd);
            fprintf(stderr, "Err: failed to get map info fd: %d ", fd);
            perror("");
            exit(EXIT_FAILURE);
        }

        if (strcmp(info.name, name) == 0)
            ret = fd;
        else
            close(fd);

        start_id = next_id;
    }

    if (ret == -1) {
        fprintf(stderr, "Err: no map found %s ", name);
        perror("");
        exit(EXIT_FAILURE);
    }

    return ret;
}

__u64 read_percpu_u64(int map_fd, __u32 key)
{
    int ncpus = libbpf_num_possible_cpus();
    __u64 *vals = calloc(ncpus, sizeof(__u64));
    __u64 sum = 0;

    if (!vals) {
        fprintf(stderr, "Err: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    if (bpf_map_lookup_elem(map_fd, &key, vals) != 0) {
        fprintf(stderr, "Err: element lookup failed fd: %d ", map_fd);
        perror("");
        exit(EXIT_FAILURE);
    }
    
    for (int i = 0; i < ncpus; i++) 
        sum += vals[i];

    free(vals);
    return sum;
}