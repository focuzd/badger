#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../include/common.h"
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

__u64 read_percpu_u64(int map_fd, __u32 key) {
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

int add_blocked_port(int map_fd, __u16 port)
{
    __u16 key = htons(port);
    __u8 value = 0x01;
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
        fprintf(stderr, "Err: failed to add port. map_id: %d port: %hu ", map_fd, port);
        perror("");
        return -1;
    }

    return 0;
}

int del_blocked_port(int map_fd, __u16 port) {
    __u16 key = htons(port);
    if (bpf_map_delete_elem(map_fd, &key) != 0) {
        fprintf(stderr, "Err: failed to remove port. map_id: %d port: %hu ", map_fd, port);
        perror("");
        return -1;
    }

    return 0;
}

void parse_ip(const char *ip_str, struct lpm_key *lkey) {
    __u8 a, b, c, d;
    __u32 len;

    errno = 0;
    int args_read = sscanf(ip_str, "%hhu.%hhu.%hhu.%hhu/%u", &a, &b, &c, &d, &len);
    if (args_read != 5 || errno == EILSEQ || errno == EINVAL || errno == ENOMEM) {
        fprintf(stderr, "Err: failed to parse ip %s", ip_str);
        perror("");
        exit(EXIT_FAILURE);
    }

    if(len > 32) {
        fprintf(stderr, "Err: len greater than 32.\n");
        exit(EXIT_FAILURE);
    }

    lkey->prefixlen = len;
    lkey->addr = (d << 24) | (c << 16) | (b << 8) | a;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage:\n");
        exit(EXIT_FAILURE);
    }

    if (strcmp(argv[1], "stats") == 0) {
        int stats_fd = find_map_fd("stats");
        if (stats_fd == -1) {
            fprintf(stderr, "Err: not found map name: stats\n");
            exit(EXIT_FAILURE);
        }
        printf("seen: %llu\npassed: %llu\ndropped: %llu\n",
                read_percpu_u64(stats_fd, SEEN), read_percpu_u64(stats_fd, PASSED), 
                read_percpu_u64(stats_fd, DROPPED));
    } else if (strcmp(argv[1], "add") == 0 || strcmp(argv[1], "del") == 0) {
        if (argv[2] == NULL) {
            fprintf(stderr, "Err: expected rule(sport/dport/src) after add\n");
            exit(EXIT_FAILURE);
        }

        bool add = (strcmp(argv[1], "add") == 0);
        
        if (strcmp(argv[2], "sport") == 0 || strcmp(argv[2], "dport") == 0) {
            if (argv[3] == NULL) {
                fprintf(stderr, "Err: expected port number after %s\n", argv[2]);
                exit(EXIT_FAILURE);
            }

            char *end;
            errno = 0;
            int port = strtol(argv[3], &end, 10);
            if (end == argv[3] || *end != '\0' || errno == ERANGE || port > USHRT_MAX || port < 0) {
                fprintf(stderr, "Err: inavlid port %s\n", argv[3]);
                exit(EXIT_FAILURE);
            }

            char map_name[12];
            sprintf(map_name, "drop_%ss", argv[2]);

            int fd = find_map_fd(map_name);
            if (add)
                return add_blocked_port(fd, port);
            else
                return del_blocked_port(fd, port);
        }

        else if (strcmp(argv[2], "src") == 0) {
            if (argv[3] == NULL) {
                fprintf(stderr, "Err: expected ip<a.b.c.d/len> after src\n");
                exit(EXIT_FAILURE);
            }
            
            struct lpm_key lkey;
            parse_ip(argv[3], &lkey);
            __u8 value = 0x01;

            int fd = find_map_fd("src_block");
            if (add) {
                if (bpf_map_update_elem(fd, &lkey, &value, BPF_ANY) != 0) {
                    fprintf(stderr, "Err: failed to add element %s ", argv[3]);
                    perror("");
                    exit(EXIT_FAILURE);
                }
            } else {
                if (bpf_map_delete_elem(fd, &lkey) != 0) {
                    fprintf(stderr, "Err: failed to del element %s ", argv[3]);
                    perror("");
                    exit(EXIT_FAILURE);
                }
            }
        }

        else {
            fprintf(stderr, "Err: Invalid argument %s\n", argv[2]);
            exit(EXIT_FAILURE);
        }
    } 

    else if (strcmp(argv[1], "set") == 0) {
        if (argv[2] == NULL) {
            fprintf(stderr, "Err: expected argument(src-budget/dst-rate/src-burst) after set.\n");
            exit(EXIT_FAILURE);
        }
        
        __u32 ckey;
        if (strcmp(argv[2], "dst-budget") == 0)
            ckey = CFG_DST_BUDGET;
        else if (strcmp(argv[2], "src-rate") == 0)
            ckey = CFG_SRC_RATE;
        else if (strcmp(argv[2], "src-burst") == 0)
            ckey = CFG_SRC_BURST;
        else {
            fprintf(stderr, "Err: Invalid argument %s\n", argv[2]);
            exit(EXIT_FAILURE);
        }
        
        if (argv[3] == NULL) {
            fprintf(stderr, "Err: missing argument value\n");
            exit(EXIT_FAILURE);
        }

        char *end;
        errno = 0;
        long long val = strtoll(argv[3], &end, 10);
        if (end == argv[3] || *end != '\0' || errno == ERANGE || val < 0)  {
            fprintf(stderr, "Err: Invalid argument %s\n", argv[3]);
            exit(EXIT_FAILURE);
        }
        
        int fd = find_map_fd("config");
        if (bpf_map_update_elem(fd, &ckey, &val, BPF_ANY) != 0) {
            fprintf(stderr, "Err: failed to update config ");
            perror("");
            exit(EXIT_FAILURE);
        }
    }

    else if (strcmp(argv[1], "list") == 0) {
        printf("to be implemented\n");
    }

    else {
        fprintf(stderr, "Err: Invalid argument %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    return 0;
}
