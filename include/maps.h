#ifndef MAPS_H
#define MAPS_H

#include <linux/types.h>
int find_map_fd(const char *name);
__u64 read_percpu_u64(int map_fd, __u32 key);

#endif