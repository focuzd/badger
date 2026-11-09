#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "Err: run the script as root." >&2
    exit 1
fi

set -euo pipefail

clang -O2 -g -target bpf -c "src/xdp_filter.c" -o xdp_filter.o
ip -n victim link set dev veth-vic xdpgeneric off
ip -n victim link set dev veth-vic xdpgeneric obj xdp_filter.o sec xdp
echo "done"
