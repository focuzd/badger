#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
    echo "run with sudo"
    exit 1
fi

ip link set dev eno1 up

if ! ip -4 addr show dev eno1 | grep -q "inet 10.0.0.2/24"; then
    ip addr add 10.0.0.2/24 dev eno1
fi
ip -4 -brief addr show dev eno1

sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.eno1.rp_filter=0

xdp-loader unload eno1 --all 2>/dev/null || true

xdp-loader load -m skb -s xdp eno1 xdp_filter.o
xdp-loader status eno1
