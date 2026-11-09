#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "Err: run the script as root." >&2
    exit 1
fi

set -euo pipefail

dir=$(dirname "$0")
bash "${dir}/lab_down.sh"

ATTACKER_IP=10.0.0.1
LEGIT_IP=10.0.0.2
VICTIM_IP=10.0.0.3

# create network namespaces

ip netns add victim
ip netns add attacker
ip netns add legit

# create three veth pairs and a bridge

ip link add veth-vic type veth peer name veth-vic-out
ip link set veth-vic netns victim

ip link add veth-atk type veth peer name veth-atk-out
ip link set veth-atk netns attacker

ip link add veth-leg type veth peer name veth-leg-out
ip link set veth-leg netns legit

ip link add br0 type bridge
ip link set br0 up

# add ip addresses to one end of the veth
ip -n victim addr add 10.0.0.3/24 dev veth-vic
ip -n attacker addr add 10.0.0.1/24 dev veth-atk
ip -n legit addr add 10.0.0.2/24 dev veth-leg

# connect another end to bridge
ip link set veth-vic-out master br0
ip link set veth-atk-out master br0
ip link set veth-leg-out master br0


ip netns exec victim sysctl -w net.ipv4.conf.all.rp_filter=0
ip netns exec victim sysctl -w net.ipv4.conf.veth-vic.rp_filter=0

# 

ip -n victim link set lo up
ip -n victim link set veth-vic up
ip link set veth-vic-out up

ip -n attacker link set lo up
ip -n attacker link set veth-atk up
ip link set veth-atk-out up

ip -n legit link set lo up
ip -n legit link set veth-leg up
ip link set veth-leg-out up

test_connection() {
    local host1="$1"
    local host1_ip="$2"
    local host2="$3"
    local host2_ip="$4"

    echo "Ping: ${host1}(${host1_ip}) -> ${host2}(${host2_ip}):"
    if ip netns exec $host1 ping -w 2 -c 2 $host2_ip &>/dev/null; then
        echo "OK"
    else
        echo "FAIL"
        exit 1
    fi
}


test_connection attacker $ATTACKER_IP victim $VICTIM_IP
test_connection legit $LEGIT_IP victim $VICTIM_IP
