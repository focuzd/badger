#!/bin/bash

nss=("victim" "attacker" "legit")

if [[ $EUID -ne 0 ]]; then
    echo "Run the script as root." >&2
    exit 1
fi

set -euo pipefail

for ns in "${nss[@]}"; do
    { ip netns pids $ns 2>/dev/null || true; } | xargs -r kill
done

ip netns del victim 2>/dev/null || true
ip netns del attacker 2>/dev/null || true
ip netns del legit 2>/dev/null || true

ip link del br0 2>/dev/null || true

echo "lab is down"
