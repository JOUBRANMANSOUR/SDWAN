#!/usr/bin/env bash
# Run commands printed by this helper inside the active Containernet CLI.
set -euo pipefail
case "${1:-}" in
  tunnel-node1-h1-bb)
    echo 'node1 ip link set wg-h1-bb down'
    echo 'node1 ip route show table 102; node1 wg show wg-h2-bb; node1 ip -s link show wg-h2-bb'
    ;;
  block-node1-h1-bb)
    echo 'node1 iptables -I OUTPUT -o node1-bb -p udp --dport 52001 -j DROP'
    echo 'node1 iptables -D OUTPUT -o node1-bb -p udp --dport 52001 -j DROP'
    ;;
  isolate-node1-h1)
    echo 'node1 ip link set wg-h1-mpls down; node1 ip link set wg-h1-bb down; node1 ip link set wg-h1-lte down'
    echo 'hub1 ip route get 10.1.0.10; hub2 ip route get 10.1.0.10'
    ;;
  hub1)
    echo 'hub1 pkill -f edge_agent_v5.py'
    echo 'node1 ip route show table 101; node1 ip route show table 102; node1 ip route show table 103'
    ;;
  interhub-bb)
    echo 'hub1 ip link set wg-ih-bb down; hub2 ip link set wg-ih-bb down'
    ;;
  interhub-all)
    echo 'hub1 ip link set wg-ih-mpls down; hub1 ip link set wg-ih-bb down; hub1 ip link set wg-ih-lte down'
    ;;
  policy-outage)
    echo 'pkill -f sdwan_v5.policy_http; node1 ip link set wg-h1-bb down'
    ;;
  ryu-outage)
    echo 'pkill -f ryu-manager'
    ;;
  *)
    echo 'usage: failure_injection.sh {tunnel-node1-h1-bb|block-node1-h1-bb|isolate-node1-h1|hub1|interhub-bb|interhub-all|policy-outage|ryu-outage}' >&2
    exit 2
    ;;
esac
