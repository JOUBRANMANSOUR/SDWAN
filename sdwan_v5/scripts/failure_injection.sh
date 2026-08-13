#!/usr/bin/env bash
# Print deterministic commands to execute inside the active Containernet CLI.
# Every destructive scenario prints its matching rollback command.
set -euo pipefail
case "${1:-}" in
  degrade-node1-mpls)
    echo 'node1 tc qdisc replace dev node1-mpls parent 5:1 handle 10: netem delay 4ms 40ms loss 4%'
    echo 'node1 tc -s qdisc show dev node1-mpls'
    ;;
  restore-node1-mpls)
    echo 'node1 tc qdisc replace dev node1-mpls parent 5:1 handle 10: netem delay 4ms 0.5ms loss 0%'
    ;;
  congest-node1-bb)
    echo 'node1_host sh -c "iperf3 -c 198.18.0.10 -p 5201 -P 4 -t 120 >/tmp/node1-bb-congestion.log 2>&1 & echo \$!"'
    echo 'node1 tc -s class show dev node1-bb; node1 ip -s link show node1-bb'
    ;;
  stop-congestion)
    echo 'node1_host pkill -f "iperf3 -c 198.18.0.10" || true'
    ;;
  broadband-down)
    echo 'node1 ip link set node1-bb down'
    echo 'node1 ip link show node1-bb'
    ;;
  broadband-up)
    echo 'node1 ip link set node1-bb up'
    ;;
  hub1-down)
    echo 'hub1 ip link set hub1-mpls down; hub1 ip link set hub1-bb down; hub1 ip link set hub1-lte down'
    echo 'hub1 ip link show hub1-mpls; hub1 ip link show hub1-bb; hub1 ip link show hub1-lte'
    ;;
  hub1-up)
    echo 'hub1 ip link set hub1-mpls up; hub1 ip link set hub1-bb up; hub1 ip link set hub1-lte up'
    ;;
  tunnel-node1-h1-bb)
    echo 'node1 ip link set wg-h1-bb down'
    echo 'node1 ip route show table 102; node1 wg show wg-h2-bb; node1 ip -s link show wg-h2-bb'
    ;;
  restore-tunnel-node1-h1-bb)
    echo 'node1 ip link set wg-h1-bb up'
    ;;
  block-node1-h1-bb)
    echo 'node1 iptables -I OUTPUT -o node1-bb -p udp --dport 52001 -j DROP'
    ;;
  unblock-node1-h1-bb)
    echo 'node1 iptables -D OUTPUT -o node1-bb -p udp --dport 52001 -j DROP'
    ;;
  interhub-bb)
    echo 'hub1 ip link set wg-ih-bb down; hub2 ip link set wg-ih-bb down'
    ;;
  restore-interhub-bb)
    echo 'hub1 ip link set wg-ih-bb up; hub2 ip link set wg-ih-bb up'
    ;;
  interhub-all)
    echo 'hub1 ip link set wg-ih-mpls down; hub1 ip link set wg-ih-bb down; hub1 ip link set wg-ih-lte down; hub2 ip link set wg-ih-mpls down; hub2 ip link set wg-ih-bb down; hub2 ip link set wg-ih-lte down'
    ;;
  restore-interhub-all)
    echo 'hub1 ip link set wg-ih-mpls up; hub1 ip link set wg-ih-bb up; hub1 ip link set wg-ih-lte up; hub2 ip link set wg-ih-mpls up; hub2 ip link set wg-ih-bb up; hub2 ip link set wg-ih-lte up'
    ;;
  ryu-outage)
    echo 'sh pkill -f ryu-manager'
    ;;
  policy-outage)
    echo 'sh pkill -f sdwan_v5.policy_http'
    ;;
  *)
    echo 'usage: failure_injection.sh {degrade-node1-mpls|restore-node1-mpls|congest-node1-bb|stop-congestion|broadband-down|broadband-up|hub1-down|hub1-up|tunnel-node1-h1-bb|restore-tunnel-node1-h1-bb|block-node1-h1-bb|unblock-node1-h1-bb|interhub-bb|restore-interhub-bb|interhub-all|restore-interhub-all|ryu-outage|policy-outage}' >&2
    exit 2
    ;;
esac
