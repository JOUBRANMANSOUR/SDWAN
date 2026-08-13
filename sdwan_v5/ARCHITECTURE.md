# v5 architecture

## Dual-hub interface matrix

Every spoke has all six hot, peer-validated WireGuard interfaces before it becomes `ACTIVE`:

| Spoke target | MPLS | Broadband | LTE |
|---|---|---|---|
| hub1 | `wg-h1-mpls`, table 1101 | `wg-h1-bb`, table 1102 | `wg-h1-lte`, table 1103 |
| hub2 | `wg-h2-mpls`, table 1201 | `wg-h2-bb`, table 1202 | `wg-h2-lte`, table 1203 |

The v4 slot tables remain 101/MPLS, 102/Broadband, and 103/LTE. Each hub has `wg-spokes-{mpls,bb,lte}` plus separate `wg-ih-{mpls,bb,lte}` interfaces. The separate inter-hub interfaces prevent direct-spoke and inter-hub `AllowedIPs` overlap.

Normal preference is node1–node3 → hub1 with hub2 standby; node4–node5 → hub2 with hub1 standby. Both hubs are active receivers throughout.

## Marks, rules, and affinity

| Field | Mask/value | Owner |
|---|---:|---|
| Transport slot | low byte; MPLS `0x01`, BB `0x02`, LTE `0x03` | native nDPI metadata result |
| Terminal/provisional/emergency | `0x100` / `0x200` / `0x400` | existing classifier/Edge lifecycle |
| Hub affinity | `0x1000` hub1, `0x2000` hub2; mask `0x3000` | Edge ingress/return affinity |
| Egress mode | direct `0x4000`, cloud `0x8000`; mask `0xc000`; hub is zero | Policy intent + Edge selection |

`CONNMARK --restore-mark` and `--save-mark` use `0xf7ff`. The original low-byte ABI is never overloaded. Hub-specific rules match `slot|hub-bit` with mask `0x30ff`, before the v4-compatible slot rule. A connection arriving through `wg-h1-bb` retains hub1/Broadband return affinity. nDPI sees LAN traffic before NAT/first route lookup and never sees WireGuard ciphertext, chooses a hub, chooses an egress mode, makes REST calls, or runs in Ryu packet-in.

v5 deliberately chooses the acceptable **baseline** failback model: after a hard target failure, the affected slot is remapped atomically to an already-established backup. Existing and new flows remain on that backup until the old cohort drains or the drain timeout expires; then the slot is restored atomically. It does not claim enhanced new-flow-first failback.

## Health, failover, and ownership

Each spoke actively measures every hub/transport tunnel. Samples include site, hub, transport, interface, wall/monotonic timestamps, sequence, source, underlay, interface, WireGuard, overlay, and optional RTT/jitter/loss evidence. Stale/out-of-order samples are rejected. Tunnel states are `UNKNOWN → HEALTHY/SUSPECT/FAILED → RECOVERING → HEALTHY`; recovery requires three successes and hold-down. One failed tunnel degrades a hub; all relevant tunnels must fail before it is unreachable.

The Edge Agent owns immediate local Linux replacement from its cached policy. It emits idempotent events with local route versions. The Policy Service owns `route_ownership` epochs. A failed old owner is fenced by a higher epoch and placed in pending reconciliation; it is not a commit dependency. The non-owner hub forwards toward the recorded owner via a healthy inter-hub path.

For total inter-hub loss, the documented research strategy is deterministic temporary convergence on the healthy hub with capacity validation. If management and every inter-hub path disappear simultaneously, the lab reports partitioned/degraded state rather than claiming global convergence.

## Egress and cloud experiment

| Network | Prefix / endpoint | Required egress |
|---|---|---|
| Data Center LAN | `10.100.0.0/24`, `dc_app` `10.100.0.10` | `HUB_OVERLAY` only |
| Simulated SaaS Internet | `198.18.0.0/24`, Nginx `198.18.0.10` | `DIRECT_INTERNET` or `HUB_BACKHAUL` by persistent policy |
| Optional Cloud VPC | `10.200.0.0/24`, app `10.200.0.10` | disabled by default; `CLOUD_GATEWAY`/hub only when enabled |

Direct Broadband/LTE breakout uses a scoped NAT chain. It returns every branch, Data Center, and enabled Cloud VPC prefix before `MASQUERADE`; MPLS is not Internet-capable by baseline configuration. Hub backhaul traverses the selected WireGuard target before the hub Internet exit. The optional Cloud VPC uses two named cloud gateway containers only when `cloud_vpc.enabled: true`; it is a simulated network, not a cloud-provider implementation.

## Responsibility boundary

- Native C nDPI/NFQUEUE in Docker: application/category/confidence metadata, once-per-flow pinning.
- Policy Service: administrator intent, SLA/egress constraints, versions, ownership, reconciliation.
- Edge Agent: local probes, target selection under cached policy, WireGuard/Linux routing/NAT/iptables actuation.
- Ryu: OpenFlow 1.3 underlay learning, datapaths, ports and counters only.
- SQLite: durable low-frequency intent/lifecycle only; never NFQUEUE or forwarding fast path.
