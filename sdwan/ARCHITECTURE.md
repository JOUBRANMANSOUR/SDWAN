# SD-WAN v5 architecture

## 1. Scope

The core research question is whether a branch edge can choose a path according to application requirements and live path quality while preserving destination policy and return-path correctness.

The active core profile contains three workloads:

| Workload | Destination | Egress | Candidate transports | Primary metric |
|---|---|---|---|---|
| `REALTIME_RTP` | another branch | `HUB_OVERLAY` | MPLS, BB, LTE | jitter/loss/RTT |
| `CENTRAL_BACKUP` | `dc_app` `10.100.0.10:8443` | `HUB_OVERLAY` | BB, MPLS, LTE | estimated available bandwidth |
| `SAAS_INTERACTIVE` | `public_saas` `198.18.0.10:443` | `DIRECT_INTERNET` | BB, LTE | RTT/loss |
| `SAAS_FILE_TRANSFER` | same SaaS | `DIRECT_INTERNET` | BB, LTE | estimated available bandwidth |

Cloud VPC is disabled by default. It remains an optional profile and is not part of the core experimental claims.

## 2. Control and data planes

- **Ryu** realizes a centrally programmed provider-facing Layer-3 FIB for the MPLS, Broadband, and LTE OVS underlays. It has no SD-WAN policy, SLA, hub, or transport-selection responsibility; see [docs/ryu_l3_underlay.md](docs/ryu_l3_underlay.md).
- **Policy Service** owns destination intent, application policy, desired state, route ownership, versions, and reconciliation.
- **ZTP Service** validates claims and CSRs and issues operational identities.
- **Edge Agent** runs on spokes and hubs and owns WireGuard, Linux routes/rules, connmark, scoped NAT, and local failover.
- **Path monitor/selector** runs at the spoke edge and extends the existing failover runtime rather than creating a separate policy engine.

Ryu does not choose the SD-WAN application path. OVS switches transport the outer WireGuard packets; application-aware selection occurs before encapsulation on the Linux edge.

## 3. Topology

Each spoke has six pre-established WireGuard paths:

| Target | MPLS | Broadband | LTE |
|---|---|---|---|
| hub1 | `wg-h1-mpls` table 1101 | `wg-h1-bb` table 1102 | `wg-h1-lte` table 1103 |
| hub2 | `wg-h2-mpls` table 1201 | `wg-h2-bb` table 1202 | `wg-h2-lte` table 1203 |

Generic transport tables remain 101/102/103. Hubs also have per-transport spoke aggregation and separate inter-hub WireGuard interfaces.

Provider-facing WAN interfaces are `/32` attachments with a synthetic provider next hop, not shared Ethernet `/24` peers. Ryu validates attachment IP/MAC bindings, proxies only provider-next-hop ARP, and forwards only the authorized FIB. MPLS is a private hub-reachability service; Broadband and LTE are independent Internet-capable services.

The underlays are emulated service profiles:

| Transport | Capacity | Delay | Jitter | Loss | Internet capable |
|---|---:|---:|---:|---:|---|
| MPLS-like | 20 Mbps | 4 ms | 0.5 ms | 0% | No |
| Broadband-like | 50 Mbps | 25 ms | 5 ms | 1% | Yes |
| LTE-like | 8 Mbps | 60 ms | 15 ms | 2% | Yes |

## 4. Measurement semantics

The monitor maintains one window per usable path:

- `rtt_ms`: ICMP round-trip time, not true one-way delay.
- `jitter_ms`: EWMA of the absolute difference between consecutive raw RTT samples.
- `loss_pct`: mean loss over a bounded sliding probe window.
- `estimated_available_bandwidth_mbps`: configured capacity minus the busiest-direction interface rate, EWMA-smoothed.
- reachability and measurement timestamp.

The available-bandwidth value is an estimate, not an active capacity test. Continuous `iperf3` is deliberately not used by the monitor.

Default timing:

```yaml
measurement:
  interval_seconds: 2
  ewma_alpha: 0.3
  stale_after_seconds: 6
  loss_window_samples: 10
```

## 5. Eligibility, scoring, and stability

A path is eligible only if it:

1. is administratively enabled;
2. is operationally reachable;
3. has non-stale measurements;
4. is allowed by destination egress policy;
5. uses a candidate transport for the application;
6. satisfies mandatory SLA thresholds.

Eligible paths are normalized and scored using the application's configured weights. Static transport cost can be included but cannot make an SLA-violating path eligible.

Anti-flapping defaults:

```yaml
path_selection:
  bad_samples_before_degraded: 3
  good_samples_before_recovered: 5
  minimum_improvement_percent: 15
  hold_down_seconds: 10
```

The selected path is retained during the initial bad-sample window unless the path has a hard operational failure. Switch events include old/new path, metrics, policy, application class, timestamp, and a concrete reason such as `SLA_VIOLATION_JITTER` or `PATH_DOWN`.

## 6. Flow behavior

The marking chain first restores a conntrack mark. Application-class rules only match packets whose owned mark bits are zero.

Consequences:

- Existing TCP connections remain pinned to their previous path.
- New TCP connections use the latest class mark.
- RTP/UDP conntrack entries on UDP/5004 can be updated after a stable path change.
- A `FAIL_CLOSED` class with no eligible path records the unavailable decision and leaves packet enforcement to the existing endpoint policy; it does not install `DROP` or `REJECT` rules in this testbed control path.

Return-path affinity is independently implemented in each spoke and hub namespace. Marks are local metadata and are not carried inside WireGuard.

## 7. Destination behavior

### Branch-to-branch RTP

Real H.264 RTP/UDP flows from `node1_host` to `node2_host` through a selected hub/transport. Other branch hosts remain available for independent branch-to-branch tests. The node1 available-bandwidth demonstration deliberately generates background traffic from `node1_host`, because the current estimator reads node1-local interface counters and cannot infer another branch's utilization.

### Central backup

`dc_app` exposes an HTTPS FastAPI repository on port 8443. It stores the uploaded object by branch, records timestamps and byte count, and returns SHA-256 evidence. It is private and hub-overlay only.

### Public SaaS

`public_saas` exposes an HTTPS collaboration API and file upload/download service. It is direct-Internet only and can use Broadband or LTE. It never transits a hub in the core policy.

`inet_gw` is the emulated Internet gateway. It owns the Broadband/LTE next-hop addresses (`192.168.20.254` and `192.168.30.254`) and routes them to the public Internet segment `inetbr` (`198.18.0.0/24`). `public_saas` is attached only to `inetbr` at `198.18.0.10`; it no longer acts as an ISP gateway.

## 8. NAT and return path

- Direct SaaS breakout uses scoped MASQUERADE only toward Internet-capable interfaces.
- Branch, Data Center, and enabled Cloud prefixes return before direct NAT.
- The baseline Data Center design applies scoped hub SNAT so `dc_app` replies to the same hub; the application observes the selected hub DC address rather than the original branch address.
- Branch-to-branch traffic is not NATed.

This baseline does not claim seamless migration of an already-established TCP connection between independent hub namespaces. Such migration requires synchronized conntrack/NAT state and shared address ownership.

## 9. Optional Cloud profile

`config/topology.cloud.yaml` plus `config/destination_policy.cloud.yaml` preserves the earlier simulated Cloud VPC and two cloud gateways. The logical role is a functional cloud-transit experiment, not an implementation of AWS Transit Gateway.
