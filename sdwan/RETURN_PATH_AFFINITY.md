> **Profile status:** Data Center and branch affinity are part of the active core profile. Cloud Gateway affinity described below applies only when `topology.cloud.yaml` and `destination_policy.cloud.yaml` are enabled together.

# Return-path affinity implementation

## Scope

This implementation pins routed connections across all v5 forwarding roles:

- Spokes: all six `wg-h{1,2}-{mpls,bb,lte}` paths.
- Hubs: all three `wg-spokes-{mpls,bb,lte}` paths on each hub.
- Cloud Gateways: both hub-facing transit links on every enabled gateway.
- Data Center ingress: the request is returned to the same hub using scoped SNAT.
- Branch-to-branch traffic: no NAT; conntrack marks on the hub and destination spoke provide the reverse path.

It does not add VRRP/keepalived or cross-node conntrack synchronization.

## Mark lifecycle

The existing v5 mark ABI is retained:

- Transport slot: `0x000000ff`.
- Terminal bit: `0x00000100`.
- Hub target: `0x00003000`.
- Egress mode: `0x0000c000`.
- Saved connection mask: `0x0000f7ff`.

Each routing namespace installs two chains:

- `SDWAN_V5_RPA_IN` in `mangle/PREROUTING` restores `ctmark`, then stamps a new connection from its ingress path.
- `SDWAN_V5_RPA_OUT` in `mangle/POSTROUTING` records the selected egress path for an unmarked connection initiated from the opposite side.

Ingress-pinned flows include the terminal bit. This prevents the reverse direction from being reclassified by nDPI and assigned a different transport slot.

## Spoke behavior

A packet arriving on, for example, `wg-h2-lte` is saved as:

```text
transport = LTE (0x03)
hub       = hub2 (0x2000)
terminal  = 0x0100
packet/connection mark = 0x2103
```

When the LAN host replies, `CONNMARK --restore-mark` restores `0x2103`. The hub-specific rule at priority `1203` selects table `1203`, returning the connection through `wg-h2-lte`.

Hub-specific rules use priorities `1101..1103` and `1201..1203`. They are intentionally evaluated before the generic transport rules at priorities `2001..2003`.

## Hub behavior

A packet arriving on `wg-spokes-bb` at hub1 is saved as `0x1102`. Replies from the Data Center, Cloud, SaaS, or another spoke restore the mark and use hub1 table `1102`, whose branch routes point to `wg-spokes-bb`.

For Data Center traffic, each hub applies scoped SNAT:

```text
hub1 -> 10.100.0.1
hub2 -> 10.100.0.2
```

This forces `dc_app` to return the connection to the same hub. Reverse NAT restores the branch destination before policy routing, and the connmark selects the original spoke transport.

## Cloud Gateway behavior

Every enabled Cloud Gateway has:

- `SDWAN_V5_CLOUD_RPA_IN` and `SDWAN_V5_CLOUD_RPA_OUT`.
- Table `3101` for hub1 and table `3102` for hub2.
- Rule priority `1301` for `hub1|CLOUD_GATEWAY` and `1302` for `hub2|CLOUD_GATEWAY`.
- `SDWAN_V5_CLOUD_SNAT`, scoped to branch prefixes and `10.200.0.0/24`.

A branch connection entering `cloud_gw2` through `c2-h1` is marked for hub1 and SNATed to `10.200.0.2`. `cloud_app` therefore returns to `cloud_gw2`; reverse NAT restores the branch destination, and table `3101` sends the packet through `c2-h1`.

## Source-address tradeoff

The application endpoints no longer see the original branch source for these paths:

- `dc_app` sees `10.100.0.1` or `10.100.0.2`.
- `cloud_app` sees `10.200.0.1` or `10.200.0.2`.

This is intentional in the baseline implementation because it provides deterministic gateway selection without changing the application hosts.

## Failure boundary

Conntrack state is local to one network namespace. The implementation guarantees:

- deterministic return paths for new flows;
- affinity for established flows while they remain on the same spoke, hub, and Cloud Gateway namespace;
- deterministic selection after a fresh connection is created following a link change.

It does not guarantee seamless migration of an already-established TCP session from hub1 to hub2 or from cloud_gw1 to cloud_gw2. That requires `conntrackd` state synchronization plus shared address ownership such as VRRP/keepalived.

## Static verification

From the directory containing the `sdwan` package:

```bash
bash sdwan/scripts/validate_static.sh
```

Verified non-privileged result for this revision:

```text
96 passed, 1 skipped
```

The skipped controller import must be executed in the Ryu virtual environment. Live conntrack counters and packet-path affinity still require the Ubuntu acceptance sequence below.

## Live verification

After starting the Cloud topology and completing ZTP/reconciliation:

```text
node1 iptables -t mangle -nvL SDWAN_V5_RPA_IN
hub1 iptables -t mangle -nvL SDWAN_V5_RPA_IN
hub1 iptables -t nat -nvL SDWAN_V5_HUB_NAT
cloud_gw1 iptables -t mangle -nvL SDWAN_V5_CLOUD_RPA_IN
cloud_gw1 iptables -t nat -nvL SDWAN_V5_CLOUD_SNAT
cloud_gw1 ip route show table 3101
cloud_gw1 ip route show table 3102
```

Primary and backup Cloud test:

```text
node1_host curl -fsS --connect-timeout 5 http://10.200.0.10/healthz
hub1 ip link set h1-c1 down
hub1 ip route get 10.200.0.10
node1_host curl -fsS --connect-timeout 5 http://10.200.0.10/healthz
cloud_gw2 iptables -t nat -nvL SDWAN_V5_CLOUD_SNAT
cloud_gw2 conntrack -L -p tcp --dport 80 -o extended
hub1 ip link set h1-c1 up
```

Use a new `curl` connection after each link-state change. Retain simultaneous captures on `h1-c2`, `c2-h1`, and `cloud_gw2-vpc` as the acceptance evidence.
