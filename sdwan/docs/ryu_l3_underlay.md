# Ryu-controlled Layer-3 WAN underlay

## Scope and boundary

The three WAN OVS bridges are provider abstractions: `s_mpls`, `s_bb`, and
`s_lte`.  Ryu controls only forwarding of the **outer** IP packet after the
Edge has already selected a hub and a transport.  It does not classify an
application, evaluate an SLA, select a transport or hub, manage WireGuard,
or alter connmarks, `ip rule`, NAT, or edge failover state.

```text
Edge application policy -> fwmark / route table -> WireGuard outer packet
                                               -> Ryu provider L3 forwarding
```

## Provider-facing addressing

The configured transport networks remain allocation pools.  Every provider
attachment is configured as `/32`, not as the old shared `/24` Ethernet
segment.  An attachment has a static route for its transport pool through a
synthetic provider next hop:

| Transport | Provider next hop | Internet capable |
|---|---|---|
| MPLS | `192.168.10.253` | no |
| Broadband | `192.168.20.253` | yes |
| LTE | `192.168.30.253` | yes |

Each attachment installs a permanent neighbour for the topology-derived
provider-gateway MAC; Ryu also proxies ARP for that next hop as a compatibility
fallback. Ryu validates the attachment MAC and its authorized routed source
prefixes, decrements IPv4 TTL, rewrites provider Ethernet addresses, and emits
on a single programmed egress port. Thus, a Linux WAN interface cannot ARP
directly for a remote hub or spoke merely because both addresses use one pool.

The public-SaaS Internet gateway remains at `.254` on Broadband/LTE, but an
Edge reaches it through the provider next hop `.253`; it is not a shared-L2
neighbor. For a provider reachability probe, bind the source IP (for example,
`ping -I 192.168.20.11 192.168.20.254`), not the WAN interface name; binding
the interface asks Linux to ARP directly for `.254` and is expected to fail.

## Underlay service semantics

- **MPLS** is private.  A spoke has provider routes only to hub MPLS
  attachments; no MPLS route is installed for the public SaaS prefix and no
  spoke-to-spoke provider mesh is built.
- **Broadband and LTE** are distinct Internet-capable provider domains.  A
  spoke can reach hubs and its Internet gateway only. The attachment is
  authorized for its own configured branch LAN prefix, and the gateway has
  the corresponding bounded return FIB entry; this supports a source-preserving
  routed deployment without creating an arbitrary spoke-to-spoke path. When
  the Edge direct-Internet policy enables MASQUERADE, as in the current core
  profile, the observed provider source is instead the Edge WAN address.
  The Internet gateway may source only its WAN address and the configured
  public-SaaS network.
- The existing WireGuard overlay still provides private branch and Data Center
  connectivity.  The public SaaS DIB route is still selected only by SD-WAN
  policy and only over Broadband/LTE.

## OpenFlow pipeline and modes

Ryu compiles one deterministic OpenFlow 1.3 pipeline per provider bridge:

| Table | Responsibility |
|---:|---|
| 0 | known attachment admission; ARP provider-next-hop proxy or IPv4 handoff |
| 10 | source IPv4 and (in `ENFORCE`) source MAC binding validation |
| 20 | authorized provider reachability FIB lookup |
| 30 | TTL decrement, Ethernet rewrite, explicit output port |

A table miss never learns a path.  It is dropped and mirrored to Ryu only for
rate-limited audit accounting.  The snapshot tracks unauthorized attachment,
source-validation, reachability-policy, and unknown-endpoint drops.

`SDWAN_UNDERLAY_MODE` is one of:

- `DISABLED`: Ryu removes only its own cookie-scoped flows.
- `AUDIT`: applies reachability controls but records source-binding evidence
  without matching source MAC.
- `ENFORCE` (default): validates source IP and MAC before forwarding.

## Inventory and dynamic branches

Inventory/ZTP remains authoritative.  Ryu reads the Policy inventory
read-only and admits only `ZTP_STAGED`, `ENROLLING`, `PROVISIONING`, or
`ACTIVE` sites.  A discovered but unauthorized attachment has no forwarding
flows.  Dynamic sites carry a stable `address_id`, `wireguard_index`, and
`interface_suffix`; their Containernet creation configures the same `/32`,
MAC binding, and provider-pool route as seed sites.  Reconciliation runs every
`SDWAN_UNDERLAY_RECONCILE_SECONDS` (default 2) seconds and is safe after a
controller restart because all rules use one controller cookie namespace.

## Observability and operation

Ryu writes an atomic read-only snapshot at
`$SDWAN_UNDERLAY_STATE_PATH` (default
`/mnt/data/sdwan-state/underlay-state.json`). It includes mode, datapath
connectivity, admitted bindings, programmed-FIB counts, security counters,
and recent events. The management API exposes it at:

```text
GET /api/v1/underlay/state
```

Start the core topology and controller:

```bash
cd /mnt/data/sdwan-lab
SDWAN_TOPOLOGY_CONFIG=$PWD/sdwan/config/topology.core.yaml   bash sdwan/scripts/run_topology.sh
SDWAN_TOPOLOGY_CONFIG=$PWD/sdwan/config/topology.core.yaml   SDWAN_UNDERLAY_MODE=ENFORCE   SDWAN_STATE_ROOT=/mnt/data/sdwan-state   bash sdwan/scripts/run_controller.sh
```

Useful non-mutating checks after enrollment:

```bash
ovs-ofctl -O OpenFlow13 dump-flows s_bb
cat /mnt/data/sdwan-state/underlay-state.json
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8090/api/v1/underlay/state
```

A controlled fault remains an existing `tc/netem`, interface, or OVS-port
operation.  The Ryu controller observes port-state changes and reconciles;
it does not choose an SD-WAN replacement path.

For a bounded live diagnostic only, `SDWAN_SKIP_PHYSICAL_CHECK=1` starts the
CLI after Ryu readiness but does not suppress controller enforcement. Do not
use it as an acceptance result; use it to inspect routes, neighbours, and OVS
flow counters when a self-check fails.
