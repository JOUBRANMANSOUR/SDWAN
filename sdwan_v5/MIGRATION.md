# Migration and rollback position

The detailed migration table and requirement matrix are frozen before source implementation in [`docs/PRE_IMPLEMENTATION.md`](docs/PRE_IMPLEMENTATION.md). v4 must remain selected until all Ubuntu live gates pass.

v5 keeps the transport ABI: MPLS=`0x01`, Broadband=`0x02`, LTE=`0x03`; v4 state bits `0x100`, `0x200`, and `0x400` retain their meanings. Hub and egress affinity use new non-overlapping bits documented in `ARCHITECTURE.md`.

Rollback is a separate-state operation: stop v5 services, remove only v5 interfaces/tables/iptables rules/containers/volumes, then start v4 using its original scripts and separately generated v4 state. Do not reuse v5 WireGuard keys, overlay addresses, conntrack state, policy or ZTP databases, certificates, claims, leases, route epochs, evidence, or volumes in v4.
