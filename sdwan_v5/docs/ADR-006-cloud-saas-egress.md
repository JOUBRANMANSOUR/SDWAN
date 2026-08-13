# ADR-006: Cloud VPC and destination-specific SaaS egress

## Status

Implemented in source; privileged Ubuntu validation remains pending.

## Decision

Cloud VPC traffic is an overlay-only private destination.  It is never a
direct-Internet candidate and it is never NATed.  The optional VPC has two
Cloud Gateway containers, connected to both active hubs through four dedicated
/30 hub-to-gateway transit links.  The default configuration keeps the VPC
disabled.  When enabled, hub1 uses `cloud_gw1` first and hub2 uses
`cloud_gw2` first; each has the other gateway as its deterministic fallback.

The route design is explicit and NAT-free: each hub has a primary dedicated
gateway route; each gateway has branch return routes through the corresponding
hub; `cloud_app` has deterministic branch routes through the gateway paired
with that branch's preferred hub.  These routes preserve the original branch
source address.

SaaS policy is destination/trust based, rather than protocol based:

| Destination | Trust class | Egress | Failure action |
|---|---|---|---|
| `198.18.0.10/32` trusted SaaS | Trusted | Broadband/LTE direct, hub fallback | Hub fallback |
| `198.18.0.20/32` sensitive SaaS | Sensitive | Hub overlay only with central inspection flag | Fail closed |
| `198.18.0.30/32` unknown SaaS | Unknown | Hub overlay only | Fail closed |
| unmatched destination | Unknown | Hub overlay only | Fail closed |

nDPI may attach application metadata to an already-selected flow.  It does
not infer trust, choose an egress, select a transport/hub/gateway, or override
the persistent destination-policy snapshot.  UDP/443 is represented only as a
generic unknown UDP workload; the lab makes no QUIC classification claim.

## Consequences

- The Cloud VPC stays behind the existing hub overlay and does not add a
  spoke-to-gateway shortcut or per-packet balancing.
- Hub egress may NAT public SaaS flows only.  Branch, Data Center, and enabled
  Cloud VPC prefixes are explicit `RETURN` exclusions before `MASQUERADE`.
- Policy records are immutable, versioned SQLite desired state.  Reapplying an
  identical policy is idempotent; an updated document creates a new version.
- The current source implements deterministic topology routes and policy
  distribution.  Live Cloud Gateway health probing and multi-gateway
  convergence timing are validation work, not a production-readiness claim.
