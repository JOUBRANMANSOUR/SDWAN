# ADR-006: Core SaaS egress and optional Cloud profile

## Decision

The core experiment uses one public collaboration SaaS destination and direct Internet breakout only. Its candidate transports are Broadband and LTE. It does not transit hub1 or hub2.

Cloud VPC is not part of the active core experiment. Its code and configuration remain available through the paired profiles:

```text
config/topology.cloud.yaml
config/destination_policy.cloud.yaml
```

## Rationale

The core topology must distinguish three testable behaviors rather than duplicate private destinations:

- Branch-to-branch real-time traffic through the hub overlay.
- Private backup traffic through the hub overlay to the Data Center.
- Public SaaS traffic through local direct breakout.

Adding active Cloud VPC to the same core experiment increases route, gateway, return-path, and failure-state complexity without improving the primary SLA-selection question.

## Consequences

- SaaS cannot silently fall back to a hub route.
- MPLS is not a SaaS candidate in the core profile.
- Cloud must be started with matching topology and destination-policy profiles.
- Cloud results must be reported as an optional extension, not mixed with core results.
