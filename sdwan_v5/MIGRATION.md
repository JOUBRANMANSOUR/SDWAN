# Migration from the previous v5 profile

## Active architecture changes

- Default topology is now `config/topology.core.yaml`.
- Cloud VPC is disabled in the core profile and retained in `config/topology.cloud.yaml`.
- Cloud destination policy is retained separately in `config/destination_policy.cloud.yaml`.
- Multiple trusted/sensitive/unknown SaaS destinations were replaced by one `public_saas` destination at `198.18.0.10`.
- Public SaaS is direct-Internet only over Broadband/LTE; no hub transit remains in core policy.
- `dc_app` now represents a central HTTPS backup repository.
- Real H.264 RTP/UDP is used for branch-to-branch real-time traffic.
- Static first-healthy ranking was extended with policy-constrained SLA eligibility, normalized scoring, and anti-flapping.

## Configuration changes

New required sections:

```text
features
measurement
application_slas
path_scoring
path_selection
```

New application classes:

```text
REALTIME_RTP
CENTRAL_BACKUP
SAAS_INTERACTIVE
SAAS_FILE_TRANSFER
```

Removed active SaaS concepts:

```text
trusted_saas
sensitive_saas
unknown_saas
central_inspection_required
HUB_BACKHAUL for SaaS
```

## Runtime/state changes

New read-only state files per spoke:

```text
path-metrics.json
path-decisions.json
path-events.json
```

`steering-rules.json` now records class marks and may include `blocked: true` when a fail-closed class has no eligible path.

Do not reuse stale policy databases or desired-state snapshots across incompatible policy schemas without running the normal staging/activation/reconciliation flow.

## Compatibility

- Low-byte route-slot ABI and route tables 101/102/103 are preserved.
- Hub-specific WireGuard tables 1101–1203 are preserved.
- Cloud source remains in the repository but requires both Cloud topology and Cloud destination-policy profiles.
