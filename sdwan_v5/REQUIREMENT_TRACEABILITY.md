# Requirement traceability

| Requirement | Implementation | Verification |
|---|---|---|
| Core Cloud/VPC disabled without deletion | `features.cloud_vpc`, core/cloud topology profiles | config and topology-plan tests |
| One public SaaS, direct only | `destination_policy.yaml`, `policy_http.py`, direct routes | destination-policy and edge-policy tests |
| Real RTP workload | `workloads/rtp_sender.sh`, receiver, SDP | workload syntax/smoke tests; live acceptance pending |
| Central backup with integrity evidence | FastAPI service/client | upload/status/SHA-256 tests |
| Public SaaS API and files | FastAPI service/client | message/upload/download tests |
| Continuous RTT/jitter/loss/bandwidth estimate | `MetricWindow`, failover runtime | metric-window unit tests |
| Policy-constrained SLA selection | `PathSelector`, `RouteResolver.resolve_sla` | eligibility/scoring tests |
| Hysteresis and hold-down | selector state | bad/good sample and hold-down tests |
| Concrete switch reason | selector decisions/events | path-selection tests |
| Existing TCP flow pinning | connmark restore before class rules | iptables command-order tests |
| RTP re-steering | conntrack update on UDP/5004 | unit-level command path; live acceptance pending |
| Fail closed when no eligible path | class-specific DROP for new/unmarked flows | fail-closed dataplane test |
| Management observability | `/api/v1/path-*`, `/api/v1/workloads` | FastAPI endpoint tests |
| Optional Cloud restorable | cloud topology and destination-policy profiles | config/plan tests; live acceptance pending |
| Portable validation and Python 3.8 syntax | `scripts/validate_static.sh` | strict tests, compile, AST 3.8 parse, YAML, shell, Core/Cloud plans |
| SQLite descriptor closure | `management/repository.py` short-lived `_rw` context | management tests with `ResourceWarning` promoted to error |
| Reversible live fault injection | `scripts/failure_injection.sh` | shell/rollback tests; privileged behavior pending |
| node1-local capacity demonstration | node1-hosted `iperf3` cross-traffic | helper test and live checklist; privileged result pending |
