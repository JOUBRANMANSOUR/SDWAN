# Requirement traceability

The initial requirement-to-code-and-test matrix is in [`docs/PRE_IMPLEMENTATION.md`](docs/PRE_IMPLEMENTATION.md). This document is updated with exact test names and saved evidence paths as each implementation phase completes.

Every mandatory ID has a positive test, a negative test and an Ubuntu evidence command. The permanent source of truth for those IDs is the persistent policy/route or ZTP store, never the Ryu packet-in loop or the NFQUEUE callback.

## Cloud VPC and SaaS destination policy

| Requirement | Responsible source | Automated coverage | Ubuntu evidence gate |
|---|---|---|---|
| Two Cloud Gateways through active hubs only | `topology_v5.py`, `common/model.py` | `test_optional_cloud_adds_gateway_nodes_without_openflow_growth` | enabled-Cloud route, return-path, and gateway-failure capture |
| Cloud Gateway and ingress-hub return affinity | `topology_v5.py` | `test_cloud_routes_have_deterministic_primary_and_backup_paths` | Cloud SNAT counter, conntrack mark, table 3101/3102, and bidirectional capture |
| Spoke six-path return affinity | `edge_agent_v5.py`, `common/marks.py` | `test_spoke_return_affinity_covers_all_six_hub_transport_paths` | branch-to-branch capture plus spoke conntrack mark |
| Hub spoke-transport return affinity | `edge_agent_v5.py` | `test_hub_backhaul_has_symmetric_branch_route_and_saas_nat` | hub `SDWAN_V5_RPA_*`, policy rule/table, and conntrack evidence |
| Data Center gateway affinity | `edge_agent_v5.py` | `test_hub_backhaul_has_symmetric_branch_route_and_saas_nat` | hub DC SNAT counter plus forward/return capture |
| Trusted/Sensitive/Unknown destination policy | `config/destination_policy.yaml`, `common/destination_models.py` | `test_explicit_trust_is_destination_policy_not_protocol`, rejection tests | direct-vs-backhaul captures and service reachability |
| Versioned persistent delivery | `persistence/migrations/policy/002_destination_policy.sql`, `policy_store.py` | `test_activation_is_monotonic_idempotent_and_restart_safe` | Policy Service restart and unchanged snapshot version |
| Transit-prefix safety | `common/model.py` | `test_cloud_transit_overlap_is_rejected` | N/A (unprivileged invariant) |

The Cloud/SaaS live gates are intentionally not marked passed until they are executed on this Ubuntu lab with Containernet, OVS, Docker, WireGuard, iptables/NFQUEUE, and captures.
