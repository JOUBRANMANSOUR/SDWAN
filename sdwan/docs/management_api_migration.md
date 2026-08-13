# Management API migration

The Management service is the northbound administrative interface. Device-facing
ZTP and Edge/Policy service endpoints remain internal and are not duplicates of
this API. The temporary compatibility aliases listed below are read-only only;
new UI, Agent, and MCP work uses the canonical endpoints.

| Old endpoint | Status | Canonical endpoint | Reason |
|---|---|---|---|
| `GET /api/v1/system/version`, `/system/health`, `/system/config`, `/system/capabilities` | compatibility | `GET /api/v1/system` and public `GET /healthz` | one system representation |
| `GET /api/v1/dashboard/summary` | compatibility | `GET /api/v1/dashboard` | duplicate summary |
| `GET /api/v1/topology/nodes`, `/topology/links` | compatibility | `GET /api/v1/topology` | topology aggregate |
| `GET /api/v1/underlay`, `/underlay/state` | compatibility | `GET /api/v1/underlays` or `/underlays/{transport}` | Ryu L3-underlay aggregate |
| `GET /api/v1/path-metrics`, `/path-decisions`, `/path-events` | compatibility | `GET /api/v1/paths` | one coherent path view |
| `GET /api/v1/sites/{site}/desired`, `/applied-state`, `/actual-state`, `/routes`, `/rules`, `/routing-rules`, `/routing-tables`, `/return-affinity` | compatibility | `/sites/{site}/desired-state`, `/runtime`, `/routing` | remove ambiguous state representations |
| `GET /api/v1/hubs/{hub}/routes`, `/return-affinity`, `/flows` | compatibility | sites/runtime/routing and `GET /traffic/flows` | hubs are sites, not duplicate resource trees |
| `GET /api/v1/audit` | compatibility | `GET /api/v1/audit/events` | canonical audit resource |
| `POST /api/v1/admin/sites` and raw `/admin/*` control endpoints | removed | `POST /api/v1/sites`, `/api/v1/intents` | no raw compiler/network/Ryu/route writes |

## Canonical public Management surface

- `POST /api/v1/auth/login`
- `GET /healthz`, `GET /api/v1/system`, `GET /api/v1/dashboard`
- `GET /api/v1/topology`
- `GET|POST /api/v1/sites`, `GET|DELETE /api/v1/sites/{site}`
- `GET /api/v1/operations/{operation_id}`
- `GET /api/v1/sites/{site}/desired-state`, `/runtime`, `/routing`, `/tunnels`
- `GET /api/v1/paths`, `/underlays`, `/underlays/{transport}`, `/policy`
- `GET|POST /api/v1/intents`, `PUT|DELETE /api/v1/intents/{intent_id}`
- `GET /api/v1/ztp/devices`, `/events`, `/events/stream`, `/audit/events`, `/traffic/flows`
- read-only graph endpoints under `/api/v1/graph/*`

## Dynamic site lifecycle

`ALLOCATING -> TOPOLOGY_CREATED -> ZTP_STAGED -> ENROLLING -> ENROLLED ->
REGISTERING -> PROVISIONING -> (PENDING_HUBS | RECONCILING) -> ACTIVE`.

On a failure the site becomes `FAILED` with `failure_stage`, `failure_reason`,
and `recoverable`; it never reports a synthetic active status. Deletion follows
`DELETING -> DELETED`, revokes the ZTP identity, retires public WireGuard
registration, removes the dynamic topology, and releases the inventory record.

Management only writes the short-lived public bootstrap inputs into the dynamic
Edge. `edge_bootstrap` creates the private identity key, CSR and WireGuard
private key inside the Edge namespace; those values do not leave the Edge.

## MCP catalog and resources

MCP runs as a local stdio service with signed short-lived agent context. It has
no HTTP transport and exposes no generic shell, raw HTTP, OpenFlow, Linux
route/rule, packet-mark, or WireGuard-private-key tool.

- **Observe:** dashboard/site/runtime/routing/tunnel/underlay/path/policy/ZTP,
  events/audit, endpoint, and traffic-flow tools.
- **Graph/evidence:** `graph_get_component`, `graph_expand_dependencies`,
  `graph_find_path`, `graph_get_expected_traffic_path`,
  `graph_calculate_impact_scope`, and `evidence_get_for_components`.
- **Controlled writes:** `create_site`, `upsert_intent`.
- **Destructive lifecycle writes:** `delete_site`, `delete_intent`.

Stable MCP Resources: `sdwan://graph/schema`,
`sdwan://architecture/planes`, `sdwan://architecture/ownership`, and
`sdwan://architecture/return-affinity`. They describe stable architecture only;
live operational data is retrieved via typed tools with provenance.

## Evidence and ownership

Graph nodes and edges carry source identifiers and a state kind:
`CONFIGURED`, `DESIRED`, `OBSERVED`, or `DERIVED`. An evidence fact carries a
fact ID, component ID, fact type, value, source, availability and observation
time when published. Configured/derived path candidates are never presented as
an observed packet trace. Edge-owned decisions remain separate from Ryu-owned
underlay admission/FIB decisions.
