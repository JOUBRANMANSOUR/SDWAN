# Management Platform Milestone 1 assessment

## Scope and evidence

This assessment was completed before adding management-platform code.  The
canonical repository is `/mnt/data/sdwan-lab`; its application package is
`/mnt/data/sdwan-lab/sdwan`.  The path `/mnt/data/sdwan` does not exist.

Baseline verification, performed before this assessment:

```bash
source /home/joubran/ryu-venv38/bin/activate
cd /mnt/data/sdwan-lab
PYTHONPATH=$PWD python -m unittest discover -s sdwan/tests -p 'test_*.py' -v
```

Result: **44 tests passed in 2.852 seconds**.  `git diff --exit-code --
sdwan_v4` also completed successfully, so the retained v4 implementation was
unchanged.  The worktree has two pre-existing untracked artifacts,
`sdwan/node1` and `sdwan/node1_host`; they are not management-platform
files and must not be staged or removed by this work.

## Existing v5 architecture

The laboratory is a Docker/Containernet topology launched by
`topology_v5.py`.  It contains two hubs (`hub1`, `hub2`), five spokes
(`node1`...`node5`), MPLS, broadband, and LTE underlays, a Data Center
(`10.100.0.0/24`), a simulated SaaS network (`198.18.0.0/24`), and an optional
two-gateway Cloud VPC (`10.200.0.0/24`, disabled in the default YAML).

Each spoke pre-establishes six WireGuard tunnel targets: hub1/hub2 crossed
with MPLS/broadband/LTE.  Its preferred and standby hubs are configured in
`config/topology.yaml`.  The Edge Agent owns local Linux routing, nft/iptables
style connmark/NAT setup, NFQUEUE attachment, and immediate cached-policy
failover.  `edge_failover_runtime.py` writes
`/var/lib/sdwan/state/failover-status.json` inside an edge container.

Ryu (`controller_v5.py`) is intentionally limited to OpenFlow 1.3 L2 underlay
learning, datapaths, ports, and counters.  It does not make policy, ZTP,
route-ownership, nDPI, or failover decisions.

Native nDPI/NFQUEUE runs inside the edge Docker image and exports bounded
metadata JSONL through `classifier_event_collector.py`; it must remain outside
the Ryu packet-in loop and never observes WireGuard ciphertext.

### Routing and return affinity

The mark ABI is already defined and must remain unchanged: low-byte transport
slot, terminal/provisional/emergency bits, hub affinity mask `0x3000`, and
egress mode mask `0xc000`.  Per-connection marks are local to each namespace.
The existing `SDWAN_V5_RPA_IN`/`SDWAN_V5_RPA_OUT` chains persist ingress and
egress selection with conntrack, with hub-specific rules before generic slot
rules.  Data Center and optional Cloud return paths use scoped SNAT at the
selected hub/gateway.  Management is observational only: it must not alter
these rules, route tables, marks, WireGuard peers, ownership epochs, or
conntrack state.

## Existing HTTP APIs (exact current surface)

Policy Service (`policy_http.py`, TLS/mTLS, default port 8080):

| Method | Path | Existing purpose | Management suitability |
|---|---|---|---|
| GET | `/healthz` | service/schema health | safe health probe |
| GET | `/v1/edge/desired` | authenticated edge retrieves its desired state | not a generic management read API |
| GET | `/v1/edge/policy/{site}` | authenticated edge retrieves only its own snapshot | not a generic management read API |
| POST | `/v1/edge/register` | device key registration | write; out of scope |
| POST | `/v1/edge/ack` | desired-state acknowledgement | write; out of scope |
| POST | `/v1/admin/activate/{site}` | activation | write; out of scope |
| POST | `/v1/edge/event` | local failover/reconciliation event | write; out of scope |

ZTP Service (`ztp_service_v5.py`, TLS/mTLS, default port 8443):

| Method | Path | Existing purpose | Management suitability |
|---|---|---|---|
| GET | `/healthz` | service/schema health | safe health probe |
| POST | `/v1/enroll` | claim/CSR enrollment | write; out of scope |
| POST | `/v1/admin/stage` | stage device | write; out of scope |
| POST | `/v1/admin/claims` | issue claim | write; out of scope |
| POST | `/v1/admin/revoke` | revoke identity | write; out of scope |

There are no current generic read APIs for inventory, topology, route
ownership, WireGuard state, failover state, audit history, or classifier
metadata.  The management backend must not reuse the `sdwan-admin` private
key or call existing write endpoints.

## Current sources of truth and observable state

| Domain | Authoritative source | Read-only management adapter |
|---|---|---|
| Static topology, interfaces, networks, expected links | `config/topology.yaml` and `common/model.py` | validated config/model adapter |
| Desired state, route ownership, policy versions, deliveries, leases | `/mnt/data/sdwan-state/policy/policy.db` | SQLite URI opened `mode=ro`, parameterized queries only |
| Device lifecycle, certificates, enrollment attempts, ZTP audit | `/mnt/data/sdwan-state/ztp/ztp.db` | SQLite URI opened `mode=ro`; redact claim secret hashes and certificate PEM |
| Policy/ZTP liveness | existing `/healthz` endpoints | mTLS health-probe adapter; no admin credentials |
| Actual container interface/WireGuard/routes/rules/tables | Docker/Containernet namespaces (`mn.<node>`) | fixed-command local runtime adapter, never browser-controlled shell |
| Local failover status/events | edge persistent volume `/var/lib/sdwan/state/*.json` and JSONL | adapter through fixed container reads; bounded tails only |
| nDPI metadata | `classifier-events.jsonl` in edge state | bounded metadata-only tail; no packet payload/ciphertext |
| Ryu datapath/port counters | Ryu runtime and OVS | currently no exported management API; show `UNAVAILABLE` until a read-only adapter is implemented |

The existing Python store classes are owner-side read/write abstractions.  The
management service must **not** instantiate them against the production DB,
because construction enables migrations and write-capable connections.  It
will use a separate read-only SQLite repository with immutable DTOs.

## Gaps, risks, and availability semantics

1. The Ryu virtual environment currently has no `fastapi`, `uvicorn`,
   `pydantic`, `mcp`, `httpx`, JWT, bcrypt, or passlib package.  A dedicated
   management dependency install into an existing virtual environment needs
   explicit approval; no global install is acceptable.
2. No current process exposes Ryu datapath/port counters or a stable topology
   event stream.  Endpoints must return an explicit `UNAVAILABLE`/`unknown`
   status rather than inventing dataplane state.
3. Docker namespace introspection needs access to Docker and is privileged in
   many installations.  It must be deployed as a narrowly scoped service
   account/adapter with a fixed allow-list of node names and read-only commands
   such as `wg show`, `ip -j link/address/route/rule`, and bounded `tail`; it
   must never accept a command, image, container, or path from an HTTP client.
4. Live router state is transient and may not be available when the topology
   is stopped.  The API will represent this as `UNAVAILABLE`, while desired
   state remains available from SQLite.
5. Local `failover-status.json` describes last observed local status, not a
   globally synchronized truth.  Timestamps and source must be returned with
   it.
6. Certificate material, ZTP claim secret hashes, private keys, WireGuard
   private keys, and classifier payloads are sensitive and will not be exposed
   in any REST, MCP, audit, UI, or chat response.
7. Claude Code/Ollama availability is not currently established.  The Web
   Agent integration must remain disabled by default and report unavailable
   safely when its configured command/runtime is absent.

## Milestone implementation plan

1. Add `sdwan/management/` with DTOs, configuration, read-only SQLite
   repositories, fixed-command runtime adapters, a shared `ManagementService`,
   local auth/RBAC, audit repository, FastAPI routes, SSE events, and a small
   static operator UI.  It will expose only safe reads plus local
   authentication/session endpoints; it will contain no policy, ZTP, routing,
   WireGuard, Docker, shell, or topology mutation endpoint.
2. Add `sdwan/sdwan_mcp/` as one streamable HTTP MCP endpoint at `/mcp`.
   MCP tools will call the same `ManagementService` as REST, with scope-aware
   read-only tools only.
3. Add a disabled-by-default Agent Gateway.  It will send only a bounded,
   redacted management snapshot to the configured local Claude Code/Ollama
   command, validate cited read-only tool calls, and persist structured
   session/message/audit records.  Browser clients never receive direct Docker
   or shell access.
4. Add docs for architecture, API, RBAC, MCP, Web Agent, testing, and an
   `.env.example`; add deterministic unit tests with fake repositories and
   runtime adapters.  Add integration tests only where the new dependencies
   are installed.
5. Verify static tests after each phase.  Live Containernet/Docker checks are
   optional privileged validation and must be run separately; passing unit
   tests will not be presented as proof of live routing/failover.

## Unsupported in this milestone

The management platform will not alter policies, ZTP lifecycle, desired state,
route ownership, tunnels, routes, failover, NAT, iptables, Cloud gateways,
Ryu flows, containers, or host networking.  It does not provide per-packet
balancing, packet inspection, packet capture, a browser shell, arbitrary Docker
execution, real cloud-provider integration, a production identity provider,
or seamless cross-hub conntrack migration.  It is a laboratory observability
and assisted-diagnosis surface, not a production-ready control plane.
