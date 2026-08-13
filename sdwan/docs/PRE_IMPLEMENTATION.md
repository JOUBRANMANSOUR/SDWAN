# v5 pre-implementation record

## Scope and preservation

- Working project root: `/mnt/data/sdwan-lab`; original inspected reference remains `/home/joubran/projects/sdwan-lab/sdwan_v4`.
- Preserved working reference: `/mnt/data/sdwan-lab/sdwan_v4` (a manifest-verified copy of the original).
- This project directory is not a Git worktree; phase commits are therefore not possible here.
- Required environments found without modification: `/home/joubran/containernet-venv38` and `/home/joubran/ryu-venv38`.
- Baseline manifest: `preservation/sdwan_v4.sha256` (all regular files in `sdwan_v4`, sorted by absolute path).
- Baseline verification command: `sha256sum -c sdwan/preservation/sdwan_v4.sha256`.

The baseline was verified before v5 source was created. v5 tests include the same command as a preservation gate.

## v4 migration table

| v4 component | Current limitation | Reusable part | v5 replacement / status | Responsible v5 file |
|---|---|---|---|---|
| `config/topology.yaml` | `home_hub` scalar; one interface per transport | Underlay names, addressing discipline, load split | Validated dual-hub/site inventory, egress and cloud schema | `config/topology.yaml`, `common/model.py` |
| Topology-generated WireGuard keys | Keys are generated around topology startup | Per-node command wiring only | Edge-local persisted keys, public-key registration and rotations | `identity_store.py`, `resource_allocator.py`, `edge_agent_v5.py` |
| `/run` edge identity | Ephemeral restart identity | None for private material | Mounted `/var/lib/sdwan/{identity,wireguard,state}` persistence | `identity_store.py`, Docker volumes |
| `/sdwan/register` | Requires every router public key in one request | Desired-state shape and idempotent reconcile concept | Independent hub/spoke enrollment and resume state machine | `ztp_service_v5.py`, `enrollment_state.py` |
| Trusted `--site` startup identity | Caller supplies trusted site identity | Containernet may name a container only | Generic bootstrap client maps authenticated UUID+claim to staged inventory | `ztp_client.py`, `device_inventory.py` |
| Shared `X-SDWAN-Token` auth | One token is not device identity or mTLS | Legacy migration boundary only | Claim bootstrap followed by CSR, CA-issued operational cert, mTLS | `identity_ca.py`, `ztp_service_v5.py`, `mtls.py` |
| Policy Service dictionaries/counters | Volatile policy, metrics, overrides and versions | SLA scoring remains metadata/policy input | SQLite-owned desired state, audit, overrides, leases and ownership | `persistence/policy_store.py`, `policy_service_v5.py` |
| Desired-state version | Version is in memory and is not attributable/durable | Canonical desired-state construction | Digest, schema, generations, acks, monotonic conflict rejection | `desired_state_v5.py`, `persistence/policy_store.py` |
| `active_hub` assignments | Cannot represent partial transport failure or ownership | 3/2 normal preference assignment | Preferred/standby, six target states, versioned prefix ownership | `route_ownership.py`, `route_resolver.py` |
| Hub failover ordering | Applies old hub before new hub and requires old-hub reachability | Reconcile/rollback intent | Surviving-hub/spoke prepare-commit and stale owner fencing | `policy_service_v5.py`, `route_ownership.py` |
| Edge cached state | In-memory state/route version; `/run` keys | Local route replacement and classifier supervision patterns | Persistent cache, queued events, restart reconciliation, local emergency mode | `edge_agent_v5.py`, `identity_store.py` |
| Ryu responsibilities | Some service coupling is still broad | OF 1.3 underlay and stats code | Strict OF underlay/telemetry boundary; no ZTP/DPI/route-owner role | `controller_v5.py` |
| nDPI/NFQUEUE data plane | Three transport paths; no egress/target-aware policy contract | Native C pre-encryption metadata and once-per-flow pinning | Docker native classifier remains metadata-only; Edge resolves healthy target | `classifier/`, `edge_agent_v5.py`, `common/marks.py` |

## Proposed v5 directory structure

```text
sdwan/
  common/                 validated model, marks, canonical JSON, mTLS helpers
  persistence/            SQLite owners, migrations, backup/restore
  config/                 topology, inventory, ZTP, policy, trust templates
  classifier/             native nDPI + NFQUEUE source and tests
  docker/                 edge, host, policy and ZTP Docker builds
  scripts/                environment-specific startup, validation and evidence tools
  workloads/              Nginx-light SaaS, DC, cloud and concurrent-download tests
  tests/                  unit, integration, preservation and live-gated tests
  preservation/           immutable v4 SHA-256 manifest
  topology_v5.py          Containernet topology and operator CLI
  controller_v5.py        Ryu OpenFlow 1.3 underlay controller
  ztp_service_v5.py       claim/CSR/certificate lifecycle API
  ztp_client.py           generic bootstrap client (no trusted --site)
  policy_service_v5.py    persistent policy/ownership coordinator
  edge_agent_v5.py        Docker edge local route/NAT/WG actuation
  desired_state_v5.py     canonical, versioned desired-state build/verify
  tunnel_health.py        raw observation and tunnel state machine
  hub_health.py           hub aggregation state machine
  route_resolver.py       local healthy target selection
  route_ownership.py      global ownership epochs and transitions
  local_failover.py       serialized emergency route changes and recovery
  identity_ca.py          laboratory CA / CSR / certificate lifecycle
  identity_store.py       edge-local durable key/state files
  resource_allocator.py   transaction-safe address, port and peer allocation
  enrollment_state.py     ZTP transition validator
  observability.py        bounded metrics/audit views
  ARCHITECTURE.md, DATABASE_SCHEMA.md, ZTP_SECURITY_MODEL.md,
  UBUNTU_RUNBOOK.md, TEST_RESULTS.md, MIGRATION.md,
  REQUIREMENT_TRACEABILITY.md, V4_BASELINE.md
```

## Requirement-to-code-and-test matrix

| ID | Responsible component / files | Configuration keys | Success and negative test | Ubuntu evidence command |
|---|---|---|---|---|
| DH-TUNNEL | `common/model.py`, `desired_state_v5.py` | `hubs`, `transports`, `wireguard` | six distinct interfaces / missing pair rejected | `sudo scripts/validate_live.sh tunnels` |
| DH-MONITOR | `tunnel_health.py`, `hub_health.py` | `health` thresholds | all six monitored / stale sample rejected | `sudo scripts/validate_live.sh health` |
| DH-OWNERSHIP | `route_ownership.py`, `policy_store.py` | `ownership` | monotonic transfer / stale epoch rejected | `sudo scripts/validate_live.sh ownership` |
| DH-LOCAL-FAILOVER | `local_failover.py`, `edge_agent_v5.py` | `failover` | local switch / unavailable target rejected | `sudo scripts/failures.sh tunnel node1 hub1 bb` |
| DH-SYMMETRY | `common/marks.py`, `edge_agent_v5.py` | `marks`, `route_tables` | TCP/UDP affinity / collision rejected | `sudo scripts/validate_live.sh symmetry` |
| DH-RECOVERY | `tunnel_health.py`, `local_failover.py` | `recovery`, `drain_timeout_s` | hysteretic drain / one probe cannot fail back | `sudo scripts/failures.sh restore-tunnel node1 hub1 bb` |
| DH-INTERHUB | `route_ownership.py`, `topology_v5.py` | `interhub` | deterministic convergence / partition marked degraded | `sudo scripts/failures.sh interhub all` |
| DH-STALE-STATE | `desired_state_v5.py`, stores | `schema_version` | exact retry / old version rejected | `source ~/ryu-venv38/bin/activate && pytest -q sdwan/tests -k stale` |
| DH-CONTROL-OUTAGE | `edge_agent_v5.py`, queues | `cache`, `event_retention` | cached failover / stale central overwrite rejected | `sudo scripts/failures.sh policy-outage` |
| DH-PRESERVATION | `tests/test_v4_preservation.py` | manifest path | baseline checksum / intentional mismatch fixture | `sha256sum -c preservation/sdwan_v4.sha256` |
| ZTP-IDENTITY | `identity_store.py`, `device_inventory.py` | `identity_root`, `inventory` | persisted identity / unbound UUID rejected | `source ~/ryu-venv38/bin/activate && pytest -q sdwan/tests -k identity` |
| ZTP-CLAIM | `ztp_store.py`, `ztp_service_v5.py` | `claim_lifetime_s` | one-time consume / replay, expiry and mismatch rejected | `source ~/ryu-venv38/bin/activate && pytest -q sdwan/tests -k claim` |
| ZTP-CSR-MTLS | `identity_ca.py`, `mtls.py` | trust paths, service IDs | CSR issuance / bad CA, site or revoked cert rejected | `sudo scripts/validate_live.sh mtls` |
| ZTP-INCREMENTAL-ENROLLMENT | `enrollment_state.py`, ZTP API | staged inventory | independent resume / cross-device takeover rejected | `sudo scripts/validate_live.sh enroll` |
| ZTP-HUB-FIRST-ACTIVATION | `policy_service_v5.py` | activation policy | both hub acks / standby preparation failure is pending | `sudo scripts/validate_live.sh activation` |
| ZTP-REVOCATION-REPLACEMENT | ZTP/policy stores | replacement policy | fenced replacement / old certificate rejected | `sudo scripts/validate_live.sh replacement` |
| DB-ZTP-PERSISTENCE | `ztp_store.py` | `ztp_db_path` | restart resume / corrupt DB explicit failure | `source ~/ryu-venv38/bin/activate && pytest -q sdwan/tests -k ztp_store` |
| DB-POLICY-PERSISTENCE | `policy_store.py` | `policy_db_path` | persisted owner/override / duplicate lease rejected | `source ~/ryu-venv38/bin/activate && pytest -q sdwan/tests -k policy_store` |
| DB-MIGRATION | `persistence/migrations/` | `schema_version` | forward migration / newer schema rejected | `source ~/ryu-venv38/bin/activate && python -m sdwan.persistence.migrate --check` |
| DB-RESTART-RECONCILIATION | `edge_agent_v5.py`, stores | cache paths | MATCHED/EDGE_AHEAD / stale overwrite rejected | `sudo scripts/validate_live.sh restart` |
| DB-BACKUP-RESTORE | `persistence/backup.py` | backup root/retention | verified restore / invalid archive rejected | `source ~/ryu-venv38/bin/activate && pytest -q sdwan/tests -k backup` |
| SECRET-NONDISCLOSURE | log redactor and tests | secret file paths | audit redaction / plaintext fixture rejected | `source ~/ryu-venv38/bin/activate && pytest -q sdwan/tests -k secret` |

## Validation classification

| Test type | May run unprivileged | Requires privileged Ubuntu execution |
|---|---|---|
| Python unit tests, state machines, config validation, SQLite transactions/migrations with temporary DBs, CSR parsing with temporary keys, manifest verification, secret scans | Yes; use `source ~/ryu-venv38/bin/activate` for control-plane tests | No |
| Ryu import/controller unit tests | Yes; use `source ~/ryu-venv38/bin/activate` | OpenFlow datapath test needs Ryu plus OVS/Containernet |
| C source/static checks | Yes where compiler/development headers are present | Native nDPI build may require Docker or system library packages |
| Docker image build and container self-tests | Docker daemon access; no `sudo` if user is in docker group | Docker daemon if group access is absent |
| Topology creation, OVS, Containernet, network namespaces | No | `sudo`, `source ~/containernet-venv38/bin/activate`, Containernet and OVS |
| WireGuard peers/handshakes, policy routes, `ip rule`, `iptables`, NFQUEUE, conntrack, NAT, packet captures, failover, DC/SaaS/cloud traffic | No | `sudo`, Docker, WireGuard, iptables/NFQUEUE, Containernet/OVS |

No live networking result will be reported as passed until its Ubuntu privileged command has actually completed and saved evidence.
