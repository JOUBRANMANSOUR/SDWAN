# Dynamic branch Zero-Touch lifecycle

Management is the sole northbound administrative lifecycle interface. The
running Containernet topology accepts only typed, inventory-validated local
operations over a mode-`0600` Unix socket: create, bootstrap, reconcile, and
delete. It does not accept shell commands, route operations, OVS flows,
firewall rules, packet marks, or WireGuard key material.

## Automatic lifecycle

`POST /api/v1/sites` creates one operation and drives:

```text
ALLOCATING -> TOPOLOGY_CREATED -> ZTP_STAGED -> ENROLLING -> ENROLLED
-> REGISTERING -> PROVISIONING -> PENDING_HUBS|RECONCILING -> ACTIVE
```

1. Policy inventory allocates collision-safe addresses, interface suffixes and
   an Edge device ID.
2. The runtime creates the typed dynamic Edge, host, LAN switch and base
   interfaces.
3. ZTP stages a device and issues a short-lived one-time claim.
4. Management writes only the claim and public CA/control-plane inputs into the
   new Edge with protected files, then invokes the existing
   `edge_bootstrap enroll` entry point inside that Edge.
5. The Edge generates its identity private key, CSR, and WireGuard private key
   locally. Only the public WireGuard identity is registered with Policy.
6. Management asks both hubs to reconcile, Policy publishes the spoke desired
   state, and the Edge reconciles it. Ryu admits only the authorized attachment
   states published by the control plane.

The response contains the `operation_id`; `GET /api/v1/operations/{operation}`
returns the latest state. A failed operation is explicitly `FAILED` with
`failure_stage`, `failure_reason`, and `recoverable`; it is never reported as
active.

## Deletion and retry

`DELETE /api/v1/sites/{site}` executes:

```text
DELETING -> revoke/cancel ZTP identity -> retire public WG registration
-> remove dynamic topology -> DELETED
```

The lifecycle is idempotent for an active same-device request and for deletion.
A deleted site can be reallocated with the same device ID without preserving
its previous claim, certificate, or public WireGuard registration.

## Canonical API

```text
POST   /api/v1/sites
GET    /api/v1/sites
GET    /api/v1/sites/{site}
DELETE /api/v1/sites/{site}
GET    /api/v1/operations/{operation_id}
GET|POST /api/v1/intents
PUT|DELETE /api/v1/intents/{intent_id}
```

Required scopes are `site:read/site:write` for lifecycle visibility/actions and
`policy:read/policy:write` for intents. `ADMIN` has every scope; a network
operator is granted only the defined operate scopes; a viewer is read-only.
The prior `/api/v1/admin/*` raw control surface is removed rather than exposed
as a public Management write API.

## Security boundary

Management, MCP, and the Agent may express controlled site or Policy intent.
They never directly program Ryu/OpenFlow, Edge Linux routes/rules/fwmarks,
CONNMARK, WireGuard private state, or path-selector output. ZTP remains the
identity service, Policy remains the desired-state service, Edge remains the
overlay/routing owner, and Ryu remains the centralized L3 underlay owner.
