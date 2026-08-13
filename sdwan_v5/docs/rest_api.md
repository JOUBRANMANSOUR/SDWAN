# Management REST API

All endpoints require a bearer token except `POST /api/v1/auth/login`. The platform is read-only with respect to the SD-WAN fabric.

| Area | Endpoints |
|---|---|
| System | `/api/v1/system/health`, `/api/v1/system/capabilities`, `/api/v1/dashboard` |
| Topology | `/api/v1/topology`, `/api/v1/topology/nodes`, `/api/v1/topology/links` |
| Sites | `/api/v1/sites`, `/api/v1/sites/{site}/desired`, `/api/v1/sites/{site}/runtime`, `/tunnels`, `/routes`, `/rules` |
| Policy/routing | `/api/v1/policy/versions`, `/api/v1/policy/destination`, `/api/v1/desired-state/summary`, `/api/v1/routes/ownership` |
| Services | `/api/v1/ztp/devices`, `/api/v1/hubs/{hub}`, `/api/v1/data-center`, `/api/v1/saas`, `/api/v1/cloud-vpc` |
| Observability | `/api/v1/events`, `/api/v1/events/stream`, `/api/v1/audit` |
| Chat | `/api/v1/chat/sessions` and session message/history paths |

A stopped Docker/Containernet runtime is represented as `UNAVAILABLE`. No endpoint substitutes configured state for live state.
