# SD-WAN v5 management architecture

The management platform is a separate FastAPI process on `127.0.0.1:8090`. It reads topology through the validated model, service state through SQLite `mode=ro`, and optional live state through a fixed Docker inspection allow-list. Its own audit/chat database is separate from Policy and ZTP databases.

```text
Browser / REST / MCP
        | bearer RBAC
FastAPI ManagementService
   | config model | read-only SQLite | fixed Docker reads
Policy/ZTP state  topology.yaml      mn.<known-node>
```

No browser request can select a Docker command, shell command, container, database SQL expression, route, tunnel, policy, ZTP action, or topology mutation. nDPI remains in Docker and outside Ryu; Ryu remains underlay-only. Runtime endpoints mark stopped/unavailable resources as `UNAVAILABLE`.
