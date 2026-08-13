# Management RBAC

`VIEWER` reads health and topology. `NETWORK_ADMIN` additionally reads routes, tunnel/runtime state, and events. `AUDITOR` reads events and management audit history. `PLATFORM_ADMIN` has all read scopes and may use the fail-closed chat interface. No role receives any fabric, Policy, ZTP, Docker, shell, WireGuard, or route mutation permission.
