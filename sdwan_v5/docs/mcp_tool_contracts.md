# MCP tool contracts

All tools are local, read-only, stdio tools and publish SDK-generated input and output
schemas. Each successful result is an `OperationalResult` with `meta`, `facts`, and
`payload`.

- `get_dashboard_summary`: bounded inventory overview; not a route lookup.
- `list_sites`: configured site inventory; not live state.
- `get_site_status`: broad runtime view of one site; not detailed routes/tunnels.
- `get_site_tunnels`: observed WireGuard status; not route selection.
- `get_site_routes`: observed route groups/rules; not a per-destination decision.
- `get_topology`: static configuration only.
- `get_hub_status`: configured/runtime information for one hub.
- `get_cloud_status`: Cloud VPC configuration; not reachability proof.
- `get_saas_status`: SaaS configuration; not active reachability proof.
- `compare_desired_actual`: Python-generated semantic comparison, with unavailable
  and non-comparable values explicit.
- `explain_route_decision`: requires `site` and `destination`; optional `source` and
  `fwmark` are passed to the runtime lookup.
- `get_recent_events`: bounded audit history only.

Unavailable values use `null` plus `unknowns`, not empty strings. Lists are bounded
before serialization; `truncated`, counts, and `next_cursor` communicate limits.


## Expanded read-only inventory

The stdio server also exposes domain-specific evidence tools rather than treating every node as a site:

- `get_system_health`, `get_topology_nodes`, `get_topology_links`, and `get_transport_inventory`;
- `get_hub_configuration`, `list_cloud_gateways`, and `get_cloud_gateway`;
- `get_data_center_configuration` and `get_saas_configuration`;
- `get_route_ownership`, `get_site_desired_state`, `list_policy_versions`, `get_destination_policy`, and `list_ztp_devices`;
- `get_site_interfaces`, `get_site_failover_status`, and `get_site_classifier_status`.

Every tool remains local stdio-only, constrained to read-only data sources, and returns a provenance-tagged `OperationalResult`. A Cloud VPC gateway is queried by its gateway identifier (for example `cloud_gw1`), not through the site inventory.


## Endpoint-aware path questions

`get_endpoint` returns one compact configured endpoint record for a known name or alias; `get_endpoint_inventory` publishes all configured endpoint identities and aliases only for discovery. `explain_endpoint_route` resolves a source and destination alias before answering a host-to-destination path question. For a branch-host source it reports two separately labelled evidence sets: the configured host-to-LAN-gateway access hop, and the observed route lookup performed at the associated edge site. It accepts `node1_host` and `node_host1`, as well as `data_center`/`dc`, `saas`, `cloud_app`, and Cloud gateway names. Supplying no fwmark leaves policy-rule selection unproven rather than inferred.


## Policy candidates and observed flows

When no fwmark is supplied, `explain_endpoint_route` reports matching installed policy-rule and route candidates separately from its unmarked lookup; these candidates do not assert a selected path. `observe_endpoint_flow` is a read-only runtime tool for an already active branch-host connection. It reads matching conntrack marks and performs a marked lookup only when a mark is observed. It never generates traffic or modifies connection tracking.

`explain_site_host_route` is the unambiguous tool for a question about “the host of nodeN”: it takes the site name and always resolves the configured branch host, never the edge router.

`get_site_tunnels` is for branch sites only. `get_hub_tunnels` is the corresponding read-only WireGuard inspection for `hub1` and `hub2`.
