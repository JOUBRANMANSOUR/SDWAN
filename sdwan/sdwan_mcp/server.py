"""Official MCP SDK server for local stdio-only SD-WAN evidence queries."""
from __future__ import annotations
import os
from typing import Any, Callable, Dict, List, Optional
try:
    from typing import Annotated
except ImportError:  # Python 3.8
    from typing_extensions import Annotated
from pydantic import Field, IPvAnyAddress
from mcp.server.fastmcp import FastMCP
from sdwan.management.auth import Principal, allowed, verify_agent_context
from sdwan.management.config import ManagementConfig
from sdwan.management.service import ManagementService
from .models.common import OperationalResult, StateKind, UnknownField, result_from_payload

MAX_ITEMS = 100

def _bounded(value: Any, limit: int = MAX_ITEMS) -> tuple[Any, bool, int]:
    """Apply structural list limits before serialization; never slice JSON text."""
    if isinstance(value, list):
        total = len(value)
        return value[:limit], total > limit, total
    if isinstance(value, dict):
        result: Dict[str, Any] = {}
        truncated = False
        total = 0
        for key, item in value.items():
            bounded, was_truncated, count = _bounded(item, limit)
            result[key] = bounded
            truncated = truncated or was_truncated
            total = max(total, count)
        return result, truncated, total
    return value, False, 0

def _tool_result(service: ManagementService, principal: Principal, name: str, payload: Dict[str, Any], source_type: str, state_kind: StateKind, *, unavailable_reason: Optional[str] = None) -> OperationalResult:
    bounded, truncated, total = _bounded(payload)
    available = unavailable_reason is None and payload.get("available", payload.get("availability", "AVAILABLE")) not in (False, "UNAVAILABLE")
    unknowns: List[UnknownField] = []
    for item in bounded.get("unknowns", []) if isinstance(bounded, dict) else []:
        if isinstance(item, dict) and item.get("field") and item.get("reason"):
            unknowns.append(UnknownField(field=str(item["field"]), reason=str(item["reason"])))
    if unavailable_reason:
        unknowns.append(UnknownField(field="result", reason=unavailable_reason))
    result = result_from_payload(name, bounded if isinstance(bounded, dict) else {"value": bounded}, source_type, state_kind, available=available, limitations=list(payload.get("limitations", [])) if isinstance(payload, dict) else [], warnings=list(payload.get("warnings", [])) if isinstance(payload, dict) else [], unknowns=unknowns)
    result.truncated = truncated
    result.returned_count = min(total, MAX_ITEMS) if total else len(result.facts)
    result.total_count = total if total else len(result.facts)
    result.next_cursor = "offset:{}".format(MAX_ITEMS) if truncated else None
    service.audit.add(principal.subject, "MCP_TOOL", name, "200" if available else "UNAVAILABLE")
    bundle_id = os.environ.get("SDWAN_EVIDENCE_BUNDLE_ID", "")
    if bundle_id:
        service.audit.append_evidence_tool(bundle_id, name, {}, result.model_dump(mode="json"))
    return result

def _require(principal: Principal, scope: str) -> None:
    if not allowed(principal, "mcp:read") or not allowed(principal, scope):
        raise PermissionError("PERMISSION_DENIED: required read-only scope is not granted")

def _require_write(principal: Principal, scope: str) -> None:
    if not allowed(principal, "mcp:operate") or not allowed(principal, scope):
        raise PermissionError("PERMISSION_DENIED: required controlled-write scope is not granted")

def _site(service: ManagementService, name: str) -> None:
    if name not in service.topology.site_names:
        raise ValueError("UNKNOWN_SITE: requested site is not configured; use list_sites")

def _hub(service: ManagementService, name: str) -> None:
    if name not in service.topology.hubs:
        raise ValueError("UNKNOWN_HUB: requested hub is not configured")

def build_server(config: ManagementConfig, principal: Principal) -> FastMCP:
    """Build a per-process authorized FastMCP server. No HTTP transport is enabled."""
    service = ManagementService(config)
    mcp = FastMCP("sdwan-management-mcp", instructions="Local stdio-only, read-only SD-WAN evidence server. Every current-state result is provenance tagged.")

    @mcp.tool(description="Create one dynamic spoke through the Management lifecycle. This is the only MCP site-creation path: it allocates topology, stages ZTP, triggers Edge-local bootstrap, registers only public identity material, reconciles desired state, and records a typed operation. It cannot accept shell commands, routes, firewall marks, or WireGuard private keys.")
    def create_site(site_id: Annotated[str, Field(min_length=1, max_length=32)], device_id: Optional[str] = None, preferred_hub: Annotated[str, Field(pattern="^hub[12]$")] = "hub1", standby_hub: Annotated[str, Field(pattern="^hub[12]$")] = "hub2") -> OperationalResult:
        _require_write(principal, "site:write")
        value = service.create_site(site=site_id, device_id=device_id or site_id + "-edge", preferred_hub=preferred_hub, standby_hub=standby_hub, actor=principal.subject)
        return _tool_result(service, principal, "create_site", value, "management_lifecycle", StateKind.desired, unavailable_reason=value.get("failure_reason") if value.get("state") == "FAILED" else None)

    @mcp.tool(description="Destructively delete one dynamic spoke through the Management lifecycle. It revokes identity, retires public WireGuard registration, requests dynamic topology removal, and records the typed operation. It never accepts raw Edge, Ryu, OVS, Linux-route, or WireGuard commands.")
    def delete_site(site_id: Annotated[str, Field(min_length=1, max_length=32)]) -> OperationalResult:
        _require_write(principal, "site:write")
        value = service.delete_site(site_id, actor=principal.subject)
        return _tool_result(service, principal, "delete_site", value, "management_lifecycle", StateKind.desired, unavailable_reason=value.get("failure_reason") if value.get("state") == "FAILED" else None)

    @mcp.tool(description="Create or update one supported administrative Policy intent. Intent contents are validated by Policy and cannot carry shell, Docker, iptables, Linux-route, OpenFlow, fwmark, or WireGuard control fields.")
    def upsert_intent(intent_id: Annotated[str, Field(min_length=1, max_length=128)], intent_type: Annotated[str, Field(pattern="^(destination_policy|site_policy|routing_preference)$")], target: Annotated[str, Field(min_length=1, max_length=128)], contents: Dict[str, Any]) -> OperationalResult:
        _require_write(principal, "policy:write")
        value = service.upsert_intent(intent_id=intent_id, intent_type=intent_type, target=target, contents=contents, actor=principal.subject)
        return _tool_result(service, principal, "upsert_intent", value, "policy_intent", StateKind.desired)

    @mcp.tool(description="Destructively delete one administrative Policy intent. This changes Policy desired state only; it cannot directly modify Ryu, OVS, Linux routing, packet marks, or WireGuard runtime.")
    def delete_intent(intent_id: Annotated[str, Field(min_length=1, max_length=128)]) -> OperationalResult:
        _require_write(principal, "policy:write")
        changed = service.delete_intent(intent_id, actor=principal.subject)
        value = {"intent_id": intent_id, "deleted": changed}
        return _tool_result(service, principal, "delete_intent", value, "policy_intent", StateKind.desired, unavailable_reason="intent not found" if not changed else None)

    @mcp.resource("sdwan://graph/schema")
    def graph_schema_resource() -> str:
        return "Typed graph nodes include Site, Hub, Host, Interface, Underlay, UnderlayAttachment, WireGuardTunnel, RoutingTable, ApplicationPolicy, Fact, and Component. Edges use typed relations such as OWNED_BY, CONTROLLED_BY, HAS_INTERFACE, BELONGS_TO_UNDERLAY, HAS_ATTACHMENT, AUTHORIZED_AS, CONNECTED_TO, and SUPPORTS. State kinds are CONFIGURED, DESIRED, OBSERVED, and DERIVED."

    @mcp.resource("sdwan://architecture/planes")
    def architecture_planes_resource() -> str:
        return "Management is the northbound lifecycle and intent API. ZTP owns device identity enrollment. Policy owns desired state. The Edge owns application-aware overlay selection, WireGuard, and Linux policy routing. Ryu owns centralized L3 underlay admission, source validation, reachability, FIB, reconciliation, faults, and telemetry."

    @mcp.resource("sdwan://architecture/ownership")
    def architecture_ownership_resource() -> str:
        return "Application classification, hub and transport selection, WireGuard runtime, and Linux routing are Edge-owned. Underlay FIB and admission are Ryu-owned. Identity authorization is ZTP/Inventory-owned. Administrative intents are Policy-owned. MCP may observe broadly and express controlled Management intent, but may not program Edge or Ryu forwarding state directly."

    @mcp.resource("sdwan://architecture/return-affinity")
    def return_affinity_resource() -> str:
        return "Return-path affinity is connmark based: packet marks are saved and restored as connection marks, policy rules select Edge routing tables, and existing TCP flows remain pinned. This is separate from Ryu underlay FIB forwarding."

    @mcp.tool(description="Return a bounded, read-only inventory summary: service health, configured topology, sites, desired-state summaries, ownership, enrolled devices, and destination-policy metadata. Use for an overview; do not use it for a route decision or live tunnel detail. Runtime data may be unavailable. Every value is tagged with provenance in structuredContent.")
    def get_dashboard_summary() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "get_dashboard_summary", service.dashboard(), "database", StateKind.configured)

    @mcp.tool(description="Return configured site records from the policy database. Use to discover valid site identifiers and their configured LAN and hub assignments. Do not use for live status, tunnels, or selected routes. Database state is not live runtime observation; unavailable data is represented by metadata. Takes no input.")
    def list_sites() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "list_sites", {"sites": service.sites()}, "database", StateKind.configured)

    @mcp.tool(description="Return the compact configured record for one site: LAN prefix, preferred hub, standby hub, and configured status. Use for questions about a site's configured identity or LAN prefix. Do not use it for routes or tunnels; use get_site_routes or get_site_tunnels for those live details. Takes one configured site identifier.")
    def get_site_status(site: Annotated[str, Field(min_length=1, max_length=64, description="Configured site identifier, for example node1")]) -> OperationalResult:
        _require(principal, "network:read"); _site(service, site)
        return _tool_result(service, principal, "get_site_status", service.site_status(site), "database", StateKind.configured)

    @mcp.tool(description="Return observed WireGuard text status for one configured site through the constrained runtime adapter. Use only for current tunnel inspection. Do not use it for routing-table decisions or to expose private keys. If Docker or the namespace is unavailable, metadata reports unavailable rather than inventing tunnel state.")
    def get_site_tunnels(site: Annotated[str, Field(min_length=1, max_length=64, description="Configured site identifier")]) -> OperationalResult:
        _require(principal, "network:read"); _site(service, site)
        return _tool_result(service, principal, "get_site_tunnels", {"site": site, "tunnels": service.runtime_view(site).get("tunnels")}, "wireguard", StateKind.observed)

    @mcp.tool(description="Return bounded observed route groups and policy rules for one configured site. Use to list routing rules, tables, prefixes, next hops, and output interfaces. Do not use it to determine the route for one destination; use explain_route_decision with destination. Missing values are represented as unknown metadata and never inferred.")
    def get_site_routes(site: Annotated[str, Field(min_length=1, max_length=64, description="Configured site identifier")]) -> OperationalResult:
        _require(principal, "network:read"); _site(service, site)
        return _tool_result(service, principal, "get_site_routes", service.route_summary(site), "routing_table", StateKind.observed)

    @mcp.tool(description="Return static topology configuration: management network, configured hubs and sites, transports, and configured data-center, SaaS, and Cloud VPC values. Use for configuration questions only. Do not use it as proof of runtime reachability or live tunnel state. Takes no input.")
    def get_topology() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "get_topology", service.topology_view(), "configuration", StateKind.configured)

    @mcp.tool(description="Return configured and runtime information for one hub. Use for hub status questions. Do not use for a spoke route lookup; explain_route_decision requires a site and destination. Runtime information can be unavailable.")
    def get_hub_status(hub: Annotated[str, Field(min_length=1, max_length=64, description="Configured hub identifier, for example hub1")]) -> OperationalResult:
        _require(principal, "network:read"); _hub(service, hub)
        return _tool_result(service, principal, "get_hub_status", service.hub_view(hub), "runtime_command", StateKind.observed)

    @mcp.tool(description="Return configured Cloud VPC status, network, endpoint, and configured gateways. Use for Cloud VPC configuration status. Do not use as proof that a Cloud VPC path is currently reachable; runtime availability is returned separately. Takes no input.")
    def get_cloud_status() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "get_cloud_status", service.network_view("cloud-vpc"), "configuration", StateKind.configured)

    @mcp.tool(description="Return configured SaaS network and endpoint information. Use for configured SaaS inventory. Do not use it as a live HTTP reachability check because this tool has no active probe adapter. Takes no input.")
    def get_saas_status() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "get_saas_status", service.network_view("saas"), "configuration", StateKind.configured)

    @mcp.tool(description="Compare desired database state and observed runtime state for one configured site in Python. Use when asking whether requested state agrees with available live evidence. Do not infer missing runtime values as mismatches; comparison entries identify unavailable and non-comparable fields.")
    def compare_desired_actual(site: Annotated[str, Field(min_length=1, max_length=64, description="Configured site identifier")]) -> OperationalResult:
        _require(principal, "network:read"); _site(service, site)
        return _tool_result(service, principal, "compare_desired_actual", service.compare_desired_actual(site), "derived", StateKind.derived)

    @mcp.tool(description="Perform a verified read-only route lookup for one site and destination. Use when the question is about the rule, table, next hop, output interface, hub, or transport selected for that destination. Do not use it to list all routes. The optional source and fwmark are passed to the runtime lookup; omitted values remain unavailable. Hub and transport, when shown, are explicitly derived from the observed interface name.")
    def explain_route_decision(site: Annotated[str, Field(min_length=1, max_length=64)], destination: IPvAnyAddress, source: Optional[IPvAnyAddress] = None, fwmark: Optional[int] = Field(default=None, ge=0)) -> OperationalResult:
        _require(principal, "network:read"); _site(service, site)
        data = service.route_decision_report(site, str(destination), str(source) if source is not None else None, fwmark)
        if not data.get("available"):
            raise ValueError("RUNTIME_UNAVAILABLE: {}".format(data.get("reason", "route lookup unavailable")))
        return _tool_result(service, principal, "explain_route_decision", data, "routing_table", StateKind.observed)

    @mcp.tool(description="Return bounded read-only management and policy audit events. Use for recent recorded events, not for current route or tunnel status. Event history can be incomplete because it is intentionally bounded. Takes no input and requires audit-read authorization.")
    def get_recent_events() -> OperationalResult:
        _require(principal, "audit:read")
        return _tool_result(service, principal, "get_recent_events", {"events": service.combined_events()}, "audit_log", StateKind.observed)

    @mcp.tool(description="Return read-only system health and source availability. Use for management API, topology, policy database, or ZTP database availability. Takes no input.")
    def get_system_health() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "get_system_health", service.health(), "management", StateKind.observed)

    @mcp.tool(description="Return the configured physical topology node inventory, including node name, kind, role, image, OpenFlow status, and DPID when defined. Use for topology inventory, not live process health. Takes no input.")
    def get_topology_nodes() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "get_topology_nodes", {"nodes":service.topology_nodes()}, "configuration", StateKind.configured)

    @mcp.tool(description="Return configured physical topology links and their named interfaces, addresses, and transport when defined. Use for topology link inventory, not a live link-state probe. Takes no input.")
    def get_topology_links() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "get_topology_links", {"links":service.topology_links()}, "configuration", StateKind.configured)

    @mcp.tool(description="Return the configured endpoint inventory and documented aliases for branch hosts and edges, hubs, data center, SaaS, Cloud VPC application, and Cloud VPC gateways. Use to discover which names can be resolved by explain_endpoint_route. Takes no input.")
    def get_endpoint_inventory() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "get_endpoint_inventory", {"endpoints":service.endpoint_inventory()}, "configuration", StateKind.configured)

    @mcp.tool(description="Return one compact configured endpoint record by name or documented alias. Use for a direct endpoint IP, type, site, or management-IP question, for example node1_host, node_host1, dc, saas, cloud_app, or cloud_gw1. Do not use get_endpoint_inventory when the requested endpoint name is already known.")
    def get_endpoint(endpoint: Annotated[str, Field(min_length=1, max_length=64, description="Configured endpoint name or documented alias")]) -> OperationalResult:
        _require(principal, "network:read")
        data=service.endpoint(endpoint)
        if not data.get("available"):
            raise ValueError("UNKNOWN_ENDPOINT: {}".format(data.get("reason", "use get_endpoint_inventory")))
        return _tool_result(service, principal, "get_endpoint", data, "configuration", StateKind.configured)

    @mcp.tool(description="Resolve configured endpoint names or aliases and report a read-only host-to-destination path. For a branch host source, reports the configured host-to-LAN-gateway hop and performs an observed route lookup from its edge site. Accepts aliases such as node1_host and node_host1, plus data_center, dc, saas, cloud_app, and cloud_gw1. The optional fwmark is used only for the edge route lookup; without it, the tool does not claim a particular policy-rule selection.")
    def explain_endpoint_route(source: Annotated[str, Field(min_length=1, max_length=64, description="Configured endpoint name or documented alias, for example node1_host or node_host1")], destination: Annotated[str, Field(min_length=1, max_length=64, description="Configured endpoint name or documented alias, for example data_center or cloud_gw1")], fwmark: Optional[int] = Field(default=None, ge=0)) -> OperationalResult:
        _require(principal, "network:read")
        data=service.endpoint_route(source,destination,fwmark)
        if not data.get("available"):
            raise ValueError("UNKNOWN_ENDPOINT: {}".format(data.get("reason", "use get_endpoint_inventory")))
        return _tool_result(service, principal, "explain_endpoint_route", data, "derived", StateKind.derived)

    @mcp.tool(description="Resolve the configured host of one site and report its read-only route evidence to a named destination endpoint. Use for questions phrased like 'route from the host of node2 to the data center'. The site argument always means the branch site, never its edge endpoint; this tool deterministically uses that site's configured host. The optional fwmark is used only for the edge route lookup.")
    def explain_site_host_route(site: Annotated[str, Field(min_length=1, max_length=64, description="Configured branch site identifier, for example node2")], destination: Annotated[str, Field(min_length=1, max_length=64, description="Configured destination endpoint name or alias, for example data_center")], fwmark: Optional[int] = Field(default=None, ge=0)) -> OperationalResult:
        _require(principal, "network:read"); _site(service, site)
        data=service.site_host_route(site, destination, fwmark)
        if not data.get("available"):
            raise ValueError("UNKNOWN_ENDPOINT: {}".format(data.get("reason", "use get_endpoint_inventory")))
        return _tool_result(service, principal, "explain_site_host_route", data, "derived", StateKind.derived)

    @mcp.tool(description="Observe an existing branch-host conntrack flow and, only when that flow has a mark, perform a marked route lookup at its edge. Use to prove the selected path for currently active traffic between two configured endpoints. This tool never creates traffic and returns zero observed flows when no matching connection exists.")
    def observe_endpoint_flow(source: Annotated[str, Field(min_length=1, max_length=64, description="Configured branch-host endpoint name or alias")], destination: Annotated[str, Field(min_length=1, max_length=64, description="Configured destination endpoint name or alias")]) -> OperationalResult:
        _require(principal, "network:read")
        data=service.observe_endpoint_flow(source, destination)
        if not data.get("available"):
            raise ValueError("FLOW_OBSERVATION_UNAVAILABLE: {}".format(data.get("reason", "runtime observation unavailable")))
        return _tool_result(service, principal, "observe_endpoint_flow", data, "routing_table", StateKind.observed)

    @mcp.tool(description="Return configured transport inventory: networks, switches, bandwidth, delay, direct-internet capability, and route-table IDs. Use for MPLS, broadband, or LTE configuration questions. Takes no input.")
    def get_transport_inventory() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "get_transport_inventory", {"transports":service.transport_inventory()}, "configuration", StateKind.configured)

    @mcp.tool(description="Return observed WireGuard text status for one configured hub through the constrained runtime adapter. Use for WireGuard tunnel questions about hub1 or hub2. This is a read-only runtime inspection and never exposes private keys; unavailable runtime data is reported as unavailable.")
    def get_hub_tunnels(hub: Annotated[str, Field(min_length=1, max_length=64, description="Configured hub identifier, for example hub2")]) -> OperationalResult:
        _require(principal, "network:read"); _hub(service, hub)
        data=service.hub_tunnels(hub)
        return _tool_result(service, principal, "get_hub_tunnels", data, "wireguard", StateKind.observed)

    @mcp.tool(description="Return compact configured information for one hub: its name, management IP address, and address ID. Use for a hub IP or identity question; use get_hub_status only when runtime information is requested.")
    def get_hub_configuration(hub: Annotated[str, Field(min_length=1, max_length=64, description="Configured hub identifier")]) -> OperationalResult:
        _require(principal, "network:read"); _hub(service, hub)
        return _tool_result(service, principal, "get_hub_configuration", service.hub_configuration(hub), "configuration", StateKind.configured)

    @mcp.tool(description="List configured Cloud VPC gateways with their VPC IP address, management IP address, address ID, and configured active flag. Use to discover cloud gateway identifiers. Takes no input.")
    def list_cloud_gateways() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "list_cloud_gateways", {"gateways":service.cloud_gateways()}, "configuration", StateKind.configured)

    @mcp.tool(description="Return one configured Cloud VPC gateway's VPC IP, management IP, active and enabled flags, Cloud VPC application address, and dedicated hub transit networks. Use for questions such as the IP address of cloud_gw1. This is configuration evidence, not runtime reachability.")
    def get_cloud_gateway(gateway: Annotated[str, Field(min_length=1, max_length=64, description="Configured Cloud VPC gateway identifier, for example cloud_gw1")]) -> OperationalResult:
        _require(principal, "network:read")
        data=service.cloud_gateway(gateway)
        if not data.get("available"):
            raise ValueError("UNKNOWN_CLOUD_GATEWAY: use list_cloud_gateways")
        return _tool_result(service, principal, "get_cloud_gateway", data, "configuration", StateKind.configured)

    @mcp.tool(description="Return configured data-center network, application name and IP address, and hub addresses. Use for data-center configuration questions. Takes no input.")
    def get_data_center_configuration() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "get_data_center_configuration", service.data_center_configuration(), "configuration", StateKind.configured)

    @mcp.tool(description="Return configured SaaS network, application name and IP address, and transport gateway addresses. Use for SaaS configuration questions. This is not a live reachability probe. Takes no input.")
    def get_saas_configuration() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "get_saas_configuration", service.saas_configuration(), "configuration", StateKind.configured)

    @mcp.tool(description="Return configured route-ownership records for all spoke prefixes, including preferred and standby hubs, current owner, epochs, route versions, state, and reason. Use for ownership or failover-control-plane questions. Takes no input.")
    def get_route_ownership() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "get_route_ownership", {"ownership":service.ownership()}, "database", StateKind.desired)

    @mcp.tool(description="Return desired-state versions for one configured site, including digest, route version, delivery, applied, and verification status. Use for desired-state delivery questions, not runtime route selection.")
    def get_site_desired_state(site: Annotated[str, Field(min_length=1, max_length=64, description="Configured site identifier")]) -> OperationalResult:
        _require(principal, "network:read"); _site(service, site)
        return _tool_result(service, principal, "get_site_desired_state", {"site":site,"desired_states":service.desired(site)}, "database", StateKind.desired)

    @mcp.tool(description="Return read-only policy-version history. Use for policy version, digest, creator, and creation-time questions. Takes no input.")
    def list_policy_versions() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "list_policy_versions", {"policy_versions":service.policy_versions()}, "database", StateKind.desired)

    @mcp.tool(description="Return the currently activated destination-policy version and its metadata. Use for the active destination policy, not for a specific packet's route selection. Takes no input.")
    def get_destination_policy() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "get_destination_policy", {"destination_policy":service.destination_policy()}, "database", StateKind.desired)

    @mcp.tool(description="Return enrolled ZTP device records with assigned site, enrollment status, public-key fingerprint, and timestamps. Use for enrollment inventory; it never returns private key material. Takes no input.")
    def list_ztp_devices() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "list_ztp_devices", {"devices":service.ztp_devices()}, "database", StateKind.configured)

    @mcp.tool(description="Return observed network-interface records for one configured site through the constrained runtime adapter. Use for live interface presence and attributes, not routes or tunnels.")
    def get_site_interfaces(site: Annotated[str, Field(min_length=1, max_length=64, description="Configured site identifier")]) -> OperationalResult:
        _require(principal, "network:read"); _site(service, site)
        return _tool_result(service, principal, "get_site_interfaces", service.site_interfaces(site), "linux_namespace", StateKind.observed)

    @mcp.tool(description="Return observed failover runtime status for one configured site. Use for current failover state and slot health; it does not change failover state.")
    def get_site_failover_status(site: Annotated[str, Field(min_length=1, max_length=64, description="Configured site identifier")]) -> OperationalResult:
        _require(principal, "network:read"); _site(service, site)
        return _tool_result(service, principal, "get_site_failover_status", service.site_failover(site), "runtime_command", StateKind.observed)

    @mcp.tool(description="Return the latest observed classifier event summary for one configured site. Use for classifier counters and latest event metadata; packet content is not exposed.")
    def get_site_classifier_status(site: Annotated[str, Field(min_length=1, max_length=64, description="Configured site identifier")]) -> OperationalResult:
        _require(principal, "network:read"); _site(service, site)
        return _tool_result(service, principal, "get_site_classifier_status", service.site_classifier(site), "runtime_command", StateKind.observed)

    @mcp.tool(description="Return one typed SD-WAN dependency-graph component. Component IDs are stable identifiers such as site:node1, underlay:bb, hub:hub1, interface:node1:bb, destination:data-center, and component:ryu. This is configured/derived graph data with provenance, not a data-plane control interface.")
    def graph_get_component(component_id: Annotated[str, Field(min_length=1, max_length=160)]) -> OperationalResult:
        _require(principal, "network:read")
        value = service.graph_component(component_id)
        if not value.get("available"):
            raise ValueError("UNKNOWN_COMPONENT: " + str(value.get("reason", component_id)))
        return _tool_result(service, principal, "graph_get_component", value, "dependency_graph", StateKind.derived)

    @mcp.tool(description="Expand typed dependency relationships from a component. Direction is outgoing, incoming, or both; depth is bounded to 1..8. Use this generic graph tool for investigation planning rather than scenario-specific troubleshooting tools.")
    def graph_expand_dependencies(component_id: Annotated[str, Field(min_length=1, max_length=160)], direction: Annotated[str, Field(pattern="^(outgoing|incoming|both)$")] = "outgoing", depth: Annotated[int, Field(ge=1, le=8)] = 1) -> OperationalResult:
        _require(principal, "network:read")
        value = service.graph_expand(component_id, direction, depth)
        if not value.get("available"):
            raise ValueError("UNKNOWN_COMPONENT: " + str(value.get("reason", component_id)))
        return _tool_result(service, principal, "graph_expand_dependencies", value, "dependency_graph", StateKind.derived)

    @mcp.tool(description="Find a deterministic directed dependency path between two graph component IDs. A missing path means no configured dependency chain is currently represented; it does not prove traffic failure or an observed packet trace.")
    def graph_find_path(source_id: Annotated[str, Field(min_length=1, max_length=160)], target_id: Annotated[str, Field(min_length=1, max_length=160)]) -> OperationalResult:
        _require(principal, "network:read")
        value = service.graph_path(source_id, target_id)
        if not value.get("available"):
            raise ValueError("UNKNOWN_COMPONENT: " + str(value.get("reason", "source or target")))
        return _tool_result(service, principal, "graph_find_path", value, "dependency_graph", StateKind.derived)

    @mcp.tool(description="Construct configured expected traffic-path candidates for a branch host and destination endpoint alias. The result deliberately distinguishes configured candidates from an observed packet trace and never claims a selected hub or transport without evidence.")
    def graph_get_expected_traffic_path(source: Annotated[str, Field(min_length=1, max_length=64)], destination: Annotated[str, Field(min_length=1, max_length=64)]) -> OperationalResult:
        _require(principal, "network:read")
        value = service.graph_expected_traffic_path(source, destination)
        if not value.get("available"):
            raise ValueError("EXPECTED_PATH_UNAVAILABLE: " + str(value.get("reason", "unknown")))
        return _tool_result(service, principal, "graph_get_expected_traffic_path", value, "dependency_graph", StateKind.derived)

    @mcp.tool(description="Calculate the typed incoming dependency impact scope of a component. The result is configured/derived blast-radius information, not proof that all listed components are currently down.")
    def graph_calculate_impact_scope(component_id: Annotated[str, Field(min_length=1, max_length=160)]) -> OperationalResult:
        _require(principal, "network:read")
        value = service.graph_impact(component_id)
        if not value.get("available"):
            raise ValueError("UNKNOWN_COMPONENT: " + str(value.get("reason", component_id)))
        return _tool_result(service, principal, "graph_calculate_impact_scope", value, "dependency_graph", StateKind.derived)

    @mcp.tool(description="Return timestamped provenance-tagged operational facts attached to graph components. Empty facts mean no published observation matches; they must not be interpreted as a healthy state.")
    def evidence_get_for_components(component_ids: List[Annotated[str, Field(min_length=1, max_length=160)]]) -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "evidence_get_for_components", service.graph_evidence(component_ids), "evidence_graph", StateKind.observed)

    return mcp

def main() -> int:
    config = ManagementConfig.from_env()
    session_id = os.environ.get("SDWAN_CHAT_SESSION_ID", "")
    token = os.environ.get("SDWAN_AGENT_CONTEXT_TOKEN", "")
    try:
        principal = verify_agent_context(config.signing_secret, token, session_id, os.environ.get("SDWAN_AGENT_CONTEXT_AUDIENCE", config.agent_context_audience), config.agent_context_ttl_seconds)
    except ValueError:
        return 2
    build_server(config, principal).run(transport="stdio")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
