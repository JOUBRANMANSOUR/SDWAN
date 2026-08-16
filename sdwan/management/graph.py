"""Typed SD-WAN dependency and evidence graph.

The graph is an ephemeral, provenance-carrying view built from the actual
Management service sources.  It is deliberately not a network controller and
not a second database of topology state.
"""
from __future__ import annotations
from collections import deque
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class StateKind(str, Enum):
    CONFIGURED = "CONFIGURED"
    DESIRED = "DESIRED"
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"


class NodeType(str, Enum):
    SITE = "SITE"
    WAN_EDGE = "WAN_EDGE"
    HUB = "HUB"
    HOST = "HOST"
    INTERFACE = "INTERFACE"
    UNDERLAY = "UNDERLAY"
    OVS_DATAPATH = "OVS_DATAPATH"
    RYU_CONTROLLER = "RYU_CONTROLLER"
    UNDERLAY_ATTACHMENT = "UNDERLAY_ATTACHMENT"
    WIREGUARD_TUNNEL = "WIREGUARD_TUNNEL"
    ROUTING_TABLE = "ROUTING_TABLE"
    APPLICATION_POLICY = "APPLICATION_POLICY"
    SLA_PROFILE = "SLA_PROFILE"
    DATA_CENTER = "DATA_CENTER"
    SAAS_DESTINATION = "SAAS_DESTINATION"
    CLOUD_APPLICATION = "CLOUD_APPLICATION"
    FACT = "FACT"
    COMPONENT = "COMPONENT"


class RelationType(str, Enum):
    HOSTS = "HOSTS"
    REPRESENTED_BY = "REPRESENTED_BY"
    CONNECTED_TO = "CONNECTED_TO"
    HAS_INTERFACE = "HAS_INTERFACE"
    BELONGS_TO_UNDERLAY = "BELONGS_TO_UNDERLAY"
    CONTROLLED_BY = "CONTROLLED_BY"
    HAS_ATTACHMENT = "HAS_ATTACHMENT"
    AUTHORIZED_AS = "AUTHORIZED_AS"
    USES_TUNNEL = "USES_TUNNEL"
    TUNNELED_TO = "TUNNELED_TO"
    SELECTS_TABLE = "SELECTS_TABLE"
    GOVERNED_BY = "GOVERNED_BY"
    HAS_SLA = "HAS_SLA"
    ATTACHED_TO = "ATTACHED_TO"
    OWNED_BY = "OWNED_BY"
    OBSERVES = "OBSERVES"
    SUPPORTS = "SUPPORTS"
    AFFECTS = "AFFECTS"


class GraphNode(BaseModel):
    model_config = ConfigDict(extra="forbid")
    node_id: str
    node_type: NodeType
    attributes: Dict[str, Any] = Field(default_factory=dict)
    source_ids: List[str] = Field(default_factory=list)


class GraphEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")
    edge_id: str
    source_id: str
    target_id: str
    relation_type: RelationType
    state_kind: StateKind
    source_ids: List[str] = Field(default_factory=list)


class EvidenceFact(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fact_id: str
    component_id: str
    fact_type: str
    value: Any
    source: str
    observed_at: Optional[str] = None
    state_kind: StateKind
    availability: str = "AVAILABLE"


class DependencyGraph:
    def __init__(self) -> None:
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[str, GraphEdge] = {}
        self.facts: Dict[str, EvidenceFact] = {}

    def add_node(self, node: GraphNode) -> GraphNode:
        self.nodes[node.node_id] = node
        return node

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        if edge.source_id not in self.nodes or edge.target_id not in self.nodes:
            raise ValueError("graph edge references an unknown node")
        self.edges[edge.edge_id] = edge
        return edge

    def add_fact(self, fact: EvidenceFact) -> EvidenceFact:
        self.facts[fact.fact_id] = fact
        return fact

    def component(self, node_id: str) -> Optional[GraphNode]:
        return self.nodes.get(node_id)

    def expand(self, node_id: str, *, direction: str = "outgoing", depth: int = 1) -> Dict[str, Any]:
        if node_id not in self.nodes:
            return {"available": False, "reason": "unknown component", "nodes": [], "edges": []}
        depth = max(0, min(depth, 8))
        visited = {node_id}
        frontier = {node_id}
        selected: List[GraphEdge] = []
        for _ in range(depth):
            next_frontier = set()
            for edge in self.edges.values():
                if direction in ("outgoing", "both") and edge.source_id in frontier:
                    selected.append(edge); next_frontier.add(edge.target_id)
                if direction in ("incoming", "both") and edge.target_id in frontier:
                    selected.append(edge); next_frontier.add(edge.source_id)
            next_frontier -= visited
            visited |= next_frontier
            frontier = next_frontier
            if not frontier:
                break
        return {"available": True, "nodes": [self.nodes[key].model_dump(mode="json") for key in sorted(visited)], "edges": [edge.model_dump(mode="json") for edge in selected]}

    def find_path(self, source_id: str, target_id: str) -> Dict[str, Any]:
        if source_id not in self.nodes or target_id not in self.nodes:
            return {"available": False, "reason": "unknown source or target", "path": []}
        queue = deque([(source_id, [])])
        seen = {source_id}
        while queue:
            current, path = queue.popleft()
            if current == target_id:
                return {"available": True, "path": [edge.model_dump(mode="json") for edge in path]}
            for edge in self.edges.values():
                if edge.source_id == current and edge.target_id not in seen:
                    seen.add(edge.target_id); queue.append((edge.target_id, path + [edge]))
        return {"available": True, "path": [], "reason": "no directed dependency path"}

    def impact_scope(self, node_id: str) -> Dict[str, Any]:
        expanded = self.expand(node_id, direction="incoming", depth=8)
        expanded["affected_component_ids"] = [item["node_id"] for item in expanded.get("nodes", []) if item["node_id"] != node_id]
        return expanded


class DependencyGraphBuilder:
    """Build graph only from ManagementService authoritative views."""
    def __init__(self, service: Any):
        self.service = service
        self.graph = DependencyGraph()

    def node(self, node_id: str, node_type: NodeType, attributes: Optional[Dict[str, Any]] = None, source: str = "management") -> None:
        self.graph.add_node(GraphNode(node_id=node_id, node_type=node_type, attributes=attributes or {}, source_ids=[source]))

    def edge(self, source_id: str, target_id: str, relation: RelationType, state: StateKind, source: str) -> None:
        edge_id = "%s:%s:%s" % (source_id, relation.value, target_id)
        if edge_id not in self.graph.edges:
            self.graph.add_edge(GraphEdge(edge_id=edge_id, source_id=source_id, target_id=target_id, relation_type=relation, state_kind=state, source_ids=[source]))

    def build(self) -> DependencyGraph:
        topology = self.service.topology_view()
        self.node("component:edge", NodeType.COMPONENT, {"owner": "SD-WAN Edge"})
        self.node("component:ryu", NodeType.RYU_CONTROLLER, {"owner": "Ryu centralized L3 underlay control"})
        self.node("component:policy", NodeType.COMPONENT, {"owner": "Policy Service"})
        self.node("component:ztp", NodeType.COMPONENT, {"owner": "ZTP Service"})
        for hub in topology["hubs"]:
            hid = "hub:" + hub["name"]; self.node(hid, NodeType.HUB, hub, "topology")
            self.edge(hid, "component:edge", RelationType.OWNED_BY, StateKind.CONFIGURED, "architecture")
        for transport in topology["transports"]:
            tid = "underlay:" + transport["name"]; self.node(tid, NodeType.UNDERLAY, transport, "topology")
            self.edge(tid, "component:ryu", RelationType.CONTROLLED_BY, StateKind.CONFIGURED, "architecture")
        for site in topology["sites"]:
            sid = "site:" + site["name"]; self.node(sid, NodeType.SITE, site, "topology")
            self.edge(sid, "component:edge", RelationType.OWNED_BY, StateKind.CONFIGURED, "architecture")
            edge_id = "edge:" + site["edge_node"]; self.node(edge_id, NodeType.WAN_EDGE, {"edge_node": site["edge_node"], "site": site["name"]}, "topology")
            self.edge(sid, edge_id, RelationType.REPRESENTED_BY, StateKind.CONFIGURED, "topology")
            self.edge(edge_id, sid, RelationType.REPRESENTED_BY, StateKind.CONFIGURED, "topology")
            self.edge(edge_id, "component:edge", RelationType.OWNED_BY, StateKind.CONFIGURED, "architecture")
            host_id = "host:" + site["host_name"]; self.node(host_id, NodeType.HOST, {"site": site["name"], "edge_node": site["edge_node"], "lan": site["lan"]}, "topology")
            self.edge(edge_id, host_id, RelationType.HOSTS, StateKind.CONFIGURED, "topology")
            self.edge(host_id, edge_id, RelationType.ATTACHED_TO, StateKind.CONFIGURED, "topology")
            for hub in (site.get("preferred_hub"), site.get("standby_hub")):
                if hub:
                    self.edge(sid, "hub:" + hub, RelationType.CONNECTED_TO, StateKind.DESIRED, "site inventory")
                    self.edge("hub:" + hub, sid, RelationType.TUNNELED_TO, StateKind.DESIRED, "site inventory")
            for transport in topology["transports"]:
                interface = "interface:%s:%s" % (site["edge_node"], transport["name"])
                self.node(interface, NodeType.INTERFACE, {"site": site["name"], "edge_node": site["edge_node"], "transport": transport["name"]}, "topology")
                self.edge(edge_id, interface, RelationType.HAS_INTERFACE, StateKind.CONFIGURED, "topology")
                self.edge(interface, "underlay:" + transport["name"], RelationType.BELONGS_TO_UNDERLAY, StateKind.CONFIGURED, "topology")
        self.node("destination:data-center", NodeType.DATA_CENTER, topology["data_center"], "topology")
        self.node("destination:public-saas", NodeType.SAAS_DESTINATION, topology["saas"], "topology")
        for hub in topology["hubs"]:
            self.edge("hub:" + hub["name"], "destination:data-center", RelationType.CONNECTED_TO, StateKind.CONFIGURED, "topology")
        for site in topology["sites"]:
            for transport in ("bb", "lte"):
                interface = "interface:%s:%s" % (site["edge_node"], transport)
                if interface in self.graph.nodes:
                    self.edge(interface, "destination:public-saas", RelationType.CONNECTED_TO, StateKind.CONFIGURED, "saas direct-internet policy")
        if topology.get("cloud_vpc", {}).get("enabled"):
            self.node("destination:cloud", NodeType.CLOUD_APPLICATION, topology["cloud_vpc"], "topology")
        for intent in self.service.administrative_intents():
            iid = "intent:" + intent["intent_id"]; self.node(iid, NodeType.APPLICATION_POLICY, intent, "policy-db")
            self.edge(iid, "component:policy", RelationType.OWNED_BY, StateKind.DESIRED, "policy-db")
        observed = self.service.underlay_state()
        if observed.get("availability") == "AVAILABLE":
            state = observed.get("state", {})
            for transport, attachments in state.get("attachments", {}).items():
                for item in attachments:
                    identity = str(item.get("site") or item.get("node") or item.get("address") or "attachment")
                    aid = "attachment:%s:%s" % (transport, identity)
                    self.node(aid, NodeType.UNDERLAY_ATTACHMENT, item, "ryu-underlay-state")
                    if "underlay:" + transport in self.graph.nodes:
                        self.edge("underlay:" + transport, aid, RelationType.HAS_ATTACHMENT, StateKind.OBSERVED, "ryu-underlay-state")
                    site = item.get("site") or item.get("node")
                    if site and "site:" + str(site) in self.graph.nodes:
                        self.edge(aid, "site:" + str(site), RelationType.AUTHORIZED_AS, StateKind.OBSERVED, "ryu-underlay-state")
            for event_no, event in enumerate(state.get("events", [])[-100:]):
                component = "underlay:" + str(event.get("transport", "unknown"))
                if component not in self.graph.nodes:
                    continue
                fact_id = "underlay-event:%s" % event_no
                self.graph.add_fact(EvidenceFact(fact_id=fact_id, component_id=component, fact_type=str(event.get("type", "underlay_event")), value=event, source="ryu-underlay-state", observed_at=event.get("timestamp"), state_kind=StateKind.OBSERVED))
        return self.graph
