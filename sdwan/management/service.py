"""Shared read-only query layer used by REST, MCP, and the Agent Gateway."""
from __future__ import annotations
from dataclasses import asdict
import json
import os
from pathlib import Path
from ipaddress import ip_address
from typing import Any
from ..lab_runtime import TopologyControlClient
from ..persistence.ztp_store import ZTPStore
from ..policy_service_v5 import PolicyService
from ..common.model import load_config
from ..topology_v5 import build_live_plan
from .config import ManagementConfig
from .repository import ReadOnlyState, AuditStore
from .runtime import RuntimeAdapter

from .lifecycle import LocalZTPProvisioner, SiteLifecycleCoordinator
class ManagementService:
    def __init__(self, config: ManagementConfig):
        self.config, self.topology = config, load_config(config.topology)
        self.policy = PolicyService(self.topology, config.policy_db)
        self.topology = self.policy.config
        self.state, self.audit = ReadOnlyState(config.policy_db, config.ztp_db), AuditStore(config.state_dir)
        self.runtime = RuntimeAdapter(self.topology)
        self.lifecycle = SiteLifecycleCoordinator(
            self.policy, LocalZTPProvisioner(ZTPStore(config.ztp_db)),
            TopologyControlClient(config.topology_control_socket),
            bootstrap_ca=config.state_dir.parent / "trust" / "ca-cert.pem",
            ztp_url=config.ztp_url, policy_url=config.policy_url,
            management_host=config.management_connect_host,
        )

    def _refresh_topology(self) -> None:
        self.topology = self.policy.config
        self.runtime = RuntimeAdapter(self.topology)

    def _logical_site(self, value: str) -> str:
        """Accept a legacy edge-node alias, but keep all control-plane state logical."""
        if value in self.topology.hubs:
            return value
        return self.topology.logical_site(value)

    def create_site(self, *, site: str, device_id: str, preferred_hub: str, standby_hub: str, actor: str) -> dict[str, Any]:
        result = self.lifecycle.create(site=site, device_id=device_id, preferred_hub=preferred_hub, standby_hub=standby_hub, actor=actor)
        self._refresh_topology()
        self.audit.add(actor, "CREATE_SITE", site, result.get("state", "UNKNOWN"))
        return result

    def delete_site(self, site: str, *, actor: str) -> dict[str, Any]:
        result = self.lifecycle.delete(site, actor=actor)
        self._refresh_topology()
        self.audit.add(actor, "DELETE_SITE", site, result.get("state", "UNKNOWN"))
        return result

    def operation(self, operation_id: str) -> dict[str, Any] | None:
        return self.policy.inventory.operation(operation_id)

    def inventory(self) -> list[dict[str, Any]]:
        return [asdict(item) for item in self.policy.inventory.list(include_deleted=True)]

    def administrative_intents(self) -> list[dict[str, Any]]:
        return self.policy.inventory.intents()

    def delete_intent(self, intent_id: str, *, actor: str) -> bool:
        changed = self.policy.inventory.delete_intent(intent_id, actor=actor)
        if changed:
            self.policy.compile_control_state(actor=actor)
            self._refresh_topology()
            self.audit.add(actor, "DELETE_INTENT", intent_id, "ok")
        return changed

    def network_state_inputs(self) -> list[dict[str, Any]]:
        return self.policy.inventory.network_state()

    def upsert_intent(self, *, intent_id: str, intent_type: str, target: str, contents: dict[str, Any], actor: str) -> dict[str, Any]:
        changed = self.policy.inventory.upsert_intent(intent_id, intent_type, target, contents, actor=actor)
        compilation = self.policy.compile_control_state(actor=actor)
        self._refresh_topology()
        self.audit.add(actor, "UPSERT_INTENT", intent_id, "changed" if changed else "idempotent")
        return {"changed": changed, "compilation": compilation}

    def put_network_state(self, *, input_key: str, value: dict[str, Any], source: str, actor: str) -> dict[str, Any]:
        changed = self.policy.inventory.put_network_state(input_key, value, source=source)
        compilation = self.policy.compile_control_state(actor=actor) if changed else {"changed": False, "changed_sites": []}
        self._refresh_topology()
        self.audit.add(actor, "NETWORK_STATE", input_key, "changed" if changed else "idempotent")
        return {"changed": changed, "compilation": compilation}

    def compile_control_state(self, *, actor: str = "management-request") -> dict[str, Any]:
        result = self.policy.compile_control_state(actor=actor)
        self._refresh_topology()
        return result

    def health(self) -> dict[str, Any]:
        return {"status":"ok", "mode":"typed-administration-and-observability", "sources":{"topology":"AVAILABLE", "policy_db":"AVAILABLE" if self.config.policy_db.is_file() else "UNAVAILABLE", "ztp_db":"AVAILABLE" if self.config.ztp_db.is_file() else "UNAVAILABLE", "runtime_control":"AVAILABLE" if self.config.topology_control_socket.exists() else "NOT_CONNECTED"}}
    def topology_view(self) -> dict[str, Any]:
        c=self.topology
        return {"management_network":str(c.management_network), "hubs":[{"name":h.name,"management_ip":str(h.management_ip)} for h in c.hubs.values()], "sites":[{"name":s.name,"edge_node":s.edge_node,"host_name":s.host_name,"lan":str(s.lan_network),"preferred_hub":s.preferred_hub,"standby_hub":s.standby_hub} for s in c.sites.values()], "transports":[{"name":t.name,"network":str(t.network),"internet_capable":t.internet_capable,"table":t.route_table} for t in c.transports.values()], "data_center":{"network":str(c.data_center_network),"app_ip":str(c.data_center_app_ip)}, "saas":{"network":str(c.saas_network),"app_ip":str(c.saas_ip)}, "cloud_vpc":{"enabled":c.cloud_vpc.enabled,"network":str(c.cloud_vpc.network)}}
    def sites(self) -> list[dict[str, Any]]:
        """Inventory uses logical site IDs and exposes the physical edge mapping."""
        rows = self.state.rows("policy", "SELECT site,device_id,lan_prefix,preferred_hub,standby_hub,status,updated_at FROM sites ORDER BY site")
        for row in rows:
            profile = self.topology.sites.get(str(row.get("site")))
            if profile is not None:
                row["edge_node"] = profile.edge_node
        return rows

    def ownership(self) -> list[dict[str, Any]]:
        return self.state.rows("policy", "SELECT prefix,spoke,preferred_hub,standby_hub,current_owner_hub,previous_owner_hub,owner_epoch,route_version,state,reason,updated_at,pending_reconciliation FROM route_ownership ORDER BY spoke")
    def desired(self, site: str) -> list[dict[str, Any]]:
        return self.state.rows("policy", "SELECT site,version,digest,route_version,ownership_epoch,created_at,delivery_status,applied_status,verification_status FROM desired_states WHERE site=? ORDER BY version DESC", (site,))
    def tunnel_status(self, site: str) -> dict[str, Any]:
        return self.runtime.tunnel_status(site)
    def policy_versions(self) -> list[dict[str, Any]]:
        return self.state.rows("policy", "SELECT version,digest,created_at,created_by FROM policy_versions ORDER BY version DESC")
    def destination_policy(self) -> list[dict[str, Any]]:
        return self.state.rows("policy", "SELECT v.version,v.digest,v.created_at,v.created_by,a.activated_at,a.activated_by FROM destination_policy_activation a JOIN destination_policy_versions v ON v.version=a.version")
    def desired_summary(self) -> list[dict[str, Any]]:
        return self.state.rows("policy", "SELECT site,MAX(version) AS latest_version,MAX(route_version) AS latest_route_version,MAX(created_at) AS last_created FROM desired_states GROUP BY site ORDER BY site")
    def ztp_devices(self) -> list[dict[str, Any]]:
        return self.state.rows("ztp", "SELECT device_id,assigned_site,status,public_key_fingerprint,created_at,updated_at FROM devices ORDER BY assigned_site")
    def events(self) -> list[dict[str, Any]]:
        return self.state.rows("policy", "SELECT actor,action,target,reason,result,before_version,after_version,created_at FROM policy_audit_events ORDER BY id DESC LIMIT 200")
    def _site_for_address(self, value: str) -> str | None:
        try:
            address = ip_address(value)
        except ValueError:
            return None
        for site, profile in self.topology.sites.items():
            if address in profile.lan_network:
                return site
        if address in self.topology.data_center_network:
            return self.topology.data_center_app_name
        return None

    def hub_flows(self, hub: str | None = None, site: str | None = None) -> list[dict[str, Any]]:
        if hub is not None and hub not in self.topology.hubs:
            return []
        for hub_id in ((hub,) if hub else tuple(self.topology.hubs)):
            observed = self.runtime.hub_flow_events(hub_id)
            if observed.get("availability") != "AVAILABLE":
                continue
            for event in observed.get("value", []):
                source, destination = self._site_for_address(str(event.get("source_ip", ""))), self._site_for_address(str(event.get("destination_ip", "")))
                if source is None or destination is None:
                    continue
                candidate = dict(event)
                if candidate.get("hub_id") == hub_id:
                    self.audit.ingest_hub_flow(candidate)
        result = []
        for event in self.audit.hub_flows(hub):
            candidate = dict(event)
            candidate["source_site"] = self._site_for_address(str(candidate["source_ip"]))
            candidate["destination_site"] = self._site_for_address(str(candidate["destination_ip"]))
            if site is not None and site not in {candidate["source_site"], candidate["destination_site"]}:
                continue
            result.append(candidate)
        return result


    def site_status(self, site: str) -> dict[str, Any]:
        site = self._logical_site(site)
        """Return compact configured status evidence; runtime detail has dedicated tools."""
        record=next((row for row in self.sites() if row.get("site") == site), None)
        if record is None:
            configured=self.topology.sites[site]
            record={"site":site,"lan_prefix":str(configured.lan_network),"preferred_hub":configured.preferred_hub,"standby_hub":configured.standby_hub,"status":"CONFIGURED"}
        result = {key:record.get(key) for key in ("site","lan_prefix","preferred_hub","standby_hub","status","updated_at") if record.get(key) is not None}
        result["edge_node"] = self.topology.edge_node(site)
        return result

    def runtime_view(self, site: str) -> dict[str, Any]:
        site = self._logical_site(site)
        if site not in self.topology.site_names: return {"availability":"UNAVAILABLE", "reason":"unknown site"}
        return {"site":site,"edge_node":self.topology.edge_node(site) if site in self.topology.sites else site,"links":self.runtime.links(site),"tunnels":self.runtime.tunnels(site),"routes":self.runtime.routes(site),"rules":self.runtime.rules(site),"failover":self.runtime.failover(site),"classifier":self.runtime.classifier(site),"path_metrics":self.runtime.state(site,"path-metrics.json"),"path_decisions":self.runtime.state(site,"path-decisions.json")}
    def _path_state(self, filename: str, field: str) -> list[dict[str, Any]]:
        result=[]
        for site in self.topology.sites:
            state=self.runtime.state(site,filename)
            if state.get("availability") == "AVAILABLE":
                result.extend(state.get("value",{}).get(field,[]))
        return result
    def path_metrics(self) -> list[dict[str, Any]]:
        return self._path_state("path-metrics.json","paths")
    def path_decisions(self) -> list[dict[str, Any]]:
        return self._path_state("path-decisions.json","decisions")
    def path_events(self) -> list[dict[str, Any]]:
        return self._path_state("path-events.json","events")
    def paths(self) -> dict[str, Any]:
        return {"paths":self.path_metrics(),"decisions":self.path_decisions(),"measurement":{"interval_seconds":self.topology.measurement.interval_seconds,"ewma_alpha":self.topology.measurement.ewma_alpha,"stale_after_seconds":self.topology.measurement.stale_after_seconds,"loss_window_samples":self.topology.measurement.loss_window_samples}}
    def underlays(self) -> dict[str, Any]:
        state = self.underlay_state()
        observed = state.get("state", {}) if state.get("availability") == "AVAILABLE" else {}
        return {"availability": state.get("availability"), "items": [self.underlay(name, observed=observed) for name in self.topology.transports], "reason": state.get("reason")}

    def underlay(self, transport: str, *, observed: dict[str, Any] | None = None) -> dict[str, Any] | None:
        profile = self.topology.transports.get(transport)
        if profile is None:
            return None
        if observed is None:
            snapshot = self.underlay_state()
            observed = snapshot.get("state", {}) if snapshot.get("availability") == "AVAILABLE" else {}
        datapath = dict(observed.get("datapaths", {}).get(transport, {}))
        return {"transport": transport, "service_type": "INTERNET" if profile.internet_capable else "PRIVATE", "internet_capable": profile.internet_capable, "network": str(profile.network), "switch": profile.switch, "dpid": profile.dpid, "state": "CONNECTED" if datapath.get("connected") else "UNAVAILABLE", "attachments": observed.get("attachments", {}).get(transport, []), "fib_entry_count": observed.get("forwarding", {}).get(transport), "security_counters": observed.get("security_counters", {}), "events": [event for event in observed.get("events", []) if event.get("transport") == transport][-20:]}

    def underlay_state(self) -> dict[str, Any]:
        """Expose the controller's atomic telemetry snapshot without controlling it."""
        default = self.config.state_dir.parent / "underlay-state.json"
        path = Path(os.environ.get("SDWAN_UNDERLAY_STATE_PATH", str(default)))
        try:
            return {"availability": "AVAILABLE", "state": json.loads(path.read_text(encoding="utf-8"))}
        except FileNotFoundError:
            return {"availability": "UNAVAILABLE", "reason": "underlay controller state has not been published"}
        except (OSError, ValueError):
            return {"availability": "UNAVAILABLE", "reason": "underlay controller state is unreadable"}

    def dependency_graph(self):
        """Build an ephemeral typed graph from current authoritative sources."""
        from .graph import DependencyGraphBuilder
        return DependencyGraphBuilder(self).build()

    def graph_component(self, component_id: str) -> dict[str, Any]:
        node = self.dependency_graph().component(component_id)
        return {"available": node is not None, "component": node.model_dump(mode="json") if node else None, "reason": None if node else "unknown component"}

    def graph_expand(self, component_id: str, direction: str = "outgoing", depth: int = 1) -> dict[str, Any]:
        return self.dependency_graph().expand(component_id, direction=direction, depth=depth)

    def graph_path(self, source_id: str, target_id: str) -> dict[str, Any]:
        return self.dependency_graph().find_path(source_id, target_id)

    def graph_impact(self, component_id: str) -> dict[str, Any]:
        return self.dependency_graph().impact_scope(component_id)

    def graph_expected_traffic_path(self, source: str, destination: str) -> dict[str, Any]:
        """Configured dependency candidates, explicitly distinct from observed flow tracing."""
        source_endpoint, destination_endpoint = self.resolve_endpoint(source), self.resolve_endpoint(destination)
        if source_endpoint is None or destination_endpoint is None:
            return {"available": False, "reason": "unresolved source or destination endpoint"}
        if source_endpoint.get("kind") != "branch_host":
            return {"available": False, "reason": "expected path currently starts at a branch host"}
        site = str(source_endpoint["site"])
        base = ["host:" + source_endpoint["name"], "site:" + site]
        if destination_endpoint.get("kind") == "data_center_application":
            profile = self.topology.sites[site]
            candidates = [base + ["hub:" + profile.preferred_hub, "destination:data-center"], base + ["hub:" + profile.standby_hub, "destination:data-center"]]
            return {"available": True, "path_kind": "EXPECTED_CONFIGURED_CANDIDATES", "source": source_endpoint, "destination": destination_endpoint, "candidates": candidates, "limitations": ["No hub or transport is claimed selected without flow or route evidence."]}
        if destination_endpoint.get("kind") == "branch_host":
            destination_site = str(destination_endpoint["site"])
            source_profile = self.topology.sites[site]
            destination_profile = self.topology.sites[destination_site]
            destination_hubs = {destination_profile.preferred_hub, destination_profile.standby_hub}
            hubs = [hub for hub in (source_profile.preferred_hub, source_profile.standby_hub) if hub in destination_hubs]
            candidates = [base + ["hub:" + hub, "site:" + destination_site, "host:" + destination_endpoint["name"]] for hub in hubs]
            return {"available": True, "path_kind": "EXPECTED_CONFIGURED_CANDIDATES", "source": source_endpoint, "destination": destination_endpoint, "candidates": candidates, "limitations": ["These are configured branch-overlay candidates. No hub, transport, or observed flow is claimed selected without runtime evidence."]}
        if destination_endpoint.get("kind") == "saas_application":
            candidates = [base + ["interface:%s:%s" % (self.topology.edge_node(site), transport), "destination:public-saas"] for transport in ("bb", "lte")]
            return {"available": True, "path_kind": "EXPECTED_CONFIGURED_CANDIDATES", "source": source_endpoint, "destination": destination_endpoint, "candidates": candidates, "limitations": ["Public SaaS candidates are direct-internet only; this is configured policy, not an observed packet trace."]}
        return {"available": False, "reason": "no deterministic expected-path template for destination kind"}

    def graph_evidence(self, component_ids: list[str]) -> dict[str, Any]:
        graph = self.dependency_graph()
        wanted = set(component_ids)
        return {"available": True, "facts": [item.model_dump(mode="json") for item in graph.facts.values() if not wanted or item.component_id in wanted]}

    def workloads(self) -> list[dict[str, Any]]:
        return [
            {"id":"branch_rtp","application_class":"REALTIME_RTP","source":"node1_host","destination":"node2_host","protocol":"real RTP/UDP","port":5004,"egress":"HUB_OVERLAY"},
            {"id":"central_backup","application_class":"CENTRAL_BACKUP","source":"branch hosts","destination":self.topology.data_center_app_name,"address":f"https://{self.topology.data_center_app_ip}:8443","egress":"HUB_OVERLAY","health":self.runtime.workload_health(self.topology.data_center_app_name)},
            {"id":"public_saas","application_classes":["SAAS_INTERACTIVE","SAAS_FILE_TRANSFER"],"source":"branch hosts","destination":self.topology.saas_app_name,"address":f"https://{self.topology.saas_ip}","egress":"DIRECT_INTERNET","candidate_transports":["bb","lte"],"health":self.runtime.workload_health(self.topology.saas_app_name)},
        ]
    def topology_resource(self) -> dict[str, Any]:
        return {"configuration": self.topology_view(), "nodes": self.topology_nodes(), "links": self.topology_links()}

    def policy_view(self) -> dict[str, Any]:
        return {"active_versions": self.policy_versions(), "destination_policy": self.destination_policy(), "intents": self.administrative_intents(), "route_ownership": self.ownership()}

    def ztp_device(self, device_id: str) -> dict[str, Any] | None:
        return next((item for item in self.ztp_devices() if item.get("device_id") == device_id), None)

    def dashboard(self) -> dict[str, Any]:
        return {"health":self.health(),"topology":self.topology_view(),"sites":self.sites(),"desired":self.desired_summary(),"ownership":self.ownership(),"devices":self.ztp_devices(),"destination_policy":self.destination_policy(),"path_decisions":self.path_decisions(),"underlay":self.underlay_state(),"workloads":self.workloads()}

    def routing(self, site: str) -> dict[str, Any]:
        value = self.route_summary(site)
        if not value.get("available", True):
            return value
        return {"site": value.get("site", site), "edge_node": value.get("edge_node"), "rules": value.get("routing_rules", []), "tables": value.get("route_groups", []), "routes": value.get("routes", []), "return_affinity": value.get("return_affinity", {})}

    def route_summary(self, site: str) -> dict[str, Any]:
        site = self._logical_site(site)
        """Bounded evidence view: exclude local, broadcast, and IPv6 noise."""
        if site not in self.topology.site_names: return {"available":False,"reason":"unknown site"}
        routes=self.runtime.routes(site); rules=self.runtime.rules(site)
        if routes.get("availability") != "AVAILABLE": return {"available":False,"reason":routes.get("reason","runtime routes unavailable")}
        selected=[]
        for route in routes.get("value",[]):
            dev=str(route.get("dev", "")); table=str(route.get("table", "")); dst=str(route.get("dst", "default"))
            is_overlay=dev.startswith("wg-")
            is_direct=table in {str(item.route_table) for item in self.topology.transports.values()} and dev in {self.topology.edge_node(site) + "-bb", self.topology.edge_node(site) + "-lte"}
            if not table or not (is_overlay or is_direct): continue
            if ":" in dst or route.get("type") in ("local","broadcast","multicast"): continue
            bits=dev.split("-"); hub=("hub"+bits[1][1:]) if is_overlay and len(bits) >= 3 and bits[1].startswith("h") else None
            transport=bits[2] if is_overlay and len(bits) >= 3 else (dev.rsplit("-",1)[-1] if is_direct else None)
            selected.append({"destination":dst,"table":table,"fwmark_table":table,"next_hop":route.get("gateway"),"output_interface":dev,"hub":hub,"transport":transport,"egress_mode":"hub_overlay" if is_overlay else "direct_internet"})
        selected.sort(key=lambda item:(str(item["table"]),str(item["destination"])))
        grouped={}
        for route in selected:
            key=(route["table"], route["output_interface"])
            group=grouped.setdefault(key,{key:value for key,value in route.items() if key not in ("destination","protocol","scope")})
            group.setdefault("destinations",[]).append(route["destination"])
            if route.get("protocol") is not None: group["protocol"]=route["protocol"]
            if route.get("scope") is not None: group["scope"]=route["scope"]
        route_groups=list(grouped.values())[:64]
        policy_rules=[]
        if rules.get("availability") == "AVAILABLE":
            for rule in rules.get("value",[]):
                if rule.get("fwmark") is not None or str(rule.get("table","")).startswith(("11","12")):
                    policy_rules.append({key:rule.get(key) for key in ("priority","fwmark","fwmask","table","src","dst") if rule.get(key) is not None})
        return {"available":True,"site":site,"edge_node":self.topology.edge_node(site) if site in self.topology.sites else site,"route_groups":route_groups,"routing_rules":policy_rules[:128],"return_affinity":{"configuration":"connmark-based; routes are selected by persistent connection mark and policy rule","evidence":"inspect the listed fwmark policy rules and selected WireGuard output interface"}}

    def compare_desired_actual(self, site: str) -> dict[str, Any]:
        site = self._logical_site(site)
        """Compare only fields with compatible semantics; never ask the model to infer it."""
        if site not in self.topology.site_names:
            return {"available": False, "reason": "unknown site"}
        desired_rows = self.desired(site)
        runtime = self.runtime_view(site)
        latest = desired_rows[0] if desired_rows else None
        comparisons = []
        comparisons.append({"field": "desired_state_record", "desired_value": bool(latest), "observed_value": None, "comparison_status": "desired_only" if latest else "unavailable", "reason": "desired-state records and runtime namespace values are not the same semantic field"})
        runtime_available = all(isinstance(runtime.get(name), dict) and runtime[name].get("availability") == "AVAILABLE" for name in ("links", "routes", "rules", "tunnels") if name in runtime)
        comparisons.append({"field": "runtime_adapter", "desired_value": None, "observed_value": "AVAILABLE" if runtime_available else "UNAVAILABLE", "comparison_status": "observed_only", "reason": "runtime availability is observed independently of desired state"})
        return {"available": True, "site": site, "edge_node": self.topology.edge_node(site) if site in self.topology.sites else site, "comparisons": comparisons, "desired_record": latest, "runtime_available": runtime_available,
                "limitations": ["No field is labeled match or mismatch unless desired and observed values have identical semantics."]}

    @staticmethod
    def _matching_policy_rule(rules: dict[str, Any], fwmark: int | None) -> dict[str, Any] | None:
        if fwmark is None or rules.get("availability") != "AVAILABLE": return None
        matched_rule=None
        for rule in rules.get("value", []):
            try:
                mark=int(str(rule.get("fwmark", "-1")), 0)
                mask=int(str(rule.get("fwmask", "0xffffffff")), 0)
                if fwmark & mask == mark & mask:
                    candidate={"priority":rule.get("priority"),"table":rule.get("table"),"fwmark":rule.get("fwmark"),"fwmask":rule.get("fwmask")}
                    if matched_rule is None or int(candidate["priority"] or 2**31) < int(matched_rule["priority"] or 2**31): matched_rule=candidate
            except (TypeError, ValueError):
                continue
        return matched_rule

    def route_decision_report(self, site: str, destination: str, source: str | None = None, fwmark: int | None = None) -> dict[str, Any]:
        site = self._logical_site(site)
        """Perform a destination-aware read-only lookup without inventing fields."""
        import ipaddress
        if site not in self.topology.site_names:
            return {"available": False, "reason": "unknown site"}
        try:
            ipaddress.ip_address(destination)
            if source is not None:
                ipaddress.ip_address(source)
        except ValueError:
            return {"available": False, "reason": "invalid destination or source"}
        lookup = self.runtime.route_lookup(site, destination, source, fwmark)
        rules = self.runtime.rules(site)
        matched_rule=self._matching_policy_rule(rules, fwmark)
        if lookup.get("availability") != "AVAILABLE":
            return {"available":False,"reason":lookup.get("reason", "runtime route lookup unavailable"),"lookup_status":"lookup unavailable","site":site,"destination":destination,"source":source,"packet_mark":fwmark,"matched_rule":matched_rule,"selected_routing_table":None,"next_hop":None,"output_interface":None,"derived":{"hub":None,"transport":None},"unknowns":[{"field":"matched_route","reason":"marked runtime lookup was unavailable"}],"limitations":["The route lookup reflects the supplied destination, optional source, and optional fwmark only."]}
        values = lookup.get("value", [])
        selected = values[0] if isinstance(values, list) and values else {}
        dev = selected.get("dev")
        derived = {"hub": None, "transport": None}
        if isinstance(dev, str) and dev.startswith("wg-"):
            parts = dev.split("-")
            if len(parts) >= 3 and parts[1].startswith("h"):
                derived["hub"] = "hub" + parts[1][1:]
                derived["transport"] = parts[2]
        unknowns = []
        if fwmark is None:
            unknowns.append({"field": "matched_rule", "reason": "no packet fwmark was supplied"})
        if not selected:
            unknowns.append({"field": "matched_route", "reason": "runtime lookup returned no route record"})
        for field, value in (("selected_routing_table", selected.get("table")), ("next_hop", selected.get("gateway")), ("output_interface", dev), ("connection_mark", None)):
            if value is None:
                unknowns.append({"field": field, "reason": "not reported by the current routing adapter"})
        return {"available": True, "site": site, "edge_node": self.topology.edge_node(site) if site in self.topology.sites else site, "destination": destination, "source": source, "packet_mark": fwmark,
                "matched_rule": matched_rule, "selected_routing_table": selected.get("table"),
                "matched_route": {key: selected.get(key) for key in ("dst", "gateway", "dev", "prefsrc", "type") if selected.get(key) is not None} or None,
                "lookup_status": "route record returned" if selected else "no route record returned",
                "next_hop": selected.get("gateway"), "output_interface": dev,
                "connection_mark": None, "derived": derived,
                "state_kind": {"packet_mark": "observed" if fwmark is not None else "unavailable", "matched_rule": "derived" if matched_rule else "unavailable", "matched_route": "observed" if selected else "unavailable", "hub": "derived" if derived["hub"] else "unavailable", "transport": "derived" if derived["transport"] else "unavailable"},
                "unknowns": unknowns,
                "limitations": ["The route lookup reflects the supplied destination, optional source, and optional fwmark only.", "A connection mark is not exposed by the current routing adapter."],
                "warnings": []}

    def hub_tunnels(self, hub: str) -> dict[str, Any]:
        if hub not in self.topology.hubs: return {"available":False,"reason":"unknown hub"}
        return {"available":True,"hub":hub,"tunnels":self.runtime.tunnels(hub)}

    def hub_view(self, hub: str) -> dict[str, Any]:
        if hub not in self.topology.hubs: return {"availability":"UNAVAILABLE", "reason":"unknown hub"}
        return {"hub":hub,"configured":{"management_ip":str(self.topology.hubs[hub].management_ip)},"runtime":self.runtime_view(hub)}
    def network_view(self, kind: str) -> dict[str, Any]:
        c=self.topology
        if kind == "data-center": return {"network":str(c.data_center_network),"endpoint":str(c.data_center_app_ip),"name":c.data_center_app_name,"egress":"hub overlay only","return_affinity":"explicit return routes plus connmark"}
        if kind == "saas": return {"network":str(c.saas_network),"endpoint":str(c.saas_ip),"name":c.saas_app_name,"egress":"direct internet only","candidate_transports":["bb","lte"]}
        if kind == "cloud-vpc": return {"enabled":c.cloud_vpc.enabled,"network":str(c.cloud_vpc.network),"endpoint":str(c.cloud_vpc.app_ip),"gateways":list(c.cloud_vpc.active_gateways),"availability":"CONFIGURED" if c.cloud_vpc.enabled else "DISABLED"}
        return {"availability":"UNAVAILABLE", "reason":"unknown network view"}

    @staticmethod
    def _endpoint_key(value: str) -> str:
        return "".join(character for character in value.lower() if character.isalnum())

    def endpoint_inventory(self) -> list[dict[str, Any]]:
        endpoints=[]
        for site in self.topology.sites.values():
            number="".join(character for character in site.name if character.isdigit())
            endpoints.append({"name":site.host_name,"kind":"branch_host","ip":str(site.host_ip),"site":site.name,"edge_node":site.edge_node,"aliases":[site.host_name,site.name+"-host","node_host"+number]})
            endpoints.append({"name":site.edge_node,"kind":"branch_edge","ip":str(site.lan_gateway),"site":site.name,"edge_node":site.edge_node,"aliases":[site.edge_node,site.name]})
        for hub in self.topology.hubs.values():
            endpoints.append({"name":hub.name,"kind":"hub","ip":str(hub.management_ip),"aliases":[hub.name]})
        endpoints.extend([
            {"name":self.topology.data_center_app_name,"kind":"data_center_application","ip":str(self.topology.data_center_app_ip),"aliases":[self.topology.data_center_app_name,"data_center","data-center","dc"]},
            {"name":self.topology.saas_app_name,"kind":"saas_application","ip":str(self.topology.saas_ip),"aliases":[self.topology.saas_app_name,"public_saas","saas"]},
        ])
        if self.topology.cloud_vpc.enabled:
            endpoints.append({"name":self.topology.cloud_vpc.app_name,"kind":"cloud_application","ip":str(self.topology.cloud_vpc.app_ip),"aliases":[self.topology.cloud_vpc.app_name,"cloud_app","cloud"]})
            for gateway in self.topology.cloud_vpc.active_gateways:
                endpoints.append({"name":gateway,"kind":"cloud_gateway","ip":str(self.topology.cloud_vpc.gateway_ips[gateway]),"management_ip":str(self.topology.cloud_vpc.gateway_management_ips[gateway]),"aliases":[gateway]})
        return endpoints

    def resolve_endpoint(self, value: str) -> dict[str, Any] | None:
        key=self._endpoint_key(value)
        for endpoint in self.endpoint_inventory():
            if key in {self._endpoint_key(alias) for alias in endpoint["aliases"]}:
                return endpoint
        return None

    def endpoint(self, name: str) -> dict[str, Any]:
        endpoint=self.resolve_endpoint(name)
        if endpoint is None:
            return {"available":False,"reason":"unknown configured endpoint"}
        return {"available":True,"endpoint":endpoint}

    def policy_route_candidates(self, site: str, destination: str) -> list[dict[str, Any]]:
        """List installed matching policy routes; this does not assert a selected path."""
        import ipaddress
        try: address=ipaddress.ip_address(destination)
        except ValueError: return []
        try:
            summary=self.route_summary(site)
        except AttributeError:
            # A constrained runtime adapter may expose lookup support without
            # a complete route-list capability; omit candidates rather than infer.
            return []
        if not summary.get("available"): return []
        rules_by_table={}
        for rule in summary.get("routing_rules", []):
            rules_by_table.setdefault(str(rule.get("table")), []).append({key:rule.get(key) for key in ("priority","fwmark","fwmask","table")})
        candidates=[]
        for group in summary.get("route_groups", []):
            matching=[]
            for prefix in group.get("destinations", []):
                try:
                    if address in ipaddress.ip_network(prefix, strict=False): matching.append(prefix)
                except ValueError:
                    continue
            if matching:
                table=str(group.get("table"))
                candidates.append({"table":table,"matching_destinations":matching,"output_interface":group.get("output_interface"),"hub":group.get("hub"),"transport":group.get("transport"),"next_hop":group.get("next_hop"),"policy_rules":rules_by_table.get(table, [])})
        return candidates

    def endpoint_route(self, source: str, destination: str, fwmark: int | None = None) -> dict[str, Any]:
        source_endpoint=self.resolve_endpoint(source)
        destination_endpoint=self.resolve_endpoint(destination)
        if source_endpoint is None or destination_endpoint is None:
            missing=[]
            if source_endpoint is None: missing.append("source endpoint")
            if destination_endpoint is None: missing.append("destination endpoint")
            return {"available":False,"reason":"unresolved " + " and ".join(missing),"source":source,"destination":destination}
        result={"available":True,"source":source_endpoint,"destination":destination_endpoint,"fwmark":fwmark}
        if source_endpoint["kind"] == "branch_host":
            site=self.topology.sites[source_endpoint["site"]]
            result["host_access"]={"source_host":source_endpoint["name"],"source_ip":source_endpoint["ip"],"edge_site":site.name,"edge_node":site.edge_node,"lan_gateway":str(site.lan_gateway),"lan_network":str(site.lan_network)}
            result["edge_route"]=self.route_decision_report(site.name,destination_endpoint["ip"],source_endpoint["ip"],fwmark)
            if fwmark is None:
                result["policy_candidates"]=self.policy_route_candidates(site.name,destination_endpoint["ip"])
            result["limitations"]=["The host-to-LAN-gateway hop is configured topology evidence. The edge route lookup reflects the supplied destination, source, and optional fwmark.", "Policy candidates are matching installed rules and routes; without an observed or supplied fwmark they do not prove the selected path."]
            return result
        result["limitations"]=["The source resolves to a configured endpoint, but this tool currently performs an observed edge route lookup only for a branch host source."]
        return result

    def site_host_route(self, site: str, destination: str, fwmark: int | None = None) -> dict[str, Any]:
        site = self._logical_site(site)
        """Resolve a configured branch host deterministically from its site identifier."""
        if site not in self.topology.site_names:
            return {"available":False,"reason":"unknown site"}
        return self.endpoint_route(self.topology.sites[site].host_name, destination, fwmark)

    def observe_endpoint_flow(self, source: str, destination: str) -> dict[str, Any]:
        """Read an active branch-host flow mark and resolve only that observed mark."""
        source_endpoint=self.resolve_endpoint(source); destination_endpoint=self.resolve_endpoint(destination)
        if source_endpoint is None or destination_endpoint is None:
            return {"available":False,"reason":"unresolved endpoint"}
        if source_endpoint["kind"] != "branch_host":
            return {"available":False,"reason":"source must resolve to a branch host"}
        site=self.topology.sites[source_endpoint["site"]]
        observed=self.runtime.connection_marks(site.name,source_endpoint["ip"],destination_endpoint["ip"])
        if observed.get("availability") != "AVAILABLE":
            return {"available":False,"reason":observed.get("reason", "conntrack observation unavailable")}
        marks=observed.get("value", [])
        result={"available":True,"source":source_endpoint,"destination":destination_endpoint,"flow_observation":{"flow_count":len(marks),"marks":marks}}
        result["configured_path_candidates"]=self.graph_expected_traffic_path(source,destination)
        if marks:
            selected=self.route_decision_report(site.name,destination_endpoint["ip"],source_endpoint["ip"],marks[0]["mark"])
            result["selected_live_route"]=selected
            if selected.get("output_interface") is None and selected.get("matched_rule"):
                table=str(selected["matched_rule"].get("table"))
                candidates=[candidate for candidate in self.policy_route_candidates(site.name,destination_endpoint["ip"]) if candidate.get("table") == table]
                result["observed_mark_policy"]={"observed_mark":marks[0],"matched_rule":selected["matched_rule"],"matching_route_candidates":candidates}
        result["limitations"]=["Only an existing conntrack flow matching the resolved source and destination can provide an observed mark.", "When multiple matching flows exist, only the first bounded observed mark is used for the marked route lookup.", "If the marked kernel lookup returns no route record, the observed-mark policy section reports only the matching installed rule and route candidate; it is not a kernel lookup result."]
        if not marks:
            result["limitations"].insert(0, "No matching runtime flow was observed; configured path candidates are possible graph paths, not a selected data-plane path.")
        return result

    def transport_inventory(self) -> list[dict[str, Any]]:
        return [{"name":item.name,"network":str(item.network),"switch":item.switch,"dpid":item.dpid,"bandwidth_mbps":item.bandwidth_mbps,"delay_ms":item.delay_ms,"internet_capable":item.internet_capable,"route_table":item.route_table} for item in self.topology.transports.values()]

    def hub_configuration(self, hub: str) -> dict[str, Any]:
        item=self.topology.hubs[hub]
        return {"hub":hub,"management_ip":str(item.management_ip),"address_id":item.address_id}

    def cloud_gateways(self) -> list[dict[str, Any]]:
        cloud=self.topology.cloud_vpc
        return [{"gateway":name,"active":name in cloud.active_gateways,"vpc_ip":str(cloud.gateway_ips[name]),"management_ip":str(cloud.gateway_management_ips[name]),"address_id":cloud.gateway_address_ids[name]} for name in cloud.gateway_names]

    def cloud_gateway(self, gateway: str) -> dict[str, Any]:
        cloud=self.topology.cloud_vpc
        if gateway not in cloud.gateway_names:
            return {"available":False,"reason":"unknown cloud gateway"}
        transits=[]
        for hub in self.topology.hubs:
            network=cloud.transit_network(hub,gateway)
            transits.append({"hub":hub,"network":str(network),"hub_ip":str(cloud.transit_ip(hub,gateway,hub)),"gateway_ip":str(cloud.transit_ip(hub,gateway,gateway))})
        return {"available":True,"gateway":gateway,"enabled":cloud.enabled,"active":gateway in cloud.active_gateways,"vpc_ip":str(cloud.gateway_ips[gateway]),"management_ip":str(cloud.gateway_management_ips[gateway]),"address_id":cloud.gateway_address_ids[gateway],"vpc_network":str(cloud.network),"application":{"name":cloud.app_name,"ip":str(cloud.app_ip)},"transits":transits}

    def data_center_configuration(self) -> dict[str, Any]:
        return {"network":str(self.topology.data_center_network),"application":{"name":self.topology.data_center_app_name,"ip":str(self.topology.data_center_app_ip)},"hub_ips":{hub:str(address) for hub,address in self.topology.data_center_hub_ips.items()}}

    def saas_configuration(self) -> dict[str, Any]:
        return {"network":str(self.topology.saas_network),"application":{"name":self.topology.saas_app_name,"ip":str(self.topology.saas_ip)},"gateway":{"name":self.topology.saas_gateway_name,"ip":str(self.topology.saas_gateway_ip),"transport_ips":{transport:str(address) for transport,address in self.topology.saas_transport_ips.items()}},"transport_ips":{transport:str(address) for transport,address in self.topology.saas_transport_ips.items()}}

    def site_interfaces(self, site: str) -> dict[str, Any]:
        return {"site":site,"interfaces":self.runtime.links(site)}

    def site_failover(self, site: str) -> dict[str, Any]:
        result=self.runtime.failover(site)
        if result.get("availability") != "AVAILABLE": return {"site":site,"failover":result}
        import json
        try: value=json.loads(str(result.get("value", "")))
        except ValueError: value={"raw_status":str(result.get("value", ""))}
        return {"site":site,"failover":{"availability":"AVAILABLE","value":value}}

    def site_classifier(self, site: str) -> dict[str, Any]:
        result=self.runtime.classifier(site)
        if result.get("availability") != "AVAILABLE": return {"site":site,"classifier":result}
        import json
        lines=[line for line in str(result.get("value", "")).splitlines() if line.strip()]
        try: value=json.loads(lines[-1]) if lines else None
        except ValueError: value=None
        return {"site":site,"classifier":{"availability":"AVAILABLE","latest_event":value,"line_count":len(lines)}}

    def topology_nodes(self) -> list[dict[str, Any]]:
        plan=build_live_plan(self.topology)
        return ([{"name":item.name,"kind":"switch","openflow":item.openflow,"dpid":item.dpid} for item in plan.switches] + [{"name":item.name,"kind":"docker","role":item.role,"image":item.image} for item in plan.docker_nodes])
    def topology_links(self) -> list[dict[str, Any]]:
        return [{"node1":item.node1,"node2":item.node2,"interface1":item.intf1,"interface2":item.intf2,"address1":item.address1,"address2":item.address2,"transport":item.transport} for item in build_live_plan(self.topology).links]
    def combined_events(self) -> list[dict[str, Any]]:
        return self.events()+[{"source":"management","event":item} for item in self.audit.list()]
