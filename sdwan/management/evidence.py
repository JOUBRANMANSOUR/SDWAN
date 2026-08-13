"""Deterministic evidence validation and operational rendering."""
from __future__ import annotations
import json
from typing import Any, Dict, List
from pydantic import ValidationError
from sdwan.sdwan_mcp.models.answers import AgentAnswer, AnswerType

class EvidenceValidator:
    def validate(self, answer_data: Dict[str, Any], bundle: Dict[str, Any]) -> Dict[str, Any]:
        try:
            answer=AgentAnswer.model_validate(answer_data)
        except ValidationError as exc:
            return {"valid":False,"errors":[{"code":"ANSWER_SCHEMA_INVALID","detail":str(exc)[:256]}],"validated_claims":[],"rejected_claims":[]}
        facts={str(item.get("fact_id")):item for item in bundle["payload"].get("facts",[]) if item.get("fact_id")}
        errors=[]; accepted=[]
        compatible = {
            "system_health": {"status", "mode", "sources"},
            "topology": {"management_network", "hubs", "sites", "transports", "nodes", "links", "cloud_vpc", "data_center", "saas"},
            "endpoint": {"endpoint", "endpoints", "source", "destination"}, "endpoint_route": {"source", "destination", "host_access", "edge_route", "policy_candidates"}, "flow_route": {"source", "destination", "flow_observation", "selected_live_route", "observed_mark_policy"},
            "transport": {"transports"},
            "site_status": {"sites", "site", "lan_prefix", "preferred_hub", "standby_hub", "status", "configured", "desired", "runtime", "links", "tunnels", "routes", "rules", "failover", "classifier"},
            "hub_status": {"hub", "management_ip", "address_id", "configured", "runtime"},
            "cloud_gateway": {"gateway", "enabled", "active", "vpc_ip", "management_ip", "address_id", "vpc_network", "application", "transits", "gateways"},
            "data_center": {"network", "application", "hub_ips"}, "saas": {"network", "application", "gateway", "transport_ips"},
            "tunnel_status": {"tunnels"}, "runtime_interfaces": {"interfaces"}, "failover_status": {"failover"}, "classifier_status": {"classifier"},
            "routing_rule": {"routing_rules", "matched_rule"}, "routing_table": {"selected_routing_table", "route_groups"}, "route": {"matched_route", "routes", "route_groups", "edge_route"},
            "next_hop": {"next_hop", "matched_route"}, "output_interface": {"output_interface", "matched_route", "route_groups"},
            "selected_hub": {"derived"}, "selected_transport": {"derived"}, "route_ownership": {"ownership"}, "desired_state": {"desired_states"},
            "policy_version": {"policy_versions"}, "destination_policy": {"destination_policy"}, "device_enrollment": {"devices"},
            "state_comparison": {"comparisons"}, "event": {"events"}, "limitation": {"limitations"},
        }
        if answer.answer_type in (AnswerType.operational, AnswerType.mixed) and not answer.claims:
            errors.append({"code":"OPERATIONAL_CLAIMS_REQUIRED"})
        complete_path_claims={"endpoint_route", "flow_route", "tunnel_status"}
        for claim in answer.claims:
            if answer.answer_type == AnswerType.conceptual:
                errors.append({"code":"CONCEPTUAL_ANSWER_HAS_OPERATIONAL_CLAIM","claim_id":claim.claim_id}); continue
            if claim.claim_type in complete_path_claims:
                # A route answer must show the complete compatible evidence set,
                # not a model-selected subset that could hide candidates or marks.
                # Drop tool metadata that a model may cite alongside path facts.
                claim.fact_ids=[fact_id for fact_id, fact in facts.items() if fact.get("fact_kind") in compatible[claim.claim_type]]
            if not claim.fact_ids:
                errors.append({"code":"CLAIM_EVIDENCE_REQUIRED","claim_id":claim.claim_id}); continue
            missing=[fact_id for fact_id in claim.fact_ids if fact_id not in facts]
            if missing:
                errors.append({"code":"UNKNOWN_FACT_ID","claim_id":claim.claim_id,"fact_ids":missing}); continue
            if not all(facts[fact_id].get("fact_kind") in compatible.get(claim.claim_type, set()) for fact_id in claim.fact_ids):
                errors.append({"code":"CLAIM_FACT_KIND_MISMATCH","claim_id":claim.claim_id}); continue
            accepted.append(claim.claim_id)
        if answer.answer_type in (AnswerType.operational, AnswerType.mixed) and not facts:
            errors.append({"code":"NO_MCP_EVIDENCE"})
        return {"valid":not errors,"answer":answer.model_dump(mode="json"),"validated_claims":accepted,"rejected_claims":[item.get("claim_id") for item in errors if item.get("claim_id")],"errors":errors}

def _markdown(value: Any) -> str:
    """Render evidence values without adding operational interpretation."""
    if value is None:
        return "not reported"
    return str(value).replace("|", "\\|").replace("\n", " ")

def _route_groups_table(groups: Any) -> List[str]:
    if not isinstance(groups, list):
        return ["- **route_groups**: `{}`".format(json.dumps(groups, sort_keys=True, default=str))]
    lines=["| Table | Interface | Hub | Transport | Next hop | Destinations |", "|---|---|---|---|---|---|"]
    for group in groups:
        if not isinstance(group, dict):
            lines.append("| not reported | not reported | not reported | not reported | not reported | `{}` |".format(_markdown(group)))
            continue
        destinations=group.get("destinations", [])
        destination_text=", ".join(_markdown(item) for item in destinations) if isinstance(destinations, list) else _markdown(destinations)
        lines.append("| {} | {} | {} | {} | {} | {} |".format(
            _markdown(group.get("table")), _markdown(group.get("output_interface")),
            _markdown(group.get("hub")), _markdown(group.get("transport")),
            _markdown(group.get("next_hop")), destination_text or "not reported"))
    return lines

def _policy_candidates_table(candidates: Any) -> List[str]:
    if not isinstance(candidates, list):
        return ["- **policy_candidates**: `{}`".format(json.dumps(candidates, sort_keys=True, default=str))]
    if not candidates:
        return ["- No matching installed policy-route candidates were reported."]
    lines=["| Table | Rule marks | Interface | Hub | Transport | Matching destination |", "|---|---|---|---|---|---|"]
    for candidate in candidates:
        rules=candidate.get("policy_rules", []) if isinstance(candidate, dict) else []
        marks=", ".join(_markdown(rule.get("fwmark")) for rule in rules if isinstance(rule, dict)) or "not reported"
        destinations=", ".join(_markdown(item) for item in candidate.get("matching_destinations", [])) if isinstance(candidate, dict) else "not reported"
        lines.append("| {} | {} | {} | {} | {} | {} |".format(_markdown(candidate.get("table")), marks, _markdown(candidate.get("output_interface")), _markdown(candidate.get("hub")), _markdown(candidate.get("transport")), destinations))
    return lines

def _routing_rules_table(rules: Any) -> List[str]:
    if not isinstance(rules, list):
        return ["- **routing_rules**: `{}`".format(json.dumps(rules, sort_keys=True, default=str))]
    lines=["| Priority | FWMark | Mask | Table | Source |", "|---|---|---|---|---|"]
    for rule in rules:
        if not isinstance(rule, dict):
            lines.append("| not reported | not reported | not reported | not reported | not reported |")
            continue
        lines.append("| {} | {} | {} | {} | {} |".format(
            _markdown(rule.get("priority")), _markdown(rule.get("fwmark")),
            _markdown(rule.get("fwmask")), _markdown(rule.get("table")),
            _markdown(rule.get("src"))))
    return lines

def _wireguard_tunnels_table(value: Any) -> List[str]:
    if not isinstance(value, dict):
        return ["- **tunnels**: `{}`".format(json.dumps(value, sort_keys=True, default=str))]
    availability=value.get("availability", "not reported")
    raw=value.get("value")
    if availability != "AVAILABLE" or not isinstance(raw, str):
        return ["- **availability**: `{}`".format(_markdown(availability))]
    rows=[]; interface=None; current=None
    for line in raw.splitlines():
        stripped=line.strip()
        if stripped.startswith("interface: "):
            if current is not None:
                rows.append(current)
            interface=stripped.split(": ",1)[1]
            current=None
        elif stripped.startswith("peer: ") and interface is not None:
            if current is not None:
                rows.append(current)
            current={"interface":interface}
        elif current is not None:
            for key, label in (("endpoint: ", "endpoint"), ("latest handshake: ", "handshake"), ("transfer: ", "transfer"), ("persistent keepalive: ", "keepalive"), ("allowed ips: ", "allowed_ips")):
                if stripped.startswith(key):
                    current[label]=stripped.split(": ",1)[1]
                    break
    if current is not None:
        rows.append(current)
    if not rows:
        return ["- **availability**: `AVAILABLE`", "- Tunnel output was present but did not contain an interface record."]
    lines=["| Interface | Endpoint | Latest handshake | Transfer | Keepalive | Allowed IPs |", "|---|---|---|---|---|---|"]
    for row in rows:
        lines.append("| {} | {} | {} | {} | {} | {} |".format(
            _markdown(row.get("interface")), _markdown(row.get("endpoint")),
            _markdown(row.get("handshake")), _markdown(row.get("transfer")),
            _markdown(row.get("keepalive")), _markdown(row.get("allowed_ips"))))
    return lines

def _key_value_table(value: Any, keys: List[tuple[str, str]]) -> List[str]:
    if not isinstance(value, dict):
        return ["- `{}`".format(json.dumps(value, sort_keys=True, default=str))]
    lines=["| Field | Value |", "|---|---|"]
    for field, label in keys:
        if field in value:
            rendered=value[field]
            if isinstance(rendered, (dict, list)):
                rendered=json.dumps(rendered, sort_keys=True, default=str)
            lines.append("| {} | {} |".format(label, _markdown(rendered)))
    return lines

def _render_fact(fact: Dict[str, Any]) -> List[str]:
    kind=str(fact.get("fact_kind", "evidence"))
    value=fact.get("value")
    if kind == "route_groups":
        return ["### Installed route groups"] + _route_groups_table(value)
    if kind == "routing_rules":
        return ["### Installed policy rules"] + _routing_rules_table(value)
    if kind == "policy_candidates":
        return ["### Matching policy-route candidates"] + _policy_candidates_table(value)
    if kind == "flow_observation":
        return ["### Observed matching flow"] + _key_value_table(value, [("flow_count", "Observed matching flows"), ("marks", "Observed marks")])
    if kind == "selected_live_route":
        return ["### Route lookup using observed flow mark"] + _key_value_table(value, [("available", "Lookup availability"), ("lookup_status", "Lookup result"), ("reason", "Lookup error"), ("packet_mark", "Observed fwmark"), ("matched_rule", "Matching policy rule"), ("selected_routing_table", "Selected table"), ("next_hop", "Next hop"), ("output_interface", "Output interface"), ("derived", "Derived interface metadata")])
    if kind == "observed_mark_policy":
        if not isinstance(value, dict): return ["### Observed-mark policy evidence", "- not reported"]
        lines=["### Observed-mark policy evidence"]
        lines += _key_value_table(value, [("observed_mark", "Observed conntrack mark"), ("matched_rule", "Matching installed policy rule")])
        lines.append("#### Matching installed route candidates")
        lines += _policy_candidates_table(value.get("matching_route_candidates"))
        return lines
    if kind == "tunnels":
        return ["### Observed WireGuard tunnels"] + _wireguard_tunnels_table(value)
    if kind in {"endpoint", "source", "destination"}:
        title = {"endpoint":"Configured endpoint", "source":"Resolved source endpoint", "destination":"Resolved destination endpoint"}[kind]
        return ["### " + title] + _key_value_table(value, [("name", "Name"), ("kind", "Kind"), ("ip", "IP address"), ("site", "Site"), ("management_ip", "Management IP"), ("aliases", "Aliases")])
    if kind == "host_access":
        return ["### Configured host access"] + _key_value_table(value, [("source_host", "Source host"), ("source_ip", "Source IP"), ("edge_site", "Edge site"), ("lan_gateway", "LAN gateway"), ("lan_network", "LAN network")])
    if kind == "edge_route":
        return ["### Observed edge route lookup"] + _key_value_table(value, [("available", "Lookup availability"), ("reason", "Lookup result"), ("site", "Edge site"), ("destination", "Destination"), ("source", "Source"), ("packet_mark", "Supplied fwmark"), ("selected_routing_table", "Selected table"), ("next_hop", "Next hop"), ("output_interface", "Output interface"), ("derived", "Derived interface metadata")])
    return ["- **{}**: `{}`".format(kind, json.dumps(value, sort_keys=True, default=str))]

def render_verified_answer(validation: Dict[str, Any], bundle: Dict[str, Any]) -> str:
    answer=validation["answer"]
    if answer["answer_type"] == "conceptual":
        return "## Conceptual explanation\n\n" + answer["summary"]
    facts={str(item.get("fact_id")):item for item in bundle["payload"].get("facts",[]) if item.get("fact_id")}
    lines=["## Verified operational facts"]
    for claim in answer["claims"]:
        for fact_id in claim["fact_ids"]:
            fact=facts[fact_id]
            rendered=_render_fact(fact)
            if rendered and rendered[0].startswith("###"):
                lines.append("\n" + rendered[0])
                lines.extend(rendered[1:])
            else:
                lines.append("\n### {}".format(claim["claim_type"]))
                lines.extend(rendered)
    unknowns=bundle["payload"].get("unknowns",[])
    limitations=bundle["payload"].get("limitations",[])
    if unknowns:
        lines.extend(["\n## Unknown or unavailable information"]+["- {}: {}".format(item.get("field"),item.get("reason")) for item in unknowns[:32]])
    if limitations:
        lines.extend(["\n## Evidence limitations"]+["- {}".format(item) for item in limitations[:32]])
    lines.append("\nEvidence bundle: `{}`".format(bundle["bundle_id"]))
    return "\n".join(lines)
