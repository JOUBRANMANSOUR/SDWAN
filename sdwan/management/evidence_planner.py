"""Deterministic evidence prefetch for bounded operational chat questions.

The language model is not responsible for discovering mandatory evidence. This
module recognizes questions whose required read-only query is unambiguous and
loads that evidence before the model is asked to describe it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from sdwan.sdwan_mcp.models.common import StateKind, result_from_payload


@dataclass(frozen=True)
class PreparedEvidence:
    tool: str
    arguments: Dict[str, str]
    result: Dict[str, Any]
    fallback_answer: Dict[str, Any]


def _endpoint_mentions(service: Any, prompt: str) -> List[Tuple[int, int, str]]:
    """Return non-overlapping endpoint mentions, preferring longer aliases."""
    text = prompt.lower()
    aliases: List[Tuple[str, str]] = []
    for endpoint in service.endpoint_inventory():
        canonical = str(endpoint["name"])
        for alias in endpoint.get("aliases", []):
            aliases.append((str(alias).lower(), canonical))

    # Support the natural form "host of node2" without teaching the model
    # topology naming conventions.
    for match in re.finditer(r"\bhost\s+(?:of|in)\s+(?:site|node)\d+\b", text):
        endpoint = service.resolve_endpoint("node" + re.search(r"\d+", match.group(1)).group(0) + "_host")
        if endpoint:
            aliases.append((match.group(0), str(endpoint["name"])))

    matches: List[Tuple[int, int, str]] = []
    for alias, canonical in sorted(set(aliases), key=lambda item: len(item[0]), reverse=True):
        pattern = r"(?<![a-z0-9])" + re.escape(alias) + r"(?![a-z0-9])"
        for match in re.finditer(pattern, text):
            candidate = (match.start(), match.end(), canonical)
            if any(not (candidate[1] <= old[0] or candidate[0] >= old[1]) for old in matches):
                continue
            matches.append(candidate)
    return sorted(matches)


def prepare_route_evidence(service: Any, prompt: str) -> Optional[PreparedEvidence]:
    """Prefetch evidence only for an unambiguous two-endpoint route question."""
    lowered = prompt.lower()
    if not any(word in lowered for word in ("route", "path")):
        return None
    mentions = _endpoint_mentions(service, prompt)
    ordered: List[str] = []
    for _, _, endpoint in mentions:
        if endpoint not in ordered:
            ordered.append(endpoint)
    if len(ordered) != 2:
        return None

    source, destination = ordered
    observed = "observed" in lowered or "current flow" in lowered or "live flow" in lowered
    if observed:
        tool = "server_prefetch_observe_endpoint_flow"
        payload = service.observe_endpoint_flow(source, destination)
        claim_type = "flow_route"
        state_kind = StateKind.observed
        source_type = "routing_table"
    else:
        tool = "server_prefetch_explain_endpoint_route"
        payload = service.endpoint_route(source, destination)
        claim_type = "endpoint_route"
        state_kind = StateKind.derived
        source_type = "derived"
    if not payload.get("available"):
        return None

    operational = result_from_payload(
        tool,
        payload,
        source_type,
        state_kind,
        limitations=list(payload.get("limitations", [])),
    ).model_dump(mode="json")
    compatible = {
        "flow_route": {"source", "destination", "flow_observation", "selected_live_route", "observed_mark_policy", "configured_path_candidates"},
        "endpoint_route": {"source", "destination", "host_access", "edge_route", "policy_candidates", "configured_path_candidates"},
    }[claim_type]
    fact_ids = [fact["fact_id"] for fact in operational["facts"] if fact["fact_kind"] in compatible]
    fallback = {
        "answer_type": "operational",
        "summary": "The management backend prepared verified route evidence.",
        "claims": [{
            "claim_id": "server-prepared-route-evidence",
            "claim_type": claim_type,
            "fact_ids": fact_ids,
            "explanation": None,
        }],
        "unknowns": [],
        "limitations": [],
    }
    return PreparedEvidence(tool, {"source": source, "destination": destination}, operational, fallback)
