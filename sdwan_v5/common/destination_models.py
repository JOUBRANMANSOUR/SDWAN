"""Validated destination policy intent for the isolated v5 laboratory.

This module deliberately contains no packet processing.  It converts a small,
deterministic configuration document into policy records used by the Policy
Service when it generates an Edge snapshot.  nDPI may annotate a flow later,
but it never changes the selected destination policy.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Network, ip_network
from pathlib import Path
from typing import Any, Mapping

import yaml

from .marks import EgressMode
from .model import HUBS, TopologyConfig


class DestinationPolicyError(ValueError):
    """Raised before an unsafe destination policy can be activated."""


class DestinationType(str, Enum):
    BRANCH_PRIVATE = "BRANCH_PRIVATE"
    DATA_CENTER = "DATA_CENTER"
    CLOUD_VPC = "CLOUD_VPC"
    SAAS = "SAAS"
    UNKNOWN = "UNKNOWN"


class TrustClass(str, Enum):
    TRUSTED = "TRUSTED"
    SENSITIVE = "SENSITIVE"
    UNKNOWN = "UNKNOWN"


class FailureAction(str, Enum):
    HUB_FALLBACK = "HUB_FALLBACK"
    FAIL_CLOSED = "FAIL_CLOSED"


@dataclass(frozen=True)
class DestinationPolicy:
    policy_id: str
    priority: int
    prefix: IPv4Network | None
    destination_type: DestinationType
    trust_class: TrustClass | None
    allowed_egress: tuple[EgressMode, ...]
    candidate_transports: tuple[str, ...]
    failure_action: FailureAction
    cloud_gateway_preferences: Mapping[str, tuple[str, ...]]
    application_matchers: tuple[str, ...]
    application_classes: tuple[str, ...]

    @property
    def ranked_transports(self) -> tuple[str, ...]:
        """Compatibility alias for older edge snapshots during migration."""
        return self.candidate_transports

    def to_intent(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "policy_id": self.policy_id,
            "priority": self.priority,
            "destination_type": self.destination_type.value,
            "allowed_egress": [value.value for value in self.allowed_egress],
            "candidate_transports": list(self.candidate_transports),
            "ranked_transports": list(self.candidate_transports),
            "failure_action": self.failure_action.value,
            "application_matchers": list(self.application_matchers),
            "application_classes": list(self.application_classes),
        }
        if self.trust_class is not None:
            result["trust_class"] = self.trust_class.value
        if self.prefix is not None:
            result["prefix"] = str(self.prefix)
        if self.cloud_gateway_preferences:
            result["cloud_gateway_preferences"] = {
                hub: list(gateways) for hub, gateways in self.cloud_gateway_preferences.items()
            }
        return result


@dataclass(frozen=True)
class DestinationPolicyDocument:
    schema_version: int
    policies: tuple[DestinationPolicy, ...]
    default_policy: DestinationPolicy

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policies": [item.to_intent() for item in self.policies],
            "default_policy": self.default_policy.to_intent(),
        }

    def policy_for_prefix(self, prefix: IPv4Network) -> DestinationPolicy:
        for policy in self.policies:
            if policy.prefix == prefix:
                return policy
        return self.default_policy


def _prefix(value: object, field: str, *, allow_none: bool = False) -> IPv4Network | None:
    if value is None and allow_none:
        return None
    try:
        return ip_network(str(value), strict=True)
    except ValueError as exc:
        raise DestinationPolicyError(f"invalid {field}: {value}") from exc


def _enum(enum: type[Enum], value: object, field: str) -> Enum:
    try:
        return enum(str(value))
    except ValueError as exc:
        options = ", ".join(item.value for item in enum)
        raise DestinationPolicyError(f"invalid {field}: expected one of {options}") from exc


def _policy(raw: Mapping[str, Any], config: TopologyConfig, *, is_default: bool) -> DestinationPolicy:
    required = {
        "policy_id", "priority", "destination_type", "allowed_egress", "failure_action",
    }
    missing = required - set(raw)
    if missing:
        raise DestinationPolicyError(f"destination policy is missing: {', '.join(sorted(missing))}")
    prefix = _prefix(raw.get("prefix"), "prefix", allow_none=is_default)
    if not is_default and prefix is None:
        raise DestinationPolicyError("non-default destination policy requires a prefix")
    allowed = tuple(_enum(EgressMode, item, "allowed_egress") for item in raw["allowed_egress"])
    transport_values = raw.get("candidate_transports", raw.get("ranked_transports"))
    if not isinstance(transport_values, list):
        raise DestinationPolicyError("candidate_transports must be a list")
    candidates = tuple(str(item) for item in transport_values)
    matchers = tuple(str(item) for item in raw.get("application_matchers", ()))
    application_classes = tuple(str(item) for item in raw.get("application_classes", ()))
    if not allowed or len(allowed) != len(set(allowed)):
        raise DestinationPolicyError("allowed_egress must contain unique values")
    if not candidates or len(candidates) != len(set(candidates)) or any(item not in config.transports for item in candidates):
        raise DestinationPolicyError("candidate_transports must contain unique configured transports")
    if len(matchers) != len(set(matchers)):
        raise DestinationPolicyError("application_matchers must be unique")
    if len(application_classes) != len(set(application_classes)):
        raise DestinationPolicyError("application_classes must be unique")
    preferences_raw = raw.get("cloud_gateway_preferences", {})
    if not isinstance(preferences_raw, Mapping):
        raise DestinationPolicyError("cloud_gateway_preferences must be a mapping")
    preferences = {str(hub): tuple(str(gateway) for gateway in gateways) for hub, gateways in preferences_raw.items()}
    trust = _enum(TrustClass, raw["trust_class"], "trust_class") if "trust_class" in raw else None
    policy = DestinationPolicy(
        policy_id=str(raw["policy_id"]), priority=int(raw["priority"]), prefix=prefix,
        destination_type=_enum(DestinationType, raw["destination_type"], "destination_type"),
        trust_class=trust, allowed_egress=allowed, candidate_transports=candidates,
        failure_action=_enum(FailureAction, raw["failure_action"], "failure_action"),
        cloud_gateway_preferences=preferences, application_matchers=matchers,
        application_classes=application_classes,
    )
    _validate_policy(policy, config, is_default=is_default)
    return policy


def _validate_policy(policy: DestinationPolicy, config: TopologyConfig, *, is_default: bool) -> None:
    allowed = set(policy.allowed_egress)
    direct = EgressMode.DIRECT_INTERNET in allowed
    hub = EgressMode.HUB_OVERLAY in allowed
    cloud = EgressMode.CLOUD_GATEWAY in allowed
    if not policy.policy_id or policy.priority < 0:
        raise DestinationPolicyError("policy_id must be nonempty and priority non-negative")
    if direct and not any(config.transports[name].internet_capable for name in policy.candidate_transports):
        raise DestinationPolicyError("direct Internet policy has no Internet-capable transport")
    if direct and any(not config.transports[name].internet_capable for name in policy.candidate_transports):
        raise DestinationPolicyError("direct Internet candidates must all be Internet-capable")
    if policy.destination_type is DestinationType.CLOUD_VPC:
        if direct or cloud or not hub:
            raise DestinationPolicyError("CLOUD_VPC must use spoke HUB_OVERLAY only")
        if policy.prefix != config.cloud_vpc.network:
            raise DestinationPolicyError("Cloud VPC policy prefix must equal the configured Cloud VPC network")
        expected = set(config.cloud_vpc.gateway_names)
        if set(policy.cloud_gateway_preferences) != set(HUBS):
            raise DestinationPolicyError("Cloud VPC requires preferences for hub1 and hub2")
        for hub_name, gateways in policy.cloud_gateway_preferences.items():
            if len(gateways) != 2 or gateways[0] == gateways[1] or set(gateways) != expected:
                raise DestinationPolicyError(f"Cloud VPC {hub_name} gateway preference must contain both distinct configured gateways")
    elif cloud or policy.cloud_gateway_preferences:
        raise DestinationPolicyError("CLOUD_GATEWAY is a hub-only Cloud VPC egress, not a spoke destination egress")
    if policy.destination_type is DestinationType.SAAS:
        if allowed != {EgressMode.DIRECT_INTERNET} or policy.failure_action is not FailureAction.FAIL_CLOSED:
            raise DestinationPolicyError("public SaaS must use DIRECT_INTERNET only and FAIL_CLOSED")
        if policy.prefix is not None and policy.prefix != ip_network(f"{config.saas_ip}/32"):
            raise DestinationPolicyError("public SaaS prefix must identify the configured SaaS endpoint")
        permitted = {"SAAS_INTERACTIVE", "SAAS_FILE_TRANSFER"}
        if not policy.application_classes or not set(policy.application_classes).issubset(permitted):
            raise DestinationPolicyError("public SaaS requires only SaaS application classes")
    if policy.destination_type is DestinationType.DATA_CENTER:
        if allowed != {EgressMode.HUB_OVERLAY} or policy.failure_action is not FailureAction.FAIL_CLOSED:
            raise DestinationPolicyError("Data Center must use HUB_OVERLAY only and FAIL_CLOSED")
        if policy.prefix is not None and policy.prefix != ip_network(f"{config.data_center_app_ip}/32"):
            raise DestinationPolicyError("Data Center policy must identify the configured backup endpoint")
        if policy.application_classes != ("CENTRAL_BACKUP",):
            raise DestinationPolicyError("Data Center policy requires CENTRAL_BACKUP")
    if policy.destination_type is DestinationType.BRANCH_PRIVATE:
        if allowed != {EgressMode.HUB_OVERLAY} or policy.failure_action is not FailureAction.FAIL_CLOSED:
            raise DestinationPolicyError("branch-private traffic must use HUB_OVERLAY only and FAIL_CLOSED")
        if policy.application_classes != ("REALTIME_RTP",):
            raise DestinationPolicyError("branch-private policy requires REALTIME_RTP")
    if is_default and (policy.destination_type is not DestinationType.UNKNOWN or direct or not hub or policy.failure_action is not FailureAction.FAIL_CLOSED):
        raise DestinationPolicyError("default policy must be conservative Unknown HUB_OVERLAY FAIL_CLOSED")


def document_from_mapping(raw: Mapping[str, Any], config: TopologyConfig) -> DestinationPolicyDocument:
    if int(raw.get("schema_version", 0)) != 5:
        raise DestinationPolicyError("destination policy schema_version must be 5")
    entries = raw.get("policies")
    default = raw.get("default_policy")
    if not isinstance(entries, list) or not isinstance(default, Mapping):
        raise DestinationPolicyError("destination policy requires policies and default_policy")
    policies = tuple(_policy(item, config, is_default=False) for item in entries if isinstance(item, Mapping))
    if len(policies) != len(entries):
        raise DestinationPolicyError("every destination policy must be a mapping")
    default_policy = _policy(default, config, is_default=True)
    ids = [item.policy_id for item in policies]
    prefixes = [item.prefix for item in policies]
    priorities = [item.priority for item in policies]
    if len(ids) != len(set(ids)) or len(prefixes) != len(set(prefixes)) or len(priorities) != len(set(priorities)):
        raise DestinationPolicyError("destination policy IDs, prefixes, and priorities must be unique")
    for index, left in enumerate(policies):
        for right in policies[index + 1:]:
            if left.prefix is not None and right.prefix is not None and left.prefix.overlaps(right.prefix):
                raise DestinationPolicyError("overlapping destination prefixes are ambiguous")
    return DestinationPolicyDocument(5, tuple(sorted(policies, key=lambda item: item.priority)), default_policy)


def load_destination_policy(path: Path, config: TopologyConfig) -> DestinationPolicyDocument:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise DestinationPolicyError(f"cannot read destination policy: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise DestinationPolicyError("destination policy must be a mapping")
    return document_from_mapping(raw, config)
