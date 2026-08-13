"""Hub aggregation that does not equate one tunnel failure with a lost hub."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from .tunnel_health import TunnelHealth, TunnelState


class HubState(str, Enum):
    UNKNOWN = "UNKNOWN"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNREACHABLE = "UNREACHABLE"
    RECOVERING = "RECOVERING"


@dataclass(frozen=True)
class HubHealth:
    hub: str
    state: HubState
    healthy_tunnels: int
    failed_tunnels: int
    recovering_tunnels: int
    reason: str


def aggregate_hub(hub: str, tunnels: Mapping[str, TunnelHealth]) -> HubHealth:
    if not tunnels:
        return HubHealth(hub, HubState.UNKNOWN, 0, 0, 0, "no tunnel measurements")
    states = [value.state for value in tunnels.values()]
    healthy = sum(state is TunnelState.HEALTHY for state in states)
    failed = sum(state is TunnelState.FAILED for state in states)
    recovering = sum(state is TunnelState.RECOVERING for state in states)
    if failed == len(states):
        return HubHealth(hub, HubState.UNREACHABLE, healthy, failed, recovering, "all spoke-to-hub tunnels failed")
    if recovering and healthy == 0:
        return HubHealth(hub, HubState.RECOVERING, healthy, failed, recovering, "only recovering tunnels are usable candidates")
    if healthy == len(states):
        return HubHealth(hub, HubState.HEALTHY, healthy, failed, recovering, "all monitored tunnels healthy")
    return HubHealth(hub, HubState.DEGRADED, healthy, failed, recovering, "one or more but not all tunnels are impaired")
