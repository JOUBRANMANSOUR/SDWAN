"""Edge-local healthy target resolution; nDPI never calls this component."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .common.marks import EgressMode
from .hub_health import HubState
from .tunnel_health import TunnelState


@dataclass(frozen=True)
class Target:
    hub: str | None
    transport: str
    interface: str
    egress_mode: EgressMode
    tunnel_state: TunnelState
    hub_state: HubState | None
    rtt_ms: float = 0.0
    jitter_ms: float = 0.0
    loss_pct: float = 0.0
    available_mbps: float = 0.0
    cost: float = 0.0

    @property
    def healthy(self) -> bool:
        if self.egress_mode is EgressMode.HUB_OVERLAY:
            return self.tunnel_state is TunnelState.HEALTHY and self.hub_state in {HubState.HEALTHY, HubState.DEGRADED}
        return self.tunnel_state is TunnelState.HEALTHY


@dataclass(frozen=True)
class Resolution:
    slot: str
    target: Target
    reason: str


class RouteResolver:
    """Stable resolver for central policy constraints plus current local health.

    Input comes from Policy Service and health machines, not nDPI.  nDPI only
    creates the application metadata/transport mark that selected `slot`.
    """

    def resolve(
        self,
        *,
        slot: str,
        ranked_transports: Iterable[str],
        allowed_egress: Iterable[EgressMode],
        preferred_hub: str,
        standby_hub: str,
        targets: Iterable[Target],
        current: Target | None = None,
        hard_failure: bool = False,
    ) -> Resolution:
        allowed = tuple(allowed_egress)
        available = tuple(targets)
        if current and current.healthy and not hard_failure and current.egress_mode in allowed:
            return Resolution(slot, current, "retain healthy stable target")
        for egress in allowed:
            for transport in ranked_transports:
                candidates = [item for item in available if item.egress_mode is egress and item.transport == transport and item.healthy]
                candidates.sort(key=lambda item: (0 if item.hub == preferred_hub else 1 if item.hub == standby_hub else 2, item.loss_pct, item.jitter_ms, item.rtt_ms, -item.available_mbps, item.cost, item.interface))
                if candidates:
                    return Resolution(slot, candidates[0], "first locally healthy policy-eligible target")
        raise LookupError(f"no healthy target for route slot {slot}")
