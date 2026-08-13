"""Edge-local healthy target resolution; nDPI never calls this component."""
from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Iterable

from .common.marks import EgressMode
from .common.path_selection import (
    ApplicationClass, ApplicationSLA, PathDecision, PathMeasurement,
    PathSelector, ScoreWeights,
)
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
    rtt_ms: float | None = None
    jitter_ms: float | None = None
    loss_pct: float | None = None
    available_mbps: float | None = None
    administratively_enabled: bool = True
    measured_at_monotonic: float = 0.0
    configured_capacity_mbps: float = 0.0
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


@dataclass(frozen=True)
class SLAResolution:
    resolution: Resolution | None
    decision: PathDecision


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
                candidates.sort(key=lambda item: (
                    0 if item.hub == preferred_hub else 1 if item.hub == standby_hub else 2,
                    item.loss_pct if item.loss_pct is not None else 101.0,
                    item.jitter_ms if item.jitter_ms is not None else float("inf"),
                    item.rtt_ms if item.rtt_ms is not None else float("inf"),
                    -(item.available_mbps if item.available_mbps is not None else 0.0),
                    item.cost, item.interface,
                ))
                if candidates:
                    return Resolution(slot, candidates[0], "first locally healthy policy-eligible target")
        raise LookupError(f"no healthy target for route slot {slot}")

    def resolve_sla(
        self, *, selector: PathSelector, application_class: ApplicationClass,
        source: str, destination: str, destination_policy: str,
        allowed_egress: Iterable[EgressMode], candidate_transports: Iterable[str],
        targets: Iterable[Target], sla: ApplicationSLA, weights: ScoreWeights,
        now_monotonic: float | None = None,
    ) -> SLAResolution:
        """Choose only among policy-permitted paths using current measurements."""
        now = time.monotonic() if now_monotonic is None else now_monotonic
        available = tuple(targets)
        measurements = tuple(
            PathMeasurement(
                path_id=item.interface,
                transport=item.transport,
                egress_mode=item.egress_mode,
                hub=item.hub,
                interface=item.interface,
                configured_capacity_mbps=item.configured_capacity_mbps or max(item.available_mbps or 0.0, 1.0),
                transport_cost=item.cost,
                measured_at_monotonic=item.measured_at_monotonic or now,
                administratively_enabled=item.administratively_enabled,
                operationally_reachable=item.healthy,
                rtt_ms=item.rtt_ms,
                jitter_ms=item.jitter_ms,
                loss_pct=item.loss_pct,
                estimated_available_bandwidth_mbps=item.available_mbps,
            )
            for item in available
        )
        decision = selector.select(
            application_class=application_class, source=source, destination=destination,
            destination_policy=destination_policy, allowed_egress=allowed_egress,
            candidate_transports=candidate_transports, measurements=measurements,
            sla=sla, weights=weights, now_monotonic=now,
        )
        if decision.selected_path is None:
            return SLAResolution(None, decision)
        selected = next(
            item for item in available
            if item.interface == decision.selected_path.interface
            and item.egress_mode is decision.selected_path.egress_mode
        )
        return SLAResolution(
            Resolution(application_class.value, selected, decision.selection_reason), decision,
        )
