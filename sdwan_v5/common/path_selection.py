"""SLA-aware path measurement, scoring, and anti-flap selection.

The selector consumes measurements produced by the existing edge path monitor.
It does not classify packets and it cannot expand a destination policy's
allowed egress modes or candidate transports.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
import time
from typing import Iterable

from .marks import EgressMode


class ApplicationClass(str, Enum):
    REALTIME_RTP = "REALTIME_RTP"
    CENTRAL_BACKUP = "CENTRAL_BACKUP"
    SAAS_INTERACTIVE = "SAAS_INTERACTIVE"
    SAAS_FILE_TRANSFER = "SAAS_FILE_TRANSFER"


class NoEligibleAction(str, Enum):
    BEST_EFFORT = "BEST_EFFORT"
    FAIL_CLOSED = "FAIL_CLOSED"


@dataclass(frozen=True)
class ApplicationSLA:
    max_rtt_ms: float | None = None
    max_jitter_ms: float | None = None
    max_loss_pct: float | None = None
    min_estimated_available_bandwidth_mbps: float | None = None
    no_eligible_action: NoEligibleAction = NoEligibleAction.FAIL_CLOSED


@dataclass(frozen=True)
class ScoreWeights:
    rtt: float = 0.0
    jitter: float = 0.0
    loss: float = 0.0
    available_bandwidth: float = 0.0
    transport_cost: float = 0.0

    def validate(self) -> None:
        values = tuple(asdict(self).values())
        if any(value < 0 for value in values) or sum(values) <= 0:
            raise ValueError("path score weights must be non-negative and have a positive sum")


@dataclass(frozen=True)
class SelectionTuning:
    bad_samples_before_degraded: int = 3
    good_samples_before_recovered: int = 5
    minimum_improvement_percent: float = 15.0
    hold_down_seconds: float = 10.0

    def validate(self) -> None:
        if self.bad_samples_before_degraded < 1:
            raise ValueError("bad_samples_before_degraded must be at least 1")
        if self.good_samples_before_recovered < 1:
            raise ValueError("good_samples_before_recovered must be at least 1")
        if self.minimum_improvement_percent < 0:
            raise ValueError("minimum_improvement_percent must be non-negative")
        if self.hold_down_seconds < 0:
            raise ValueError("hold_down_seconds must be non-negative")


@dataclass(frozen=True)
class MeasurementTuning:
    interval_seconds: float = 2.0
    ewma_alpha: float = 0.3
    stale_after_seconds: float = 6.0
    loss_window_samples: int = 10

    def validate(self) -> None:
        if self.interval_seconds <= 0:
            raise ValueError("measurement interval must be positive")
        if not 0 < self.ewma_alpha <= 1:
            raise ValueError("ewma_alpha must be in (0, 1]")
        if self.stale_after_seconds <= 0:
            raise ValueError("stale_after_seconds must be positive")
        if self.loss_window_samples < 1:
            raise ValueError("loss_window_samples must be at least 1")


@dataclass(frozen=True)
class PathMeasurement:
    path_id: str
    transport: str
    egress_mode: EgressMode
    hub: str | None
    interface: str
    configured_capacity_mbps: float
    transport_cost: float
    measured_at_monotonic: float
    administratively_enabled: bool
    operationally_reachable: bool
    rtt_ms: float | None
    jitter_ms: float | None
    loss_pct: float | None
    estimated_available_bandwidth_mbps: float | None

    def is_stale(self, now_monotonic: float, stale_after_seconds: float) -> bool:
        return now_monotonic - self.measured_at_monotonic > stale_after_seconds

    def to_mapping(self) -> dict[str, object]:
        result = asdict(self)
        result["egress_mode"] = self.egress_mode.value
        return result


@dataclass(frozen=True)
class ScoredPath:
    measurement: PathMeasurement
    score: float
    rejection_reasons: tuple[str, ...]
    sla_violations: tuple[str, ...] = ()
    sla_state: str = "ELIGIBLE"
    bad_samples: int = 0
    good_samples: int = 0

    def to_mapping(self) -> dict[str, object]:
        result = self.measurement.to_mapping()
        result.update({
            "score": self.score,
            "rejection_reasons": list(self.rejection_reasons),
            "sla_violations": list(self.sla_violations),
            "sla_state": self.sla_state,
            "bad_samples": self.bad_samples,
            "good_samples": self.good_samples,
        })
        return result


@dataclass(frozen=True)
class PathDecision:
    application_class: ApplicationClass
    source: str
    destination: str
    destination_policy: str
    allowed_egress: tuple[EgressMode, ...]
    candidate_transports: tuple[str, ...]
    candidates: tuple[ScoredPath, ...]
    selected_path: PathMeasurement | None
    selection_reason: str
    changed: bool
    previous_path_id: str | None
    timestamp_monotonic: float
    timestamp: str

    @property
    def eligible_paths(self) -> tuple[ScoredPath, ...]:
        return tuple(item for item in self.candidates if not item.rejection_reasons)

    @property
    def rejected_paths(self) -> tuple[ScoredPath, ...]:
        return tuple(item for item in self.candidates if item.rejection_reasons)

    def to_mapping(self) -> dict[str, object]:
        return {
            "application_class": self.application_class.value,
            "source": self.source,
            "destination": self.destination,
            "destination_policy": self.destination_policy,
            "allowed_egress": [item.value for item in self.allowed_egress],
            "candidate_transports": list(self.candidate_transports),
            "candidate_paths": [item.to_mapping() for item in self.candidates],
            "eligible_paths": [item.to_mapping() for item in self.eligible_paths],
            "rejected_paths": [item.to_mapping() for item in self.rejected_paths],
            "selected_path": self.selected_path.to_mapping() if self.selected_path else None,
            "selection_reason": self.selection_reason,
            "changed": self.changed,
            "previous_path_id": self.previous_path_id,
            "timestamp_monotonic": self.timestamp_monotonic,
            "timestamp": self.timestamp,
        }


class MetricWindow:
    """EWMA metrics plus sliding-window loss and counter-derived bandwidth.

    Jitter is the EWMA of the absolute difference between consecutive raw RTT
    samples. Loss is the mean packet-loss percentage over a bounded probe
    window. Available bandwidth is an estimate: configured capacity minus the
    busiest-direction bit rate derived from interface counters, EWMA-smoothed.
    The first counter sample bootstraps the estimate at configured capacity.
    """

    def __init__(self, tuning: MeasurementTuning, capacity_mbps: float):
        tuning.validate()
        if capacity_mbps <= 0:
            raise ValueError("configured capacity must be positive")
        self.tuning = tuning
        self.capacity_mbps = capacity_mbps
        self.rtt_ms: float | None = None
        self.jitter_ms: float | None = None
        self.available_mbps: float | None = None
        self._previous_rtt_sample: float | None = None
        self._loss_samples: list[float] = []
        self._last_counter: tuple[float, int] | None = None

    def update(
        self,
        *,
        successful: bool,
        rtt_ms: float | None,
        counter_timestamp: float | None = None,
        interface_bytes: int | None = None,
        loss_pct_sample: float | None = None,
        transmitted_packets: int | None = None,
        received_packets: int | None = None,
    ) -> tuple[float | None, float | None, float, float | None]:
        alpha = self.tuning.ewma_alpha
        if successful and rtt_ms is not None:
            previous_ewma = self.rtt_ms
            self.rtt_ms = rtt_ms if previous_ewma is None else alpha * rtt_ms + (1 - alpha) * previous_ewma
            variation = 0.0 if self._previous_rtt_sample is None else abs(rtt_ms - self._previous_rtt_sample)
            self.jitter_ms = variation if self.jitter_ms is None else alpha * variation + (1 - alpha) * self.jitter_ms
            self._previous_rtt_sample = rtt_ms

        if transmitted_packets is not None:
            transmitted = max(0, int(transmitted_packets))
            received = max(0, min(transmitted, int(received_packets or 0)))
            # Preserve the packet denominator across probe rounds. Averaging
            # percentages from three-packet batches quantizes one loss as
            # 33.3%, which creates false SLA violations.
            self._loss_samples.extend(
                [0.0] * received + [100.0] * (transmitted - received)
            )
        else:
            sample_loss = loss_pct_sample if loss_pct_sample is not None else (0.0 if successful else 100.0)
            self._loss_samples.append(min(100.0, max(0.0, sample_loss)))
        self._loss_samples = self._loss_samples[-self.tuning.loss_window_samples:]
        loss_pct = sum(self._loss_samples) / len(self._loss_samples) if self._loss_samples else 100.0

        if counter_timestamp is not None and interface_bytes is not None:
            if self._last_counter is None:
                self.available_mbps = self.capacity_mbps
            else:
                elapsed = counter_timestamp - self._last_counter[0]
                delta = interface_bytes - self._last_counter[1]
                if elapsed > 0 and delta >= 0:
                    used = delta * 8.0 / elapsed / 1_000_000.0
                    available = max(0.0, self.capacity_mbps - used)
                    self.available_mbps = (
                        available if self.available_mbps is None
                        else alpha * available + (1 - alpha) * self.available_mbps
                    )
            self._last_counter = (counter_timestamp, interface_bytes)
        return self.rtt_ms, self.jitter_ms, loss_pct, self.available_mbps


class PathSelector:
    """Stateful lower-score-is-better selector with SLA hysteresis.

    Hysteresis applies to the currently selected path. A new candidate must
    satisfy mandatory SLA thresholds immediately; the current path is retained
    through a configurable number of consecutive bad samples unless it is
    administratively disabled, unreachable, or stale.
    """

    _HARD_REJECTIONS = {
        "EGRESS_NOT_ALLOWED",
        "TRANSPORT_NOT_CANDIDATE",
        "ADMINISTRATIVELY_DISABLED",
        "PATH_DOWN",
        "MEASUREMENT_STALE",
    }

    def __init__(self, tuning: SelectionTuning, *, stale_after_seconds: float):
        tuning.validate()
        if stale_after_seconds <= 0:
            raise ValueError("stale_after_seconds must be positive")
        self.tuning = tuning
        self.stale_after_seconds = stale_after_seconds
        self._selection: dict[tuple[str, str, str], tuple[str, float, float]] = {}
        self._sla_state: dict[tuple[tuple[str, str, str], str], tuple[bool, int, int, tuple[str, ...]]] = {}

    @staticmethod
    def _mandatory_violations(item: PathMeasurement, sla: ApplicationSLA) -> list[str]:
        violations: list[str] = []
        checks = (
            (sla.max_rtt_ms, item.rtt_ms, "SLA_VIOLATION_RTT", lambda value, limit: value > limit),
            (sla.max_jitter_ms, item.jitter_ms, "SLA_VIOLATION_JITTER", lambda value, limit: value > limit),
            (sla.max_loss_pct, item.loss_pct, "SLA_VIOLATION_LOSS", lambda value, limit: value > limit),
            (
                sla.min_estimated_available_bandwidth_mbps,
                item.estimated_available_bandwidth_mbps,
                "SLA_VIOLATION_BANDWIDTH",
                lambda value, limit: value < limit,
            ),
        )
        for limit, value, reason, compare in checks:
            if limit is not None and (value is None or compare(value, limit)):
                suffix = reason.rsplit("_", 1)[-1]
                violations.append(reason if value is not None else f"MEASUREMENT_UNAVAILABLE_{suffix}")
        return violations

    @staticmethod
    def _ratio(value: float | None, reference: float | None, fallback: float = 1.0) -> float:
        if value is None:
            return 2.0
        denominator = reference if reference is not None and reference > 0 else fallback
        return max(0.0, value / denominator)

    def _score(self, item: PathMeasurement, sla: ApplicationSLA, weights: ScoreWeights) -> float:
        weights.validate()
        bandwidth_reference = sla.min_estimated_available_bandwidth_mbps or item.configured_capacity_mbps
        bandwidth_ratio = self._ratio(
            bandwidth_reference,
            item.estimated_available_bandwidth_mbps,
            1.0,
        )
        weighted = (
            weights.rtt * self._ratio(item.rtt_ms, sla.max_rtt_ms, 100.0)
            + weights.jitter * self._ratio(item.jitter_ms, sla.max_jitter_ms, 20.0)
            + weights.loss * self._ratio(item.loss_pct, sla.max_loss_pct, 1.0)
            + weights.available_bandwidth * bandwidth_ratio
            + weights.transport_cost * max(0.0, item.transport_cost)
        )
        return weighted / sum(asdict(weights).values())

    def _evaluate_candidate(
        self,
        *,
        key: tuple[str, str, str],
        item: PathMeasurement,
        sla: ApplicationSLA,
        allowed_egress: set[EgressMode],
        candidate_transports: set[str],
        now: float,
        is_current: bool,
    ) -> tuple[tuple[str, ...], tuple[str, ...], str, int, int]:
        immediate: list[str] = []
        if item.egress_mode not in allowed_egress:
            immediate.append("EGRESS_NOT_ALLOWED")
        if item.transport not in candidate_transports:
            immediate.append("TRANSPORT_NOT_CANDIDATE")
        if not item.administratively_enabled:
            immediate.append("ADMINISTRATIVELY_DISABLED")
        if not item.operationally_reachable:
            immediate.append("PATH_DOWN")
        if item.is_stale(now, self.stale_after_seconds):
            immediate.append("MEASUREMENT_STALE")
        if immediate:
            return tuple(immediate), (), "UNAVAILABLE", 0, 0

        violations = tuple(self._mandatory_violations(item, sla))
        state_key = (key, item.path_id)
        degraded, bad, good, previous_violations = self._sla_state.get(state_key, (False, 0, 0, ()))
        if violations:
            bad, good = bad + 1, 0
            previous_violations = violations
            if bad >= self.tuning.bad_samples_before_degraded:
                degraded = True
        else:
            bad = 0
            if degraded:
                good += 1
                if good >= self.tuning.good_samples_before_recovered:
                    degraded, good, previous_violations = False, 0, ()
            else:
                good = min(good + 1, self.tuning.good_samples_before_recovered)
                previous_violations = ()
        self._sla_state[state_key] = (degraded, bad, good, previous_violations)

        if degraded:
            reasons = violations or previous_violations or ("RECOVERY_HYSTERESIS",)
            state = "DEGRADED" if violations else "PENDING_RECOVERY"
            return tuple(reasons), violations, state, bad, good
        if violations:
            if is_current:
                return (), violations, "PENDING_DEGRADATION", bad, good
            return violations, violations, "SLA_INELIGIBLE", bad, good
        return (), (), "ELIGIBLE", bad, good

    @staticmethod
    def _reason_from_rejections(rejections: tuple[str, ...]) -> str:
        priority = (
            "PATH_DOWN",
            "ADMINISTRATIVELY_DISABLED",
            "MEASUREMENT_STALE",
            "SLA_VIOLATION_JITTER",
            "SLA_VIOLATION_LOSS",
            "SLA_VIOLATION_RTT",
            "SLA_VIOLATION_BANDWIDTH",
            "MEASUREMENT_UNAVAILABLE_JITTER",
            "MEASUREMENT_UNAVAILABLE_LOSS",
            "MEASUREMENT_UNAVAILABLE_RTT",
            "MEASUREMENT_UNAVAILABLE_BANDWIDTH",
            "RECOVERY_HYSTERESIS",
            "EGRESS_NOT_ALLOWED",
            "TRANSPORT_NOT_CANDIDATE",
        )
        for reason in priority:
            if reason in rejections:
                return reason
        return rejections[0] if rejections else "BETTER_SLA_SCORE"

    def select(
        self,
        *,
        application_class: ApplicationClass,
        source: str,
        destination: str,
        destination_policy: str,
        allowed_egress: Iterable[EgressMode],
        candidate_transports: Iterable[str],
        measurements: Iterable[PathMeasurement],
        sla: ApplicationSLA,
        weights: ScoreWeights,
        now_monotonic: float | None = None,
    ) -> PathDecision:
        now = time.monotonic() if now_monotonic is None else now_monotonic
        timestamp = datetime.now(timezone.utc).isoformat()
        key = (application_class.value, source, destination)
        allowed = tuple(allowed_egress)
        transports = tuple(candidate_transports)
        if not allowed or not transports:
            raise ValueError("destination policy must provide allowed egress and candidate transports")
        previous = self._selection.get(key)
        previous_id = previous[0] if previous else None
        allowed_set, transport_set = set(allowed), set(transports)

        evaluated: list[ScoredPath] = []
        for item in measurements:
            rejections, violations, state, bad, good = self._evaluate_candidate(
                key=key,
                item=item,
                sla=sla,
                allowed_egress=allowed_set,
                candidate_transports=transport_set,
                now=now,
                is_current=item.path_id == previous_id,
            )
            evaluated.append(ScoredPath(
                item,
                self._score(item, sla, weights),
                rejections,
                violations,
                state,
                bad,
                good,
            ))
        candidates = tuple(evaluated)
        eligible = sorted(
            (item for item in candidates if not item.rejection_reasons),
            key=lambda item: (item.score, item.measurement.path_id),
        )
        fallback_used = False
        if not eligible and sla.no_eligible_action is NoEligibleAction.BEST_EFFORT:
            eligible = sorted(
                (
                    item for item in candidates
                    if not any(reason in self._HARD_REJECTIONS for reason in item.rejection_reasons)
                ),
                key=lambda item: (item.score, item.measurement.path_id),
            )
            fallback_used = bool(eligible)

        if not eligible:
            changed = previous_id is not None
            return PathDecision(
                application_class,
                source,
                destination,
                destination_policy,
                allowed,
                transports,
                candidates,
                None,
                "NO_ELIGIBLE_PATH",
                changed,
                previous_id,
                now,
                timestamp,
            )

        best = eligible[0]
        selected = best
        reason = "NO_ELIGIBLE_PATH_BEST_EFFORT" if fallback_used else "INITIAL_BEST_ELIGIBLE"

        if previous is not None:
            current_candidate = next(
                (item for item in candidates if item.measurement.path_id == previous_id),
                None,
            )
            current_eligible = next(
                (item for item in eligible if item.measurement.path_id == previous_id),
                None,
            )
            if current_eligible is not None and current_eligible.sla_state == "PENDING_DEGRADATION":
                selected = current_eligible
                pending = current_eligible.sla_violations[0] if current_eligible.sla_violations else "SLA_VIOLATION"
                reason = f"{pending}_PENDING_HYSTERESIS"
            elif current_eligible is None:
                reason = self._reason_from_rejections(
                    current_candidate.rejection_reasons if current_candidate else ("PATH_DOWN",)
                )
                if fallback_used:
                    reason = "NO_ELIGIBLE_PATH_BEST_EFFORT"
            elif best.measurement.path_id == previous_id:
                selected = current_eligible
                reason = "RETAIN_CURRENT_PATH"
            else:
                improvement = (
                    100.0 if current_eligible.score <= 0
                    else 100.0 * (current_eligible.score - best.score) / current_eligible.score
                )
                if now - previous[2] < self.tuning.hold_down_seconds:
                    selected, reason = current_eligible, "HOLD_DOWN_RETAINED"
                elif improvement < self.tuning.minimum_improvement_percent:
                    selected, reason = current_eligible, "MINIMUM_IMPROVEMENT_NOT_MET"
                else:
                    reason = (
                        "HIGHER_AVAILABLE_BANDWIDTH"
                        if weights.available_bandwidth >= max(weights.rtt, weights.jitter, weights.loss)
                        else "BETTER_SLA_SCORE"
                    )

        changed = previous_id is not None and previous_id != selected.measurement.path_id
        switched_at = now if changed or previous is None else previous[2]
        self._selection[key] = (selected.measurement.path_id, selected.score, switched_at)
        return PathDecision(
            application_class,
            source,
            destination,
            destination_policy,
            allowed,
            transports,
            candidates,
            selected.measurement,
            reason,
            changed,
            previous_id,
            now,
            timestamp,
        )
