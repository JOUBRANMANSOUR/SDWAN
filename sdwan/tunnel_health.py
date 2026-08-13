"""Freshness-aware local tunnel state machine; raw samples stay outside databases."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import time


class TunnelState(str, Enum):
    UNKNOWN = "UNKNOWN"
    HEALTHY = "HEALTHY"
    SUSPECT = "SUSPECT"
    FAILED = "FAILED"
    RECOVERING = "RECOVERING"


@dataclass(frozen=True)
class TunnelSample:
    site: str
    hub: str
    transport: str
    interface: str
    wall_timestamp: float
    monotonic_timestamp: float
    probe_sequence: int
    source: str
    link_up: bool
    underlay_reachable: bool
    wireguard_up: bool
    overlay_reachable: bool
    handshake_age_s: float | None
    rtt_ms: float | None = None
    jitter_ms: float | None = None
    loss_pct: float | None = None

    @property
    def usable(self) -> bool:
        # A recent handshake is supportive evidence.  Overlay probes decide
        # liveness so idle but usable tunnels are not declared failed solely by age.
        return self.link_up and self.underlay_reachable and self.wireguard_up and self.overlay_reachable


@dataclass(frozen=True)
class TunnelHealth:
    state: TunnelState
    successes: int
    failures: int
    last_sequence: int
    last_reason: str
    hold_down_until: float
    last_success_monotonic: float | None


class StaleMeasurement(ValueError):
    pass


class TunnelHealthMachine:
    def __init__(self, *, suspect_failures: int, failed_failures: int, recovery_successes: int, hold_down_s: float, stale_after_s: float):
        if not (0 < suspect_failures < failed_failures and recovery_successes > 0 and hold_down_s >= 0 and stale_after_s > 0):
            raise ValueError("invalid health thresholds")
        self.suspect_failures = suspect_failures
        self.failed_failures = failed_failures
        self.recovery_successes = recovery_successes
        self.hold_down_s = hold_down_s
        self.stale_after_s = stale_after_s
        self._health = TunnelHealth(TunnelState.UNKNOWN, 0, 0, -1, "not measured", 0.0, None)

    @property
    def health(self) -> TunnelHealth:
        return self._health

    def observe(self, sample: TunnelSample, *, now_monotonic: float | None = None) -> TunnelHealth:
        now = time.monotonic() if now_monotonic is None else now_monotonic
        if sample.probe_sequence <= self._health.last_sequence:
            raise StaleMeasurement("duplicate or out-of-order probe sequence")
        if now - sample.monotonic_timestamp > self.stale_after_s:
            raise StaleMeasurement("stale probe sample")
        old = self._health
        if sample.usable:
            successes, failures = old.successes + 1, 0
            if old.state is TunnelState.FAILED:
                state, reason = TunnelState.RECOVERING, "first usable probe after failure"
            elif old.state is TunnelState.RECOVERING:
                if successes >= self.recovery_successes and now >= old.hold_down_until:
                    state, reason = TunnelState.HEALTHY, "recovery threshold and hold-down complete"
                else:
                    state, reason = TunnelState.RECOVERING, "awaiting recovery threshold or hold-down"
            else:
                state, reason = TunnelState.HEALTHY, "usable active overlay probe"
            self._health = TunnelHealth(state, successes, failures, sample.probe_sequence, reason, old.hold_down_until, sample.monotonic_timestamp)
            return self._health
        failures, successes = old.failures + 1, 0
        hold_down_until = max(old.hold_down_until, now + self.hold_down_s)
        if failures >= self.failed_failures:
            state, reason = TunnelState.FAILED, "consecutive failure threshold reached"
        elif failures >= self.suspect_failures:
            state, reason = TunnelState.SUSPECT, "consecutive suspect threshold reached"
        else:
            state, reason = old.state, "single failed observation"
        self._health = TunnelHealth(state, successes, failures, sample.probe_sequence, reason, hold_down_until, old.last_success_monotonic)
        return self._health
