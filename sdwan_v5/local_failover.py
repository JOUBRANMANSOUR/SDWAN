"""Serialized local route-slot emergency transitions and baseline failback."""
from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from typing import Callable, Mapping


class StaleRouteVersion(ValueError):
    pass


@dataclass(frozen=True)
class SlotTarget:
    hub: str
    transport: str
    interface: str
    route_table: int


@dataclass(frozen=True)
class LocalFailoverEvent:
    event_id: str
    site: str
    slot: str
    old_target: SlotTarget
    new_target: SlotTarget
    reason: str
    local_route_version: int
    monotonic_timestamp: float


@dataclass
class _SlotState:
    current: SlotTarget
    previous_confirmed: SlotTarget
    emergency: bool = False
    drain_deadline: float | None = None


class LocalFailoverManager:
    def __init__(self, site: str, targets: Mapping[str, SlotTarget], *, drain_timeout_s: float):
        if drain_timeout_s <= 0:
            raise ValueError("drain timeout must be positive")
        self.site = site
        self._slots = {name: _SlotState(target, target) for name, target in targets.items()}
        self.drain_timeout_s = drain_timeout_s
        self.route_version = 0
        self._events: dict[str, LocalFailoverEvent] = {}
        self._lock = threading.RLock()

    def target(self, slot: str) -> SlotTarget:
        return self._slots[slot].current

    @property
    def slots(self) -> tuple[str, ...]:
        return tuple(self._slots)

    def is_emergency(self, slot: str) -> bool:
        return self._slots[slot].emergency

    def previous_target(self, slot: str) -> SlotTarget:
        return self._slots[slot].previous_confirmed
    def emergency_remap(self, *, event_id: str, slot: str, replacement: SlotTarget, reason: str, expected_version: int | None = None, now: float | None = None) -> LocalFailoverEvent:
        with self._lock:
            if event_id in self._events:
                return self._events[event_id]
            if expected_version is not None and expected_version != self.route_version:
                raise StaleRouteVersion("local route version changed before emergency transaction")
            state = self._slots[slot]
            if state.current == replacement:
                raise ValueError("emergency replacement must change target")
            old = state.current
            state.previous_confirmed, state.current, state.emergency, state.drain_deadline = old, replacement, True, None
            self.route_version += 1
            event = LocalFailoverEvent(event_id, self.site, slot, old, replacement, reason, self.route_version, time.monotonic() if now is None else now)
            self._events[event_id] = event
            return event

    def begin_recovery(self, slot: str, *, now: float | None = None) -> None:
        with self._lock:
            state = self._slots[slot]
            if not state.emergency:
                return
            state.drain_deadline = (time.monotonic() if now is None else now) + self.drain_timeout_s

    def complete_recovery(self, slot: str, active_flows: int, *, now: float | None = None) -> SlotTarget | None:
        with self._lock:
            state = self._slots[slot]
            if not state.emergency or state.drain_deadline is None:
                return None
            instant = time.monotonic() if now is None else now
            if active_flows > 0 and instant < state.drain_deadline:
                return None
            state.current = state.previous_confirmed
            state.emergency, state.drain_deadline = False, None
            self.route_version += 1
            return state.current
