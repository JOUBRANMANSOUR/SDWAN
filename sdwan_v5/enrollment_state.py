"""Explicit, audited zero-touch enrollment state machine."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class EnrollmentState(str, Enum):
    UNCLAIMED = "UNCLAIMED"
    BOOTSTRAP_NETWORK_READY = "BOOTSTRAP_NETWORK_READY"
    DISCOVERED = "DISCOVERED"
    ENROLLING = "ENROLLING"
    AUTHENTICATED = "AUTHENTICATED"
    SITE_ASSIGNED = "SITE_ASSIGNED"
    HUBS_PREPARING = "HUBS_PREPARING"
    EDGE_CONFIGURING = "EDGE_CONFIGURING"
    VERIFYING = "VERIFYING"
    ACTIVE = "ACTIVE"
    RETRY_WAIT = "RETRY_WAIT"
    PENDING_HUBS = "PENDING_HUBS"
    PENDING_RECONCILIATION = "PENDING_RECONCILIATION"
    QUARANTINED = "QUARANTINED"
    FAILED = "FAILED"
    REVOKED = "REVOKED"


_TRANSITIONS: Mapping[EnrollmentState, set[EnrollmentState]] = {
    EnrollmentState.UNCLAIMED: {EnrollmentState.BOOTSTRAP_NETWORK_READY, EnrollmentState.QUARANTINED},
    EnrollmentState.BOOTSTRAP_NETWORK_READY: {EnrollmentState.DISCOVERED, EnrollmentState.RETRY_WAIT, EnrollmentState.FAILED},
    EnrollmentState.DISCOVERED: {EnrollmentState.ENROLLING, EnrollmentState.RETRY_WAIT, EnrollmentState.QUARANTINED},
    EnrollmentState.ENROLLING: {EnrollmentState.AUTHENTICATED, EnrollmentState.RETRY_WAIT, EnrollmentState.FAILED, EnrollmentState.QUARANTINED},
    EnrollmentState.AUTHENTICATED: {EnrollmentState.SITE_ASSIGNED, EnrollmentState.QUARANTINED},
    EnrollmentState.SITE_ASSIGNED: {EnrollmentState.HUBS_PREPARING, EnrollmentState.PENDING_HUBS, EnrollmentState.FAILED},
    EnrollmentState.HUBS_PREPARING: {EnrollmentState.EDGE_CONFIGURING, EnrollmentState.PENDING_HUBS, EnrollmentState.PENDING_RECONCILIATION, EnrollmentState.FAILED},
    EnrollmentState.PENDING_HUBS: {EnrollmentState.HUBS_PREPARING, EnrollmentState.RETRY_WAIT, EnrollmentState.FAILED},
    EnrollmentState.EDGE_CONFIGURING: {EnrollmentState.VERIFYING, EnrollmentState.RETRY_WAIT, EnrollmentState.FAILED},
    EnrollmentState.VERIFYING: {EnrollmentState.ACTIVE, EnrollmentState.PENDING_RECONCILIATION, EnrollmentState.FAILED},
    EnrollmentState.PENDING_RECONCILIATION: {EnrollmentState.VERIFYING, EnrollmentState.ACTIVE, EnrollmentState.RETRY_WAIT, EnrollmentState.FAILED},
    EnrollmentState.RETRY_WAIT: {EnrollmentState.DISCOVERED, EnrollmentState.ENROLLING, EnrollmentState.HUBS_PREPARING, EnrollmentState.EDGE_CONFIGURING, EnrollmentState.FAILED},
    EnrollmentState.ACTIVE: {EnrollmentState.PENDING_RECONCILIATION, EnrollmentState.REVOKED, EnrollmentState.FAILED},
    EnrollmentState.FAILED: {EnrollmentState.RETRY_WAIT, EnrollmentState.QUARANTINED, EnrollmentState.REVOKED},
    EnrollmentState.QUARANTINED: {EnrollmentState.REVOKED},
    EnrollmentState.REVOKED: set(),
}


class InvalidEnrollmentTransition(ValueError):
    pass


@dataclass(frozen=True)
class EnrollmentTransition:
    device_id: str
    site: str | None
    previous: EnrollmentState
    current: EnrollmentState
    reason: str
    event_id: str
    timestamp: str
    desired_state_version: int | None = None


def transition(
    device_id: str,
    site: str | None,
    previous: EnrollmentState,
    current: EnrollmentState,
    *,
    reason: str,
    event_id: str,
    timestamp: str,
    desired_state_version: int | None = None,
) -> EnrollmentTransition:
    if current not in _TRANSITIONS[previous]:
        raise InvalidEnrollmentTransition(f"{previous.value} -> {current.value} is invalid")
    if not reason or not event_id:
        raise InvalidEnrollmentTransition("every transition needs a reason and event identifier")
    return EnrollmentTransition(device_id, site, previous, current, reason, event_id, timestamp, desired_state_version)
