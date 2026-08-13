"""Central monotonically versioned prefix owner transitions."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Callable

from .persistence.policy_store import PolicyStore


@dataclass(frozen=True)
class OwnershipRecord:
    prefix: str
    spoke: str
    preferred_hub: str
    standby_hub: str
    current_owner_hub: str
    previous_owner_hub: str | None
    owner_epoch: int
    policy_version: int
    route_version: int
    state: str
    reason: str
    pending_reconciliation: bool
    valid_until: str | None = None


class OwnershipCoordinator:
    """Policy-service authority; it never requires failed-owner acknowledgement."""

    def __init__(self, store: PolicyStore):
        self.store = store

    def transfer(
        self,
        current: OwnershipRecord,
        *,
        new_owner: str,
        new_owner_usable: Callable[[], bool],
        old_owner_reachable: bool,
        actor: str,
        reason: str,
    ) -> OwnershipRecord:
        if new_owner not in {current.preferred_hub, current.standby_hub}:
            raise ValueError("new owner is not a site-assigned hub")
        if not new_owner_usable():
            raise RuntimeError("standby/new owner is not safe to receive traffic")
        if new_owner == current.current_owner_hub:
            return current
        next_record = OwnershipRecord(
            prefix=current.prefix, spoke=current.spoke, preferred_hub=current.preferred_hub, standby_hub=current.standby_hub,
            current_owner_hub=new_owner, previous_owner_hub=current.current_owner_hub,
            owner_epoch=current.owner_epoch + 1, policy_version=current.policy_version, route_version=current.route_version + 1,
            state="COMMITTED", reason=reason, pending_reconciliation=not old_owner_reachable,
        )
        self.store.transfer_ownership(asdict(next_record), actor)
        return next_record
