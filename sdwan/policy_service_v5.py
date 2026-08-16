"""Persistent Policy Service core; no packet, nDPI or OpenFlow decision path."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .common.model import TopologyConfig
from .desired_state_v5 import DesiredState, build_hub_desired_state, build_spoke_desired_state
from .persistence.policy_store import PolicyStore
from .dynamic_control import DynamicInventory, IntentCompiler, InventorySite


@dataclass(frozen=True)
class ActivationResult:
    site: str
    state: str
    detail: str
    desired_state: DesiredState | None


class PolicyService:
    def __init__(self, config: TopologyConfig, database: Path):
        self.base_config = config
        self.store = PolicyStore(database)
        self.inventory = DynamicInventory(self.store)
        self.inventory.seed_from_config(config, actor="policy-seed")
        self.config = self.inventory.topology(config)
        self.compiler = IntentCompiler(self.store, self.inventory, config)

    def stage_inventory(self, actor: str = "admin") -> None:
        self.inventory.seed_from_config(self.base_config, actor=actor)
        self.config = self.inventory.topology(self.base_config)

    def create_site(self, *, site: str, device_id: str, preferred_hub: str, standby_hub: str, actor: str) -> InventorySite:
        record = self.inventory.allocate(site=site, device_id=device_id, preferred_hub=preferred_hub, standby_hub=standby_hub, actor=actor)
        self.config = self.inventory.topology(self.base_config)
        self.compiler.compile(actor="policy-compiler")
        return record

    def transition_site(self, site: str, lifecycle: str, *, actor: str, error: str | None = None, operation_id: str | None = None, failure_stage: str | None = None, recoverable: bool = True) -> InventorySite:
        record = self.inventory.transition(site, lifecycle, actor=actor, error=error, operation_id=operation_id, failure_stage=failure_stage, recoverable=recoverable)
        self.config = self.inventory.topology(self.base_config)
        self.compiler.compile(actor="policy-compiler")
        return record

    def compile_control_state(self, *, actor: str = "policy-compiler") -> dict[str, Any]:
        self.config = self.inventory.topology(self.base_config)
        return self.compiler.compile(actor=actor)

    def register_edge_identity(self, site: str, public_key: str, *, actor: str) -> dict[str, str]:
        if site not in self.config.hubs:
            try:
                site = self.config.logical_site(site)
            except KeyError:
                pass
        """Register only an authenticated edge public key and publish hub intent.

        A spoke is intentionally not activated here: both hubs must first
        reconcile the peer update that contains this spoke.
        """
        if site not in self.config.site_names:
            raise ValueError("unknown edge site")
        repeated = self.store.register_wireguard_public_key(site, public_key, actor)
        self.stage_inventory(actor="policy")
        record = self.inventory.get(site)
        if record is not None and site not in self.config.hubs:
            # The Edge has already enrolled before it can authenticate this
            # request.  These transitions retain that evidence without moving
            # key generation, CSR generation, or enrollment into Policy.
            if record.lifecycle == "ZTP_STAGED":
                self.transition_site(site, "ENROLLING", actor="policy")
                record = self.inventory.get(site)
            if record is not None and record.lifecycle == "ENROLLING":
                self.transition_site(site, "ENROLLED", actor="policy")
                record = self.inventory.get(site)
            if record is not None and record.lifecycle == "ENROLLED":
                self.transition_site(site, "REGISTERING", actor="policy")
                record = self.inventory.get(site)
            if record is not None and record.lifecycle == "REGISTERING":
                self.transition_site(site, "PROVISIONING", actor="policy")
        self.compile_control_state(actor="policy-compiler")
        state = "HUB_READY" if site in self.config.hubs else "PENDING_HUBS"
        return {"site": site, "registration": "IDEMPOTENT" if repeated else "RECORDED", "state": state}

    def _publish_hub_desired_states(self, keys: Mapping[str, str], *, actor: str) -> None:
        self.compile_control_state(actor=actor)

    def desired_state_for(self, site: str) -> dict[str, Any] | None:
        state = self.store.latest_desired_state(site)
        record = self.inventory.get(site)
        if state is None or record is None:
            return state
        result = dict(state)
        result["site_profile"] = record.__dict__.copy()
        return result

    def acknowledge_edge(self, site: str, version: int, state_digest: str, route_version: int, status: str, detail: str) -> None:
        self.store.ack_desired_state(site, version, state_digest, route_version, status, detail)
        record = self.inventory.get(site)
        if status == "VERIFIED" and record is not None and record.lifecycle in {"PROVISIONING", "RECONCILING"}:
            self.transition_site(site, "ACTIVE", actor="policy")
        # An ACK records application of existing desired state; it is not a control-plane input and must not create a new revision.

    def activate_spoke(self, site: str, *, actor: str) -> ActivationResult:
        if site not in self.config.sites:
            raise ValueError("only configured spokes can be activated")
        keys = self.store.active_wireguard_public_keys()
        if not {"hub1", "hub2", site}.issubset(keys):
            return ActivationResult(site, "PENDING_HUBS", "spoke and both hub public keys are required", None)
        if not (self.store.latest_desired_state_is_verified("hub1") and self.store.latest_desired_state_is_verified("hub2")):
            return ActivationResult(site, "PENDING_HUBS", "both hubs must verify the current peer desired state", None)
        existing_desired = self.store.latest_desired_state(site)
        if existing_desired is not None:
            return ActivationResult(site, "EDGE_CONFIGURING", "existing spoke desired state is available for reconciliation", None)
        profile = self.config.sites[site]
        addresses = [
            (str(self.config.overlay_ip(site, target.hub, target.transport)), target.hub, target.transport, target.interface_name)
            for target in self.config.spoke_targets(site)
        ]
        ports = [
            (site, self.config.wireguard_port(site, target.hub, target.transport), target.interface_name)
            for target in self.config.spoke_targets(site)
        ]
        try:
            self.store.reserve_resources(site, addresses, ports, actor)
        except Exception as exc:
            return ActivationResult(site, "PENDING_RECONCILIATION", f"resource reservation failed: {exc}", None)
        existing = self.store.route_owner(str(profile.lan_network))
        epoch = 1 if existing is None else int(existing["owner_epoch"]) + 1
        route_version = epoch
        ownership = {
            "prefix": str(profile.lan_network), "spoke": site,
            "preferred_hub": profile.preferred_hub, "standby_hub": profile.standby_hub,
            "current_owner_hub": profile.preferred_hub,
            "previous_owner_hub": None if existing is None else str(existing["current_owner_hub"]),
            "owner_epoch": epoch, "policy_version": epoch, "route_version": route_version,
            "state": "PREPARED", "reason": "hub-first initial activation", "pending_reconciliation": False,
        }
        self.store.transfer_ownership(ownership, actor)
        version = self.store.next_desired_state_version(site)
        desired = build_spoke_desired_state(
            self.config, site, {hub: keys[hub] for hub in ("hub1", "hub2")},
            generation=f"policy-{site}-{version}", desired_state_version=version,
            route_version=route_version, ownership_epoch=epoch,
        )
        self.store.put_desired_state(desired.to_dict(), actor)
        return ActivationResult(site, "EDGE_CONFIGURING", "both hubs verified; spoke desired state published", desired)

    def hub_first_activate(
        self,
        site: str,
        public_keys: Mapping[str, str],
        *,
        generation: str,
        desired_state_version: int,
        ownership_epoch: int,
        prepare_hub: Callable[[str, str], bool],
        apply_spoke: Callable[[DesiredState], bool],
        actor: str = "policy",
    ) -> ActivationResult:
        if site not in self.config.sites:
            raise ValueError("site is not a staged spoke")
        for hub in ("hub1", "hub2"):
            if not prepare_hub(hub, site):
                return ActivationResult(site, "PENDING_HUBS", f"{hub} preparation/verification failed", None)
        desired = build_spoke_desired_state(self.config, site, public_keys, generation=generation, desired_state_version=desired_state_version, route_version=desired_state_version, ownership_epoch=ownership_epoch)
        payload = desired.to_dict()
        self.store.put_desired_state(payload, actor)
        if not apply_spoke(desired):
            return ActivationResult(site, "PENDING_RECONCILIATION", "both hubs prepared; spoke apply/verify pending", desired)
        self.store.ack_desired_state(site, desired_state_version, payload["configuration_digest"], desired_state_version, "VERIFIED", "six interfaces/peers verified")
        return ActivationResult(site, "ACTIVE", "both hubs prepared and spoke verified", desired)

    def reconcile_edge_report(self, site: str, desired_version: int, route_version: int, status: str) -> str:
        row = self.store.connection.execute("SELECT route_version FROM desired_states WHERE site = ? AND version = ?", (site, desired_version)).fetchone()
        if row is None:
            return "STALE"
        if route_version > int(row["route_version"]):
            return "EDGE_AHEAD"
        return status
