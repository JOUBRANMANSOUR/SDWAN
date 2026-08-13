"""Authoritative dynamic branch inventory and event-driven policy compilation.

This module is owned by :class:`PolicyService`.  It has no packet, shell, or
Docker control path; it only stores typed administrative intent and compiles
the normal per-site desired state consumed by existing agents.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
import json
import re
from typing import Any, Mapping

from .common.model import HUBS, Site, TopologyConfig
from .desired_state_v5 import build_hub_desired_state, build_spoke_desired_state
from .persistence.base import utc_now
from .persistence.policy_store import PolicyStore, canonical_json


class InventoryError(ValueError):
    """A typed inventory or intent request could not be accepted."""


_SITE_NAME = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_ACTIVE_CONFIGURATION_STATES = {"TOPOLOGY_CREATED", "ZTP_STAGED", "ENROLLING", "ENROLLED", "REGISTERING", "PROVISIONING", "PENDING_HUBS", "RECONCILING", "ACTIVE"}
_TRANSITIONS = {
    "ALLOCATING": {"TOPOLOGY_CREATED", "FAILED", "DELETING"},
    "TOPOLOGY_CREATED": {"ZTP_STAGED", "FAILED", "DELETING"},
    "ZTP_STAGED": {"ENROLLING", "FAILED", "DELETING"},
    "ENROLLING": {"ENROLLED", "FAILED", "DELETING"},
    "ENROLLED": {"REGISTERING", "FAILED", "DELETING"},
    "REGISTERING": {"PROVISIONING", "FAILED", "DELETING"},
    "PROVISIONING": {"PENDING_HUBS", "RECONCILING", "ACTIVE", "FAILED", "DELETING"},
    "PENDING_HUBS": {"RECONCILING", "FAILED", "DELETING"},
    "RECONCILING": {"ACTIVE", "PENDING_HUBS", "FAILED", "DELETING"},
    "ACTIVE": {"DELETING", "FAILED"},
    # A recoverable failure resumes at the last proven boundary.  In
    # particular, PROVISIONING means Edge-local enrollment and public-key
    # registration already succeeded and must not be repeated.
    "FAILED": {"TOPOLOGY_CREATED", "PROVISIONING", "RECONCILING", "DELETING"},
    "DELETING": {"DELETED", "FAILED"},
    "DELETED": {"ALLOCATING"},
    # Legacy states remain readable/migratable for pre-existing lab databases.
    "REQUESTED": {"ALLOCATING", "FAILED"},
    "ALLOCATED": {"TOPOLOGY_CREATED", "ZTP_STAGED", "FAILED", "DELETING"},
    "DECOMMISSIONING": {"REVOKED", "DELETED", "FAILED"},
    "REVOKED": {"DELETED"},
}



@dataclass(frozen=True)
class InventorySite:
    site: str
    device_id: str
    lifecycle: str
    address_id: int
    wireguard_index: int
    management_ip: str
    lan_prefix: str
    lan_gateway: str
    lan_switch: str
    lan_dpid: int
    host_name: str
    host_ip: str
    interface_suffix: str
    preferred_hub: str
    standby_hub: str
    runtime_status: str
    last_error: str | None
    failure_stage: str | None
    recoverable: int
    created_at: str
    updated_at: str
    deleted_at: str | None

    def to_site(self) -> Site:
        return Site(
            name=self.site, address_id=self.address_id,
            management_ip=ip_address(self.management_ip),
            lan_network=ip_network(self.lan_prefix), lan_gateway=ip_address(self.lan_gateway),
            lan_switch=self.lan_switch, lan_dpid=self.lan_dpid,
            host_name=self.host_name, host_ip=ip_address(self.host_ip),
            preferred_hub=self.preferred_hub, standby_hub=self.standby_hub,
            device_id=self.device_id, wireguard_index=self.wireguard_index,
            interface_suffix=self.interface_suffix,
        )


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class DynamicInventory:
    """Policy-owned site inventory with deterministic collision-safe allocation."""

    def __init__(self, store: PolicyStore):
        self.store = store

    @staticmethod
    def _record(row: Mapping[str, Any]) -> InventorySite:
        values = dict(row)
        return InventorySite(**{name: values.get(name) for name in InventorySite.__dataclass_fields__})

    def list(self, *, include_deleted: bool = False) -> list[InventorySite]:
        query = "SELECT * FROM site_inventory"
        if not include_deleted:
            query += " WHERE lifecycle != 'DELETED'"
        return [self._record(row) for row in self.store.connection.execute(query + " ORDER BY site")]

    def get(self, site: str) -> InventorySite | None:
        row = self.store.connection.execute("SELECT * FROM site_inventory WHERE site = ?", (site,)).fetchone()
        return self._record(row) if row else None

    def seed_from_config(self, config: TopologyConfig, *, actor: str) -> None:
        """Seed only missing records; persisted inventory wins on later reloads."""
        now = utc_now()
        with self.store.transaction() as connection:
            for item in config.sites.values():
                existing = connection.execute("SELECT site FROM site_inventory WHERE site = ?", (item.name,)).fetchone()
                if existing:
                    continue
                connection.execute(
                    "INSERT INTO site_inventory(site,device_id,lifecycle,address_id,wireguard_index,management_ip,lan_prefix,lan_gateway,lan_switch,lan_dpid,host_name,host_ip,interface_suffix,preferred_hub,standby_hub,runtime_status,last_error,created_at,updated_at,deleted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
                    (item.name, item.device_id, "ZTP_STAGED", item.address_id, item.wireguard_index,
                     str(item.management_ip), str(item.lan_network), str(item.lan_gateway), item.lan_switch,
                     item.lan_dpid, item.host_name, str(item.host_ip), item.interface_suffix or f"n{item.address_id}",
                     item.preferred_hub, item.standby_hub, "SEED", None, now, now),
                )
                connection.execute(
                    "INSERT INTO sites(site,device_id,lan_prefix,preferred_hub,standby_hub,status,created_at,updated_at) VALUES (?,?,?,?,?,'STAGED',?,?) ON CONFLICT(site) DO NOTHING",
                    (item.name, item.device_id, str(item.lan_network), item.preferred_hub, item.standby_hub, now, now),
                )
                self.store.audit(connection, actor, "SEED_SITE_INVENTORY", item.name, "topology-seed", "ok")

    def topology(self, base: TopologyConfig) -> TopologyConfig:
        sites = {item.site: item.to_site() for item in self.list() if item.lifecycle in _ACTIVE_CONFIGURATION_STATES}
        if not sites:
            # Topology validation intentionally requires a seed.  A fully
            # decommissioned lab still retains the last static seed view for
            # read-only topology rendering, but it does not compile a new site.
            sites = dict(base.sites)
        return base.with_sites(sites)

    def allocate(self, *, site: str, device_id: str, preferred_hub: str, standby_hub: str, actor: str) -> InventorySite:
        site = site.strip().lower()
        if not _SITE_NAME.fullmatch(site):
            raise InventoryError("site must be a lowercase DNS-style identifier")
        if len(site) > 10:
            raise InventoryError("site name must be at most 10 characters for Linux interface names")
        if site in HUBS or site in {"public-saas", "dc-app", "cloud-app"}:
            raise InventoryError("site name is reserved")
        if not device_id or len(device_id) > 128:
            raise InventoryError("device_id is required and must be at most 128 characters")
        if preferred_hub not in HUBS or standby_hub not in HUBS or preferred_hub == standby_hub:
            raise InventoryError("preferred_hub and standby_hub must be distinct known hubs")
        now = utc_now()
        with self.store.transaction() as connection:
            existing_by_device = connection.execute("SELECT site,lifecycle FROM site_inventory WHERE device_id = ?", (device_id,)).fetchone()
            if existing_by_device and str(existing_by_device["site"]) != site:
                raise InventoryError("device_id is already assigned")
            rows = list(connection.execute("SELECT address_id, wireguard_index, lan_prefix, lan_dpid FROM site_inventory"))
            used_address_ids = {int(row["address_id"]) for row in rows}
            address_id = next((value for value in range(11, 254) if value not in used_address_ids), None)
            used_lan_octets = {int(str(row["lan_prefix"]).split(".")[1]) for row in rows}
            lan_octet = next((value for value in range(1, 254) if value not in used_lan_octets), None)
            if address_id is None or lan_octet is None:
                raise InventoryError("the configured IPv4 branch allocation pool is exhausted")
            wireguard_index = max([len(HUBS) - 1, *(int(row["wireguard_index"]) for row in rows)]) + 1
            lan_dpid = max([100, *(int(row["lan_dpid"]) for row in rows)]) + 1
            suffix = f"n{address_id}"
            host_name = f"{site.replace('-', '_')}_host"
            lan_prefix, lan_gateway, host_ip = f"10.{lan_octet}.0.0/24", f"10.{lan_octet}.0.1", f"10.{lan_octet}.0.10"
            existing = connection.execute("SELECT device_id,lifecycle FROM site_inventory WHERE site=?", (site,)).fetchone()
            if existing:
                if str(existing["device_id"]) != device_id:
                    raise InventoryError("site name is already bound to another device_id")
                if str(existing["lifecycle"]) != "DELETED":
                    return self.get(site) or (_ for _ in ()).throw(InventoryError("existing site disappeared"))
                connection.execute("UPDATE site_inventory SET lifecycle='ALLOCATING', runtime_status='NOT_REQUESTED', last_error=NULL, failure_stage=NULL, recoverable=1, updated_at=?, deleted_at=NULL WHERE site=?", (now, site))
                connection.execute("UPDATE sites SET status='ALLOCATING', updated_at=? WHERE site=?", (now, site))
                self._event(connection, "SITE_REALLOCATED", site, {"site": site, "device_id": device_id})
                return self.get(site) or (_ for _ in ()).throw(InventoryError("reallocated site disappeared"))
            values = (site, device_id, "ALLOCATING", address_id, wireguard_index, f"172.30.0.{address_id}", lan_prefix, lan_gateway, f"lsw{address_id}", lan_dpid, host_name, host_ip, suffix, preferred_hub, standby_hub, "NOT_REQUESTED", None, None, 1, now, now)
            connection.execute(
                "INSERT INTO site_inventory(site,device_id,lifecycle,address_id,wireguard_index,management_ip,lan_prefix,lan_gateway,lan_switch,lan_dpid,host_name,host_ip,interface_suffix,preferred_hub,standby_hub,runtime_status,last_error,failure_stage,recoverable,created_at,updated_at,deleted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)", values,
            )
            connection.execute("INSERT INTO sites(site,device_id,lan_prefix,preferred_hub,standby_hub,status,created_at,updated_at) VALUES (?,?,?,?,?,'ALLOCATED',?,?)", (site, device_id, lan_prefix, preferred_hub, standby_hub, now, now))
            self.store.audit(connection, actor, "CREATE_SITE", site, "administrative-intent", "ok")
            self._event(connection, "SITE_ALLOCATED", site, {"site": site, "device_id": device_id})
        return self.get(site) or (_ for _ in ()).throw(InventoryError("allocated site disappeared"))

    def transition(self, site: str, lifecycle: str, *, actor: str, error: str | None = None, operation_id: str | None = None, failure_stage: str | None = None, recoverable: bool = True) -> InventorySite:
        if lifecycle not in _TRANSITIONS:
            raise InventoryError("unknown lifecycle state")
        with self.store.transaction() as connection:
            row = connection.execute("SELECT lifecycle FROM site_inventory WHERE site = ?", (site,)).fetchone()
            if row is None:
                raise InventoryError("unknown site")
            current = str(row["lifecycle"])
            if current == lifecycle:
                return self.get(site) or (_ for _ in ()).throw(InventoryError("site disappeared"))
            if lifecycle not in _TRANSITIONS[current]:
                raise InventoryError(f"invalid lifecycle transition {current} -> {lifecycle}")
            now = utc_now()
            connection.execute("UPDATE site_inventory SET lifecycle=?, last_error=?, failure_stage=?, recoverable=?, updated_at=?, deleted_at=CASE WHEN ?='DELETED' THEN ? ELSE deleted_at END WHERE site=?", (lifecycle, error, failure_stage, int(recoverable), now, lifecycle, now, site))
            connection.execute("UPDATE sites SET status=?, updated_at=? WHERE site=?", (lifecycle, now, site))
            self.store.audit(connection, actor, "SITE_LIFECYCLE", site, f"{current}->{lifecycle}", "ok")
            self._event(connection, "SITE_LIFECYCLE", site, {"from": current, "to": lifecycle, "error": error, "failure_stage": failure_stage, "recoverable": recoverable, "operation_id": operation_id})
        return self.get(site) or (_ for _ in ()).throw(InventoryError("site disappeared"))

    def set_runtime_status(self, site: str, status: str, *, actor: str, error: str | None = None) -> None:
        with self.store.transaction() as connection:
            if connection.execute("SELECT 1 FROM site_inventory WHERE site=?", (site,)).fetchone() is None:
                raise InventoryError("unknown site")
            connection.execute("UPDATE site_inventory SET runtime_status=?, last_error=?, updated_at=? WHERE site=?", (status, error, utc_now(), site))
            self.store.audit(connection, actor, "SITE_RUNTIME", site, status, "ok")

    @staticmethod
    def _event(connection: Any, event_type: str, subject: str, payload: Mapping[str, Any]) -> int:
        result = connection.execute("INSERT INTO control_events(event_type,subject,payload_json,created_at,consumed_at) VALUES (?,?,?,?,NULL)", (event_type, subject, canonical_json(payload), utc_now()))
        return int(result.lastrowid)

    def create_operation(self, operation_id: str, site: str, operation_type: str) -> None:
        now = utc_now()
        with self.store.transaction() as connection:
            connection.execute("INSERT OR IGNORE INTO site_operations(operation_id,site,operation_type,state,recoverable,created_at,updated_at) VALUES (?,?,?,'RUNNING',1,?,?)", (operation_id, site, operation_type, now, now))

    def update_operation(self, operation_id: str, state: str, *, failure_stage: str | None = None, failure_reason: str | None = None, recoverable: bool = True) -> None:
        now = utc_now()
        with self.store.transaction() as connection:
            connection.execute("UPDATE site_operations SET state=?, failure_stage=?, failure_reason=?, recoverable=?, updated_at=?, completed_at=CASE WHEN ? IN ('SUCCEEDED','FAILED') THEN ? ELSE completed_at END WHERE operation_id=?", (state, failure_stage, failure_reason, int(recoverable), now, state, now, operation_id))

    def operation(self, operation_id: str) -> dict[str, Any] | None:
        row = self.store.connection.execute("SELECT * FROM site_operations WHERE operation_id=?", (operation_id,)).fetchone()
        return dict(row) if row else None

    def put_network_state(self, key: str, value: Mapping[str, Any], *, source: str) -> bool:
        if not key or len(key) > 128:
            raise InventoryError("network-state key is invalid")
        serialized, value_digest = canonical_json(value), _digest(value)
        with self.store.transaction() as connection:
            current = connection.execute("SELECT digest FROM network_state_inputs WHERE input_key=?", (key,)).fetchone()
            if current and str(current["digest"]) == value_digest:
                return False
            connection.execute("INSERT INTO network_state_inputs(input_key,value_json,digest,source,updated_at) VALUES (?,?,?,?,?) ON CONFLICT(input_key) DO UPDATE SET value_json=excluded.value_json,digest=excluded.digest,source=excluded.source,updated_at=excluded.updated_at", (key, serialized, value_digest, source, utc_now()))
            self._event(connection, "NETWORK_STATE", key, {"source": source, "digest": value_digest})
        return True

    def upsert_intent(self, intent_id: str, intent_type: str, target: str, contents: Mapping[str, Any], *, actor: str) -> bool:
        if intent_type not in {"destination_policy", "site_policy", "routing_preference"}:
            raise InventoryError("intent type is not supported")
        forbidden = {"command", "shell", "docker", "iptables", "ip_route", "exec"}
        if forbidden.intersection(contents):
            raise InventoryError("administrative intent cannot contain raw host commands")
        document = {"intent_type": intent_type, "target": target, "contents": dict(contents)}
        value_digest = _digest(document)
        with self.store.transaction() as connection:
            current = connection.execute("SELECT digest FROM administrative_intents WHERE intent_id=?", (intent_id,)).fetchone()
            if current and str(current["digest"]) == value_digest:
                return False
            now = utc_now()
            connection.execute("INSERT INTO administrative_intents(intent_id,intent_type,target,contents_json,digest,status,created_by,created_at,updated_at) VALUES (?,?,?,?,?,'ACTIVE',?,?,?) ON CONFLICT(intent_id) DO UPDATE SET intent_type=excluded.intent_type,target=excluded.target,contents_json=excluded.contents_json,digest=excluded.digest,status='ACTIVE',created_by=excluded.created_by,updated_at=excluded.updated_at", (intent_id, intent_type, target, canonical_json(contents), value_digest, actor, now, now))
            self.store.audit(connection, actor, "UPSERT_INTENT", intent_id, intent_type, "ok")
            self._event(connection, "ADMINISTRATIVE_INTENT", intent_id, document)
        return True

    def delete_intent(self, intent_id: str, *, actor: str) -> bool:
        with self.store.transaction() as connection:
            changed = connection.execute("UPDATE administrative_intents SET status='DELETED', updated_at=? WHERE intent_id=? AND status='ACTIVE'", (utc_now(), intent_id)).rowcount > 0
            if changed:
                self.store.audit(connection, actor, "DELETE_INTENT", intent_id, "administrative-intent", "ok")
                self._event(connection, "ADMINISTRATIVE_INTENT_DELETED", intent_id, {"intent_id": intent_id})
            return changed

    def intents(self) -> list[dict[str, Any]]:
        return [{**dict(row), "contents": json.loads(str(row["contents_json"]))} for row in self.store.connection.execute("SELECT * FROM administrative_intents WHERE status='ACTIVE' ORDER BY intent_id")]

    def network_state(self) -> list[dict[str, Any]]:
        return [{**dict(row), "value": json.loads(str(row["value_json"]))} for row in self.store.connection.execute("SELECT * FROM network_state_inputs ORDER BY input_key")]


class IntentCompiler:
    """Deterministic, event-driven compiler for existing desired-state objects."""

    def __init__(self, store: PolicyStore, inventory: DynamicInventory, base_config: TopologyConfig):
        self.store, self.inventory, self.base_config = store, inventory, base_config

    @staticmethod
    def _effective(state: Mapping[str, Any]) -> Any:
        if isinstance(state, Mapping):
            return {key: IntentCompiler._effective(value) for key, value in sorted(state.items()) if key not in {"configuration_digest", "generation", "desired_state_version", "route_version", "ownership_epoch"}}
        if isinstance(state, list):
            return [IntentCompiler._effective(value) for value in state]
        return state

    def _effective_changed(self, state: Mapping[str, Any]) -> bool:
        latest = self.store.latest_desired_state(str(state["site"]))
        return latest is None or canonical_json(self._effective(latest)) != canonical_json(self._effective(state))

    def compile(self, *, actor: str = "policy-compiler", trigger_event_id: int | None = None) -> dict[str, Any]:
        config = self.inventory.topology(self.base_config)
        inputs = {"inventory": [asdict(item) for item in self.inventory.list(include_deleted=True)], "intents": self.inventory.intents(), "network_state": self.inventory.network_state()}
        input_digest = _digest(inputs)
        keys = self.store.active_wireguard_public_keys()
        changed_sites: list[str] = []
        ownership = {str(row["prefix"]): dict(row) for row in self.store.connection.execute("SELECT * FROM route_ownership")}
        if set(HUBS).issubset(keys):
            for hub in HUBS:
                provisional = build_hub_desired_state(config, hub, keys, ownership, generation="compiler", desired_state_version=1, route_version=1, ownership_epoch=1)
                if self._effective_changed(provisional.to_dict()):
                    version = self.store.next_desired_state_version(hub)
                    actual = build_hub_desired_state(config, hub, keys, ownership, generation=f"compiler-{hub}-{version}", desired_state_version=version, route_version=version, ownership_epoch=version)
                    self.store.put_desired_state(actual.to_dict(), actor)
                    changed_sites.append(hub)
        for item in self.inventory.list():
            if item.lifecycle != "ACTIVE" or item.site not in keys or not set(HUBS).issubset(keys):
                continue
            provisional = build_spoke_desired_state(config, item.site, {hub: keys[hub] for hub in HUBS}, generation="compiler", desired_state_version=1, route_version=1, ownership_epoch=1)
            if self._effective_changed(provisional.to_dict()):
                version = self.store.next_desired_state_version(item.site)
                actual = build_spoke_desired_state(config, item.site, {hub: keys[hub] for hub in HUBS}, generation=f"compiler-{item.site}-{version}", desired_state_version=version, route_version=version, ownership_epoch=version)
                self.store.put_desired_state(actual.to_dict(), actor)
                changed_sites.append(item.site)
        output_digest = _digest({site: self.store.latest_desired_state(site) for site in (*HUBS, *config.sites) if self.store.latest_desired_state(site) is not None})
        with self.store.transaction() as connection:
            connection.execute("INSERT INTO control_compilations(trigger_event_id,input_digest,output_digest,changed,detail,created_at) VALUES (?,?,?,?,?,?)", (trigger_event_id, input_digest, output_digest, int(bool(changed_sites)), canonical_json({"changed_sites": changed_sites}), utc_now()))
            if trigger_event_id is not None:
                connection.execute("UPDATE control_events SET consumed_at=? WHERE id=?", (utc_now(), trigger_event_id))
        return {"input_digest": input_digest, "output_digest": output_digest, "changed": bool(changed_sites), "changed_sites": changed_sites}
