"""Policy-service-owned persistent desired state and route ownership."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Mapping

from .base import SQLiteStore, VersionConflict, utc_now


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class PolicyStore(SQLiteStore):
    def __init__(self, path: Path):
        super().__init__(path, Path(__file__).with_name("migrations") / "policy")

    def stage_site(self, site: str, device_id: str, lan_prefix: str, preferred_hub: str, standby_hub: str, actor: str) -> None:
        if preferred_hub == standby_hub:
            raise ValueError("preferred and standby hub must differ")
        now = utc_now()
        with self.transaction() as connection:
            row = connection.execute("SELECT device_id, lan_prefix FROM sites WHERE site = ?", (site,)).fetchone()
            if row and (row["device_id"] != device_id or row["lan_prefix"] != lan_prefix):
                raise VersionConflict("site inventory identity is immutable outside replacement workflow")
            connection.execute(
                "INSERT INTO sites(site, device_id, lan_prefix, preferred_hub, standby_hub, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'STAGED', ?, ?) ON CONFLICT(site) DO UPDATE SET preferred_hub=excluded.preferred_hub, standby_hub=excluded.standby_hub, updated_at=excluded.updated_at",
                (site, device_id, lan_prefix, preferred_hub, standby_hub, now, now),
            )
            self.audit(connection, actor, "STAGE_SITE", site, "inventory", "ok")


    def register_wireguard_public_key(self, site: str, public_key: str, actor: str) -> bool:
        """Persist one device-level public key, retaining rotation history.

        Returns ``True`` for an exact idempotent re-registration and ``False``
        when a new generation was recorded.
        """
        if not public_key or len(public_key) > 256:
            raise ValueError("invalid WireGuard public key")
        fingerprint = hashlib.sha256(public_key.encode("ascii")).hexdigest()
        with self.transaction() as connection:
            current = connection.execute(
                "SELECT generation, public_key FROM wireguard_public_keys WHERE site = ? AND interface_name = 'wg-device' AND status = 'ACTIVE'",
                (site,),
            ).fetchone()
            if current and str(current["public_key"]) == public_key:
                return True
            generation = 1 if current is None else int(current["generation"]) + 1
            if current is not None:
                connection.execute(
                    "UPDATE wireguard_public_keys SET status = 'RETIRED' WHERE site = ? AND interface_name = 'wg-device' AND status = 'ACTIVE'",
                    (site,),
                )
            connection.execute(
                "INSERT INTO wireguard_public_keys(site, interface_name, generation, public_key, fingerprint, status, created_at) VALUES (?, 'wg-device', ?, ?, ?, 'ACTIVE', ?)",
                (site, generation, public_key, fingerprint, utc_now()),
            )
            self.audit(connection, actor, "REGISTER_WIREGUARD_KEY", site, "device-key", "ok", after_version=generation)
        return False

    def active_wireguard_public_keys(self) -> dict[str, str]:
        rows = self.connection.execute(
            "SELECT site, public_key FROM wireguard_public_keys WHERE interface_name = 'wg-device' AND status = 'ACTIVE'"
        )
        return {str(row["site"]): str(row["public_key"]) for row in rows}

    def next_desired_state_version(self, site: str) -> int:
        row = self.connection.execute("SELECT COALESCE(MAX(version), 0) AS version FROM desired_states WHERE site = ?", (site,)).fetchone()
        return int(row["version"]) + 1

    def latest_desired_state(self, site: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT contents_json FROM desired_states WHERE site = ? ORDER BY version DESC LIMIT 1", (site,)
        ).fetchone()
        return json.loads(str(row["contents_json"])) if row else None

    def latest_desired_state_is_verified(self, site: str) -> bool:
        row = self.connection.execute(
            "SELECT a.status FROM desired_states AS d LEFT JOIN desired_state_acks AS a ON a.site = d.site AND a.version = d.version WHERE d.site = ? ORDER BY d.version DESC LIMIT 1",
            (site,),
        ).fetchone()
        return bool(row and row["status"] == "VERIFIED")

    def reserve_resources(self, site: str, addresses: list[tuple[str, str, str, str]], ports: list[tuple[str, int, str]], actor: str) -> None:
        now = utc_now()
        with self.transaction() as connection:
            for address, hub, transport, interface_name in addresses:
                connection.execute("INSERT INTO address_leases(address, owner_site, hub, transport, interface_name, state, created_at) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?)", (address, site, hub, transport, interface_name, now))
            for node, port, interface_name in ports:
                connection.execute("INSERT INTO port_leases(node, port, owner_site, interface_name, state, created_at) VALUES (?, ?, ?, ?, 'ACTIVE', ?)", (node, port, site, interface_name, now))
            self.audit(connection, actor, "RESERVE_RESOURCES", site, "lease", "ok")

    def put_desired_state(self, state: Mapping[str, Any], actor: str) -> tuple[str, bool]:
        site, version = str(state["site"]), int(state["desired_state_version"])
        canonical_state = {key: value for key, value in state.items() if key != "configuration_digest"}
        state_digest = hashlib.sha256(canonical_json(canonical_state).encode("utf-8")).hexdigest()
        advertised_digest = state.get("configuration_digest")
        if advertised_digest is not None and str(advertised_digest) != state_digest:
            raise VersionConflict("desired-state configuration digest is invalid")
        contents = canonical_json(state)
        with self.transaction() as connection:
            latest = connection.execute("SELECT version, digest FROM desired_states WHERE site = ? ORDER BY version DESC LIMIT 1", (site,)).fetchone()
            if latest and version < latest["version"]:
                raise VersionConflict("stale desired state")
            existing = connection.execute("SELECT digest FROM desired_states WHERE site = ? AND version = ?", (site, version)).fetchone()
            if existing:
                if existing["digest"] != state_digest:
                    raise VersionConflict("same desired-state version has different content")
                return state_digest, True
            if latest:
                connection.execute("UPDATE desired_states SET superseded_by = ? WHERE site = ? AND version = ?", (version, site, latest["version"]))
            connection.execute(
                "INSERT INTO desired_states(site, version, digest, schema_version, generation, route_version, ownership_epoch, contents_json, created_at, created_by, delivery_status, applied_status, verification_status, superseded_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', 'PENDING', 'UNVERIFIED', NULL)",
                (site, version, state_digest, int(state["schema_version"]), str(state["generation"]), int(state["route_version"]), int(state["ownership_epoch"]), contents, utc_now(), actor),
            )
            self.audit(connection, actor, "PUT_DESIRED_STATE", site, "version", "ok", after_version=version)
        return state_digest, False

    def ack_desired_state(self, site: str, version: int, state_digest: str, route_version: int, status: str, detail: str) -> None:
        with self.transaction() as connection:
            state = connection.execute("SELECT digest FROM desired_states WHERE site = ? AND version = ?", (site, version)).fetchone()
            if state is None or state["digest"] != state_digest:
                raise VersionConflict("ack does not match desired state")
            connection.execute("INSERT INTO desired_state_acks(site, version, digest, applied_route_version, status, detail, acknowledged_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(site, version) DO UPDATE SET digest=excluded.digest, applied_route_version=excluded.applied_route_version, status=excluded.status, detail=excluded.detail, acknowledged_at=excluded.acknowledged_at", (site, version, state_digest, route_version, status, detail, utc_now()))
            if status == "VERIFIED":
                connection.execute("UPDATE desired_states SET applied_status='APPLIED', verification_status='VERIFIED' WHERE site = ? AND version = ?", (site, version))

    def transfer_ownership(self, record: Mapping[str, Any], actor: str) -> bool:
        required = {"prefix", "spoke", "preferred_hub", "standby_hub", "current_owner_hub", "previous_owner_hub", "owner_epoch", "policy_version", "route_version", "state", "reason", "pending_reconciliation"}
        if required - set(record):
            raise ValueError("ownership record is incomplete")
        with self.transaction() as connection:
            current = connection.execute("SELECT owner_epoch FROM route_ownership WHERE prefix = ?", (record["prefix"],)).fetchone()
            if current and int(record["owner_epoch"]) < int(current["owner_epoch"]):
                raise VersionConflict("stale ownership epoch")
            if current and int(record["owner_epoch"]) == int(current["owner_epoch"]):
                return True
            connection.execute(
                "INSERT INTO route_ownership(prefix, spoke, preferred_hub, standby_hub, current_owner_hub, previous_owner_hub, owner_epoch, policy_version, route_version, state, reason, updated_at, valid_until, pending_reconciliation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(prefix) DO UPDATE SET preferred_hub=excluded.preferred_hub, standby_hub=excluded.standby_hub, current_owner_hub=excluded.current_owner_hub, previous_owner_hub=excluded.previous_owner_hub, owner_epoch=excluded.owner_epoch, policy_version=excluded.policy_version, route_version=excluded.route_version, state=excluded.state, reason=excluded.reason, updated_at=excluded.updated_at, valid_until=excluded.valid_until, pending_reconciliation=excluded.pending_reconciliation",
                (record["prefix"], record["spoke"], record["preferred_hub"], record["standby_hub"], record["current_owner_hub"], record["previous_owner_hub"], int(record["owner_epoch"]), int(record["policy_version"]), int(record["route_version"]), record["state"], record["reason"], utc_now(), record.get("valid_until"), int(bool(record["pending_reconciliation"]))),
            )
            if record["pending_reconciliation"]:
                connection.execute("INSERT OR IGNORE INTO pending_reconciliation(site, owner_epoch, reason, created_at, resolved_at) VALUES (?, ?, ?, ?, NULL)", (record["spoke"], int(record["owner_epoch"]), record["reason"], utc_now()))
            self.audit(connection, actor, "TRANSFER_OWNERSHIP", str(record["prefix"]), "epoch", "ok", after_version=int(record["owner_epoch"]))
        return False

    def route_owner(self, prefix: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM route_ownership WHERE prefix = ?", (prefix,)).fetchone()
        return dict(row) if row else None

    def audit(self, connection: sqlite3.Connection, actor: str, action: str, target: str, reason: str, result: str, before_version: int | None = None, after_version: int | None = None) -> None:
        connection.execute("INSERT INTO policy_audit_events(actor, action, target, reason, request_id, result, before_version, after_version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (actor, action, target, reason, "internal", result, before_version, after_version, utc_now()))
