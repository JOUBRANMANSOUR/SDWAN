"""Idempotent Management orchestration for dynamic Edge lifecycle requests.

Management coordinates typed operations only.  The existing Edge bootstrap code
still generates the private identity key, CSR, and WireGuard private key inside
the Edge container; this module never receives those values.
"""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from ..dynamic_control import InventoryError, InventorySite
from ..persistence.base import utc_now
from ..policy_service_v5 import PolicyService
from ..persistence.ztp_store import ZTPStore

def _bounded_error(value: str, limit: int = 1000) -> str:
    value = value.strip()
    if len(value) <= limit:
        return value
    marker = "\n... error truncated ...\n"
    head = limit // 4
    return value[:head] + marker + value[-(limit - head - len(marker)):]



class LabRuntime(Protocol):
    def create_site(self, site: InventorySite) -> dict[str, Any]: ...
    def delete_site(self, site: InventorySite) -> dict[str, Any]: ...
    def bootstrap_site(self, site: InventorySite, bootstrap: dict[str, str]) -> dict[str, Any]: ...
    def reconcile_site(self, target: str, bootstrap: dict[str, str]) -> dict[str, Any]: ...


class UnavailableLabRuntime:
    """Honest fallback when Management is not attached to a live topology."""
    def _unavailable(self, *_: Any, **__: Any) -> dict[str, Any]:
        return {"available": False, "reason": "no active Containernet control socket"}
    create_site = _unavailable
    delete_site = _unavailable
    bootstrap_site = _unavailable
    reconcile_site = _unavailable


class LocalZTPProvisioner:
    """Typed local-lab adapter around the one-time ZTP claim store."""
    def __init__(self, store: ZTPStore):
        self.store = store

    def stage_and_claim(self, site: InventorySite, actor: str) -> dict[str, str]:
        self.store.stage_device(site.device_id, site.site, actor)
        claim_id, secret = self.store.create_claim(site.device_id, site.site, lifetime_s=900, actor=actor)
        return {"claim_id": claim_id, "claim_secret": secret, "device_id": site.device_id, "expires_in_seconds": "900"}

    def revoke_site(self, site: InventorySite, actor: str) -> None:
        with self.store.transaction() as connection:
            now = utc_now()
            connection.execute("UPDATE claims SET status='CANCELLED' WHERE expected_device_id=? AND status='ACTIVE'", (site.device_id,))
            serials = [str(row["serial"]) for row in connection.execute("SELECT serial FROM certificates WHERE device_id=? AND status='ACTIVE'", (site.device_id,))]
            for serial in serials:
                connection.execute("UPDATE certificates SET status='REVOKED' WHERE serial=?", (serial,))
                connection.execute("INSERT OR REPLACE INTO revocations(serial,reason,revoked_at,actor) VALUES (?, 'site decommissioned', ?, ?)", (serial, now, actor))
            connection.execute("UPDATE devices SET status='REVOKED', updated_at=? WHERE device_id=?", (now, site.device_id))
            self.store._audit(connection, actor, "REVOKE_SITE", site.site, "revoked", "ok", "site decommissioned")


class SiteLifecycleCoordinator:
    def __init__(self, policy: PolicyService, ztp: LocalZTPProvisioner, runtime: LabRuntime | None = None, *, bootstrap_ca: Path | None = None, ztp_url: str = "https://ztp:8443", policy_url: str = "https://policy:8080", management_host: str = "172.30.0.254"):
        self.policy, self.ztp, self.runtime = policy, ztp, runtime or UnavailableLabRuntime()
        self.bootstrap_ca, self.ztp_url, self.policy_url, self.management_host = bootstrap_ca, ztp_url, policy_url, management_host

    @staticmethod
    def _payload(record: InventorySite) -> dict[str, Any]:
        return asdict(record)

    def _operation(self, site: str, operation_type: str) -> str:
        operation_id = "site-op-" + uuid4().hex
        self.policy.inventory.create_operation(operation_id, site, operation_type)
        return operation_id

    def _transition(self, site: str, state: str, *, actor: str, operation_id: str, error: str | None = None, failure_stage: str | None = None, recoverable: bool = True) -> InventorySite:
        record = self.policy.inventory.get(site)
        if record is None:
            raise InventoryError("unknown site")
        if record.lifecycle != state:
            record = self.policy.transition_site(site, state, actor=actor, error=error, operation_id=operation_id, failure_stage=failure_stage, recoverable=recoverable)
        self.policy.inventory.update_operation(operation_id, state, failure_stage=failure_stage, failure_reason=error, recoverable=recoverable)
        return record

    def _control_plane(self, claim: dict[str, str] | None = None) -> dict[str, str]:
        if self.bootstrap_ca is None or not self.bootstrap_ca.is_file():
            raise RuntimeError("bootstrap CA is unavailable for Edge-side enrollment")
        value = {"bootstrap_ca_pem": self.bootstrap_ca.read_text(encoding="utf-8"), "policy_url": self.policy_url, "management_host": self.management_host}
        if claim is not None:
            value.update({"claim_id": claim["claim_id"], "claim_secret": claim["claim_secret"], "ztp_url": self.ztp_url})
        return value

    def _failure(self, site: str, operation_id: str, stage: str, exc: Exception, actor: str) -> dict[str, Any]:
        raw_reason = str(exc) or exc.__class__.__name__
        reason = _bounded_error(raw_reason)
        record = self.policy.inventory.get(site)
        if record is not None and record.lifecycle not in {"FAILED", "DELETED", "DELETING"}:
            try:
                record = self._transition(site, "FAILED", actor=actor, operation_id=operation_id, error=reason, failure_stage=stage, recoverable=True)
            except InventoryError:
                pass
        self.policy.inventory.update_operation(operation_id, "FAILED", failure_stage=stage, failure_reason=reason, recoverable=True)
        return {"site_id": site, "state": "FAILED", "operation_id": operation_id, "failure_stage": stage, "failure_reason": reason, "recoverable": True, "site": self._payload(record) if record else None}

    def create(self, *, site: str, device_id: str, preferred_hub: str, standby_hub: str, actor: str) -> dict[str, Any]:
        """Create or safely resume one site using its persisted lifecycle.

        Retries retain the original device binding and never create a second
        allocation. A failed partial topology is retried through the same
        typed runtime callback; completed ZTP phases are not moved backwards.
        """
        existing = self.policy.inventory.get(site)
        if existing is not None and existing.device_id != device_id:
            raise InventoryError("site name is already bound to another device_id")
        if existing is not None and existing.lifecycle == "ACTIVE":
            return {"site_id": site, "state": "ACTIVE", "operation_id": None, "idempotent": True, "site": self._payload(existing)}
        record = self.policy.create_site(site=site, device_id=device_id, preferred_hub=preferred_hub, standby_hub=standby_hub, actor=actor)
        resume_failure_stage = record.failure_stage if record.lifecycle == "FAILED" else None
        operation_id = self._operation(record.site, "CREATE")
        stage = "TOPOLOGY_CREATED"
        try:
            runtime = self.runtime.create_site(record)
            if not runtime.get("available"):
                raise RuntimeError(str(runtime.get("reason", "topology creation unavailable")))
            self.policy.inventory.set_runtime_status(record.site, "CREATED", actor=actor)
            if record.lifecycle == "FAILED" and resume_failure_stage in {"PROVISIONING", "RECONCILING"}:
                # Durable Edge enrollment and WG public registration are
                # already proven. Resume control-plane reconciliation without
                # issuing another one-time claim or certificate.
                record = self._transition(record.site, "PROVISIONING", actor=actor, operation_id=operation_id)
            elif record.lifecycle in {"ALLOCATING", "FAILED"}:
                record = self._transition(record.site, "TOPOLOGY_CREATED", actor=actor, operation_id=operation_id)
            else:
                record = self.policy.inventory.get(record.site) or record

            claim: dict[str, str] | None = None
            if record.lifecycle == "TOPOLOGY_CREATED":
                stage = "ZTP_STAGED"
                claim = self.ztp.stage_and_claim(record, actor)
                record = self._transition(record.site, "ZTP_STAGED", actor=actor, operation_id=operation_id)
            if record.lifecycle == "ZTP_STAGED":
                # Claims are one-time and may have expired while a previous
                # topology request timed out; issue a fresh one on resume.
                stage = "ENROLLING"
                claim = claim or self.ztp.stage_and_claim(record, actor)
                record = self._transition(record.site, "ENROLLING", actor=actor, operation_id=operation_id)
            if record.lifecycle == "ENROLLING":
                if claim is None:
                    claim = self.ztp.stage_and_claim(record, actor)
                bootstrap = self.runtime.bootstrap_site(record, self._control_plane(claim))
                if not bootstrap.get("available"):
                    raise RuntimeError(str(bootstrap.get("reason", "edge bootstrap unavailable")))
                record = self.policy.inventory.get(record.site) or record
            if record.lifecycle not in {"PROVISIONING", "PENDING_HUBS", "RECONCILING", "ACTIVE"}:
                raise RuntimeError("Edge bootstrap completed without Policy registration")
            if record.lifecycle == "ACTIVE":
                self.policy.inventory.update_operation(operation_id, "SUCCEEDED")
                return {"site_id": record.site, "state": "ACTIVE", "operation_id": operation_id, "created_at": record.created_at, "site": self._payload(record), "idempotent": True}

            stage = "PROVISIONING"
            control = self._control_plane()
            for hub in ("hub1", "hub2"):
                result = self.runtime.reconcile_site(hub, control)
                if not result.get("available"):
                    raise RuntimeError(str(result.get("reason", f"{hub} reconciliation unavailable")))
            activation = self.policy.activate_spoke(record.site, actor=actor)
            if activation.state == "PENDING_HUBS":
                if record.lifecycle != "PENDING_HUBS":
                    record = self._transition(record.site, "PENDING_HUBS", actor=actor, operation_id=operation_id)
                return {"site_id": record.site, "state": record.lifecycle, "operation_id": operation_id, "created_at": record.created_at, "site": self._payload(record), "detail": activation.detail}
            if activation.state != "EDGE_CONFIGURING":
                raise RuntimeError(activation.detail)
            stage = "RECONCILING"
            if record.lifecycle != "RECONCILING":
                record = self._transition(record.site, "RECONCILING", actor=actor, operation_id=operation_id)
            result = self.runtime.reconcile_site(record.edge_node, control)
            if not result.get("available"):
                raise RuntimeError(str(result.get("reason", "edge reconciliation unavailable")))
            record = self.policy.inventory.get(record.site) or record
            if record.lifecycle != "ACTIVE":
                raise RuntimeError(f"Edge reconciliation did not reach ACTIVE (current state: {record.lifecycle})")
            self.policy.inventory.set_runtime_status(record.site, "OPERATIONAL", actor=actor)
            self.policy.inventory.update_operation(operation_id, "SUCCEEDED")
            return {"site_id": record.site, "state": "ACTIVE", "operation_id": operation_id, "created_at": record.created_at, "site": self._payload(record)}
        except Exception as exc:
            return self._failure(record.site, operation_id, stage, exc, actor)

    def delete(self, site: str, *, actor: str) -> dict[str, Any]:
        record = self.policy.inventory.get(site)
        if record is None:
            raise InventoryError("unknown site")
        if record.lifecycle == "DELETED":
            return {"site_id": site, "state": "DELETED", "operation_id": None, "idempotent": True, "site": self._payload(record)}
        operation_id = self._operation(site, "DELETE")
        try:
            record = self._transition(site, "DELETING", actor=actor, operation_id=operation_id)
            self.ztp.revoke_site(record, actor)
            with self.policy.store.transaction() as connection:
                connection.execute("UPDATE wireguard_public_keys SET status='RETIRED' WHERE site=? AND status='ACTIVE'", (site,))
            runtime = self.runtime.delete_site(record)
            if not runtime.get("available"):
                raise RuntimeError(str(runtime.get("reason", "topology deletion unavailable")))
            record = self._transition(site, "DELETED", actor=actor, operation_id=operation_id)
            self.policy.inventory.set_runtime_status(site, "DELETED", actor=actor)
            self.policy.inventory.update_operation(operation_id, "SUCCEEDED")
            return {"site_id": site, "state": "DELETED", "operation_id": operation_id, "site": self._payload(record)}
        except Exception as exc:
            return self._failure(site, operation_id, "DELETING", exc, actor)
