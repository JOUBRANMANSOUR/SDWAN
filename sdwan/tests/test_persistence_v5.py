from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import unittest

from sdwan.common.model import load_config
from sdwan.desired_state_v5 import build_spoke_desired_state
from sdwan.persistence.base import VersionConflict
from sdwan.persistence.policy_store import PolicyStore
from sdwan.persistence.ztp_store import ClaimRejected, ZTPStore


ROOT = Path(__file__).resolve().parents[1]


class PersistenceTests(unittest.TestCase):
    def test_claim_is_one_time_and_audit_does_not_store_secret(self) -> None:
        with TemporaryDirectory() as directory:
            store = ZTPStore(Path(directory) / "ztp.db")
            try:
                store.stage_device("device-1", "node1")
                claim_id, secret = store.create_claim("device-1", "node1", lifetime_s=60, actor="admin")
                future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
                outcome = store.consume_claim(
                    claim_id, secret, "device-1", "nonce-1",
                    lambda site: ("serial-1", "fingerprint-1", datetime.now(timezone.utc).isoformat(), future, "CERTIFICATE"),
                    request_id="request-1",
                )
                self.assertEqual(outcome["site"], "node1")
                self.assertTrue(store.certificate_is_active("serial-1", "node1"))
                with self.assertRaises(ClaimRejected):
                    store.consume_claim(claim_id, secret, "device-1", "nonce-2", lambda site: ("serial-2", "fingerprint-2", "a", "b", "CERT"), request_id="request-2")
                audit_text = "\n".join(row[0] for row in store.connection.execute("SELECT reason FROM ztp_audit_events"))
                self.assertNotIn(secret, audit_text)
            finally:
                store.close()

    def test_certificate_failure_rolls_back_claim_consumption(self) -> None:
        with TemporaryDirectory() as directory:
            store = ZTPStore(Path(directory) / "ztp.db")
            try:
                store.stage_device("device-rollback", "node2")
                claim_id, secret = store.create_claim("device-rollback", "node2", lifetime_s=60, actor="admin")
                with self.assertRaises(RuntimeError):
                    store.consume_claim(claim_id, secret, "device-rollback", "nonce", lambda site: (_ for _ in ()).throw(RuntimeError("issuer failed")), request_id="request")
                claim = store.connection.execute("SELECT status, current_uses FROM claims WHERE claim_id = ?", (claim_id,)).fetchone()
                self.assertEqual(claim["status"], "ACTIVE")
                self.assertEqual(claim["current_uses"], 0)
            finally:
                store.close()

    def test_policy_versions_ownership_leases_and_backup(self) -> None:
        with TemporaryDirectory() as directory:
            store = PolicyStore(Path(directory) / "policy.db")
            try:
                store.stage_site("node1", "device-1", "10.1.0.0/24", "hub1", "hub2", "admin")
                store.reserve_resources("node1", [("172.31.10.11", "hub1", "mpls", "wg-h1-mpls")], [("node1", 52128, "wg-h1-mpls")], "admin")
                with self.assertRaises(sqlite3.IntegrityError):
                    store.reserve_resources("node2", [("172.31.10.11", "hub1", "mpls", "wg-h1-mpls")], [], "admin")
                state = {"schema_version": 5, "site": "node1", "generation": "g1", "desired_state_version": 1, "route_version": 1, "ownership_epoch": 1}
                state_digest, repeated = store.put_desired_state(state, "admin")
                self.assertFalse(repeated)
                self.assertTrue(store.put_desired_state(state, "admin")[1])
                changed = dict(state)
                changed["route_version"] = 2
                with self.assertRaises(VersionConflict):
                    store.put_desired_state(changed, "admin")
                record = {"prefix": "10.1.0.0/24", "spoke": "node1", "preferred_hub": "hub1", "standby_hub": "hub2", "current_owner_hub": "hub1", "previous_owner_hub": None, "owner_epoch": 1, "policy_version": 1, "route_version": 1, "state": "COMMITTED", "reason": "initial", "pending_reconciliation": False}
                self.assertFalse(store.transfer_ownership(record, "admin"))
                stale = dict(record)
                stale["owner_epoch"] = 0
                with self.assertRaises(VersionConflict):
                    store.transfer_ownership(stale, "admin")
                backup = store.backup_to(Path(directory) / "backup" / "policy.db")
                self.assertTrue(backup.exists())
                self.assertEqual(store.route_owner("10.1.0.0/24")["current_owner_hub"], "hub1")
                self.assertEqual(len(state_digest), 64)
            finally:
                store.close()

    def test_desired_state_has_exact_six_spoke_tunnels(self) -> None:
        config = load_config(ROOT / "config" / "topology.yaml")
        state = build_spoke_desired_state(config, "node1", {"hub1": "A" * 44, "hub2": "B" * 44}, generation="g", desired_state_version=1, route_version=1, ownership_epoch=1)
        self.assertEqual(len(state.interfaces), 6)
        self.assertEqual({item.name for item in state.interfaces}, {"wg-h1-mpls", "wg-h1-bb", "wg-h1-lte", "wg-h2-mpls", "wg-h2-bb", "wg-h2-lte"})


if __name__ == "__main__":
    unittest.main()
