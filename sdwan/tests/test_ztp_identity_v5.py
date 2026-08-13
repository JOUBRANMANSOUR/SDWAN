from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import stat
import unittest

from sdwan.enrollment_state import EnrollmentState, InvalidEnrollmentTransition, transition
from sdwan.identity_ca import generate_device_csr
from sdwan.identity_store import IdentityStore


class ZTPIdentityTests(unittest.TestCase):
    def test_valid_and_invalid_enrollment_transitions(self) -> None:
        item = transition("edge-node1", None, EnrollmentState.UNCLAIMED, EnrollmentState.BOOTSTRAP_NETWORK_READY, reason="network ready", event_id="e1", timestamp=datetime.now(timezone.utc).isoformat())
        self.assertEqual(item.current, EnrollmentState.BOOTSTRAP_NETWORK_READY)
        with self.assertRaises(InvalidEnrollmentTransition):
            transition("edge-node1", "node1", EnrollmentState.UNCLAIMED, EnrollmentState.ACTIVE, reason="skip", event_id="e2", timestamp="now")

    def test_identity_private_key_and_enrollment_state_are_persistent_and_private(self) -> None:
        with TemporaryDirectory() as directory:
            store = IdentityStore(Path(directory))
            csr = generate_device_csr(store, "edge-node1")
            self.assertIn("BEGIN CERTIFICATE REQUEST", csr)
            key = store.private_key_path()
            self.assertTrue(key.exists())
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
            store.persist_json("last-confirmed.json", {"site": "node1", "route_version": 7})
            resumed = IdentityStore(Path(directory))
            self.assertEqual(resumed.load_json("last-confirmed.json")["route_version"], 7)


if __name__ == "__main__":
    unittest.main()
