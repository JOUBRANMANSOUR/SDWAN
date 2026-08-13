from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest

from sdwan.common.model import load_config
from sdwan.policy_service_v5 import PolicyService
from sdwan.runtime_restore import (
    PersistentSiteReconciler,
    load_active_dynamic_sites,
    persistent_reconciliation_targets,
)


ROOT = Path(__file__).resolve().parents[1]


class RuntimeRestoreTests(unittest.TestCase):
    def test_loader_returns_only_active_nonstatic_sites(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "policy.db"
            config = load_config(ROOT / "config" / "topology.core.yaml")
            service = PolicyService(config, database)
            try:
                active = service.create_site(
                    site="node7", device_id="node7-edge",
                    preferred_hub="hub1", standby_hub="hub2", actor="test",
                )
                failed = service.create_site(
                    site="node8", device_id="node8-edge",
                    preferred_hub="hub1", standby_hub="hub2", actor="test",
                )
                with service.store.transaction() as connection:
                    connection.execute(
                        "UPDATE site_inventory SET lifecycle='ACTIVE' WHERE site=?",
                        (active.site,),
                    )
                    connection.execute(
                        "UPDATE site_inventory SET lifecycle='FAILED' WHERE site=?",
                        (failed.site,),
                    )
            finally:
                service.store.close()

            records = load_active_dynamic_sites(database, config.site_names)
            self.assertEqual([record.site for record in records], ["node7"])
            self.assertEqual(records[0].device_id, "node7-edge")
            self.assertEqual(records[0].lan_prefix, "10.6.0.0/24")

    def test_loader_is_empty_before_policy_database_exists(self) -> None:
        with TemporaryDirectory() as temporary:
            records = load_active_dynamic_sites(
                Path(temporary) / "missing.db", ("node1", "node2")
            )
            self.assertEqual(records, ())

    def test_targets_include_hubs_static_sites_and_restored_sites_once(self) -> None:
        class Record:
            site = "node7"

        targets = persistent_reconciliation_targets(
            ("hub1", "hub2"), ("node1", "node2"), (Record(), Record()),
        )
        self.assertEqual(targets, ("hub1", "hub2", "node1", "node2", "node7"))

    def test_reconciler_retries_and_preserves_dependency_order(self) -> None:
        calls: list[str] = []
        reports: list[str] = []

        class Runtime:
            def __init__(self) -> None:
                self.hub1_attempts = 0

            def reconcile_site(self, target: str, bootstrap: dict[str, str]):
                self.assert_bootstrap(bootstrap)
                calls.append(target)
                if target == "hub1" and self.hub1_attempts == 0:
                    self.hub1_attempts += 1
                    raise RuntimeError("policy is starting")
                return {"site": target, "state": "MATCHED"}

            @staticmethod
            def assert_bootstrap(bootstrap: dict[str, str]) -> None:
                if bootstrap["policy_url"] != "https://policy:8080":
                    raise AssertionError("unexpected policy URL")

        reconciler = PersistentSiteReconciler(
            Runtime(), ("hub1", "hub2", "node7"),
            {
                "bootstrap_ca_pem": "certificate",
                "policy_url": "https://policy:8080",
                "management_host": "172.30.0.254",
            },
            retry_seconds=0.01,
            report=reports.append,
        )
        reconciler.start()
        deadline = time.monotonic() + 2
        while len(calls) < 4 and time.monotonic() < deadline:
            time.sleep(0.01)
        reconciler.close()

        self.assertEqual(calls, ["hub1", "hub1", "hub2", "node7"])
        self.assertTrue(any("waiting for hub1" in line for line in reports))
        self.assertTrue(any("completed for node7" in line for line in reports))
