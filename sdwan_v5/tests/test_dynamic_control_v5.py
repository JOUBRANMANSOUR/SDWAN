from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from sdwan_v5.common.model import load_config
from sdwan_v5.hub_flow_collector import parse_new_flow
from sdwan_v5.management.repository import AuditStore
from sdwan_v5.policy_service_v5 import PolicyService




class DynamicControlTests(unittest.TestCase):
    def test_inventory_allocates_next_free_site_address_without_static_site_loop(self) -> None:
        with TemporaryDirectory() as temporary:
            service = PolicyService(load_config(ROOT / "config" / "topology.core.yaml"), Path(temporary) / "policy.sqlite")
            record = service.create_site(site="branch-6", device_id="edge-branch-6", preferred_hub="hub1", standby_hub="hub2", actor="test")
            self.assertEqual(record.site, "branch-6")
            self.assertEqual(record.lan_prefix, "10.6.0.0/24")
            self.assertEqual(record.lifecycle, "ALLOCATING")

    def test_intent_compiler_revisions_only_the_changed_dynamic_site(self) -> None:
        with TemporaryDirectory() as temporary:
            service = PolicyService(load_config(ROOT / "config" / "topology.core.yaml"), Path(temporary) / "policy.sqlite")
            before = service.compile_control_state()
            self.assertEqual(before["changed_sites"], [])
            service.create_site(site="branch-6", device_id="edge-branch-6", preferred_hub="hub1", standby_hub="hub2", actor="test")
            after = service.compile_control_state()
            self.assertNotEqual(before["input_digest"], after["input_digest"])
            self.assertEqual(after["changed_sites"], [])
            unchanged = service.compile_control_state()
            self.assertEqual(unchanged["changed_sites"], [])

    def test_hub_ack_does_not_create_a_duplicate_desired_state(self) -> None:
        with TemporaryDirectory() as temporary:
            service = PolicyService(load_config(ROOT / "config" / "topology.core.yaml"), Path(temporary) / "policy.sqlite")
            for site, key in (("hub1", "A" * 44), ("hub2", "B" * 44), ("node1", "C" * 44)):
                service.register_edge_identity(site, key, actor="test")
            before = service.store.latest_desired_state("hub1")
            self.assertIsNotNone(before)
            service.acknowledge_edge("hub1", int(before["desired_state_version"]), str(before["configuration_digest"]), int(before["route_version"]), "VERIFIED", "test")
            after = service.store.latest_desired_state("hub1")
            self.assertEqual(after["desired_state_version"], before["desired_state_version"])

    def test_passive_hub_flow_parser_and_repository_are_idempotent(self) -> None:

        line = "[NEW] tcp      6 120 SYN_SENT src=10.1.0.10 dst=10.100.0.10 sport=45678 dport=8443 [UNREPLIED] src=10.100.0.10 dst=10.1.0.10 sport=8443 dport=45678 mark=0x1001"
        flow = parse_new_flow("hub1", line, datetime(2026, 8, 10, tzinfo=timezone.utc))
        self.assertIsNotNone(flow)
        self.assertEqual(flow.conntrack_state, "NEW")
        with TemporaryDirectory() as temporary:
            store = AuditStore(Path(temporary))
            store.ingest_hub_flow(flow.__dict__)
            store.ingest_hub_flow(flow.__dict__)
            records = store.hub_flows("hub1")
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["source_ip"], "10.1.0.10")
ROOT = Path(__file__).resolve().parents[1]
