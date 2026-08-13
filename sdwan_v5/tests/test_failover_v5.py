from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from sdwan_v5.common.marks import EgressMode
from sdwan_v5.hub_health import HubState, aggregate_hub
from sdwan_v5.local_failover import LocalFailoverManager, SlotTarget, StaleRouteVersion
from sdwan_v5.persistence.policy_store import PolicyStore
from sdwan_v5.route_ownership import OwnershipCoordinator, OwnershipRecord
from sdwan_v5.route_resolver import RouteResolver, Target
from sdwan_v5.tunnel_health import StaleMeasurement, TunnelHealthMachine, TunnelSample, TunnelState

from sdwan_v5.edge_failover_runtime import FailoverRouteActuator
from sdwan_v5.common.model import load_config

def sample(sequence: int, usable: bool, timestamp: float) -> TunnelSample:
    return TunnelSample("node1", "hub1", "bb", "wg-h1-bb", timestamp, timestamp, sequence, "active-probe", usable, usable, usable, usable, 1.0)
class RecordingRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def run(self, command: list[str]) -> None:
        self.commands.append(command)




class FailoverTests(unittest.TestCase):
    def test_hysteretic_health_and_stale_sample_rejection(self) -> None:
        machine = TunnelHealthMachine(suspect_failures=2, failed_failures=3, recovery_successes=3, hold_down_s=20, stale_after_s=10)
        self.assertEqual(machine.observe(sample(1, False, 1), now_monotonic=1).state, TunnelState.UNKNOWN)
        self.assertEqual(machine.observe(sample(2, False, 2), now_monotonic=2).state, TunnelState.SUSPECT)
        self.assertEqual(machine.observe(sample(3, False, 3), now_monotonic=3).state, TunnelState.FAILED)
        self.assertEqual(machine.observe(sample(4, True, 4), now_monotonic=4).state, TunnelState.RECOVERING)
        self.assertEqual(machine.observe(sample(5, True, 5), now_monotonic=5).state, TunnelState.RECOVERING)
        self.assertEqual(machine.observe(sample(6, True, 24), now_monotonic=24).state, TunnelState.HEALTHY)
        with self.assertRaises(StaleMeasurement):
            machine.observe(sample(6, True, 24), now_monotonic=24)

    def test_one_tunnel_failure_degrades_not_downs_hub_and_resolves_standby(self) -> None:
        healthy = TunnelHealthMachine(suspect_failures=2, failed_failures=3, recovery_successes=2, hold_down_s=1, stale_after_s=10).observe(sample(1, True, 1), now_monotonic=1)
        failed_machine = TunnelHealthMachine(suspect_failures=2, failed_failures=3, recovery_successes=2, hold_down_s=1, stale_after_s=10)
        for sequence in (1, 2, 3):
            failed = failed_machine.observe(sample(sequence, False, float(sequence)), now_monotonic=float(sequence))
        hub = aggregate_hub("hub1", {"mpls": healthy, "bb": failed, "lte": healthy})
        self.assertEqual(hub.state, HubState.DEGRADED)
        resolver = RouteResolver()
        targets = [
            Target("hub1", "bb", "wg-h1-bb", EgressMode.HUB_OVERLAY, TunnelState.FAILED, HubState.DEGRADED),
            Target("hub2", "bb", "wg-h2-bb", EgressMode.HUB_OVERLAY, TunnelState.HEALTHY, HubState.HEALTHY),
            Target("hub1", "mpls", "wg-h1-mpls", EgressMode.HUB_OVERLAY, TunnelState.HEALTHY, HubState.DEGRADED),
        ]
        result = resolver.resolve(slot="bb", ranked_transports=("bb", "mpls"), allowed_egress=(EgressMode.HUB_OVERLAY,), preferred_hub="hub1", standby_hub="hub2", targets=targets, hard_failure=True)
        self.assertEqual(result.target.interface, "wg-h2-bb")

    def test_baseline_failback_waits_for_flow_drain_or_timeout(self) -> None:
        primary = SlotTarget("hub1", "bb", "wg-h1-bb", 1102)
        backup = SlotTarget("hub2", "bb", "wg-h2-bb", 1202)
        manager = LocalFailoverManager("node1", {"bb": primary}, drain_timeout_s=20)
        event = manager.emergency_remap(event_id="event-1", slot="bb", replacement=backup, reason="tunnel failed", expected_version=0, now=1)
        self.assertEqual(event.local_route_version, 1)
        self.assertEqual(manager.target("bb"), backup)
        self.assertTrue(manager.is_emergency("bb"))
        self.assertEqual(manager.previous_target("bb"), primary)
        with self.assertRaises(StaleRouteVersion):
            manager.emergency_remap(event_id="event-2", slot="bb", replacement=primary, reason="bad", expected_version=0, now=2)
        manager.begin_recovery("bb", now=10)
        self.assertIsNone(manager.complete_recovery("bb", active_flows=1, now=20))
        self.assertEqual(manager.complete_recovery("bb", active_flows=0, now=20), primary)

    def test_failover_repoints_only_overlay_prefixes(self) -> None:
        config = load_config(Path(__file__).resolve().parents[1] / "config" / "topology.yaml")
        desired = {
            "interfaces": [{
                "name": "wg-h2-bb", "transport_slot": 2,
                "routes": ["10.100.0.0/24", "10.2.0.0/24", "198.18.0.0/24"],
            }],
        }
        runner = RecordingRunner()
        FailoverRouteActuator("node1", config, desired, runner).repoint("bb", "wg-h2-bb")
        self.assertIn(["ip", "route", "replace", "10.100.0.0/24", "dev", "wg-h2-bb", "table", "102"], runner.commands)
        self.assertNotIn(["ip", "route", "replace", "198.18.0.0/24", "dev", "wg-h2-bb", "table", "102"], runner.commands)

    def test_ownership_transfer_fences_old_unreachable_hub(self) -> None:
        with TemporaryDirectory() as directory:
            store = PolicyStore(Path(directory) / "policy.db")
            try:
                coordinator = OwnershipCoordinator(store)
                previous = OwnershipRecord("10.1.0.0/24", "node1", "hub1", "hub2", "hub1", None, 4, 8, 12, "COMMITTED", "initial", False)
                store.transfer_ownership(previous.__dict__, "admin")
                moved = coordinator.transfer(previous, new_owner="hub2", new_owner_usable=lambda: True, old_owner_reachable=False, actor="policy", reason="node1 isolated from hub1")
                self.assertEqual(moved.current_owner_hub, "hub2")
                self.assertEqual(moved.owner_epoch, 5)
                self.assertTrue(moved.pending_reconciliation)
                self.assertEqual(store.route_owner("10.1.0.0/24")["current_owner_hub"], "hub2")
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
