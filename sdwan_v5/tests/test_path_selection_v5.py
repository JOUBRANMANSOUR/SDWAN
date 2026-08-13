from __future__ import annotations

import unittest

from sdwan_v5.common.marks import EgressMode
from sdwan_v5.common.path_selection import (
    ApplicationClass, ApplicationSLA, MeasurementTuning, MetricWindow,
    NoEligibleAction, PathMeasurement, PathSelector, ScoreWeights, SelectionTuning,
)


def measurement(
    path_id: str,
    transport: str,
    *,
    now: float,
    egress: EgressMode = EgressMode.HUB_OVERLAY,
    rtt: float = 20.0,
    jitter: float = 2.0,
    loss: float = 0.0,
    bandwidth: float = 20.0,
    reachable: bool = True,
    enabled: bool = True,
) -> PathMeasurement:
    return PathMeasurement(
        path_id=path_id,
        transport=transport,
        egress_mode=egress,
        hub="hub1" if egress is EgressMode.HUB_OVERLAY else None,
        interface="test-" + transport,
        configured_capacity_mbps=50.0,
        transport_cost=0.0,
        measured_at_monotonic=now,
        administratively_enabled=enabled,
        operationally_reachable=reachable,
        rtt_ms=rtt,
        jitter_ms=jitter,
        loss_pct=loss,
        estimated_available_bandwidth_mbps=bandwidth,
    )


class PathSelectionTests(unittest.TestCase):
    def realtime_selector(self, *, hold_down: float = 0.0, minimum: float = 15.0) -> PathSelector:
        return PathSelector(
            SelectionTuning(
                bad_samples_before_degraded=3,
                good_samples_before_recovered=5,
                minimum_improvement_percent=minimum,
                hold_down_seconds=hold_down,
            ),
            stale_after_seconds=6.0,
        )

    @staticmethod
    def realtime_sla(action: NoEligibleAction = NoEligibleAction.BEST_EFFORT) -> ApplicationSLA:
        return ApplicationSLA(max_rtt_ms=100, max_jitter_ms=20, max_loss_pct=1, no_eligible_action=action)

    @staticmethod
    def realtime_weights() -> ScoreWeights:
        return ScoreWeights(rtt=0.20, jitter=0.45, loss=0.35)

    def decide(self, selector: PathSelector, paths: list[PathMeasurement], now: float,
               action: NoEligibleAction = NoEligibleAction.BEST_EFFORT):
        return selector.select(
            application_class=ApplicationClass.REALTIME_RTP,
            source="node1_host",
            destination="node2_host",
            destination_policy="branch_private_node2",
            allowed_egress=[EgressMode.HUB_OVERLAY],
            candidate_transports=["mpls", "bb", "lte"],
            measurements=paths,
            sla=self.realtime_sla(action),
            weights=self.realtime_weights(),
            now_monotonic=now,
        )

    def test_metric_window_computes_ewma_jitter_loss_and_available_bandwidth(self) -> None:
        window = MetricWindow(MeasurementTuning(2, 0.5, 6, 4), 50.0)
        first = window.update(successful=True, rtt_ms=20, counter_timestamp=1, interface_bytes=1000)
        self.assertEqual(first, (20, 0.0, 0.0, 50.0))
        second = window.update(successful=True, rtt_ms=30, counter_timestamp=3, interface_bytes=5_001_000)
        self.assertEqual(second[0], 25.0)
        self.assertEqual(second[1], 5.0)
        self.assertAlmostEqual(second[2], 0.0)
        self.assertAlmostEqual(second[3], 40.0, places=3)
        third = window.update(successful=False, rtt_ms=None, loss_pct_sample=100)
        self.assertAlmostEqual(third[2], 100 / 3, places=3)

    def test_metric_window_uses_packet_weighted_loss_samples(self) -> None:
        window = MetricWindow(MeasurementTuning(2, 0.5, 6, 100), 50.0)
        first = window.update(
            successful=True, rtt_ms=20, transmitted_packets=10, received_packets=9
        )
        self.assertAlmostEqual(first[2], 10.0)
        for _ in range(9):
            current = window.update(
                successful=True, rtt_ms=20, transmitted_packets=10, received_packets=10
            )
        self.assertAlmostEqual(current[2], 1.0)

    def test_policy_constraints_reject_wrong_egress_and_transport(self) -> None:
        selector = self.realtime_selector()
        decision = self.decide(selector, [
            measurement("direct-bb", "bb", now=1, egress=EgressMode.DIRECT_INTERNET),
            measurement("hub-unknown", "satellite", now=1),
        ], 1, NoEligibleAction.FAIL_CLOSED)
        self.assertIsNone(decision.selected_path)
        reasons = {item.measurement.path_id: set(item.rejection_reasons) for item in decision.candidates}
        self.assertIn("EGRESS_NOT_ALLOWED", reasons["direct-bb"])
        self.assertIn("TRANSPORT_NOT_CANDIDATE", reasons["hub-unknown"])

    def test_three_bad_samples_are_required_before_switch(self) -> None:
        selector = self.realtime_selector()
        first = self.decide(selector, [
            measurement("mpls", "mpls", now=1),
            measurement("bb", "bb", now=1, rtt=35, jitter=6, loss=0.2),
        ], 1)
        self.assertEqual(first.selected_path.path_id, "mpls")
        for now in (2, 3):
            pending = self.decide(selector, [
                measurement("mpls", "mpls", now=now, jitter=40, loss=4),
                measurement("bb", "bb", now=now, rtt=35, jitter=6, loss=0.2),
            ], now)
            self.assertEqual(pending.selected_path.path_id, "mpls")
            self.assertIn("PENDING_HYSTERESIS", pending.selection_reason)
            self.assertFalse(pending.changed)
        switched = self.decide(selector, [
            measurement("mpls", "mpls", now=4, jitter=40, loss=4),
            measurement("bb", "bb", now=4, rtt=35, jitter=6, loss=0.2),
        ], 4)
        self.assertEqual(switched.selected_path.path_id, "bb")
        self.assertEqual(switched.selection_reason, "SLA_VIOLATION_JITTER")
        self.assertTrue(switched.changed)

    def test_five_good_samples_are_required_before_recovery(self) -> None:
        selector = self.realtime_selector(minimum=0)
        self.decide(selector, [measurement("mpls", "mpls", now=1), measurement("bb", "bb", now=1, rtt=35, jitter=6)], 1)
        for now in (2, 3, 4):
            self.decide(selector, [measurement("mpls", "mpls", now=now, jitter=40, loss=4), measurement("bb", "bb", now=now, rtt=35, jitter=6)], now)
        for now in (5, 6, 7, 8):
            decision = self.decide(selector, [measurement("mpls", "mpls", now=now), measurement("bb", "bb", now=now, rtt=35, jitter=6)], now)
            self.assertEqual(decision.selected_path.path_id, "bb")
            mpls = next(item for item in decision.candidates if item.measurement.path_id == "mpls")
            self.assertEqual(mpls.sla_state, "PENDING_RECOVERY")
        recovered = self.decide(selector, [measurement("mpls", "mpls", now=9), measurement("bb", "bb", now=9, rtt=35, jitter=6)], 9)
        self.assertEqual(recovered.selected_path.path_id, "mpls")
        self.assertTrue(recovered.changed)

    def test_hard_path_down_switches_immediately(self) -> None:
        selector = self.realtime_selector()
        self.decide(selector, [measurement("mpls", "mpls", now=1), measurement("bb", "bb", now=1, rtt=35)], 1)
        decision = self.decide(selector, [
            measurement("mpls", "mpls", now=2, reachable=False),
            measurement("bb", "bb", now=2, rtt=35),
        ], 2)
        self.assertEqual(decision.selected_path.path_id, "bb")
        self.assertEqual(decision.selection_reason, "PATH_DOWN")

    def test_stale_measurement_is_ineligible(self) -> None:
        selector = self.realtime_selector()
        decision = self.decide(selector, [measurement("mpls", "mpls", now=1)], 8, NoEligibleAction.FAIL_CLOSED)
        self.assertIsNone(decision.selected_path)
        self.assertIn("MEASUREMENT_STALE", decision.candidates[0].rejection_reasons)

    def test_best_effort_and_fail_closed_have_different_no_eligible_behavior(self) -> None:
        bad = [measurement("mpls", "mpls", now=1, jitter=50, loss=10)]
        best_effort = self.decide(self.realtime_selector(), bad, 1, NoEligibleAction.BEST_EFFORT)
        self.assertEqual(best_effort.selected_path.path_id, "mpls")
        self.assertEqual(best_effort.selection_reason, "NO_ELIGIBLE_PATH_BEST_EFFORT")
        fail_closed = self.decide(self.realtime_selector(), bad, 1, NoEligibleAction.FAIL_CLOSED)
        self.assertIsNone(fail_closed.selected_path)
        self.assertEqual(fail_closed.selection_reason, "NO_ELIGIBLE_PATH")

    def test_hold_down_and_minimum_improvement_prevent_flapping(self) -> None:
        hold = self.realtime_selector(hold_down=10, minimum=0)
        self.decide(hold, [measurement("mpls", "mpls", now=1, rtt=30), measurement("bb", "bb", now=1, rtt=40)], 1)
        decision = self.decide(hold, [measurement("mpls", "mpls", now=2, rtt=30), measurement("bb", "bb", now=2, rtt=5, jitter=1)], 2)
        self.assertEqual(decision.selected_path.path_id, "mpls")
        self.assertEqual(decision.selection_reason, "HOLD_DOWN_RETAINED")

        threshold = self.realtime_selector(hold_down=0, minimum=90)
        self.decide(threshold, [measurement("mpls", "mpls", now=1, rtt=20), measurement("bb", "bb", now=1, rtt=21)], 1)
        decision = self.decide(threshold, [measurement("mpls", "mpls", now=2, rtt=21), measurement("bb", "bb", now=2, rtt=20)], 2)
        self.assertEqual(decision.selected_path.path_id, "mpls")
        self.assertEqual(decision.selection_reason, "MINIMUM_IMPROVEMENT_NOT_MET")


if __name__ == "__main__":
    unittest.main()
