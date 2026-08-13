from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sdwan.management.config import ManagementConfig
from sdwan.management.evidence import EvidenceValidator, render_verified_answer
from sdwan.management.evidence_planner import prepare_route_evidence
from sdwan.management.service import ManagementService


ROOT = Path(__file__).resolve().parents[1]


class ZeroFlowRuntime:
    def connection_marks(self, site, source, destination):
        return {"availability": "AVAILABLE", "value": []}


class EvidencePlannerTests(unittest.TestCase):
    def service(self, directory):
        config = ManagementConfig(
            ROOT / "config/topology.yaml",
            Path(directory) / "policy.db",
            Path(directory) / "ztp.db",
            Path(directory),
            "test-secret",
            "",
            "",
        )
        service = ManagementService(config)
        service.runtime = ZeroFlowRuntime()
        return service

    def test_observed_route_is_prefetched_without_model_tool_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            prepared = prepare_route_evidence(
                self.service(directory),
                "What is the observed route from node1_host to node3_host?",
            )
        self.assertIsNotNone(prepared)
        self.assertEqual(
            prepared.arguments,
            {"source": "node1_host", "destination": "node3_host"},
        )
        kinds = {fact["fact_kind"] for fact in prepared.result["facts"]}
        self.assertIn("flow_observation", kinds)
        self.assertIn("configured_path_candidates", kinds)

    def test_prepared_fallback_is_valid_and_renders_graph_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            prepared = prepare_route_evidence(
                self.service(directory),
                "What is the observed route from node1_host to node3_host?",
            )
        bundle = {
            "bundle_id": "prepared-route",
            "payload": {
                "facts": prepared.result["facts"],
                "unknowns": prepared.result["meta"]["unknowns"],
                "limitations": prepared.result["meta"]["limitations"],
            },
        }
        outcome = EvidenceValidator().validate(prepared.fallback_answer, bundle)
        self.assertTrue(outcome["valid"])
        rendered = render_verified_answer(outcome, bundle)
