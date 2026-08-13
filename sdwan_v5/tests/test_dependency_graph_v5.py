from __future__ import annotations
import tempfile
from pathlib import Path
import unittest
from sdwan_v5.management.config import ManagementConfig
from sdwan_v5.management.service import ManagementService

ROOT = Path(__file__).resolve().parents[1]

class DependencyGraphTests(unittest.TestCase):
    def service(self, directory: str) -> ManagementService:
        return ManagementService(ManagementConfig(ROOT / "config/topology.yaml", Path(directory) / "policy.db", Path(directory) / "ztp.db", Path(directory), "test-secret", "", ""))

    def test_configured_graph_has_ownership_and_underlay_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            graph = self.service(directory).dependency_graph()
        self.assertEqual(graph.component("site:node1").node_type.value, "SITE")
        self.assertIn("site:node1:OWNED_BY:component:edge", graph.edges)
        self.assertIn("interface:node1:bb:BELONGS_TO_UNDERLAY:underlay:bb", graph.edges)
        self.assertIn("underlay:bb:CONTROLLED_BY:component:ryu", graph.edges)

    def test_expected_data_center_path_is_candidate_not_observed_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            value = self.service(directory).graph_expected_traffic_path("node_host1", "dc")
        self.assertTrue(value["available"])
        self.assertEqual(value["path_kind"], "EXPECTED_CONFIGURED_CANDIDATES")
        self.assertEqual(len(value["candidates"]), 2)
        self.assertIn("No hub or transport is claimed selected", value["limitations"][0])

    def test_expected_saas_path_has_only_direct_internet_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            value = self.service(directory).graph_expected_traffic_path("node1_host", "saas")
        self.assertTrue(value["available"])
        self.assertEqual(len(value["candidates"]), 2)
        self.assertTrue(all("interface:node1:" in path[2] for path in value["candidates"]))
        self.assertTrue(all("hub:" not in node for path in value["candidates"] for node in path))
