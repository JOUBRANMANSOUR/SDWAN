from __future__ import annotations
import tempfile
from pathlib import Path
import unittest
from sdwan.management.config import ManagementConfig
from sdwan.management.service import ManagementService

ROOT = Path(__file__).resolve().parents[1]

class DependencyGraphTests(unittest.TestCase):
    def service(self, directory: str) -> ManagementService:
        return ManagementService(ManagementConfig(ROOT / "config/topology.yaml", Path(directory) / "policy.db", Path(directory) / "ztp.db", Path(directory), "test-secret", "", ""))

    def test_configured_graph_has_ownership_and_underlay_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            graph = self.service(directory).dependency_graph()
        self.assertEqual(graph.component("site:site1").node_type.value, "SITE")
        self.assertIn("site:site1:OWNED_BY:component:edge", graph.edges)
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

    def test_expected_branch_path_has_shared_hub_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            value = self.service(directory).graph_expected_traffic_path("node1_host", "node3_host")
        self.assertTrue(value["available"])
        self.assertEqual(value["path_kind"], "EXPECTED_CONFIGURED_CANDIDATES")
        self.assertEqual(value["candidates"][0], ["host:node1_host", "site:site1", "hub:hub1", "site:site3", "host:node3_host"])
        self.assertEqual(value["candidates"][1][2], "hub:hub2")

    def test_directed_graph_traverses_host_site_hub_site_host(self):
        with tempfile.TemporaryDirectory() as directory:
            value = self.service(directory).graph_path("host:node1_host", "host:node3_host")
        self.assertTrue(value["available"])
        relations = [edge["relation_type"] for edge in value["path"]]
        self.assertEqual(relations, ["ATTACHED_TO", "REPRESENTED_BY", "CONNECTED_TO", "TUNNELED_TO", "REPRESENTED_BY", "HOSTS"])
