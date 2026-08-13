from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import unittest
import json
import os
import socket
import subprocess
import sys
import time
import inspect
from tempfile import TemporaryDirectory

import yaml

from sdwan_v5.edge_agent_v5 import EdgeAgent
from sdwan_v5.topology_visualization import render_dot, render_files
from sdwan_v5.common.marks import EgressMode, FlowMarkStage
from sdwan_v5.common.model import ConfigurationError, config_from_mapping, load_config


ROOT = Path(__file__).resolve().parents[1]


class ConfigAndMarkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config(ROOT / "config" / "topology.yaml")

    def test_five_spokes_have_six_distinct_preestablished_targets(self) -> None:
        expected = {(hub, transport) for hub in ("hub1", "hub2") for transport in ("mpls", "bb", "lte")}
        for site in self.config.sites:
            targets = self.config.spoke_targets(site)
            self.assertEqual(len(targets), 6)
            self.assertEqual(len({target.interface_name for target in targets}), 6)
            self.assertEqual({(target.hub, target.transport) for target in targets}, expected)

    def test_v4_mark_abi_and_v5_affinity_are_nonoverlapping(self) -> None:
        layout = self.config.settings.marks
        mark = layout.encode(2, FlowMarkStage.TERMINAL, emergency=True, hub="hub2", egress=EgressMode.DIRECT_INTERNET)
        self.assertEqual(layout.transport(mark), 2)
        self.assertEqual(layout.stage(mark), FlowMarkStage.TERMINAL)
        self.assertEqual(layout.target_hub(mark), "hub2")
        self.assertEqual(layout.egress_mode(mark), EgressMode.DIRECT_INTERNET)
        self.assertEqual(mark & 0xFF, 2)
        self.assertEqual(layout.connection_mask, 0xF7FF)

    def test_duplicate_preferred_and_standby_hub_is_rejected(self) -> None:
        raw = deepcopy(yaml.safe_load((ROOT / "config" / "topology.yaml").read_text()))
        raw["spokes"]["node1"]["standby_hub"] = "hub1"
        with self.assertRaises(ConfigurationError):
            config_from_mapping(raw)

    def test_prefix_overlap_is_rejected(self) -> None:
        raw = deepcopy(yaml.safe_load((ROOT / "config" / "topology.yaml").read_text()))
        raw["data_center"]["network"] = "10.1.0.0/24"
        with self.assertRaises(ConfigurationError):
            config_from_mapping(raw)

    def test_mpls_cannot_be_direct_internet_by_default(self) -> None:
        raw = deepcopy(yaml.safe_load((ROOT / "config" / "topology.yaml").read_text()))
        raw["transports"]["mpls"]["internet_capable"] = True
        with self.assertRaises(ConfigurationError):
            config_from_mapping(raw)


    def test_host_image_packages_the_concurrent_workload_client(self) -> None:
        dockerfile = (ROOT / "docker" / "Dockerfile.host.v5").read_text(encoding="utf-8")
        self.assertIn("COPY sdwan_v5/workloads/http_load.py /opt/sdwan_v5/workloads/http_load.py", dockerfile)


    def test_classifier_events_are_collected_as_bounded_metadata_only_jsonl(self) -> None:
        collector = (ROOT / "classifier_event_collector.py").read_text(encoding="utf-8")
        agent = (ROOT / "edge_agent_v5.py").read_text(encoding="utf-8")
        self.assertIn("socket.SOCK_DGRAM", collector)
        self.assertIn('event.pop("payload", None)', collector)
        self.assertIn('event.pop("packet", None)', collector)
        worker = (ROOT / "classifier" / "nfqueue_worker.c").read_text(encoding="utf-8")
        flow_table = (ROOT / "classifier" / "flow_table.c").read_text(encoding="utf-8")
        self.assertIn("expiration_event", worker)
        self.assertIn("expiration_event, worker", worker)
        self.assertIn("sdwan_flow_expiry_observer observer", flow_table)
        native_start = inspect.getsource(EdgeAgent._start_native_classifier)
        collector_start = inspect.getsource(EdgeAgent._start_classifier_event_collector)
        self.assertIn("classifier.json", native_start)
        self.assertNotIn("queue_number", collector_start)
        self.assertIn("sdwan_v5.classifier_event_collector", agent)
        self.assertIn("classifier-events.jsonl", agent)

    def test_classifier_event_collector_strips_packet_content(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            socket_path = root / "classifier-events.sock"
            output = root / "classifier-events.jsonl"
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(ROOT.parent)
            process = subprocess.Popen(
                [sys.executable, "-m", "sdwan_v5.classifier_event_collector", "--socket", str(socket_path), "--output", str(output)],
                env=environment,
            )
            try:
                deadline = time.monotonic() + 3.0
                while not socket_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(socket_path.exists(), "collector did not bind its socket")
                sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                try:
                    sender.sendto(json.dumps({"site": "node1", "protocol": "http", "payload": "forbidden", "packet": "forbidden"}).encode("utf-8"), str(socket_path))
                finally:
                    sender.close()
                while (not output.exists() or not output.read_text(encoding="utf-8")) and time.monotonic() < deadline:
                    time.sleep(0.02)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3.0)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), {"protocol": "http", "site": "node1"})

    def test_graphviz_renderer_has_a_readable_logical_view_and_exact_physical_view(self) -> None:
        logical = render_dot(self.config)
        physical = render_dot(self.config, detail="physical")
        self.assertEqual(logical.count(" -- "), 23)
        self.assertEqual(physical.count(" -- "), 47)
        for name in ("hub1", "hub2", "node1", "node5", "s_mpls", "s_bb", "s_lte", "dc_app", "saas_nginx"):
            self.assertIn(name, logical)
        self.assertIn("transport_fabric", logical)
        self.assertIn("SD-WAN v5 logical topology", logical)
        with TemporaryDirectory() as directory:
            dot_path = Path(directory) / "topology.dot"
            render_files(ROOT / "config" / "topology.yaml", dot_path, None)
            self.assertEqual(dot_path.read_text(encoding="utf-8"), logical)
        raw = yaml.safe_load((ROOT / "config" / "topology.yaml").read_text(encoding="utf-8"))
        raw["cloud_vpc"]["enabled"] = True
        self.assertIn('"cloud_gw1"', render_dot(config_from_mapping(raw)))
    def test_cloud_transit_overlap_is_rejected(self) -> None:
        raw = deepcopy(yaml.safe_load((ROOT / "config" / "topology.yaml").read_text()))
        raw["cloud_vpc"]["transit_networks"]["hub1_cloud_gw1"] = "10.1.0.0/30"
        with self.assertRaises(ConfigurationError):
            config_from_mapping(raw)

if __name__ == "__main__":
    unittest.main()
