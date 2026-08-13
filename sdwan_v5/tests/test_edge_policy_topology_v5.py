from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import types
import unittest
from unittest.mock import patch

import yaml

from sdwan_v5.common.model import ConfigurationError, config_from_mapping, load_config
from sdwan_v5.desired_state_v5 import build_spoke_desired_state
from sdwan_v5.topology_v5 import (
    _configure_addresses,
    _wait_for_underlay_readiness,
    _flush_route_table_if_present,
    build_live_plan,
    build_plan,
    launch_live,
    validate_plan,
)
from sdwan_v5.edge_agent_v5 import ClassMarkRule, EdgeAgent
from sdwan_v5.policy_service_v5 import PolicyService
from sdwan_v5.policy_http import PolicyApplication


ROOT = Path(__file__).resolve().parents[1]


class RecordingRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def run(self, command: list[str]) -> None:
        self.commands.append(command)


class EdgePolicyTopologyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config(ROOT / "config" / "topology.yaml")

    def test_internet_gateway_underlay_links_retain_their_transport_identity(self) -> None:
        config = load_config(ROOT / "config" / "topology.core.yaml")
        plan = build_live_plan(config)
        gateway_links = [
            link for link in plan.links
            if link.node1 == config.saas_gateway_name and link.node2 in {item.switch for item in config.transports.values()}
        ]
        self.assertEqual({link.transport for link in gateway_links}, {"bb", "lte"})

    def test_underlay_readiness_reports_missing_controller_snapshot(self) -> None:
        with TemporaryDirectory() as directory, patch.dict("os.environ", {
            "SDWAN_STATE_ROOT": directory,
            "SDWAN_UNDERLAY_READY_TIMEOUT": "0",
        }, clear=False):
            with self.assertRaisesRegex(RuntimeError, "Ryu underlay readiness timeout"):
                _wait_for_underlay_readiness(self.config)

    def test_edge_reconciliation_is_persistent_and_rejects_stale_route(self) -> None:
        with TemporaryDirectory() as directory:
            runner = RecordingRunner()
            desired = build_spoke_desired_state(self.config, "node1", {"hub1": "A" * 44, "hub2": "B" * 44}, generation="g", desired_state_version=1, route_version=3, ownership_epoch=1).to_dict()
            agent = EdgeAgent("node1", self.config, Path(directory), runner)
            self.assertEqual(agent.reconcile(desired).status, "VERIFIED")
            runner.commands.clear()
            resumed = EdgeAgent("node1", self.config, Path(directory), runner)
            self.assertEqual(resumed.reconcile(desired).status, "MATCHED")
            self.assertIn(["ip", "link", "add", "dev", "wg-h1-mpls", "type", "wireguard"], runner.commands)
            self.assertTrue(any(command[:3] == ["ip", "route", "replace"] and "101" in command for command in runner.commands))
            stale = dict(desired)
            stale["desired_state_version"], stale["route_version"], stale["configuration_digest"] = 2, 2, "different"
            self.assertEqual(resumed.reconcile(stale).status, "EDGE_AHEAD")
            self.assertTrue(any(command[:3] == ["wg", "set", "wg-h1-mpls"] for command in runner.commands))

    def test_direct_nat_returns_private_prefixes_before_masquerade(self) -> None:
        with TemporaryDirectory() as directory:
            runner = RecordingRunner()
            agent = EdgeAgent("node1", self.config, Path(directory), runner)
            agent.install_scoped_direct_nat("10.1.0.0/24", {"bb": "node1-bb", "lte": "node1-lte"})
            commands = [" ".join(command) for command in runner.commands]
            first_masquerade = next(index for index, command in enumerate(commands) if "MASQUERADE" in command)
            self.assertTrue(all("RETURN" in command for command in commands[3:first_masquerade]))
            self.assertFalse(any("10.100.0.0/24" in command and "MASQUERADE" in command for command in commands))

    def test_policy_intent_installs_class_marks_nfqueue_and_direct_saas_route(self) -> None:
        with TemporaryDirectory() as directory:
            application = PolicyApplication(
                self.config, Path(directory) / "policy.db", ROOT / "config" / "app_policy.yaml",
                ROOT / "config" / "site_inventory.yaml", ROOT / "config" / "destination_policy.yaml",
            )
            try:
                policy = application.snapshot("node1")
            finally:
                application.service.store.close()
            runner = RecordingRunner()
            desired = build_spoke_desired_state(
                self.config, "node1", {"hub1": "A" * 44, "hub2": "B" * 44},
                generation="g", desired_state_version=1, route_version=1, ownership_epoch=1,
            ).to_dict()
            agent = EdgeAgent("node1", self.config, Path(directory), runner)
            agent.reconcile(desired)
            runner.commands.clear()
            agent.install_spoke_dataplane(desired, policy)
            commands = [" ".join(command) for command in runner.commands]
            self.assertTrue(any("-d 10.100.0.10/32" in command and "--set-xmark" in command for command in commands))
            self.assertTrue(any("-d 198.18.0.10/32" in command and "--set-xmark" in command for command in commands))
            self.assertTrue(any("--dports 5004" in command and "-p udp" in command for command in commands))
            self.assertTrue(any("--dscp 18" in command and "--dports 443,80" in command for command in commands))
            self.assertTrue(any("--dscp 10" in command and "--dports 443,80" in command for command in commands))
            self.assertIn(["ip", "route", "replace", "198.18.0.10/32", "via", "192.168.20.253", "dev", "node1-bb", "onlink", "table", "102"], runner.commands)
            self.assertFalse(any("198.18.0.10/32" in command and "wg-h" in command for command in commands))
            self.assertTrue(any("NFQUEUE --queue-num 4100 --queue-bypass" in command for command in commands))

    def test_no_eligible_class_never_installs_packet_drop(self) -> None:
        with TemporaryDirectory() as directory:
            runner = RecordingRunner()
            agent = EdgeAgent("node1", self.config, Path(directory), runner)
            agent.install_connmark_rules(
                "node1-lan",
                [("198.18.0.10/32", 0x4102)],
                0x1101,
                class_marks=(ClassMarkRule(
                    "SAAS_INTERACTIVE", "198.18.0.10/32", 0x4102,
                    "tcp", (443, 80), 18, True,
                ),),
            )
            commands = [" ".join(command) for command in runner.commands]
            restore_index = next(index for index, command in enumerate(commands) if "CONNMARK --restore-mark" in command)
            self.assertGreaterEqual(restore_index, 0)
            self.assertFalse(any("-j DROP" in command or "-j REJECT" in command for command in commands))

    def test_hub_backhaul_has_private_routes_and_no_saas_transit(self) -> None:
        with TemporaryDirectory() as directory:
            runner = RecordingRunner()
            agent = EdgeAgent("hub1", self.config, Path(directory), runner)
            agent.install_hub_backhaul()
            commands = [" ".join(command) for command in runner.commands]
            self.assertIn(["ip", "route", "replace", "10.1.0.0/24", "dev", "wg-spokes-mpls"], runner.commands)
            self.assertFalse(any("198.18.0." in command for command in commands))
            self.assertFalse(any(command[-2:] == ["-j", "MASQUERADE"] for command in runner.commands))
            self.assertIn(
                ["iptables", "-t", "nat", "-A", "SDWAN_V5_HUB_NAT", "-d", "10.100.0.0/24", "-o", "hub1-dc", "-j", "SNAT", "--to-source", "10.100.0.1"],
                runner.commands,
            )
            self.assertTrue(any(
                command[:7] == ["iptables", "-t", "mangle", "-A", "SDWAN_V5_RPA_IN", "-i", "wg-spokes-mpls"]
                and "0x1101/0xf1ff" in command
                for command in runner.commands
            ))

    def test_spoke_return_affinity_covers_all_six_hub_transport_paths(self) -> None:
        with TemporaryDirectory() as directory:
            runner = RecordingRunner()
            agent = EdgeAgent("node1", self.config, Path(directory), runner)
            agent.install_spoke_return_affinity()
            commands = [" ".join(command) for command in runner.commands]
            ingress = [command for command in commands if "-A SDWAN_V5_RPA_IN -i wg-h" in command and "--set-xmark" in command]
            egress = [command for command in commands if "-A SDWAN_V5_RPA_OUT -o wg-h" in command and "--set-xmark" in command]
            self.assertEqual(len(ingress), 6)
            self.assertEqual(len(egress), 6)
            self.assertTrue(any("-i wg-h1-mpls" in command and "0x1101/0xf1ff" in command for command in ingress))
            self.assertTrue(any("-i wg-h2-lte" in command and "0x2103/0xf1ff" in command for command in ingress))
            self.assertTrue(any("CONNMARK --restore-mark --nfmask 0xf7ff --ctmask 0xf7ff" in command for command in commands))

    def test_policy_rules_use_portable_owned_priority_replacement(self) -> None:

        with TemporaryDirectory() as directory:
            runner = RecordingRunner()
            agent = EdgeAgent("node1", self.config, Path(directory), runner)
            agent.install_policy_rules()
            self.assertFalse(any(command[:3] == ["ip", "rule", "replace"] for command in runner.commands))
            self.assertIn(["ip", "rule", "del", "priority", "2001"], runner.commands)
            self.assertIn(["ip", "rule", "add", "priority", "2001", "fwmark", "1/255", "lookup", "101"], runner.commands)
            self.assertIn(["ip", "rule", "add", "priority", "1101", "fwmark", "4097/12543", "lookup", "1101"], runner.commands)
            specific_index = runner.commands.index(["ip", "rule", "add", "priority", "1101", "fwmark", "4097/12543", "lookup", "1101"])
            generic_index = runner.commands.index(["ip", "rule", "add", "priority", "2001", "fwmark", "1/255", "lookup", "101"])
            self.assertGreater(specific_index, generic_index)  # command order is irrelevant; numeric priority is authoritative
            self.assertLess(1101, 2001)

    def test_policy_snapshot_exposes_authoritative_destination_intents(self) -> None:
        with TemporaryDirectory() as directory:
            application = PolicyApplication(
                self.config, Path(directory) / "policy.db", ROOT / "config" / "app_policy.yaml",
                ROOT / "config" / "site_inventory.yaml", ROOT / "config" / "destination_policy.yaml",
            )
            try:
                snapshot = application.snapshot("node1")
                by_prefix = {item["prefix"]: item for item in snapshot["destination_intents"]}
                self.assertEqual(by_prefix["10.100.0.10/32"]["application_classes"], ["CENTRAL_BACKUP"])
                self.assertEqual(by_prefix["10.100.0.10/32"]["allowed_egress"], ["HUB_OVERLAY"])
                self.assertEqual(by_prefix["198.18.0.10/32"]["application_classes"], ["SAAS_INTERACTIVE", "SAAS_FILE_TRANSFER"])
                self.assertEqual(by_prefix["198.18.0.10/32"]["allowed_egress"], ["DIRECT_INTERNET"])
                self.assertEqual(by_prefix["10.2.0.0/24"]["application_classes"], ["REALTIME_RTP"])
                self.assertNotIn("10.200.0.0/24", by_prefix)
                self.assertEqual(snapshot["default_intent"]["failure_action"], "FAIL_CLOSED")
                self.assertEqual(snapshot["policy_version"], 1)
            finally:
                application.service.store.close()

    def test_recoverable_dynamic_site_failure_keeps_operational_identity_authorized(self) -> None:
        with TemporaryDirectory() as directory:
            application = PolicyApplication(
                self.config, Path(directory) / "policy.db", ROOT / "config" / "app_policy.yaml",
                ROOT / "config" / "site_inventory.yaml", ROOT / "config" / "destination_policy.yaml",
            )
            try:
                application.service.inventory.allocate(
                    site="node7", device_id="node7-edge",
                    preferred_hub="hub1", standby_hub="hub2", actor="test",
                )
                application.service.inventory.transition(
                    "node7", "FAILED", actor="test", failure_stage="RECONCILING",
                    error="temporary reconciliation failure", recoverable=True,
                )
                self.assertEqual(application.site_for_device("node7-edge"), "node7")
            finally:
                application.service.store.close()

    def test_nonrecoverable_dynamic_site_failure_denies_operational_identity(self) -> None:
        with TemporaryDirectory() as directory:
            application = PolicyApplication(
                self.config, Path(directory) / "policy.db", ROOT / "config" / "app_policy.yaml",
                ROOT / "config" / "site_inventory.yaml", ROOT / "config" / "destination_policy.yaml",
            )
            try:
                application.service.inventory.allocate(
                    site="node7", device_id="node7-edge",
                    preferred_hub="hub1", standby_hub="hub2", actor="test",
                )
                application.service.inventory.transition(
                    "node7", "FAILED", actor="test", failure_stage="RECONCILING",
                    error="terminal identity failure", recoverable=False,
                )
                with self.assertRaisesRegex(PermissionError, "non-recoverable inventory"):
                    application.site_for_device("node7-edge")
            finally:
                application.service.store.close()

    def test_hub_first_activation_requires_both_hubs(self) -> None:
        with TemporaryDirectory() as directory:
            service = PolicyService(self.config, Path(directory) / "policy.db")
            try:
                service.stage_inventory()
                denied = service.hub_first_activate("node1", {"hub1": "A" * 44, "hub2": "B" * 44}, generation="g", desired_state_version=1, ownership_epoch=1, prepare_hub=lambda hub, site: hub == "hub1", apply_spoke=lambda state: True)
                self.assertEqual(denied.state, "PENDING_HUBS")
                active = service.hub_first_activate("node1", {"hub1": "A" * 44, "hub2": "B" * 44}, generation="g", desired_state_version=1, ownership_epoch=1, prepare_hub=lambda hub, site: True, apply_spoke=lambda state: True)
                self.assertEqual(active.state, "ACTIVE")
            finally:
                service.store.close()

    def test_registered_hubs_must_ack_before_spoke_activation(self) -> None:
        with TemporaryDirectory() as directory:
            service = PolicyService(self.config, Path(directory) / "policy.db")
            try:
                service.stage_inventory()
                self.assertEqual(service.register_edge_identity("hub1", "A" * 44, actor="mtls:edge-hub1")["state"], "HUB_READY")
                self.assertEqual(service.register_edge_identity("hub2", "B" * 44, actor="mtls:edge-hub2")["state"], "HUB_READY")
                self.assertEqual(service.register_edge_identity("node1", "C" * 44, actor="mtls:edge-node1")["state"], "PENDING_HUBS")
                self.assertEqual(service.activate_spoke("node1", actor="mtls:sdwan-admin").state, "PENDING_HUBS")
                for hub in ("hub1", "hub2"):
                    desired = service.desired_state_for(hub)
                    self.assertIsNotNone(desired)
                    service.acknowledge_edge(hub, int(desired["desired_state_version"]), str(desired["configuration_digest"]), int(desired["route_version"]), "VERIFIED", "hub peer state verified")
                activation = service.activate_spoke("node1", actor="mtls:sdwan-admin")
                self.assertEqual(activation.state, "EDGE_CONFIGURING")
                self.assertIsNotNone(activation.desired_state)
                self.assertEqual(len(activation.desired_state.interfaces), 6)
                owner = service.store.route_owner("10.1.0.0/24")
                self.assertEqual(owner["current_owner_hub"], "hub1")
                self.assertEqual(owner["owner_epoch"], 1)
            finally:
                service.store.close()

    def test_topology_plan_has_expected_physical_inventory(self) -> None:
        plan = build_plan(self.config)
        live = build_live_plan(self.config)
        self.assertEqual(len(plan.routers), 7)
        self.assertEqual(plan.expected_openflow_datapaths, 8)
        self.assertEqual(plan.cloud_nodes, ())
        self.assertEqual(validate_plan(ROOT / "config" / "topology.yaml"), plan)
        self.assertEqual(len(live.switches), 11)
        self.assertEqual(sum(switch.openflow for switch in live.switches), 8)
        self.assertEqual(len(live.docker_nodes), 15)
        self.assertEqual(len(live.links), 46)
        self.assertEqual(sum(link.transport is not None for link in live.links), 23)
        self.assertEqual(plan.saas_nodes, ("inetbr", "inet_gw", "public_saas"))
        self.assertIn("inet_gw", live.forwarding_nodes)
        self.assertNotIn("public_saas", live.forwarding_nodes)
        self.assertTrue(any(node.name == "inet_gw" and node.role == "internet-gateway" for node in live.docker_nodes))
        self.assertTrue(any(
            link.node1 == "public_saas" and link.node2 == "inetbr"
            and link.intf1 == "saas-inet" and link.address1 == "198.18.0.10/24"
            for link in live.links
        ))
        self.assertTrue(any(
            link.node1 == "inet_gw" and link.node2 == "inetbr"
            and link.intf1 == "inet-public" and link.address1 == "198.18.0.1/24"
            for link in live.links
        ))
        self.assertTrue(any(
            link.node1 == "inet_gw" and link.node2 == "s_bb"
            and link.intf1 == "inet-bb" and link.address1 == "192.168.20.254/32"
            for link in live.links
        ))
        self.assertTrue(any(
            link.node1 == "inet_gw" and link.node2 == "s_lte"
            and link.intf1 == "inet-lte" and link.address1 == "192.168.30.254/32"
            for link in live.links
        ))
        self.assertFalse(any(
            link.node1 == "public_saas" and link.node2 in {"s_bb", "s_lte"}
            for link in live.links
        ))
        self.assertIn(
            ("public_saas", "198.18.0.1", "saas-inet"),
            tuple((route.node, str(route.gateway), route.interface) for route in live.host_default_routes),
        )
        self.assertLessEqual(max(len(interface) for link in live.links for interface in (link.intf1, link.intf2)), 15)

    def test_config_rejects_duplicate_openflow_dpid(self) -> None:
        raw = yaml.safe_load((ROOT / "config" / "topology.yaml").read_text(encoding="utf-8"))
        raw["spokes"]["node1"]["lan_dpid"] = 1
        with self.assertRaisesRegex(ConfigurationError, "unique positive DPIDs"):
            config_from_mapping(raw)

    def test_optional_cloud_adds_gateway_nodes_without_openflow_growth(self) -> None:
        cloud_config = load_config(ROOT / "config" / "topology.cloud.yaml")
        plan = build_live_plan(cloud_config)
        self.assertEqual(plan.inventory.cloud_nodes, ("cloud_gw1", "cloud_gw2", "cloud_app"))
        self.assertEqual(sum(switch.openflow for switch in plan.switches), 8)
        self.assertEqual(len(plan.switches), 12)
        self.assertEqual(len(plan.docker_nodes), 18)
        self.assertEqual(len(plan.links), 53)
        self.assertEqual(len(plan.forwarding_nodes), 10)
        gateway_links = [link for link in plan.links if link.node1.startswith("cloud_gw") or link.node2.startswith("cloud_gw")]
        self.assertEqual(len(gateway_links), 6)
        self.assertFalse(any(link.transport is not None for link in gateway_links))
        self.assertFalse(any(link.node1.startswith("node") and link.node2.startswith("cloud_gw") for link in plan.links))
        cloud_gateway_links = [link for link in plan.links if link.node1.startswith("cloud_gw") or link.node2.startswith("cloud_gw")]
        self.assertEqual(len(cloud_gateway_links), 6)
        self.assertFalse(any(link.transport for link in cloud_gateway_links))
        self.assertFalse(any(link.node1.startswith("node") and link.node2.startswith("cloud_gw") for link in plan.links))

    def test_missing_cloud_policy_table_is_harmless_on_first_launch(self) -> None:
        class Node:
            name = "cloud_gw1"

            def pexec(self, command: list[str]) -> tuple[str, str, int]:
                self.command = command
                return "", "Error: ipv4: FIB table does not exist.\nFlush terminated", 2

        node = Node()
        _flush_route_table_if_present(node, 3101)
        self.assertEqual(node.command, ["ip", "route", "flush", "table", "3101"])

    def test_cloud_policy_table_flush_keeps_unexpected_errors_fatal(self) -> None:
        class Node:
            name = "cloud_gw1"

            def pexec(self, command: list[str]) -> tuple[str, str, int]:
                return "", "RTNETLINK answers: Operation not permitted", 2

        with self.assertRaisesRegex(RuntimeError, "Operation not permitted"):
            _flush_route_table_if_present(Node(), 3101)

    def test_cloud_routes_have_deterministic_primary_and_backup_paths(self) -> None:
        raw = yaml.safe_load((ROOT / "config" / "topology.cloud.yaml").read_text(encoding="utf-8"))
        cloud_config = config_from_mapping(raw)
        plan = build_live_plan(cloud_config)

        class Node:
            def __init__(self) -> None:
                self.commands: list[list[str]] = []

            def pexec(self, command: list[str]) -> tuple[str, str, int]:
                self.commands.append(command)
                return "", "", 0

        names = {name for link in plan.links for name in (link.node1, link.node2)}
        nodes = {name: Node() for name in names}
        _configure_addresses(nodes, cloud_config, plan)
        self.assertIn(["ip", "route", "replace", "10.200.0.0/24", "via", "172.20.1.2", "dev", "h1-c1", "metric", "100"], nodes["hub1"].commands)
        self.assertIn(["ip", "route", "replace", "10.200.0.0/24", "via", "172.20.2.2", "dev", "h1-c2", "metric", "200"], nodes["hub1"].commands)
        self.assertIn(["ip", "route", "replace", "10.1.0.0/24", "via", "172.20.3.1", "dev", "c1-h2", "metric", "200"], nodes["cloud_gw1"].commands)
        self.assertIn(["ip", "route", "replace", "10.1.0.0/24", "via", "10.200.0.2", "dev", "cloud_app-vpc", "metric", "200"], nodes["cloud_app"].commands)
        cloud_commands = [" ".join(command) for command in nodes["cloud_gw1"].commands]
        self.assertTrue(any("CONNMARK --restore-mark --nfmask 0xf7ff --ctmask 0xf7ff" in command for command in cloud_commands))
        self.assertTrue(any("-i c1-h1" in command and "--set-xmark 0x9100/0xf1ff" in command for command in cloud_commands))
        self.assertIn(
            ["ip", "rule", "add", "priority", "1301", "fwmark", "36864/61440", "lookup", "3101"],
            nodes["cloud_gw1"].commands,
        )
        self.assertIn(
            ["ip", "route", "replace", "10.1.0.0/24", "via", "172.20.1.1", "dev", "c1-h1", "table", "3101"],
            nodes["cloud_gw1"].commands,
        )
        self.assertTrue(any(
            "-A SDWAN_V5_CLOUD_SNAT -s 10.1.0.0/24 -d 10.200.0.0/24 -o cloud_gw1-vpc -j SNAT --to-source 10.200.0.1" in command
            for command in cloud_commands
        ))

    def test_launch_live_builds_expected_containernet_lifecycle(self) -> None:
        calls: list[tuple[str, object]] = []
        pexec_commands: list[tuple[str, tuple[str, ...]]] = []

        class FakeNode:
            def __init__(self, name: str, **_: object) -> None:
                self.name = name

            def pexec(self, command: list[str]) -> tuple[str, str, int]:
                pexec_commands.append((self.name, tuple(command)))
                return "", "", 0

        class FakeController(FakeNode):
            pass

        class FakeOVSSwitch(FakeNode):
            @classmethod
            def setup(cls) -> None:
                calls.append(("ovs_setup", None))

        class FakeLinuxBridge(FakeNode):
            @classmethod
            def setup(cls) -> None:
                calls.append(("bridge_setup", None))

        class FakeLink:
            pass

        class FakeTCIntf:
            def tc(self, _command: str, _tc: str = "tc") -> str:
                return ""

        class FakeTCLink:
            def __init__(self, *_: object, **__: object) -> None:
                return None

        class FakeNet:
            def __init__(self, **params: object) -> None:
                calls.append(("net", params))

            def addController(self, name: str, controller: type[FakeController], **params: object) -> FakeController:
                calls.append(("controller", {"name": name, **params}))
                return controller(name, **params)

            def addHost(self, name: str, cls: type[FakeNode], **params: object) -> FakeNode:
                calls.append(("host", {"name": name, **params}))
                return cls(name, **params)

            def addSwitch(self, name: str, cls: type[FakeNode], **params: object) -> FakeNode:
                calls.append(("switch", {"name": name, "cls": cls, **params}))
                return cls(name, **params)

            def addDocker(self, name: str, **params: object) -> FakeNode:
                calls.append(("docker", {"name": name, **params}))
                return FakeNode(name, **params)

            def addLink(self, left: FakeNode, right: FakeNode, cls: type[object], **params: object) -> object:
                calls.append(("link", {"left": left.name, "right": right.name, "cls": cls, **params}))
                return object()

            def start(self) -> None:
                calls.append(("start", None))

            def waitConnected(self, timeout: int) -> bool:
                calls.append(("wait", timeout))
                return True

            def stop(self) -> None:
                calls.append(("stop", None))

        fake_net_module = types.ModuleType("mininet.net")
        fake_cli_module = types.ModuleType("mininet.cli")
        fake_link_module = types.ModuleType("mininet.link")
        fake_node_module = types.ModuleType("mininet.node")
        fake_nodelib_module = types.ModuleType("mininet.nodelib")
        fake_net_module.Containernet = FakeNet
        fake_cli_module.CLI = lambda _net: calls.append(("cli", None))
        fake_link_module.Link = FakeLink
        fake_link_module.TCIntf = FakeTCIntf
        fake_link_module.TCLink = FakeTCLink
        fake_node_module.Node = FakeNode
        fake_node_module.OVSSwitch = FakeOVSSwitch
        fake_node_module.RemoteController = FakeController
        fake_nodelib_module.LinuxBridge = FakeLinuxBridge

        with patch.dict(sys.modules, {
            "mininet": types.ModuleType("mininet"),
            "mininet.net": fake_net_module,
            "mininet.cli": fake_cli_module,
            "mininet.link": fake_link_module,
            "mininet.node": fake_node_module,
            "mininet.nodelib": fake_nodelib_module,
        }), patch("os.geteuid", return_value=0), patch("sdwan_v5.topology_v5.load_config", return_value=self.config), patch("sdwan_v5.topology_v5._wait_for_underlay_readiness"), patch("builtins.print"):
            launch_live(ROOT / "config" / "topology.yaml")

        events = [kind for kind, _ in calls]
        self.assertIn("ovs_setup", events)
        self.assertIn("bridge_setup", events)
        self.assertLess(events.index("controller"), events.index("switch"))
        switch_calls = [payload for kind, payload in calls if kind == "switch"]
        self.assertEqual(sum(payload["cls"] is FakeOVSSwitch for payload in switch_calls), 8)
        self.assertEqual(sum(payload["cls"] is FakeLinuxBridge for payload in switch_calls), 3)
        self.assertTrue(all(payload["protocols"] == "OpenFlow13" for payload in switch_calls if payload["cls"] is FakeOVSSwitch))
        self.assertEqual(len({payload["dpid"] for payload in switch_calls if payload["cls"] is FakeOVSSwitch}), 8)

        docker_calls = [payload for kind, payload in calls if kind == "docker"]
        self.assertEqual(len(docker_calls), 15)
        node1 = next(payload for payload in docker_calls if payload["name"] == "node1")
        self.assertEqual(node1["network_mode"], "none")
        self.assertIn("net_admin", node1["cap_add"])
        self.assertIn("net_raw", node1["cap_add"])
        self.assertEqual(node1["volumes"], ["sdwan-node1-identity:/var/lib/sdwan:rw", f"{(ROOT / 'config' / 'topology.yaml').resolve()}:/opt/sdwan_v5/config/topology.yaml:ro"])
        self.assertEqual(node1["sysctls"], {
            "net.ipv4.conf.all.rp_filter": "0",
            "net.ipv4.conf.default.rp_filter": "0",
            "net.ipv4.conf.all.src_valid_mark": "1",
            "net.ipv4.conf.default.src_valid_mark": "1",
            "net.ipv4.conf.all.ignore_routes_with_linkdown": "1",
            "net.ipv4.conf.default.ignore_routes_with_linkdown": "1",
        })

        link_calls = [payload for kind, payload in calls if kind == "link"]
        self.assertEqual(len(link_calls), 46)
        self.assertTrue(all(payload["cls"] is FakeLink for payload in link_calls))
        self.assertIn(("node1", ("ip", "address", "replace", "192.168.20.11/32", "dev", "node1-bb")), pexec_commands)
        self.assertIn(("node1", ("tc", "qdisc", "replace", "dev", "node1-bb", "root", "handle", "5:0", "hfsc", "default", "1")), pexec_commands)
        self.assertIn(("node1", ("tc", "class", "replace", "dev", "node1-bb", "parent", "5:0", "classid", "5:1", "hfsc", "sc", "rate", "50.0Mbit", "ul", "rate", "50.0Mbit")), pexec_commands)
        self.assertIn(("node1", ("tc", "qdisc", "replace", "dev", "node1-bb", "parent", "5:1", "handle", "10:", "netem", "delay", "25.0ms", "5.0ms", "loss", "1.0%")), pexec_commands)
        self.assertTrue(any(name == "public_saas" and "uvicorn sdwan_v5.workloads.public_saas_service:app" in " ".join(command) for name, command in pexec_commands))
        self.assertTrue(any(name == "dc_app" and "uvicorn sdwan_v5.workloads.backup_service:app" in " ".join(command) for name, command in pexec_commands))
        self.assertIn(("node1_host", ("ping", "-c", "2", "-W", "2", "10.1.0.1")), pexec_commands)
        self.assertIn(("hub1", ("ping", "-c", "2", "-W", "2", "10.100.0.10")), pexec_commands)
        self.assertIn(("dc_app", ("ip", "route", "replace", "10.1.0.0/24", "via", "10.100.0.1", "dev", "dc_app-net")), pexec_commands)
        self.assertIn(("dc_app", ("ip", "route", "replace", "10.4.0.0/24", "via", "10.100.0.2", "dev", "dc_app-net")), pexec_commands)
        self.assertIn(("node1", ("ping", "-I", "192.168.20.11", "-c", "2", "-W", "2", "192.168.20.254")), pexec_commands)
        self.assertIn(("inet_gw", ("ip", "address", "replace", "198.18.0.1/24", "dev", "inet-public")), pexec_commands)
        self.assertIn(("inet_gw", ("ip", "address", "replace", "192.168.20.254/32", "dev", "inet-bb")), pexec_commands)
        self.assertIn(("inet_gw", ("ip", "address", "replace", "192.168.30.254/32", "dev", "inet-lte")), pexec_commands)
        self.assertIn(("public_saas", ("ip", "route", "replace", "default", "via", "198.18.0.1", "dev", "saas-inet")), pexec_commands)
        self.assertIn(("inet_gw", ("sysctl", "-w", "net.ipv4.ip_forward=1")), pexec_commands)
        self.assertIn(("inet_gw", ("ping", "-c", "2", "-W", "2", "198.18.0.10")), pexec_commands)
        self.assertFalse(any(command[0] in {"wg", "iptables"} for _, command in pexec_commands))
        events = [kind for kind, _ in calls]
        self.assertLess(events.index("start"), events.index("wait"))
        self.assertLess(events.index("wait"), events.index("cli"))
        self.assertLess(events.index("cli"), events.index("stop"))


if __name__ == "__main__":
    unittest.main()
