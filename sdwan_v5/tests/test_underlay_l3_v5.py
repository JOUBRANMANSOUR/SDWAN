from __future__ import annotations

from ipaddress import ip_address
from pathlib import Path
import unittest

from sdwan_v5.common.model import load_config
from sdwan_v5.underlay_l3 import UnderlayMode, UnderlayRegistry, ServiceType, matching_fib_routes, service_profiles


ROOT = Path(__file__).resolve().parents[1]


class UnderlayL3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config(ROOT / "config" / "topology.core.yaml")
        self.registry = UnderlayRegistry(self.config)

    def test_provider_attachments_are_host_routes_with_stable_bindings(self) -> None:
        attachment = self.registry.attachment("bb", "node1")
        self.assertEqual(str(attachment.address), "192.168.20.11")
        self.assertEqual(attachment.port_name, "s_bb-n1")
        self.assertEqual(attachment.expected_mac, self.config.underlay_mac("node1", "bb"))
        self.assertEqual(self.config.underlay_interface_cidr("node1", "bb"), "192.168.20.11/32")
        self.assertEqual(str(self.config.underlay_gateway_ip("bb")), "192.168.20.253")

    def test_mpls_is_private_and_spokes_have_only_hub_endpoint_routes(self) -> None:
        profiles = service_profiles(self.config)
        self.assertEqual(profiles["mpls"].service_type, ServiceType.PRIVATE)
        routes = self.registry.fib("mpls")
        node1 = tuple(item for item in routes if item.source_site == "node1")
        self.assertEqual({item.egress_site for item in node1}, {"hub1", "hub2"})
        self.assertFalse(matching_fib_routes(routes, "node1", ip_address("198.18.0.10")))
        self.assertFalse(any(item.egress_site == "node2" for item in node1))

    def test_internet_underlays_offer_gateway_and_hub_reachability_without_spoke_mesh(self) -> None:
        for transport in ("bb", "lte"):
            routes = self.registry.fib(transport)
            node1 = tuple(item for item in routes if item.source_site == "node1")
            self.assertEqual({item.egress_site for item in node1}, {"hub1", "hub2", "inet_gw"})
            public = matching_fib_routes(routes, "node1", ip_address("198.18.0.10"))
            self.assertEqual(len(public), 1)
            self.assertEqual(public[0].egress_site, "inet_gw")
            self.assertEqual(public[0].reason, "DIRECT_INTERNET_BREAKOUT")
            self.assertFalse(any(item.egress_site == "node2" for item in node1))

    def test_unauthorized_site_is_not_admitted_to_bindings_or_fib(self) -> None:
        registry = UnderlayRegistry(self.config, authorized_sites={"hub1", "hub2", "node1"})
        self.assertFalse(registry.attachment("mpls", "node2").authorized)
        self.assertFalse(any(
            item.source_site == "node2" or item.egress_site == "node2"
            for item in registry.fib("mpls")
        ))

    def test_operating_modes_are_explicit(self) -> None:
        self.assertEqual({item.value for item in UnderlayMode}, {"DISABLED", "AUDIT", "ENFORCE"})


if __name__ == "__main__":
    unittest.main()
