from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import yaml

from sdwan_v5.common.destination_models import (
    DestinationPolicyError, DestinationType, FailureAction, TrustClass,
    document_from_mapping, load_destination_policy,
)
from sdwan_v5.common.model import load_config
from sdwan_v5.persistence.policy_store import PolicyStore


ROOT = Path(__file__).resolve().parents[1]


class DestinationPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config(ROOT / "config" / "topology.yaml")
        self.raw = yaml.safe_load((ROOT / "config" / "destination_policy.yaml").read_text(encoding="utf-8"))

    def test_explicit_trust_is_destination_policy_not_protocol(self) -> None:
        document = document_from_mapping(self.raw, self.config)
        by_id = {policy.policy_id: policy for policy in document.policies}
        self.assertEqual(by_id["trusted_saas"].trust_class, TrustClass.TRUSTED)
        self.assertEqual(by_id["sensitive_saas"].trust_class, TrustClass.SENSITIVE)
        self.assertEqual(by_id["unknown_saas"].trust_class, TrustClass.UNKNOWN)
        self.assertIn("HTTPS", by_id["trusted_saas"].application_matchers)
        self.assertIn("HTTPS", by_id["sensitive_saas"].application_matchers)
        self.assertNotIn("QUIC", by_id["unknown_saas"].application_matchers)
        self.assertEqual(document.default_policy.failure_action, FailureAction.FAIL_CLOSED)

    def test_sensitive_unknown_and_cloud_direct_paths_are_rejected(self) -> None:
        for policy_id in ("sensitive_saas", "unknown_saas", "cloud_vpc"):
            raw = deepcopy(self.raw)
            item = next(policy for policy in raw["policies"] if policy["policy_id"] == policy_id)
            item["allowed_egress"] = ["DIRECT_INTERNET", "HUB_OVERLAY"]
            with self.assertRaises(DestinationPolicyError):
                document_from_mapping(raw, self.config)

    def test_invalid_transport_overlap_and_cloud_gateway_preference_are_rejected(self) -> None:
        raw = deepcopy(self.raw)
        trusted = next(policy for policy in raw["policies"] if policy["policy_id"] == "trusted_saas")
        trusted["ranked_transports"] = ["mpls", "bb"]
        with self.assertRaises(DestinationPolicyError):
            document_from_mapping(raw, self.config)
        raw = deepcopy(self.raw)
        unknown = next(policy for policy in raw["policies"] if policy["policy_id"] == "unknown_saas")
        unknown["prefix"] = "198.18.0.10/32"
        with self.assertRaises(DestinationPolicyError):
            document_from_mapping(raw, self.config)
        raw = deepcopy(self.raw)
        cloud = next(policy for policy in raw["policies"] if policy["policy_id"] == "cloud_vpc")
        cloud["cloud_gateway_preferences"]["hub1"] = ["cloud_gw1", "cloud_gw1"]
        with self.assertRaises(DestinationPolicyError):
            document_from_mapping(raw, self.config)

    def test_cloud_policy_is_hub_overlay_and_default_is_conservative(self) -> None:
        document = load_destination_policy(ROOT / "config" / "destination_policy.yaml", self.config)
        cloud = next(policy for policy in document.policies if policy.destination_type is DestinationType.CLOUD_VPC)
        self.assertEqual([entry.value for entry in cloud.allowed_egress], ["HUB_OVERLAY"])
        self.assertEqual(cloud.cloud_gateway_preferences["hub1"], ("cloud_gw1", "cloud_gw2"))
        self.assertEqual(cloud.cloud_gateway_preferences["hub2"], ("cloud_gw2", "cloud_gw1"))
        self.assertEqual(document.default_policy.trust_class, TrustClass.UNKNOWN)

    def test_activation_is_monotonic_idempotent_and_restart_safe(self) -> None:
        document = load_destination_policy(ROOT / "config" / "destination_policy.yaml", self.config)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "policy.db"
            store = PolicyStore(path)
            try:
                self.assertEqual(store.activate_destination_policy(document.to_mapping(), "test"), (1, False))
                self.assertEqual(store.activate_destination_policy(document.to_mapping(), "test"), (1, True))
                changed = document.to_mapping()
                changed["policies"][3]["trust_class"] = "TRUSTED"
                changed["policies"][3]["allowed_egress"] = ["DIRECT_INTERNET", "HUB_OVERLAY"]
                changed["policies"][3]["failure_action"] = "HUB_FALLBACK"
                self.assertEqual(store.activate_destination_policy(changed, "test"), (2, False))
                self.assertEqual(store.active_destination_policy()[0], 2)
            finally:
                store.close()
            reopened = PolicyStore(path)
            try:
                self.assertEqual(reopened.schema_version, 2)
                self.assertEqual(reopened.active_destination_policy()[0], 2)
            finally:
                reopened.close()


if __name__ == "__main__":
    unittest.main()
