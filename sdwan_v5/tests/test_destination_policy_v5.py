from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import yaml

from sdwan_v5.common.destination_models import (
    DestinationPolicyError, DestinationType, FailureAction,
    document_from_mapping, load_destination_policy,
)
from sdwan_v5.common.marks import EgressMode
from sdwan_v5.common.model import load_config
from sdwan_v5.persistence.policy_store import PolicyStore


ROOT = Path(__file__).resolve().parents[1]


class DestinationPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config(ROOT / "config" / "topology.core.yaml")
        self.raw = yaml.safe_load((ROOT / "config" / "destination_policy.yaml").read_text(encoding="utf-8"))

    def test_core_policy_has_distinct_private_and_public_egress(self) -> None:
        document = document_from_mapping(self.raw, self.config)
        by_id = {policy.policy_id: policy for policy in document.policies}
        backup = by_id["private_dc_backup"]
        saas = by_id["public_saas"]
        self.assertEqual(backup.destination_type, DestinationType.DATA_CENTER)
        self.assertEqual(backup.allowed_egress, (EgressMode.HUB_OVERLAY,))
        self.assertEqual(backup.candidate_transports, ("bb", "mpls", "lte"))
        self.assertEqual(backup.application_classes, ("CENTRAL_BACKUP",))
        self.assertEqual(saas.destination_type, DestinationType.SAAS)
        self.assertEqual(saas.allowed_egress, (EgressMode.DIRECT_INTERNET,))
        self.assertEqual(saas.candidate_transports, ("bb", "lte"))
        self.assertEqual(saas.application_classes, ("SAAS_INTERACTIVE", "SAAS_FILE_TRANSFER"))
        self.assertEqual(document.default_policy.failure_action, FailureAction.FAIL_CLOSED)

    def test_public_saas_cannot_use_hub_or_mpls(self) -> None:
        raw = deepcopy(self.raw)
        saas = next(item for item in raw["policies"] if item["policy_id"] == "public_saas")
        saas["allowed_egress"] = ["DIRECT_INTERNET", "HUB_OVERLAY"]
        with self.assertRaises(DestinationPolicyError):
            document_from_mapping(raw, self.config)
        raw = deepcopy(self.raw)
        saas = next(item for item in raw["policies"] if item["policy_id"] == "public_saas")
        saas["candidate_transports"] = ["bb", "mpls"]
        with self.assertRaises(DestinationPolicyError):
            document_from_mapping(raw, self.config)

    def test_data_center_cannot_use_direct_internet(self) -> None:
        raw = deepcopy(self.raw)
        backup = next(item for item in raw["policies"] if item["policy_id"] == "private_dc_backup")
        backup["allowed_egress"] = ["DIRECT_INTERNET"]
        with self.assertRaises(DestinationPolicyError):
            document_from_mapping(raw, self.config)

    def test_overlapping_prefixes_are_rejected(self) -> None:
        raw = deepcopy(self.raw)
        raw["policies"].append({
            "policy_id": "duplicate_saas",
            "priority": 30,
            "prefix": "198.18.0.10/32",
            "destination_type": "SAAS",
            "allowed_egress": ["DIRECT_INTERNET"],
            "candidate_transports": ["bb", "lte"],
            "failure_action": "FAIL_CLOSED",
            "application_classes": ["SAAS_INTERACTIVE"],
            "application_matchers": ["HTTPS"],
        })
        with self.assertRaises(DestinationPolicyError):
            document_from_mapping(raw, self.config)

    def test_cloud_profile_preserves_optional_cloud_policy(self) -> None:
        cloud_config = load_config(ROOT / "config" / "topology.cloud.yaml")
        document = load_destination_policy(ROOT / "config" / "destination_policy.cloud.yaml", cloud_config)
        cloud = next(policy for policy in document.policies if policy.destination_type is DestinationType.CLOUD_VPC)
        self.assertEqual(cloud.allowed_egress, (EgressMode.HUB_OVERLAY,))
        self.assertEqual(cloud.cloud_gateway_preferences["hub1"], ("cloud_gw1", "cloud_gw2"))
        self.assertEqual(cloud.cloud_gateway_preferences["hub2"], ("cloud_gw2", "cloud_gw1"))

    def test_cloud_policy_cannot_be_direct_or_have_invalid_preferences(self) -> None:
        cloud_config = load_config(ROOT / "config" / "topology.cloud.yaml")
        raw = yaml.safe_load((ROOT / "config" / "destination_policy.cloud.yaml").read_text(encoding="utf-8"))
        cloud = next(item for item in raw["policies"] if item["policy_id"] == "cloud_vpc")
        cloud["allowed_egress"] = ["DIRECT_INTERNET"]
        with self.assertRaises(DestinationPolicyError):
            document_from_mapping(raw, cloud_config)
        raw = yaml.safe_load((ROOT / "config" / "destination_policy.cloud.yaml").read_text(encoding="utf-8"))
        cloud = next(item for item in raw["policies"] if item["policy_id"] == "cloud_vpc")
        cloud["cloud_gateway_preferences"]["hub1"] = ["cloud_gw1", "cloud_gw1"]
        with self.assertRaises(DestinationPolicyError):
            document_from_mapping(raw, cloud_config)

    def test_activation_is_monotonic_idempotent_and_restart_safe(self) -> None:
        document = load_destination_policy(ROOT / "config" / "destination_policy.yaml", self.config)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "policy.db"
            store = PolicyStore(path)
            try:
                self.assertEqual(store.activate_destination_policy(document.to_mapping(), "test"), (1, False))
                self.assertEqual(store.activate_destination_policy(document.to_mapping(), "test"), (1, True))
                changed = document.to_mapping()
                changed["policies"][0]["candidate_transports"] = ["mpls", "bb", "lte"]
                changed["policies"][0]["ranked_transports"] = ["mpls", "bb", "lte"]
                self.assertEqual(store.activate_destination_policy(changed, "test"), (2, False))
                self.assertEqual(store.active_destination_policy()[0], 2)
            finally:
                store.close()
            reopened = PolicyStore(path)
            try:
                self.assertEqual(reopened.schema_version, 4)
                self.assertEqual(reopened.active_destination_policy()[0], 2)
            finally:
                reopened.close()


if __name__ == "__main__":
    unittest.main()
