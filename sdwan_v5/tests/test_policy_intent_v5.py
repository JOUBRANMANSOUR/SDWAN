from __future__ import annotations

from pathlib import Path
import unittest

from sdwan_v5.common.model import load_config
from sdwan_v5.policy_http import load_application_policy


ROOT = Path(__file__).resolve().parents[1]


class PolicyIntentTests(unittest.TestCase):
    def test_application_policy_maps_to_sla_egress_and_ranked_transports(self) -> None:
        config = load_config(ROOT / "config" / "topology.yaml")
        policy = load_application_policy(ROOT / "config" / "app_policy.yaml", config)
        self.assertEqual(policy["web"]["allowed_egress"][0], "DIRECT_INTERNET")
        self.assertEqual(policy["corporate"]["allowed_egress"], ["HUB_OVERLAY"])
        self.assertEqual(policy["cloud"]["ranked_transports"], ["bb", "mpls", "lte"])


if __name__ == "__main__":
    unittest.main()
