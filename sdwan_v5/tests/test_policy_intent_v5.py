from __future__ import annotations

from pathlib import Path
import unittest

from sdwan_v5.common.model import load_config
from sdwan_v5.policy_http import load_application_policy


ROOT = Path(__file__).resolve().parents[1]


class PolicyIntentTests(unittest.TestCase):
    def test_application_policy_maps_all_four_workloads(self) -> None:
        config = load_config(ROOT / "config" / "topology.core.yaml")
        policy = load_application_policy(ROOT / "config" / "app_policy.yaml", config)
        self.assertEqual(set(policy), {
            "REALTIME_RTP", "CENTRAL_BACKUP", "SAAS_INTERACTIVE", "SAAS_FILE_TRANSFER",
        })
        self.assertEqual(policy["REALTIME_RTP"]["allowed_egress"], ["HUB_OVERLAY"])
        self.assertEqual(policy["REALTIME_RTP"]["candidate_transports"], ["mpls", "bb", "lte"])
        self.assertEqual(policy["CENTRAL_BACKUP"]["candidate_transports"], ["bb", "mpls", "lte"])
        self.assertEqual(policy["SAAS_INTERACTIVE"]["allowed_egress"], ["DIRECT_INTERNET"])
        self.assertEqual(policy["SAAS_INTERACTIVE"]["candidate_transports"], ["bb", "lte"])
        self.assertEqual(policy["SAAS_INTERACTIVE"]["match"]["dscp"], 18)
        self.assertEqual(policy["SAAS_FILE_TRANSFER"]["match"]["dscp"], 10)

    def test_direct_internet_application_rejects_non_internet_transport(self) -> None:
        import tempfile
        import yaml
        config = load_config(ROOT / "config" / "topology.core.yaml")
        raw = yaml.safe_load((ROOT / "config" / "app_policy.yaml").read_text(encoding="utf-8"))
        raw["classes"]["SAAS_INTERACTIVE"]["candidate_transports"] = ["bb", "mpls"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.yaml"
            path.write_text(yaml.safe_dump(raw), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_application_policy(path, config)


if __name__ == "__main__":
    unittest.main()
