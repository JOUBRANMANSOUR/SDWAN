from __future__ import annotations

from pathlib import Path
import subprocess
import unittest

from sdwan_v5.common.model import load_config
from sdwan_v5.topology_v5 import build_live_plan


ROOT = Path(__file__).resolve().parents[1]


class ScriptAndPackagingTests(unittest.TestCase):
    def test_all_shell_scripts_pass_bash_syntax_check(self) -> None:
        scripts = sorted(ROOT.rglob("*.sh"))
        self.assertTrue(scripts)
        for script in scripts:
            result = subprocess.run(
                ["bash", "-n", str(script)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, f"{script}: {result.stderr}")

    def test_failure_injection_scenarios_are_reversible_and_non_destructive_by_default(self) -> None:
        script = ROOT / "scripts" / "failure_injection.sh"
        pairs = {
            "degrade-node1-mpls": "restore-node1-mpls",
            "congest-node1-bb": "stop-congestion",
            "broadband-down": "broadband-up",
            "hub1-down": "hub1-up",
            "tunnel-node1-h1-bb": "restore-tunnel-node1-h1-bb",
            "block-node1-h1-bb": "unblock-node1-h1-bb",
            "interhub-bb": "restore-interhub-bb",
            "interhub-all": "restore-interhub-all",
        }
        for inject, restore in pairs.items():
            inject_result = subprocess.run(
                ["bash", str(script), inject],
                check=False,
                capture_output=True,
                text=True,
            )
            restore_result = subprocess.run(
                ["bash", str(script), restore],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(inject_result.returncode, 0, inject_result.stderr)
            self.assertEqual(restore_result.returncode, 0, restore_result.stderr)
            self.assertTrue(inject_result.stdout.strip())
            self.assertTrue(restore_result.stdout.strip())
            # The helper prints commands for the active Containernet CLI; it must
            # never execute ip/tc/iptables itself from the host namespace.
            self.assertNotIn("RTNETLINK", inject_result.stderr)
            if inject == "congest-node1-bb":
                self.assertIn("node1_host", inject_result.stdout)
                self.assertNotIn("node3_host", inject_result.stdout)

        unknown = subprocess.run(
            ["bash", str(script), "not-a-scenario"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(unknown.returncode, 2)
        self.assertIn("usage:", unknown.stderr)

    def test_core_and_cloud_interface_names_fit_linux_limit(self) -> None:
        for profile in ("topology.core.yaml", "topology.cloud.yaml"):
            config = load_config(ROOT / "config" / profile)
            plan = build_live_plan(config)
            for link in plan.links:
                self.assertLessEqual(len(link.intf1), 15, f"{profile}: {link.intf1}")
                self.assertLessEqual(len(link.intf2), 15, f"{profile}: {link.intf2}")

    def test_static_validator_has_portable_python_fallback(self) -> None:
        script = (ROOT / "scripts" / "validate_static.sh").read_text(encoding="utf-8")
        self.assertIn("SDWAN_TEST_PYTHON", script)
        self.assertIn("command -v python3", script)
        self.assertNotIn("source ~/ryu-venv38/bin/activate", script)
        self.assertIn("topology.core.yaml", script)
        self.assertIn("topology.cloud.yaml", script)

    def test_delivery_tree_has_no_patch_or_editor_artifacts(self) -> None:
        forbidden = []
        for pattern in ("*.orig", "*.rej"):
            forbidden.extend(ROOT.rglob(pattern))
        self.assertEqual(forbidden, [])
        self.assertFalse((ROOT / "node1").exists())
        self.assertFalse((ROOT / "node1_host").exists())


if __name__ == "__main__":
    unittest.main()
