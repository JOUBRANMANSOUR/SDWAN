from __future__ import annotations

from types import SimpleNamespace
import unittest

from sdwan import controller_v5


@unittest.skipUnless(controller_v5.RYU_AVAILABLE, "Ryu is installed in the controller virtual environment")
class UnderlayControllerTests(unittest.TestCase):
    def test_programming_fingerprint_is_stable_until_effective_input_changes(self) -> None:
        config = controller_v5.load_config(controller_v5._config_path())
        registry = controller_v5.UnderlayRegistry(config)
        controller = object.__new__(controller_v5.SDWANV5UnderlayController)
        controller.mode = controller_v5.UnderlayMode.ENFORCE
        ports = {item.port_name: index + 1 for index, item in enumerate(registry.attachments("bb"))}

        baseline = controller._programming_fingerprint("bb", registry, ports)
        self.assertEqual(baseline, controller._programming_fingerprint("bb", registry, dict(ports)))

        changed_ports = dict(ports)
        first_port = next(iter(changed_ports))
        changed_ports[first_port] += 100
        self.assertNotEqual(baseline, controller._programming_fingerprint("bb", registry, changed_ports))

    def test_default_flows_are_permanent_and_mirror_only_for_audit(self) -> None:
        messages = []

        class Parser:
            def OFPMatch(self):
                return "match-all"

            def OFPActionOutput(self, port, max_len):
                return ("output", port, max_len)

            def OFPInstructionActions(self, kind, actions):
                return ("apply", kind, actions)

            def OFPFlowMod(self, **kwargs):
                return kwargs

        class Datapath:
            ofproto = SimpleNamespace(
                OFPIT_APPLY_ACTIONS=4,
                OFPP_CONTROLLER=0xFFFFFFFD,
                OFPCML_NO_BUFFER=0xFFFF,
            )
            ofproto_parser = Parser()

            def send_msg(self, message):
                messages.append(message)

        controller = object.__new__(controller_v5.SDWANV5UnderlayController)
        controller._install_default_drop(Datapath())

        self.assertEqual([message["table_id"] for message in messages], [0, 10, 20, 30])
        self.assertTrue(all(message["priority"] == 0 for message in messages))
        self.assertTrue(all(message["idle_timeout"] == 0 and message["hard_timeout"] == 0 for message in messages))
        self.assertTrue(all(message["instructions"] for message in messages))


if __name__ == "__main__":
    unittest.main()
