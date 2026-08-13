from __future__ import annotations

from types import SimpleNamespace
import unittest

from sdwan_v5 import controller_v5


@unittest.skipUnless(controller_v5.RYU_AVAILABLE, "Ryu is installed in the controller virtual environment")
class UnderlayControllerTests(unittest.TestCase):
    def test_table_miss_flow_never_expires(self) -> None:
        flow: dict[str, object] = {}

        class Parser:
            def OFPMatch(self) -> str:
                return "match-all"

            def OFPActionOutput(self, port: int, max_len: int) -> tuple[str, int, int]:
                return ("output", port, max_len)

            def OFPInstructionActions(self, kind: int, actions: list[object]) -> tuple[str, int, list[object]]:
                return ("apply", kind, actions)

            def OFPFlowMod(self, **kwargs: object) -> dict[str, object]:
                return kwargs

        class Datapath:
            ofproto = SimpleNamespace(OFPIT_APPLY_ACTIONS=4, OFPP_CONTROLLER=0xFFFFFFFD, OFPCML_NO_BUFFER=0xFFFF)
            ofproto_parser = Parser()

            def send_msg(self, message: dict[str, object]) -> None:
                flow.update(message)

        controller = object.__new__(controller_v5.SDWANV5UnderlayController)
        controller.switch_features(SimpleNamespace(msg=SimpleNamespace(datapath=Datapath())))

        self.assertEqual(flow["priority"], 0)
        self.assertEqual(flow["idle_timeout"], 0)
        self.assertEqual(flow["hard_timeout"], 0)
