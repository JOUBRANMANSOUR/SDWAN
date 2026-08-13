#!/usr/bin/env python3
"""Ryu OpenFlow 1.3 underlay controller; deliberately no ZTP/DPI/route ownership."""
from __future__ import annotations

from typing import Any

try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.lib.packet import ethernet, ether_types, packet
    from ryu.ofproto import ofproto_v1_3
    RYU_AVAILABLE = True
except ImportError:
    RYU_AVAILABLE = False


if RYU_AVAILABLE:
    class SDWANV5UnderlayController(app_manager.RyuApp):
        """Bounded L2 underlay learning, datapath state, ports and counters only."""

        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

        def __init__(self, *args: Any, **kwargs: Any):
            super().__init__(*args, **kwargs)
            self.mac_to_port: dict[int, dict[str, int]] = {}
            self.datapaths: dict[int, Any] = {}
        def add_flow(
            self,
            datapath: Any,
            priority: int,
            match: Any,
            actions: list[Any],
            *,
            idle_timeout: int = 120,
        ) -> None:
            parser, ofproto = datapath.ofproto_parser, datapath.ofproto
            datapath.send_msg(
                parser.OFPFlowMod(
                    datapath=datapath,
                    priority=priority,
                    match=match,
                    instructions=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)],
                    idle_timeout=idle_timeout,
                    hard_timeout=0,
                )
            )

        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def switch_features(self, event: Any) -> None:
            datapath = event.msg.datapath
            # Keep table-miss active for the switch lifetime.  Otherwise ARP
            # and unknown unicast stop reaching the controller after 120 seconds.
            self.add_flow(
                datapath,
                0,
                datapath.ofproto_parser.OFPMatch(),
                [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER, datapath.ofproto.OFPCML_NO_BUFFER)],
                idle_timeout=0,
            )

        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def packet_in(self, event: Any) -> None:
            msg, datapath = event.msg, event.msg.datapath
            parsed = packet.Packet(msg.data)
            frame = parsed.get_protocol(ethernet.ethernet)
            if frame is None or frame.ethertype == ether_types.ETH_TYPE_LLDP:
                return
            table = self.mac_to_port.setdefault(datapath.id, {})
            in_port = msg.match["in_port"]
            table[frame.src] = in_port
            output = table.get(frame.dst, datapath.ofproto.OFPP_FLOOD)
            actions = [datapath.ofproto_parser.OFPActionOutput(output)]
            if output != datapath.ofproto.OFPP_FLOOD:
                self.add_flow(datapath, 10, datapath.ofproto_parser.OFPMatch(in_port=in_port, eth_src=frame.src, eth_dst=frame.dst), actions)
            datapath.send_msg(datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data))


def main() -> None:
    if not RYU_AVAILABLE:
        raise SystemExit("run via ryu-manager in ~/ryu-venv38; this controller does underlay only")


if __name__ == "__main__":
    main()
