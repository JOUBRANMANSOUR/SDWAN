#!/usr/bin/env python3
"""Ryu OpenFlow 1.3 controller for the SD-WAN provider-facing L3 underlays.

Ryu owns only outer-packet forwarding after an Edge selected a transport.  It
does not classify applications, evaluate SLAs, select hubs/transports, or
modify Linux/ WireGuard policy state on an Edge.
"""
from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Any

from sdwan_v5.common.model import TopologyConfig, load_config
from sdwan_v5.dynamic_control import InventorySite
from sdwan_v5.underlay_l3 import UnderlayMode, UnderlayRegistry

try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.lib import hub
    from ryu.lib.packet import arp, ethernet, ether_types, packet
    from ryu.ofproto import ofproto_v1_3
    RYU_AVAILABLE = True
except ImportError:
    RYU_AVAILABLE = False


COOKIE = 0x534457414E4C3300
COOKIE_MASK = 0xFFFFFFFFFFFFFF00
AUTHORIZED_LIFECYCLES = {"ZTP_STAGED", "ENROLLING", "ENROLLED", "REGISTERING", "PROVISIONING", "PENDING_HUBS", "RECONCILING", "ACTIVE"}


def _config_path() -> Path:
    configured = os.environ.get("SDWAN_TOPOLOGY_CONFIG")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parent / "config" / "topology.core.yaml"


def _mode() -> UnderlayMode:
    try:
        return UnderlayMode(os.environ.get("SDWAN_UNDERLAY_MODE", "ENFORCE").upper())
    except ValueError as exc:
        raise RuntimeError("SDWAN_UNDERLAY_MODE must be DISABLED, AUDIT, or ENFORCE") from exc


class InventorySnapshot:
    """Read-only projection of the Policy-owned site inventory."""

    def __init__(self, base_config: TopologyConfig):
        self.base_config = base_config
        root = Path(os.environ.get("SDWAN_STATE_ROOT", "/mnt/data/sdwan-state"))
        self.database = Path(os.environ.get("SDWAN_POLICY_DB", str(root / "policy" / "policy.db")))

    def load(self) -> tuple[TopologyConfig, set[str]]:
        if not self.database.exists():
            return self.base_config, set(self.base_config.site_names)
        try:
            connection = sqlite3.connect("file:" + str(self.database) + "?mode=ro", uri=True)
            connection.row_factory = sqlite3.Row
            rows = list(connection.execute("SELECT * FROM site_inventory"))
            connection.close()
        except (sqlite3.Error, OSError):
            return self.base_config, set(self.base_config.site_names)
        sites: dict[str, Any] = {}
        authorized = set(self.base_config.hubs)
        for row in rows:
            try:
                record = InventorySite(**dict(row))
            except (TypeError, ValueError):
                continue
            if record.lifecycle in AUTHORIZED_LIFECYCLES:
                sites[record.site] = record.to_site()
                authorized.add(record.site)
        if not sites:
            sites = dict(self.base_config.sites)
            authorized.update(sites)
        return self.base_config.with_sites(sites), authorized


if RYU_AVAILABLE:
    class SDWANV5UnderlayController(app_manager.RyuApp):
        """Reconciled, multi-table L3 forwarding for MPLS, BB, and LTE."""

        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

        def __init__(self, *args: Any, **kwargs: Any):
            super().__init__(*args, **kwargs)
            self.base_config = load_config(_config_path())
            self.inventory = InventorySnapshot(self.base_config)
            self.mode = _mode()
            self.datapaths: dict[int, Any] = {}
            self.port_names: dict[int, dict[str, int]] = {}
            # Branch LAN switches are intentionally separate from provider
            # underlays.  They retain bounded local L2 learning only.
            self.lan_mac_to_port: dict[int, dict[str, int]] = {}
            self.underlay_events: deque[dict[str, Any]] = deque(maxlen=200)
            self.drop_counters = {
                "unauthorized_attachment_drops": 0,
                "source_validation_drops": 0,
                "reachability_policy_drops": 0,
                "unknown_endpoint_drops": 0,
            }
            self._last_drop: dict[tuple[int, str], float] = {}
            # A provider switch is reprogrammed only when its effective input
            # changes.  Reinstalling every reconciliation interval creates
            # transient drops and makes OpenFlow counters unusable.
            self._programmed_fingerprints: dict[int, str] = {}
            self.state_path = Path(os.environ.get("SDWAN_UNDERLAY_STATE_PATH", "/mnt/data/sdwan-state/underlay-state.json"))
            self.reconcile_interval = float(os.environ.get("SDWAN_UNDERLAY_RECONCILE_SECONDS", "2"))
            self._record_event("CONTROLLER_MODE", mode=self.mode.value)
            self.reconciler = hub.spawn(self._reconcile_loop)

        def _record_event(self, event_type: str, **fields: Any) -> None:
            event = {"timestamp": time.time(), "event": event_type, **fields}
            self.underlay_events.append(event)
            detail = " ".join(f"{name}={value}" for name, value in fields.items())
            self.logger.info("%s %s", event_type, detail)

        def _record_drop(self, datapath: Any, in_port: int, reason: str) -> None:
            key = (datapath.id, reason)
            now = time.monotonic()
            if now - self._last_drop.get(key, 0.0) < 1.0:
                return
            self._last_drop[key] = now
            counter = {
                "UNAUTHORIZED_ATTACHMENT": "unauthorized_attachment_drops",
                "SOURCE_BINDING_MISMATCH": "source_validation_drops",
                "REACHABILITY_DENIED": "reachability_policy_drops",
            }.get(reason, "unknown_endpoint_drops")
            self.drop_counters[counter] += 1
            self._record_event("UNDERLAY_DROP", datapath=datapath.id, port=in_port, reason=reason)

        def _topology(self) -> tuple[TopologyConfig, UnderlayRegistry]:
            config, authorized = self.inventory.load()
            return config, UnderlayRegistry(config, authorized_sites=authorized)

        def _transport(self, datapath_id: int, config: TopologyConfig) -> str | None:
            return next((name for name, item in config.transports.items() if item.dpid == datapath_id), None)

        def _lan_site(self, datapath_id: int, config: TopologyConfig) -> str | None:
            return next((name for name, item in config.sites.items() if item.lan_dpid == datapath_id), None)

        def _install_lan_table_miss(self, datapath: Any) -> None:
            """Keep local branch LAN connectivity outside the provider pipeline."""
            parser, ofproto = datapath.ofproto_parser, datapath.ofproto
            self._add_flow(
                datapath, table=0, priority=0, match=parser.OFPMatch(),
                actions=[parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)],
            )

        def _learn_lan_packet(self, msg: Any, datapath: Any) -> None:
            parsed = packet.Packet(msg.data)
            frame = parsed.get_protocol(ethernet.ethernet)
            if frame is None or frame.ethertype == ether_types.ETH_TYPE_LLDP:
                return
            in_port = msg.match["in_port"]
            table = self.lan_mac_to_port.setdefault(datapath.id, {})
            table[frame.src] = in_port
            output = table.get(frame.dst, datapath.ofproto.OFPP_FLOOD)
            actions = [datapath.ofproto_parser.OFPActionOutput(output)]
            if output != datapath.ofproto.OFPP_FLOOD:
                parser, ofproto = datapath.ofproto_parser, datapath.ofproto
                datapath.send_msg(parser.OFPFlowMod(
                    datapath=datapath, cookie=COOKIE, table_id=0, priority=100,
                    match=parser.OFPMatch(in_port=in_port, eth_src=frame.src, eth_dst=frame.dst),
                    instructions=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)],
                    idle_timeout=120, hard_timeout=0,
                ))
            datapath.send_msg(datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                actions=actions, data=msg.data,
            ))

        def _add_flow(
            self,
            datapath: Any,
            *,
            table: int,
            priority: int,
            match: Any,
            actions: list[Any] | None = None,
            goto: int | None = None,
        ) -> None:
            parser, ofproto = datapath.ofproto_parser, datapath.ofproto
            instructions: list[Any] = []
            if actions:
                instructions.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))
            if goto is not None:
                instructions.append(parser.OFPInstructionGotoTable(goto))
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath, cookie=COOKIE, table_id=table, priority=priority,
                match=match, instructions=instructions, idle_timeout=0, hard_timeout=0,
            ))

        def _delete_owned_flows(self, datapath: Any) -> None:
            parser, ofproto = datapath.ofproto_parser, datapath.ofproto
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath, cookie=COOKIE, cookie_mask=COOKIE_MASK,
                table_id=ofproto.OFPTT_ALL, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                match=parser.OFPMatch(),
            ))

        def _install_default_drop(self, datapath: Any) -> None:
            """Drop by default and mirror bounded evidence to the controller.

            The controller does not learn or install a path from these packets.
            Packet-In is used only to count and audit a denied packet, with
            per-reason rate limiting in ``_record_drop``.
            """
            parser, ofproto = datapath.ofproto_parser, datapath.ofproto
            for table in (0, 10, 20, 30):
                self._add_flow(
                    datapath, table=table, priority=0, match=parser.OFPMatch(),
                    actions=[parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)],
                )

        def _programming_fingerprint(
            self,
            transport: str,
            registry: UnderlayRegistry,
            ports: dict[str, int],
        ) -> str:
            """Return the effective provider dataplane input for one switch."""
            attachments = [item for item in registry.attachments(transport) if item.port_name in ports]
            return json.dumps({
                "mode": self.mode.value,
                "transport": transport,
                "ports": sorted((name, number) for name, number in ports.items()),
                "attachments": sorted((
                    item.site, item.port_name, str(item.address), item.expected_mac,
                    item.authorized, item.role,
                ) for item in attachments),
                "routes": sorted((
                    route.source_site, route.egress_site, str(route.destination), route.transport,
                ) for route in registry.fib(transport)),
            }, sort_keys=True, separators=(",", ":"))

        def reconcile_datapath(self, datapath: Any) -> None:
            config, registry = self._topology()
            transport = self._transport(datapath.id, config)
            if transport is None:
                return
            if self.mode is UnderlayMode.DISABLED:
                if self._programmed_fingerprints.pop(datapath.id, None) is not None:
                    self._delete_owned_flows(datapath)
                    self._record_event("RECONCILE", transport=transport, mode="DISABLED", added=0, removed=0)
                self._write_state()
                return
            parser, ofproto = datapath.ofproto_parser, datapath.ofproto
            ports = self.port_names.get(datapath.id, {})
            fingerprint = self._programming_fingerprint(transport, registry, ports)
            if self._programmed_fingerprints.get(datapath.id) == fingerprint:
                self._write_state()
                return
            attachments = [item for item in registry.attachments(transport) if item.port_name in ports]
            by_site = {item.site: item for item in attachments}
            self._delete_owned_flows(datapath)
            self._install_default_drop(datapath)
            route_count = 0
            for attachment in attachments:
                in_port = ports[attachment.port_name]
                if not attachment.authorized:
                    continue
                self._add_flow(datapath, table=0, priority=400, match=parser.OFPMatch(
                    in_port=in_port, eth_type=ether_types.ETH_TYPE_ARP,
                ), actions=[parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)])
                self._add_flow(datapath, table=0, priority=400, match=parser.OFPMatch(
                    in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                ), goto=10)
                validation_match: dict[str, Any] = {
                    "in_port": in_port,
                    "eth_type": ether_types.ETH_TYPE_IP,
                    "ipv4_src": str(attachment.address),
                }
                if self.mode is UnderlayMode.ENFORCE:
                    validation_match["eth_src"] = attachment.expected_mac
                self._add_flow(datapath, table=10, priority=400, match=parser.OFPMatch(**validation_match), goto=20)

            for route in registry.fib(transport):
                source = by_site.get(route.source_site)
                target = by_site.get(route.egress_site)
                if source is None or target is None:
                    continue
                in_port, out_port = ports[source.port_name], ports[target.port_name]
                destination_match: dict[str, Any] = {
                    "in_port": in_port,
                    "eth_type": ether_types.ETH_TYPE_IP,
                    "ipv4_dst": (str(route.destination.network_address), str(route.destination.netmask)),
                }
                self._add_flow(datapath, table=20, priority=300, match=parser.OFPMatch(**destination_match), goto=30)
                actions = [
                    parser.OFPActionDecNwTtl(),
                    parser.OFPActionSetField(eth_src=config.underlay_gateway_mac(transport)),
                    parser.OFPActionSetField(eth_dst=target.expected_mac),
                    parser.OFPActionOutput(out_port),
                ]
                self._add_flow(datapath, table=30, priority=300, match=parser.OFPMatch(**destination_match), actions=actions)
                route_count += 1
            self._programmed_fingerprints[datapath.id] = fingerprint
            self._record_event(
                "RECONCILE", transport=transport, mode=self.mode.value,
                attachments=len(attachments), routes=route_count,
            )
            self._write_state()

        def _reconcile_loop(self) -> None:
            while True:
                try:
                    for datapath in list(self.datapaths.values()):
                        self.reconcile_datapath(datapath)
                except Exception as exc:
                    self.logger.warning("UNDERLAY_RECONCILE_FAILED detail=%s", str(exc)[:220])
                hub.sleep(self.reconcile_interval)

        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def switch_features(self, event: Any) -> None:
            datapath = event.msg.datapath
            self.datapaths[datapath.id] = datapath
            self._programmed_fingerprints.pop(datapath.id, None)
            config, _ = self._topology()
            lan_site = self._lan_site(datapath.id, config)
            if lan_site is not None:
                self._install_lan_table_miss(datapath)
                self._record_event("LAN_DATAPATH_STATE", datapath=datapath.id, site=lan_site, state="CONNECTED")
            else:
                datapath.send_msg(datapath.ofproto_parser.OFPPortDescStatsRequest(datapath, 0))
                self._record_event("DATAPATH_STATE", datapath=datapath.id, state="CONNECTED")

        @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
        def port_desc_reply(self, event: Any) -> None:
            datapath = event.msg.datapath
            self.datapaths[datapath.id] = datapath
            self._programmed_fingerprints.pop(datapath.id, None)
            self.port_names[datapath.id] = {
                item.name.decode("utf-8") if isinstance(item.name, bytes) else str(item.name): item.port_no
                for item in event.msg.body
                if item.port_no < datapath.ofproto.OFPP_MAX
            }
            self.reconcile_datapath(datapath)

        @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
        def port_status(self, event: Any) -> None:
            datapath = event.msg.datapath
            self._programmed_fingerprints.pop(datapath.id, None)
            self._record_event("PORT_STATE", datapath=datapath.id, port=event.msg.desc.port_no, reason=event.msg.reason)
            datapath.send_msg(datapath.ofproto_parser.OFPPortDescStatsRequest(datapath, 0))

        @set_ev_cls(ofp_event.EventOFPStateChange, [DEAD_DISPATCHER])
        def datapath_dead(self, event: Any) -> None:
            self.datapaths.pop(event.datapath.id, None)
            self.port_names.pop(event.datapath.id, None)
            self._programmed_fingerprints.pop(event.datapath.id, None)
            self._record_event("DATAPATH_STATE", datapath=event.datapath.id, state="DISCONNECTED")
            self._write_state()

        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def packet_in(self, event: Any) -> None:
            msg, datapath = event.msg, event.msg.datapath
            config, registry = self._topology()
            transport = self._transport(datapath.id, config)
            if transport is None:
                if self._lan_site(datapath.id, config) is not None:
                    self._learn_lan_packet(msg, datapath)
                return
            in_port = msg.match["in_port"]
            port_name = next((name for name, number in self.port_names.get(datapath.id, {}).items() if number == in_port), "")
            attachment = registry.attachment_by_port(transport, port_name)
            parsed = packet.Packet(msg.data)
            frame = parsed.get_protocol(ethernet.ethernet)
            request = parsed.get_protocol(arp.arp)
            if attachment is None or not attachment.authorized:
                self._record_drop(datapath, in_port, "UNAUTHORIZED_ATTACHMENT")
                return
            if frame is None:
                self._record_drop(datapath, in_port, "UNKNOWN_ENDPOINT")
                return
            if request is None:
                reason = {10: "SOURCE_BINDING_MISMATCH", 20: "REACHABILITY_DENIED"}.get(
                    msg.table_id, "UNKNOWN_ENDPOINT"
                )
                self._record_drop(datapath, in_port, reason)
                return
            if request.opcode != arp.ARP_REQUEST or request.dst_ip != str(config.underlay_gateway_ip(transport)):
                self._record_drop(datapath, in_port, "UNKNOWN_ENDPOINT")
                return
            if request.src_ip != str(attachment.address) or request.src_mac.lower() != attachment.expected_mac.lower():
                self._record_drop(datapath, in_port, "SOURCE_BINDING_MISMATCH")
                return
            response = packet.Packet()
            gateway_mac = config.underlay_gateway_mac(transport)
            response.add_protocol(ethernet.ethernet(
                dst=request.src_mac, src=gateway_mac, ethertype=ether_types.ETH_TYPE_ARP,
            ))
            response.add_protocol(arp.arp(
                opcode=arp.ARP_REPLY, src_mac=gateway_mac,
                src_ip=str(config.underlay_gateway_ip(transport)),
                dst_mac=request.src_mac, dst_ip=request.src_ip,
            ))
            response.serialize()
            datapath.send_msg(datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                in_port=datapath.ofproto.OFPP_CONTROLLER,
                actions=[datapath.ofproto_parser.OFPActionOutput(in_port)],
                data=response.data,
            ))

        def _write_state(self) -> None:
            config, registry = self._topology()
            state = {
                "mode": self.mode.value,
                "datapaths": {
                    name: {"dpid": item.dpid, "connected": item.dpid in self.datapaths}
                    for name, item in config.transports.items()
                },
                "attachments": {
                    name: [
                        {
                            "site": item.site, "port": item.port_name,
                            "address": str(item.address), "expected_mac": item.expected_mac,
                            "authorized": item.authorized, "role": item.role,
                        }
                        for item in registry.attachments(name)
                    ]
                    for name in config.transports
                },
                "forwarding": {name: len(registry.fib(name)) for name in config.transports},
                "security_counters": dict(self.drop_counters),
                "events": list(self.underlay_events),
            }
            try:
                self.state_path.parent.mkdir(parents=True, exist_ok=True)
                temporary = self.state_path.with_suffix(".tmp")
                temporary.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
                temporary.replace(self.state_path)
            except OSError:
                pass


def main() -> None:
    if not RYU_AVAILABLE:
        raise SystemExit("run via ryu-manager in ~/ryu-venv38")


if __name__ == "__main__":
    main()
