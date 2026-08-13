#!/usr/bin/env python3
"""Containernet v5 physical topology and privileged-launch boundary.

This module deliberately separates a deterministic physical lab from the SD-WAN
control plane.  It creates the Docker nodes, Linux bridges, OpenFlow underlay,
and base interface addresses only.  ZTP, WireGuard peers, desired-state routes,
NAT, NFQUEUE, and failover are installed later by their respective services.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
import os
from pathlib import Path
import sys
from typing import Any, Mapping

from .common.model import HUBS, TRANSPORTS, TopologyConfig, load_config


@dataclass(frozen=True)
class TopologyPlan:
    """Configuration-derived inventory used by validation and documentation."""

    routers: tuple[str, ...]
    branch_switches: tuple[str, ...]
    underlay_switches: tuple[str, ...]
    data_center_nodes: tuple[str, ...]
    saas_nodes: tuple[str, ...]
    cloud_nodes: tuple[str, ...]

    @property
    def expected_openflow_datapaths(self) -> int:
        return len(self.branch_switches) + len(self.underlay_switches)


@dataclass(frozen=True)
class SwitchSpec:
    """A switch that the physical Containernet launcher must create."""

    name: str
    openflow: bool
    dpid: int | None = None


@dataclass(frozen=True)
class DockerNodeSpec:
    """A Docker node and its minimal runtime privileges."""

    name: str
    image: str
    role: str
    persistent_identity: bool = False


@dataclass(frozen=True)
class LinkSpec:
    """An explicit point-to-switch attachment with optional transport shaping."""

    node1: str
    node2: str
    intf1: str
    intf2: str
    address1: str | None = None
    address2: str | None = None
    transport: str | None = None


@dataclass(frozen=True)
class RouteSpec:
    """A base host route, intentionally not an SD-WAN policy route."""

    node: str
    gateway: IPv4Address
    interface: str


@dataclass(frozen=True)
class LiveTopologyPlan:
    """Pure, inspectable input to the privileged Containernet runtime."""

    inventory: TopologyPlan
    switches: tuple[SwitchSpec, ...]
    docker_nodes: tuple[DockerNodeSpec, ...]
    links: tuple[LinkSpec, ...]
    host_default_routes: tuple[RouteSpec, ...]
    forwarding_nodes: tuple[str, ...]
    nginx_nodes: tuple[str, ...]


def _cidr(address: IPv4Address, network: IPv4Network) -> str:
    return f"{address}/{network.prefixlen}"


def _short_name(name: str) -> str:
    names = {
        "hub1": "h1",
        "hub2": "h2",
        "node1": "n1",
        "node2": "n2",
        "node3": "n3",
        "node4": "n4",
        "node5": "n5",
        "cloud_gw1": "c1",
        "cloud_gw2": "c2",
    }
    try:
        return names[name]
    except KeyError as exc:
        raise ValueError(f"no short interface suffix is defined for {name}") from exc


def _bridge_port(bridge_name: str, suffix: str) -> str:
    """Return a LinuxBridge port name that this Containernet release attaches."""
    interface = f"{bridge_name}-{suffix}"
    if len(interface) > 15:
        raise ValueError(f"LinuxBridge port name exceeds Linux's 15-character limit: {interface}")
    return interface


def build_plan(config: TopologyConfig) -> TopologyPlan:
    cloud = ()
    if config.cloud_vpc.enabled:
        cloud = config.cloud_vpc.active_gateways + (config.cloud_vpc.app_name,)
    return TopologyPlan(
        routers=config.site_names,
        branch_switches=tuple(site.lan_switch for site in config.sites.values()),
        underlay_switches=tuple(transport.switch for transport in config.transports.values()),
        data_center_nodes=(config.data_center_switch, config.data_center_app_name),
        saas_nodes=(config.saas_switch, config.saas_app_name, "sensitive_saas", "unknown_saas"),
        cloud_nodes=cloud,
    )


def build_live_plan(config: TopologyConfig) -> LiveTopologyPlan:
    """Build a complete physical topology without importing Containernet.

    Keeping this function pure makes the privileged boundary small and permits
    unit tests to verify names, DPIDs, links, and addresses without sudo.
    """
    inventory = build_plan(config)
    active_cloud_gateways = config.cloud_vpc.active_gateways if config.cloud_vpc.enabled else ()
    edge_nodes = config.site_names

    switches = [
        *(SwitchSpec(transport.switch, openflow=True, dpid=transport.dpid)
          for transport in config.transports.values()),
        *(SwitchSpec(site.lan_switch, openflow=True, dpid=site.lan_dpid)
          for site in config.sites.values()),
        SwitchSpec(config.management_switch, openflow=False),
        SwitchSpec(config.data_center_switch, openflow=False),
        SwitchSpec(config.saas_switch, openflow=False),
    ]
    if config.cloud_vpc.enabled:
        switches.append(SwitchSpec(config.cloud_vpc.switch, openflow=False))

    docker_nodes = [
        *(DockerNodeSpec(name, config.edge_image, "edge-router", persistent_identity=True)
          for name in config.site_names),
        *(DockerNodeSpec(name, config.edge_image, "cloud-gateway", persistent_identity=False)
          for name in active_cloud_gateways),
        *(DockerNodeSpec(site.host_name, config.host_image, "branch-client")
          for site in config.sites.values()),
        DockerNodeSpec(config.data_center_app_name, config.host_image, "data-center-app"),
        DockerNodeSpec(config.saas_app_name, config.host_image, "saas-app"),
        DockerNodeSpec("sensitive_saas", config.host_image, "sensitive-saas"),
        DockerNodeSpec("unknown_saas", config.host_image, "unknown-saas"),
    ]
    if config.cloud_vpc.enabled:
        docker_nodes.append(DockerNodeSpec(config.cloud_vpc.app_name, config.host_image, "cloud-app"))

    links: list[LinkSpec] = []
    routes: list[RouteSpec] = []

    # The root-namespace management endpoint makes controller, Policy, and ZTP
    # services reachable from the isolated management bridge without putting
    # lab containers on Docker's default network.
    links.append(LinkSpec(
        "mgmtroot", config.management_switch, "mgmt-root",
        _bridge_port(config.management_switch, "root"),
        config.controller.management_address,
    ))
    for name in edge_nodes:
        management_ip = config.hubs[name].management_ip if name in config.hubs else config.sites[name].management_ip
        links.append(LinkSpec(
            name, config.management_switch, f"{name}-mgmt",
            _bridge_port(config.management_switch, _short_name(name)),
            _cidr(management_ip, config.management_network),
        ))
    # Every hub and spoke is physically attached to every transport. Cloud
    # Gateways are deliberately reached only through dedicated hub-to-gateway
    # links; they are not additional spoke underlay attachments.
    for name in edge_nodes:
        for transport in config.transports.values():
            links.append(LinkSpec(
                name, transport.switch, f"{name}-{transport.name}",
                f"{transport.switch}-{_short_name(name)}",
                _cidr(config.underlay_ip(name, transport.name), transport.network),
                transport=transport.name,
            ))

    for site in config.sites.values():
        links.append(LinkSpec(
            site.name, site.lan_switch, f"{site.name}-lan", f"{site.lan_switch}-r",
            _cidr(site.lan_gateway, site.lan_network),
        ))
        client_interface = f"{site.host_name}-lan"
        links.append(LinkSpec(
            site.host_name, site.lan_switch, client_interface, f"{site.lan_switch}-h",
            _cidr(site.host_ip, site.lan_network),
        ))
        routes.append(RouteSpec(site.host_name, site.lan_gateway, client_interface))

    for hub in HUBS:
        links.append(LinkSpec(
            hub, config.data_center_switch, f"{hub}-dc",
            _bridge_port(config.data_center_switch, _short_name(hub)),
            _cidr(config.data_center_hub_ips[hub], config.data_center_network),
        ))
    links.append(LinkSpec(
        config.data_center_app_name, config.data_center_switch,
        f"{config.data_center_app_name}-net", _bridge_port(config.data_center_switch, "app"),
        _cidr(config.data_center_app_ip, config.data_center_network),
    ))

    links.append(LinkSpec(
        config.saas_app_name, config.saas_switch,
        f"{config.saas_app_name}-inet", _bridge_port(config.saas_switch, "saas"),
        _cidr(config.saas_ip, config.saas_network),
    ))
    for transport_name, address in config.saas_transport_ips.items():
        transport = config.transports[transport_name]
        links.append(LinkSpec(
            config.saas_app_name, transport.switch, f"saas-{transport_name}",
            f"{transport.switch}-saas", _cidr(address, transport.network),
        ))

    for name, address, suffix in (("sensitive_saas", "198.18.0.20/24", "sens"), ("unknown_saas", "198.18.0.30/24", "unk")):
        interface = "sens-inet" if name == "sensitive_saas" else "unk-inet"
        links.append(LinkSpec(name, config.saas_switch, interface, _bridge_port(config.saas_switch, suffix), address))
        routes.append(RouteSpec(name, config.saas_ip, interface))
    if config.cloud_vpc.enabled:
        for gateway in active_cloud_gateways:
            links.append(LinkSpec(
                gateway, config.cloud_vpc.switch, f"{gateway}-vpc",
                _bridge_port(config.cloud_vpc.switch, _short_name(gateway)),
                _cidr(config.cloud_vpc.gateway_ips[gateway], config.cloud_vpc.network),
            ))
        for hub in HUBS:
            for gateway in active_cloud_gateways:
                network = config.cloud_vpc.transit_network(hub, gateway)
                links.append(LinkSpec(hub, gateway, f"{_short_name(hub)}-{_short_name(gateway)}", f"{_short_name(gateway)}-{_short_name(hub)}", _cidr(config.cloud_vpc.transit_ip(hub, gateway, hub), network), _cidr(config.cloud_vpc.transit_ip(hub, gateway, gateway), network)))
        links.append(LinkSpec(
            config.cloud_vpc.app_name, config.cloud_vpc.switch,
            f"{config.cloud_vpc.app_name}-vpc", _bridge_port(config.cloud_vpc.switch, "app"),
            _cidr(config.cloud_vpc.app_ip, config.cloud_vpc.network),
        ))

    plan = LiveTopologyPlan(
        inventory=inventory,
        switches=tuple(switches),
        docker_nodes=tuple(docker_nodes),
        links=tuple(links),
        host_default_routes=tuple(routes),
        forwarding_nodes=edge_nodes + active_cloud_gateways + (config.saas_app_name,),
        nginx_nodes=tuple(
            name for name in (
                config.data_center_app_name,
                config.saas_app_name,
                config.cloud_vpc.app_name if config.cloud_vpc.enabled else None,
            ) if name is not None
        ),
    )
    _validate_live_plan(plan)
    return plan


def _validate_live_plan(plan: LiveTopologyPlan) -> None:
    openflow = [switch for switch in plan.switches if switch.openflow]
    if len(openflow) != plan.inventory.expected_openflow_datapaths:
        raise ValueError("live topology does not have exactly eight OpenFlow datapaths")
    dpids = [switch.dpid for switch in openflow]
    if any(dpid is None for dpid in dpids) or len(dpids) != len(set(dpids)):
        raise ValueError("OpenFlow DPIDs must be present and unique")

    names = {"mgmtroot"}
    names.update(switch.name for switch in plan.switches)
    names.update(node.name for node in plan.docker_nodes)
    if len(names) != 1 + len(plan.switches) + len(plan.docker_nodes):
        raise ValueError("a physical topology node or switch name is duplicated")

    non_openflow_bridges = {switch.name for switch in plan.switches if not switch.openflow}
    command_names = {"mgmtroot", *(switch.name for switch in plan.switches), *(node.name for node in plan.docker_nodes)}
    if any(not name.isidentifier() for name in command_names):
        raise ValueError("Containernet CLI node and switch names must be valid Python identifiers")

    interfaces: set[tuple[str, str]] = set()
    for link in plan.links:
        for node, interface in ((link.node1, link.intf1), (link.node2, link.intf2)):
            if node not in names:
                raise ValueError(f"link references unknown node {node}")
            if not interface or len(interface) > 15:
                raise ValueError(f"interface name is invalid for {node}: {interface!r}")
            if node in non_openflow_bridges and node not in interface:
                raise ValueError(f"LinuxBridge port name must contain its bridge name: {node}/{interface}")
            key = (node, interface)
            if key in interfaces:
                raise ValueError(f"interface name is reused: {node}/{interface}")
            interfaces.add(key)


def validate_plan(config_path: Path) -> TopologyPlan:
    config = load_config(config_path)
    plan = build_plan(config)
    if len(plan.routers) != 7 or plan.expected_openflow_datapaths != 8:
        raise ValueError("v5 requires seven edge routers and eight OpenFlow datapaths")
    build_live_plan(config)
    return plan


def _run_checked(node: Any, command: list[str]) -> None:
    output, error, status = node.pexec(command)
    if status != 0:
        detail = (error or output).strip()
        raise RuntimeError(f"{node.name}: {' '.join(command)} failed ({status}): {detail}")


def _flush_route_table_if_present(node: Any, table: int) -> None:
    """Flush a policy-routing table without failing on its first creation.

    Linux returns exit status 2 when an unallocated FIB table is flushed.
    That state is harmless here because the subsequent ``ip route replace``
    commands create the table. Other errors remain fatal.
    """
    command = ["ip", "route", "flush", "table", str(table)]
    output, error, status = node.pexec(command)
    if status == 0:
        return
    detail = (error or output).strip()
    if "FIB table does not exist" in detail:
        return
    raise RuntimeError(f"{node.name}: {' '.join(command)} failed ({status}): {detail}")


def _configure_cloud_return_affinity(nodes: Mapping[str, Any], config: TopologyConfig) -> None:
    """Pin Cloud VPC flows to their ingress gateway and ingress hub.

    Conntrack state is local to each Cloud Gateway namespace. Branch-originated
    traffic is therefore SNATed to the ingress gateway's VPC address so the
    Cloud application returns the connection to that same gateway. A connmark
    records which hub-facing transit interface carried the flow, and policy
    tables send the reverse-NAT packet back through that same hub.
    """
    if not config.cloud_vpc.enabled:
        return
    marks = config.settings.marks
    connection_mask = hex(marks.connection_mask)
    affinity_mask = hex(marks.affinity_mask)
    stamp_mask = hex(marks.affinity_mask | marks.terminal_bit)
    cloud_route_mask = marks.target_hub_mask | marks.egress_mask
    ingress_chain = "SDWAN_V5_CLOUD_RPA_IN"
    egress_chain = "SDWAN_V5_CLOUD_RPA_OUT"
    nat_chain = "SDWAN_V5_CLOUD_SNAT"
    route_tables = {"hub1": 3101, "hub2": 3102}
    rule_priorities = {"hub1": 1301, "hub2": 1302}

    for gateway in config.cloud_vpc.active_gateways:
        node = nodes[gateway]
        for table, chain in (("mangle", ingress_chain), ("mangle", egress_chain), ("nat", nat_chain)):
            _run_checked(node, ["sh", "-c", f"iptables -t {table} -N {chain} 2>/dev/null || true"])
            _run_checked(node, ["iptables", "-t", table, "-F", chain])
        _run_checked(node, [
            "sh", "-c",
            f"iptables -t mangle -C PREROUTING -j {ingress_chain} 2>/dev/null || "
            f"iptables -t mangle -A PREROUTING -j {ingress_chain}",
        ])
        _run_checked(node, [
            "sh", "-c",
            f"iptables -t mangle -C POSTROUTING -j {egress_chain} 2>/dev/null || "
            f"iptables -t mangle -A POSTROUTING -j {egress_chain}",
        ])
        _run_checked(node, [
            "sh", "-c",
            f"iptables -t nat -C POSTROUTING -j {nat_chain} 2>/dev/null || "
            f"iptables -t nat -A POSTROUTING -j {nat_chain}",
        ])

        _run_checked(node, [
            "iptables", "-t", "mangle", "-A", ingress_chain,
            "-j", "CONNMARK", "--restore-mark",
            "--nfmask", connection_mask, "--ctmask", connection_mask,
        ])
        for hub in HUBS:
            hub_bit = marks.hub1_bit if hub == "hub1" else marks.hub2_bit
            affinity_mark = hub_bit | marks.cloud_gateway_bit
            stamped_mark = affinity_mark | marks.terminal_bit
            interface = f"{_short_name(gateway)}-{_short_name(hub)}"
            _run_checked(node, [
                "iptables", "-t", "mangle", "-A", ingress_chain,
                "-i", interface, "-m", "conntrack", "--ctstate", "NEW",
                "-m", "mark", "--mark", f"0/{affinity_mask}",
                "-j", "MARK", "--set-xmark", f"{hex(stamped_mark)}/{stamp_mask}",
            ])
        _run_checked(node, [
            "iptables", "-t", "mangle", "-A", ingress_chain,
            "-j", "CONNMARK", "--save-mark",
            "--nfmask", connection_mask, "--ctmask", connection_mask,
        ])

        for hub in HUBS:
            hub_bit = marks.hub1_bit if hub == "hub1" else marks.hub2_bit
            affinity_mark = hub_bit | marks.cloud_gateway_bit
            stamped_mark = affinity_mark | marks.terminal_bit
            interface = f"{_short_name(gateway)}-{_short_name(hub)}"
            _run_checked(node, [
                "iptables", "-t", "mangle", "-A", egress_chain,
                "-o", interface, "-m", "conntrack", "--ctstate", "NEW",
                "-m", "mark", "--mark", f"0/{affinity_mask}",
                "-j", "MARK", "--set-xmark", f"{hex(stamped_mark)}/{stamp_mask}",
            ])
            _run_checked(node, [
                "iptables", "-t", "mangle", "-A", egress_chain,
                "-o", interface, "-m", "conntrack", "--ctstate", "NEW",
                "-m", "mark", "--mark", f"{hex(stamped_mark)}/{stamp_mask}",
                "-j", "CONNMARK", "--save-mark",
                "--nfmask", connection_mask, "--ctmask", connection_mask,
            ])

        for hub in HUBS:
            table = route_tables[hub]
            priority = rule_priorities[hub]
            hub_bit = marks.hub1_bit if hub == "hub1" else marks.hub2_bit
            affinity_mark = hub_bit | marks.cloud_gateway_bit
            interface = f"{_short_name(gateway)}-{_short_name(hub)}"
            next_hop = config.cloud_vpc.transit_ip(hub, gateway, hub)
            _flush_route_table_if_present(node, table)
            for site in config.sites.values():
                _run_checked(node, [
                    "ip", "route", "replace", str(site.lan_network),
                    "via", str(next_hop), "dev", interface, "table", str(table),
                ])
            _run_checked(node, ["sh", "-c", f"ip rule del priority {priority} 2>/dev/null || true"])
            _run_checked(node, [
                "ip", "rule", "add", "priority", str(priority),
                "fwmark", f"{affinity_mark}/{cloud_route_mask}", "lookup", str(table),
            ])

        vpc_interface = f"{gateway}-vpc"
        for site in config.sites.values():
            _run_checked(node, [
                "iptables", "-t", "nat", "-A", nat_chain,
                "-s", str(site.lan_network), "-d", str(config.cloud_vpc.network),
                "-o", vpc_interface, "-j", "SNAT", "--to-source",
                str(config.cloud_vpc.gateway_ips[gateway]),
            ])


def _configure_addresses(nodes: Mapping[str, Any], config: TopologyConfig, plan: LiveTopologyPlan) -> None:
    for link in plan.links:
        if link.address1:
            _run_checked(nodes[link.node1], ["ip", "address", "replace", link.address1, "dev", link.intf1])
            _run_checked(nodes[link.node1], ["ip", "link", "set", "dev", link.intf1, "up"])
        if link.address2:
            _run_checked(nodes[link.node2], ["ip", "address", "replace", link.address2, "dev", link.intf2])
            _run_checked(nodes[link.node2], ["ip", "link", "set", "dev", link.intf2, "up"])
    for route in plan.host_default_routes:
        _run_checked(nodes[route.node], [
            "ip", "route", "replace", "default", "via", str(route.gateway), "dev", route.interface,
        ])
    # Data Center applications need an explicit return route for every branch.
    # The initial owner is the site's preferred hub; this keeps return traffic
    # inside the overlay and avoids exposing private prefixes through Internet NAT.
    dc_app = config.data_center_app_name
    dc_interface = f"{dc_app}-net"
    for site in config.sites.values():
        owner_hub = site.preferred_hub
        _run_checked(nodes[dc_app], [
            "ip", "route", "replace", str(site.lan_network), "via",
            str(config.data_center_hub_ips[owner_hub]), "dev", dc_interface,
        ])
    if config.cloud_vpc.enabled:
        gateways = config.cloud_vpc.active_gateways
        if not gateways:
            raise RuntimeError("Cloud VPC is enabled without an active gateway")
        gateway_orders = {
            "hub1": (gateways[0], *gateways[1:]),
            "hub2": (gateways[-1], *gateways[:-1]),
        }
        cloud_app = config.cloud_vpc.app_name
        cloud_interface = f"{cloud_app}-vpc"
        for hub, gateways_for_hub in gateway_orders.items():
            for priority, gateway in enumerate(gateways_for_hub):
                _run_checked(nodes[hub], ["ip", "route", "replace", str(config.cloud_vpc.network), "via", str(config.cloud_vpc.transit_ip(hub, gateway, gateway)), "dev", f"{_short_name(hub)}-{_short_name(gateway)}", "metric", str(100 + priority * 100)])
        for gateway in gateways:
            for site in config.sites.values():
                for priority, hub in enumerate((site.preferred_hub, site.standby_hub)):
                    _run_checked(nodes[gateway], ["ip", "route", "replace", str(site.lan_network), "via", str(config.cloud_vpc.transit_ip(hub, gateway, hub)), "dev", f"{_short_name(gateway)}-{_short_name(hub)}", "metric", str(100 + priority * 100)])
        for site in config.sites.values():
            for priority, gateway in enumerate(gateway_orders[site.preferred_hub]):
                _run_checked(nodes[cloud_app], ["ip", "route", "replace", str(site.lan_network), "via", str(config.cloud_vpc.gateway_ips[gateway]), "dev", cloud_interface, "metric", str(100 + priority * 100)])
        _configure_cloud_return_affinity(nodes, config)
    for name in plan.forwarding_nodes:
        _run_checked(nodes[name], ["sysctl", "-w", "net.ipv4.ip_forward=1"])


def _configure_transport_qdiscs(nodes: Mapping[str, Any], config: TopologyConfig, plan: LiveTopologyPlan) -> None:
    """Apply deterministic HFSC/netem shaping without Containernet's noisy TCLink.

    TCLink configures a qdisc while links are being created and writes an
    unhelpful ``*** Error:`` for control-character-only command output on this
    Ubuntu/Containernet combination. Applying the equivalent idempotent
    commands after the network starts preserves the configured impairment model
    and makes genuine tc failures actionable.
    """
    for link in plan.links:
        if not link.transport:
            continue
        transport = config.transports[link.transport]
        for node_name, interface in ((link.node1, link.intf1), (link.node2, link.intf2)):
            rate = f"{transport.bandwidth_mbps}Mbit"
            _run_checked(nodes[node_name], [
                "tc", "qdisc", "replace", "dev", interface, "root", "handle", "5:0",
                "hfsc", "default", "1",
            ])
            _run_checked(nodes[node_name], [
                "tc", "class", "replace", "dev", interface, "parent", "5:0",
                "classid", "5:1", "hfsc", "sc", "rate", rate, "ul", "rate", rate,
            ])
            netem = ["tc", "qdisc", "replace", "dev", interface, "parent", "5:1", "handle", "10:", "netem"]
            if transport.delay_ms:
                netem.extend(["delay", f"{transport.delay_ms}ms"])
                if transport.jitter_ms:
                    netem.append(f"{transport.jitter_ms}ms")
            if transport.loss_pct:
                netem.extend(["loss", f"{transport.loss_pct}%"])
            _run_checked(nodes[node_name], netem)


def _start_workloads(nodes: Mapping[str, Any], plan: LiveTopologyPlan, config: TopologyConfig) -> None:
    for name in plan.nginx_nodes:
        _run_checked(nodes[name], ["nginx", "-t"])
        _run_checked(nodes[name], ["nginx"])
    _run_checked(nodes["sensitive_saas"], ["sh", "-c", "setsid nohup python3 /opt/sdwan_v5/workloads/saas_service.py </dev/null >/var/log/sensitive-saas.log 2>&1 & sleep 0.2; pgrep -f saas_service.py"])
    for port in (9000, 9001, 443):
        _run_checked(nodes["unknown_saas"], ["sh", "-c", f"setsid nohup iperf3 -s -p {port} </dev/null >/var/log/unknown-{port}.log 2>&1 & sleep 0.2; pgrep -f 'iperf3 -s -p {port}'"])


def _verify_physical_topology(nodes: Mapping[str, Any], config: TopologyConfig) -> None:
    """Fail early if the base lab is not forwarding before ZTP begins."""
    checks = (
        (
            "branch LAN through lsw1/OpenFlow",
            "node1_host",
            ["ping", "-c", "2", "-W", "2", str(config.sites["node1"].lan_gateway)],
        ),
        (
            "management bridge",
            "node1",
            ["ping", "-c", "2", "-W", "2", str(config.controller.management_address).split("/", 1)[0]],
        ),
        (
            "Data Center bridge",
            "hub1",
            ["ping", "-c", "2", "-W", "2", str(config.data_center_app_ip)],
        ),
        (
            "Broadband underlay through s_bb/OpenFlow",
            "node1",
            ["ping", "-I", "node1-bb", "-c", "2", "-W", "2", str(config.saas_transport_ips["bb"])],
        ),
        (
            "local SaaS Nginx",
            config.saas_app_name,
            ["curl", "--fail", "--silent", "http://198.18.0.10/healthz"],
        ),
    )
    for description, node_name, command in checks:
        try:
            _run_checked(nodes[node_name], command)
        except RuntimeError as exc:
            raise RuntimeError(f"physical topology self-check failed: {description}: {exc}") from exc


def launch_live(config_path: Path) -> None:
    """Create the physical v5 lab, enter the CLI, and clean it up reliably."""
    config = load_config(config_path)
    live_plan = build_live_plan(config)
    if os.geteuid() != 0:
        raise RuntimeError("live topology requires sudo on Ubuntu; use scripts/run_topology.sh")

    try:
        # Containernet's mininet.link and mininet.node modules import each
        # other.  Importing Containernet first establishes their supported
        # initialization order on Ubuntu 24.04/Python 3.8.
        from mininet.net import Containernet  # type: ignore
        from mininet.node import Node, OVSSwitch, RemoteController  # type: ignore
        from mininet.link import Link  # type: ignore
        from mininet.nodelib import LinuxBridge  # type: ignore
        from mininet.cli import CLI  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "activate ~/containernet-venv38 and run this on Ubuntu with Containernet installed"
        ) from exc

    # This Containernet fork does not run switch setup from Mininet.init().
    # OVS setup validates the daemon and initializes OVSSwitch.OVSVersion;
    # LinuxBridge setup validates brctl before any namespace work is created.
    OVSSwitch.setup()
    LinuxBridge.setup()

    net: Any | None = None
    try:
        net = Containernet(controller=None, switch=OVSSwitch, link=Link, build=False, autoSetMacs=True)
        # This must happen before OVS instances are created so all eight OF 1.3
        # datapaths are attached to the intended Ryu endpoint from startup.
        net.addController(
            "c0", controller=RemoteController,
            ip=config.controller.openflow_host, port=config.controller.openflow_port,
        )

        nodes: dict[str, Any] = {
            "mgmtroot": net.addHost("mgmtroot", cls=Node, inNamespace=False, ip=None),
        }
        for switch_index, switch in enumerate(live_plan.switches):
            if switch.openflow:
                nodes[switch.name] = net.addSwitch(
                    switch.name, cls=OVSSwitch, dpid=f"{switch.dpid:016x}",
                    protocols="OpenFlow13", failMode="secure",
                )
            else:
                # LinuxBridge is not an OpenFlow datapath, but its Mininet base
                # class still requires a hexadecimal DPID during construction.
                nodes[switch.name] = net.addSwitch(
                    switch.name, cls=LinuxBridge, dpid=f"{0x1000 + switch_index:016x}",
                )
        for node in live_plan.docker_nodes:
            parameters: dict[str, Any] = {
                "dimage": node.image,
                "dcmd": "sleep infinity",
                "ip": None,
                "network_mode": "none",
            }
            if node.persistent_identity:
                parameters.update({
                    "volumes": [
                        f"sdwan-{node.name}-identity:/var/lib/sdwan:rw",
                        f"{config.source.resolve()}:/opt/sdwan_v5/config/topology.yaml:ro",
                    ],
                    "cap_add": ["net_admin", "net_raw"],
                })
            if node.name in live_plan.forwarding_nodes:
                capabilities = list(parameters.get("cap_add", []))
                for capability in ("net_admin", "net_raw"):
                    if capability not in capabilities:
                        capabilities.append(capability)
                parameters["cap_add"] = capabilities
                # Docker must apply these before Containernet attaches interfaces.
                # Per-interface sysctls are read-only from inside this container.
                parameters["sysctls"] = {
                    "net.ipv4.conf.all.rp_filter": "0",
                    "net.ipv4.conf.default.rp_filter": "0",
                    "net.ipv4.conf.all.src_valid_mark": "1",
                    "net.ipv4.conf.default.src_valid_mark": "1",
                    "net.ipv4.conf.all.ignore_routes_with_linkdown": "1",
                    "net.ipv4.conf.default.ignore_routes_with_linkdown": "1",
                }
            nodes[node.name] = net.addDocker(node.name, **parameters)

        for link in live_plan.links:
            parameters: dict[str, Any] = {
                "intfName1": link.intf1,
                "intfName2": link.intf2,
            }
            # Shape after net.start(); see _configure_transport_qdiscs.
            net.addLink(nodes[link.node1], nodes[link.node2], cls=Link, **parameters)

        net.start()
        if not net.waitConnected(timeout=10):
            raise RuntimeError("not all OpenFlow switches connected to the configured Ryu controller within 10 seconds")
        _configure_addresses(nodes, config, live_plan)
        _configure_transport_qdiscs(nodes, config, live_plan)
        _start_workloads(nodes, live_plan, config)
        _verify_physical_topology(nodes, config)
        cloud_status = (
            "Cloud Gateway conntrack/SNAT return affinity is installed."
            if config.cloud_vpc.enabled
            else "Cloud VPC is disabled in this profile."
        )
        print(
            f"Physical v5 topology is ready. {cloud_status} ZTP, WireGuard, desired-state "
            "edge routes, NFQUEUE, and dynamic failover still require the control-plane "
            "services before end-to-end tests."
        )
        CLI(net)
    finally:
        if net is not None:
            try:
                net.stop()
            except Exception:
                if sys.exc_info()[0] is None:
                    raise


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("config") / "topology.yaml")
    parser.add_argument("--validate-config", action="store_true")
    arguments = parser.parse_args()
    if arguments.validate_config:
        print(validate_plan(arguments.config))
    else:
        launch_live(arguments.config)
