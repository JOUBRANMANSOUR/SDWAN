"""Graphviz rendering for the configuration-derived SD-WAN v5 physical lab."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
from typing import Mapping

from .common.model import TopologyConfig, load_config
from .topology_v5 import DockerNodeSpec, LinkSpec, LiveTopologyPlan, SwitchSpec, build_live_plan


_TRANSPORT_COLORS = {
    "mpls": "#2563eb",
    "bb": "#16a34a",
    "lte": "#d97706",
}


def _quote(value: object) -> str:
    return json.dumps(str(value))


def _attributes(values: Mapping[str, object]) -> str:
    return "[" + ", ".join(f"{key}={_quote(value)}" for key, value in values.items()) + "]"


def _node_line(name: str, attributes: Mapping[str, object]) -> str:
    return f"  {_quote(name)} {_attributes(attributes)};"


def _switch_attributes(switch: SwitchSpec, config: TopologyConfig) -> dict[str, object]:
    transport = next((item for item in config.transports.values() if item.switch == switch.name), None)
    if transport is not None:
        return {
            "shape": "hexagon", "style": "filled", "fillcolor": _TRANSPORT_COLORS[transport.name],
            "fontcolor": "white", "label": (
                f"{switch.name}\\n{transport.name.upper()} underlay\\n"
                f"{transport.bandwidth_mbps} Mbps; {transport.delay_ms} ms"
            ),
        }
    if switch.openflow:
        return {
            "shape": "diamond", "style": "filled", "fillcolor": "#dbeafe",
            "label": f"{switch.name}\\nOpenFlow 1.3\\nDPID {switch.dpid}",
        }
    return {"shape": "diamond", "style": "filled", "fillcolor": "#e5e7eb", "label": switch.name}


def _docker_attributes(node: DockerNodeSpec, config: TopologyConfig) -> dict[str, object]:
    if node.role == "edge-router":
        if node.name in config.sites:
            profile = config.sites[node.name]
            label = f"{node.name}\\nEdge router\\nprimary {profile.preferred_hub}; standby {profile.standby_hub}"
        else:
            label = f"{node.name}\\nActive-active hub"
        return {"shape": "box", "style": "rounded,filled", "fillcolor": "#ede9fe", "label": label}
    if node.role == "cloud-gateway":
        return {"shape": "box", "style": "rounded,filled", "fillcolor": "#fce7f3", "label": f"{node.name}\\nCloud gateway"}
    if node.role == "branch-client":
        return {"shape": "ellipse", "style": "filled", "fillcolor": "#fef3c7", "label": f"{node.name}\\nBranch client"}
    if node.role == "data-center-app":
        return {"shape": "component", "style": "filled", "fillcolor": "#cffafe", "label": f"{node.name}\\nData Center\\n{config.data_center_app_ip}"}
    if node.role == "saas-app":
        return {"shape": "component", "style": "filled", "fillcolor": "#dcfce7", "label": f"{node.name}\\nNginx SaaS\\n{config.saas_ip}"}
    return {"shape": "component", "style": "filled", "fillcolor": "#fce7f3", "label": f"{node.name}\\nCloud VPC app"}


def _link_attributes(link: LinkSpec, detail: str) -> dict[str, object]:
    if link.transport:
        attributes: dict[str, object] = {"color": _TRANSPORT_COLORS[link.transport], "penwidth": "1.8"}
    elif link.node1 == "mgmtroot" or link.node2 == "mgmtroot" or "mgmt" in (link.intf1, link.intf2):
        attributes = {"color": "#6b7280", "style": "dashed"}
    else:
        attributes = {"color": "#374151"}
    if detail == "physical":
        label = f"{link.intf1} <-> {link.intf2}"
        addresses = ", ".join(address for address in (link.address1, link.address2) if address)
        attributes["label"] = f"{label}\\n{addresses}" if addresses else label
        attributes["fontsize"] = "8"
    return attributes


def _emit_cluster(lines: list[str], cluster_id: str, label: str, names: tuple[str, ...], attributes: Mapping[str, Mapping[str, object]]) -> None:
    if not names:
        return
    lines.append(f"  subgraph cluster_{cluster_id} {{")
    lines.append(f"    label={_quote(label)};")
    lines.append('    color="#9ca3af"; style="rounded";')
    for name in names:
        lines.append("    " + _node_line(name, attributes[name]).strip())
    lines.append("  }")


def _plan_attributes(plan: LiveTopologyPlan, config: TopologyConfig) -> dict[str, dict[str, object]]:
    switch_by_name = {switch.name: switch for switch in plan.switches}
    docker_by_name = {node.name: node for node in plan.docker_nodes}
    return {
        "mgmtroot": {"shape": "house", "style": "filled", "fillcolor": "#e5e7eb", "label": "mgmtroot\\ncontroller / services"},
        **{name: _switch_attributes(spec, config) for name, spec in switch_by_name.items()},
        **{name: _docker_attributes(spec, config) for name, spec in docker_by_name.items()},
    }


def _graph_header(title: str) -> list[str]:
    return [
        "graph sdwan_v5 {",
        f'  graph [rankdir="LR", bgcolor="white", pad="0.25", nodesep="0.35", ranksep="1.0", splines="polyline", fontname="Arial", label={_quote(title)}, labelloc="t", fontsize="20"];',
        '  node [fontname="Arial", fontsize="10", color="#374151"];',
        '  edge [fontname="Arial", fontsize="9", dir="none"];',
    ]


def _render_physical_dot(config: TopologyConfig, plan: LiveTopologyPlan, attributes: dict[str, dict[str, object]]) -> str:
    lines = _graph_header("SD-WAN v5 physical topology (all attachments)")
    hub_names = tuple(config.hubs)
    transport_switches = tuple(item.switch for item in config.transports.values())
    management = ("mgmtroot", config.management_switch)
    data_center = (config.data_center_switch, config.data_center_app_name)
    saas = (config.saas_switch, config.saas_app_name)
    used: set[str] = set()
    _emit_cluster(lines, "management", "Management", management, attributes); used.update(management)
    _emit_cluster(lines, "hubs", "Dual active-active hubs", hub_names, attributes); used.update(hub_names)
    _emit_cluster(lines, "underlay", "Transport underlay", transport_switches, attributes); used.update(transport_switches)
    for site in config.sites.values():
        branch = (site.host_name, site.lan_switch, site.name)
        _emit_cluster(lines, f"branch_{site.name}", f"{site.name} LAN ({site.lan_network})", branch, attributes)
        used.update(branch)
    _emit_cluster(lines, "data_center", f"Data Center ({config.data_center_network})", data_center, attributes); used.update(data_center)
    _emit_cluster(lines, "saas", f"Simulated SaaS ({config.saas_network})", saas, attributes); used.update(saas)
    if config.cloud_vpc.enabled:
        cloud = config.cloud_vpc.active_gateways + (config.cloud_vpc.switch, config.cloud_vpc.app_name)
        _emit_cluster(lines, "cloud", f"Optional Cloud VPC ({config.cloud_vpc.network})", cloud, attributes)
        used.update(cloud)
    for name in sorted(set(attributes) - used):
        lines.append(_node_line(name, attributes[name]))
    for link in plan.links:
        lines.append(f"  {_quote(link.node1)} -- {_quote(link.node2)} {_attributes(_link_attributes(link, 'physical'))};")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _render_logical_dot(config: TopologyConfig, plan: LiveTopologyPlan, attributes: dict[str, dict[str, object]]) -> str:
    """Render a readable abstraction: one fabric edge represents three underlay links."""
    fabric = "transport_fabric"
    attributes[fabric] = {
        "shape": "box", "style": "rounded,filled", "fillcolor": "#dbeafe",
        "label": "Transport fabric\\nMPLS: s_mpls (20 Mbps, 4 ms)\\nBroadband: s_bb (50 Mbps, 25 ms)\\nLTE: s_lte (8 Mbps, 60 ms)",
    }
    lines = _graph_header("SD-WAN v5 logical topology")
    used: set[str] = set()
    management = ("mgmtroot", config.management_switch)
    _emit_cluster(lines, "management", "Management: mgmtbr reaches all Edge routers", management, attributes); used.update(management)
    _emit_cluster(lines, "hubs", "Dual active-active hubs", tuple(config.hubs), attributes); used.update(config.hubs)
    _emit_cluster(lines, "underlay", "Three physical underlays", (fabric,), attributes); used.add(fabric)
    for site in config.sites.values():
        branch = (site.host_name, site.lan_switch, site.name)
        _emit_cluster(lines, f"branch_{site.name}", f"{site.name} LAN ({site.lan_network})", branch, attributes)
        used.update(branch)
    data_center = (config.data_center_switch, config.data_center_app_name)
    _emit_cluster(lines, "data_center", f"Data Center ({config.data_center_network})", data_center, attributes); used.update(data_center)
    saas = (config.saas_switch, config.saas_app_name)
    _emit_cluster(lines, "saas", f"Simulated SaaS ({config.saas_network})", saas, attributes); used.update(saas)
    if config.cloud_vpc.enabled:
        cloud = config.cloud_vpc.active_gateways + (config.cloud_vpc.switch, config.cloud_vpc.app_name)
        _emit_cluster(lines, "cloud", f"Optional Cloud VPC ({config.cloud_vpc.network})", cloud, attributes)
        used.update(cloud)
    for name in sorted(set(attributes) - used):
        lines.append(_node_line(name, attributes[name]))

    lines.append(f"  {_quote('mgmtroot')} -- {_quote(config.management_switch)} {_attributes({'color': '#6b7280', 'style': 'dashed'})};")
    for site in config.sites.values():
        lines.append(f"  {_quote(site.host_name)} -- {_quote(site.lan_switch)} {_attributes({'color': '#374151'})};")
        lines.append(f"  {_quote(site.lan_switch)} -- {_quote(site.name)} {_attributes({'color': '#374151'})};")
    for router in config.site_names:
        lines.append(f"  {_quote(router)} -- {_quote(fabric)} {_attributes({'color': '#2563eb', 'penwidth': '1.8'})};")
    for hub in config.hubs:
        lines.append(f"  {_quote(hub)} -- {_quote(config.data_center_switch)} {_attributes({'color': '#374151'})};")
    lines.append(f"  {_quote(config.data_center_switch)} -- {_quote(config.data_center_app_name)} {_attributes({'color': '#374151'})};")
    lines.append(f"  {_quote(fabric)} -- {_quote(config.saas_switch)} {_attributes({'color': '#16a34a', 'penwidth': '1.8'})};")
    lines.append(f"  {_quote(config.saas_switch)} -- {_quote(config.saas_app_name)} {_attributes({'color': '#374151'})};")
    if config.cloud_vpc.enabled:
        for gateway in config.cloud_vpc.active_gateways:
            lines.append(f"  {_quote(gateway)} -- {_quote(fabric)} {_attributes({'color': '#d97706', 'penwidth': '1.8'})};")
            lines.append(f"  {_quote(gateway)} -- {_quote(config.cloud_vpc.switch)} {_attributes({'color': '#374151'})};")
        lines.append(f"  {_quote(config.cloud_vpc.switch)} -- {_quote(config.cloud_vpc.app_name)} {_attributes({'color': '#374151'})};")
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_dot(config: TopologyConfig, detail: str = "logical") -> str:
    """Return a readable logical view or exact physical attachment view without sudo."""
    if detail not in {"logical", "physical"}:
        raise ValueError("detail must be 'logical' or 'physical'")
    plan = build_live_plan(config)
    attributes = _plan_attributes(plan, config)
    if detail == "physical":
        return _render_physical_dot(config, plan, attributes)
    return _render_logical_dot(config, plan, attributes)


def render_files(config_path: Path, dot_output: Path, svg_output: Path | None, detail: str = "logical", dot_binary: str = "dot") -> None:
    """Write DOT and, when requested, render it with the locally installed Graphviz binary."""
    dot = render_dot(load_config(config_path), detail=detail)
    dot_output.parent.mkdir(parents=True, exist_ok=True)
    dot_output.write_text(dot, encoding="utf-8")
    if svg_output is None:
        return
    binary = shutil.which(dot_binary)
    if binary is None:
        raise RuntimeError(f"Graphviz executable not found: {dot_binary}")
    svg_output.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run([binary, "-Tsvg", "-o", str(svg_output)], input=dot, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise RuntimeError(f"Graphviz failed: {result.stderr.strip()}")


def main() -> int:
    v5_root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Render the configuration-derived SD-WAN v5 physical topology.")
    parser.add_argument("--config", type=Path, default=v5_root / "config" / "topology.yaml")
    parser.add_argument("--dot-output", type=Path, default=v5_root / "docs" / "topology-v5.dot")
    parser.add_argument("--svg-output", type=Path, default=v5_root / "docs" / "topology-v5.svg")
    parser.add_argument("--detail", choices=("logical", "physical"), default="logical")
    parser.add_argument("--dot-binary", default="dot")
    parser.add_argument("--no-svg", action="store_true")
    arguments = parser.parse_args()
    render_files(arguments.config, arguments.dot_output, None if arguments.no_svg else arguments.svg_output, arguments.detail, arguments.dot_binary)
    print(f"wrote {arguments.dot_output}")
    if not arguments.no_svg:
        print(f"wrote {arguments.svg_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
