"""Typed live-Containernet branch lifecycle adapter.

This module is deliberately small and is instantiated only by
``topology_v5.launch_live`` after the base topology has started.  It does not
accept commands from the management API: it receives an already validated,
allocated :class:`InventorySite` over the local typed control socket.
"""
from __future__ import annotations

from pathlib import Path
import json
import subprocess
from threading import RLock
from typing import Any

from .common.model import TopologyConfig
from .dynamic_control import InventorySite

def _bounded_error(value: str, limit: int = 800) -> str:
    value = value.strip()
    if len(value) <= limit:
        return value
    marker = "\n... error truncated ...\n"
    head = limit // 4
    return value[:head] + marker + value[-(limit - head - len(marker)):]



class DynamicContainernetRuntime:
    """Create and remove the physical pieces of one allocated branch.

    A failed callback raises, causing the socket client to report unavailable;
    callers therefore never receive a fabricated successful topology result.
    """

    def __init__(self, net: Any, nodes: dict[str, Any], config: TopologyConfig, *, ovs_switch: Any, link: Any):
        self.net, self.nodes, self.config = net, nodes, config
        self.ovs_switch, self.link = ovs_switch, link
        self._managed: dict[str, tuple[str, str, str]] = {}
        self._lock = RLock()

    @staticmethod
    def _run(node: Any, command: list[str]) -> None:
        output, error, status = node.pexec(command)
        if status != 0:
            raise RuntimeError(f"{node.name}: {' '.join(command)} failed: {(error or output).strip()}")

    @staticmethod
    def _bridge_port(bridge: str, suffix: str) -> str:
        value = f"{bridge}-{suffix}"
        if len(value) > 15:
            raise ValueError(f"dynamic bridge port is too long: {value}")
        return value

    def _edge_parameters(self, site: InventorySite) -> dict[str, Any]:
        return {
            "dimage": self.config.edge_image,
            "dcmd": "sleep infinity",
            "ip": None,
            "network_mode": "none",
            "volumes": [
                f"sdwan-{site.site}-identity:/var/lib/sdwan:rw",
                f"{self.config.source.resolve()}:/opt/sdwan/config/topology.yaml:ro",
            ],
            "cap_add": ["net_admin", "net_raw"],
            "sysctls": {
                "net.ipv4.conf.all.rp_filter": "0",
                "net.ipv4.conf.default.rp_filter": "0",
                "net.ipv4.conf.all.src_valid_mark": "1",
                "net.ipv4.conf.default.src_valid_mark": "1",
                "net.ipv4.conf.all.ignore_routes_with_linkdown": "1",
                "net.ipv4.conf.default.ignore_routes_with_linkdown": "1",
            },
        }

    @staticmethod
    def _attach_running_switch(switch: Any, link: Any, switch_is_second: bool = True) -> None:
        """Attach a dynamic port to a switch that was already started.

        Static links are attached during ``net.start()``. Dynamic OVS switches
        support ``attach()``, whereas the management plane is a LinuxBridge and
        needs an explicit ``brctl addif``. Both cases are L2 attachment only;
        Ryu remains responsible for L3 forwarding on OpenFlow underlays.
        """
        interface = link.intf2 if switch_is_second else link.intf1
        if hasattr(switch, "attach"):
            switch.attach(interface)
            return
        name = getattr(interface, "name", str(interface))
        output = switch.cmd("brctl addif %s %s" % (switch.name, name))
        if output and "File exists" not in output:
            raise RuntimeError("%s: failed to attach dynamic bridge port %s: %s" % (switch.name, name, output.strip()))

    def _remove_managed_nodes(self, names: tuple[str, str, str]) -> None:
        for name in reversed(names):
            node = self.nodes.get(name)
            if node is not None:
                self.net.delNode(node, deleteIntfs=True)
                self.nodes.pop(name, None)

    def _shape(self, node: Any, interface: str, transport: str) -> None:
        profile = self.config.transports[transport]
        rate = f"{profile.bandwidth_mbps}Mbit"
        self._run(node, ["tc", "qdisc", "replace", "dev", interface, "root", "handle", "5:0", "hfsc", "default", "1"])
        self._run(node, ["tc", "class", "replace", "dev", interface, "parent", "5:0", "classid", "5:1", "hfsc", "sc", "rate", rate, "ul", "rate", rate])
        netem = ["tc", "qdisc", "replace", "dev", interface, "parent", "5:1", "handle", "10:", "netem"]
        if profile.delay_ms:
            netem.extend(["delay", f"{profile.delay_ms}ms"])
            if profile.jitter_ms:
                netem.append(f"{profile.jitter_ms}ms")
        if profile.loss_pct:
            netem.extend(["loss", f"{profile.loss_pct}%"])
        self._run(node, netem)

    def create_site(self, record: InventorySite) -> None:
        site = record.to_site()
        runtime_config = self.config.with_sites({**self.config.sites, site.name: site})
        with self._lock:
            if record.site in self._managed:
                return
            names = (record.site, site.host_name, site.lan_switch)
            existing = {name for name in names if name in self.nodes}
            if existing:
                # A previous dynamic request can fail after Docker/links have
                # been created but before configuration completes.  Only clean
                # the exact three inventory-owned names; never touch a static
                # topology node or an unrelated resource.
                if existing == set(names):
                    self._remove_managed_nodes(names)
                else:
                    raise ValueError("dynamic site collides with an existing live node")
            if len(record.site) > 10:
                raise ValueError("dynamic site name is too long for Linux interfaces")
            lan = self.net.addSwitch(site.lan_switch, cls=self.ovs_switch, dpid=f"{site.lan_dpid:016x}", protocols="OpenFlow13", failMode="secure")
            edge = self.net.addDocker(record.site, **self._edge_parameters(record))
            host = self.net.addDocker(site.host_name, dimage=self.config.host_image, dcmd="sleep infinity", ip=None, network_mode="none")
            self.nodes.update({site.lan_switch: lan, record.site: edge, site.host_name: host})
            self._managed[record.site] = names
            try:
                suffix = site.interface_suffix or f"n{site.address_id}"
                management_link = self.net.addLink(edge, self.nodes[self.config.management_switch], cls=self.link, intfName1=f"{record.site}-mgmt", intfName2=self._bridge_port(self.config.management_switch, suffix))
                self._attach_running_switch(self.nodes[self.config.management_switch], management_link)
                for transport in self.config.transports.values():
                    transport_link = self.net.addLink(edge, self.nodes[transport.switch], cls=self.link, intfName1=f"{record.site}-{transport.name}", intfName2=f"{transport.switch}-{suffix}")
                    self._attach_running_switch(self.nodes[transport.switch], transport_link)
                self.net.addLink(edge, lan, cls=self.link, intfName1=f"{record.site}-lan", intfName2=f"{site.lan_switch}-r")
                self.net.addLink(host, lan, cls=self.link, intfName1=f"{site.host_name}-lan", intfName2=f"{site.lan_switch}-h")
                lan.start(self.net.controllers)
            except Exception:
                self._remove_managed_nodes(names)
                self._managed.pop(record.site, None)
                raise
            self._run(edge, ["ip", "address", "replace", f"{site.management_ip}/{self.config.management_network.prefixlen}", "dev", f"{record.site}-mgmt"])
            self._run(edge, ["ip", "link", "set", "dev", f"{record.site}-mgmt", "up"])
            for transport in self.config.transports.values():
                interface = f"{record.site}-{transport.name}"
                self._run(edge, ["ip", "link", "set", "dev", interface, "address", runtime_config.underlay_mac(record.site, transport.name)])
                self._run(edge, ["ip", "address", "replace", runtime_config.underlay_interface_cidr(record.site, transport.name), "dev", interface])
                self._run(edge, ["ip", "link", "set", "dev", interface, "up"])
                self._run(edge, ["ip", "route", "replace", str(transport.network), "via", str(runtime_config.underlay_gateway_ip(transport.name)), "dev", interface, "onlink"])
                self._run(edge, [
                    "ip", "neigh", "replace", str(runtime_config.underlay_gateway_ip(transport.name)),
                    "lladdr", runtime_config.underlay_gateway_mac(transport.name), "nud", "permanent", "dev", interface,
                ])
                self._shape(edge, interface, transport.name)
            self._run(edge, ["ip", "address", "replace", f"{site.lan_gateway}/{site.lan_network.prefixlen}", "dev", f"{record.site}-lan"])
            self._run(edge, ["ip", "link", "set", "dev", f"{record.site}-lan", "up"])
            host_interface = f"{site.host_name}-lan"
            self._run(host, ["ip", "address", "replace", f"{site.host_ip}/{site.lan_network.prefixlen}", "dev", host_interface])
            self._run(host, ["ip", "link", "set", "dev", host_interface, "up"])
            self._run(host, ["ip", "route", "replace", "default", "via", str(site.lan_gateway), "dev", host_interface])
            self._run(edge, ["sysctl", "-w", "net.ipv4.ip_forward=1"])
            dc_interface = f"{self.config.data_center_app_name}-net"
            self._run(self.nodes[self.config.data_center_app_name], ["ip", "route", "replace", str(site.lan_network), "via", str(self.config.data_center_hub_ips[site.preferred_hub]), "dev", dc_interface])

    @staticmethod
    def _docker(container: str, arguments: list[str], *, input_text: str | None = None) -> str:
        result = subprocess.run(["docker", "exec", "-i", container, *arguments], input=input_text, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode:
            detail = _bounded_error(result.stderr or result.stdout)
            raise RuntimeError(f"{container}: lifecycle command failed: {detail}")
        return result.stdout

    def _write_protected(self, container: str, destination: str, contents: str) -> None:
        program = (
            "import os,sys; from pathlib import Path; "
            "path=Path(sys.argv[1]); path.parent.mkdir(parents=True,exist_ok=True); "
            "fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600); "
            "os.write(fd,sys.stdin.buffer.read()); os.close(fd); os.chmod(path,0o600)"
        )
        self._docker(container, ["python3", "-c", program, destination], input_text=contents)

    @staticmethod
    def _result(output: str, site: str) -> dict[str, Any]:
        try:
            value = json.loads(output)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"{site}: edge lifecycle returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise RuntimeError(f"{site}: edge lifecycle returned invalid result")
        return {key: str(value[key]) for key in ("site", "state", "registration", "route_version", "serial") if key in value}

    def bootstrap_site(self, record: InventorySite, bootstrap: dict[str, str]) -> dict[str, Any]:
        """Run the existing Edge-owned enrollment flow inside one managed Edge.

        The claim is installed using stdin into a mode-0600 temporary file and
        removed regardless of the outcome.  The Management service never sees
        or generates private identity/WireGuard material.
        """
        with self._lock:
            if record.site not in self._managed:
                raise ValueError("dynamic site is not managed by this live topology")
            container = f"mn.{record.site}"
            self._write_protected(container, "/var/lib/sdwan/bootstrap-ca.pem", bootstrap["bootstrap_ca_pem"])
            self._write_protected(container, "/run/sdwan/claim.json", json.dumps({"claim_id": bootstrap["claim_id"], "claim_secret": bootstrap["claim_secret"]}, separators=(",", ":")))
            try:
                output = self._docker(container, [
                    "python3", "-m", "sdwan.edge_bootstrap", "enroll",
                    "--device-id", record.device_id, "--claim-file", "/run/sdwan/claim.json",
                    "--ztp-url", bootstrap["ztp_url"], "--ztp-connect-host", bootstrap["management_host"],
                    "--policy-url", bootstrap["policy_url"], "--policy-connect-host", bootstrap["management_host"],
                ])
            finally:
                self._docker(container, ["python3", "-c", "from pathlib import Path; Path('/run/sdwan/claim.json').unlink(missing_ok=True)"])
            return self._result(output, record.site)

    def reconcile_site(self, target: str, bootstrap: dict[str, str]) -> dict[str, Any]:
        """Run existing desired-state reconciliation inside a managed Edge/Hub."""
        with self._lock:
            if target not in self.nodes:
                raise ValueError("site is not present in this live topology")
            container = f"mn.{target}"
            self._write_protected(container, "/var/lib/sdwan/bootstrap-ca.pem", bootstrap["bootstrap_ca_pem"])
            output = self._docker(container, [
                "python3", "-m", "sdwan.edge_bootstrap", "reconcile",
                "--policy-url", bootstrap["policy_url"], "--policy-connect-host", bootstrap["management_host"],
            ])
            return self._result(output, target)

    def delete_site(self, record: InventorySite) -> None:
        with self._lock:
            names = self._managed.get(record.site)
            if names is None:
                raise ValueError("dynamic site is not managed by this live topology")
            self._remove_managed_nodes(names)
            self._managed.pop(record.site, None)
