"""Constrained Docker namespace inspection; never executes client-provided commands."""
from __future__ import annotations
import json, re, subprocess
from typing import Any
from ..common.model import TopologyConfig

class RuntimeAdapter:
    def __init__(self, topology: TopologyConfig): self.topology = topology
    def _runtime_node(self, node: str) -> str:
        """Resolve a logical branch site to its immutable Containernet node."""
        try:
            return self.topology.edge_node(node)
        except KeyError:
            return node

    def _allowed(self, node: str) -> bool:
        allowed = set(self.topology.site_names)
        allowed.update(self.topology.hubs)
        allowed.update({self.topology.data_center_app_name, self.topology.saas_app_name})
        if self.topology.cloud_vpc.enabled:
            allowed.update(self.topology.cloud_vpc.active_gateways)
            allowed.add(self.topology.cloud_vpc.app_name)
        return node in allowed

    def _run(self, node: str, command: list[str]) -> dict[str, Any]:
        if not self._allowed(node):
            return {"availability":"UNAVAILABLE","reason":"unknown or disabled topology node"}
        runtime_node = self._runtime_node(node)
        try:
            result=subprocess.run(
                ["docker","exec","mn."+runtime_node,*command],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=False,timeout=5,
            )
        except FileNotFoundError:
            return {"availability":"UNAVAILABLE","reason":"docker executable is not installed"}
        except subprocess.TimeoutExpired:
            return {"availability":"UNAVAILABLE","reason":"runtime inspection timed out"}
        except OSError as exc:
            return {"availability":"UNAVAILABLE","reason":str(exc)[:240]}
        if result.returncode:
            return {"availability":"UNAVAILABLE","reason":result.stderr.strip()[:240] or "runtime inspection failed"}
        return {"availability":"AVAILABLE","value":result.stdout}
    def json(self,node: str, command: list[str]) -> dict[str, Any]:
        result=self._run(node,command)
        if result["availability"] != "AVAILABLE": return result
        try: return {"availability":"AVAILABLE","value":json.loads(result["value"])}
        except ValueError: return {"availability":"UNAVAILABLE","reason":"runtime returned malformed JSON"}
    def tunnels(self,node: str): return self._run(node,["wg","show"])

    @staticmethod
    def parse_wireguard_show(output: str) -> list[dict[str, Any]]:
        """Convert human-oriented wg show output to structured API JSON.

        Private keys are deliberately ignored. A WireGuard interface can have
        more than one peer, so peers remain nested under their interface.
        """
        interfaces: list[dict[str, Any]] = []
        interface: dict[str, Any] | None = None
        peer: dict[str, Any] | None = None

        def finish_peer() -> None:
            nonlocal peer
            if peer is not None and interface is not None:
                interface["peers"].append(peer)
            peer = None

        def finish_interface() -> None:
            nonlocal interface
            finish_peer()
            if interface is not None:
                interfaces.append(interface)
            interface = None

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("interface: "):
                finish_interface()
                interface = {"name": line.split(": ", 1)[1], "peers": []}
                continue
            if interface is None:
                continue
            if line.startswith("peer: "):
                finish_peer()
                peer = {"public_key": line.split(": ", 1)[1]}
                continue
            if peer is None:
                if line.startswith("public key: "):
                    interface["public_key"] = line.split(": ", 1)[1]
                elif line.startswith("listening port: "):
                    value = line.split(": ", 1)[1]
                    try:
                        interface["listening_port"] = int(value)
                    except ValueError:
                        interface["listening_port"] = value
                continue
            if line.startswith("endpoint: "):
                peer["endpoint"] = line.split(": ", 1)[1]
            elif line.startswith("allowed ips: "):
                value = line.split(": ", 1)[1]
                peer["allowed_ips"] = [item.strip() for item in value.split(",") if item.strip()]
            elif line.startswith("latest handshake: "):
                peer["latest_handshake"] = line.split(": ", 1)[1]
            elif line.startswith("persistent keepalive: "):
                peer["persistent_keepalive"] = line.split(": ", 1)[1]
            elif line.startswith("transfer: "):
                value = line.split(": ", 1)[1]
                match = re.match(r"^(.*) received, (.*) sent$", value)
                peer["transfer"] = ({"received": match.group(1), "sent": match.group(2)} if match else {"reported": value})
        finish_interface()
        return interfaces

    def tunnel_status(self, node: str) -> dict[str, Any]:
        """Return structured, read-only WireGuard status for one topology node."""
        result = self.tunnels(node)
        runtime_node = self._runtime_node(node)
        if result.get("availability") != "AVAILABLE":
            return {
                "availability": result.get("availability", "UNAVAILABLE"),
                "site": node if node in self.topology.sites else None,
                "edge_node": runtime_node,
                "interfaces": [],
                "reason": result.get("reason", "runtime inspection failed"),
            }
        return {
            "availability": "AVAILABLE",
                "site": node if node in self.topology.sites else None,
                "edge_node": runtime_node,
            "interfaces": self.parse_wireguard_show(str(result.get("value", ""))),
        }
    def routes(self,node: str): return self.json(node,["ip","-j","route","show","table","all"])
    def rules(self,node: str): return self.json(node,["ip","-j","rule","show"])
    def route_lookup(self, node: str, destination: str, source: str | None = None, fwmark: int | None = None) -> dict[str, Any]:
        command = ["ip", "-j", "route", "get", destination]
        if source is not None:
            command.extend(["from", source])
        if fwmark is not None:
            command.extend(["mark", str(fwmark)])
        return self.json(node, command)
    def connection_marks(self, node: str, source: str, destination: str) -> dict[str, Any]:
        """Return marks for matching existing conntrack flows; never alters state."""
        result=self._run(node,["conntrack","-L","-o","extended"])
        if result["availability"] != "AVAILABLE": return result
        matches=[]
        for line in str(result.get("value", "")).splitlines():
            if "src=" + source not in line or "dst=" + destination not in line: continue
            match=re.search(r"\bmark=(0x[0-9A-Fa-f]+|[0-9]+)", line)
            if match is None: continue
            try: mark=int(match.group(1), 0)
            except ValueError: continue
            matches.append({"mark":mark,"raw_mark":match.group(1)})
        return {"availability":"AVAILABLE","value":matches[:32]}
    def links(self,node: str): return self.json(node,["ip","-j","link","show"])
    def failover(self,node: str): return self._run(node,["cat","/var/lib/sdwan/state/failover-status.json"])
    def classifier(self,node: str): return self._run(node,["tail","-n","50","/var/lib/sdwan/state/classifier-events.jsonl"])
    def hub_flow_events(self, hub: str) -> dict[str, Any]:
        if hub not in self.topology.hubs:
            return {"availability":"UNAVAILABLE","reason":"unknown hub"}
        result = self._run(hub, ["tail", "-n", "500", "/var/lib/sdwan/state/hub-flow-events.jsonl"])
        if result["availability"] != "AVAILABLE":
            return result
        events = []
        for line in str(result["value"]).splitlines():
            try: events.append(json.loads(line))
            except ValueError: continue
        return {"availability":"AVAILABLE","value":events}
    def state(self, node: str, name: str) -> dict[str, Any]:
        allowed = {"path-metrics.json", "path-decisions.json", "path-events.json"}
        if name not in allowed:
            return {"availability":"UNAVAILABLE","reason":"state file is not approved"}
        return self.json(node, ["cat", "/var/lib/sdwan/state/" + name])
    def workload_health(self, node: str) -> dict[str, Any]:
        if node == self.topology.data_center_app_name:
            return self._run(node, ["curl","--insecure","--fail","--silent","https://10.100.0.10:8443/healthz"])
        if node == self.topology.saas_app_name:
            return self._run(node, ["curl","--insecure","--fail","--silent","https://198.18.0.10/healthz"])
        return {"availability":"UNAVAILABLE","reason":"unknown workload"}
