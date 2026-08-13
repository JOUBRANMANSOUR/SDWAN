"""Constrained Docker namespace inspection; never executes client-provided commands."""
from __future__ import annotations
import json, re, subprocess
from typing import Any
from ..common.model import TopologyConfig

class RuntimeAdapter:
    def __init__(self, topology: TopologyConfig): self.topology = topology
    def _allowed(self, node: str) -> bool:
        return node in self.topology.site_names or node in set(self.topology.hubs) or node in {self.topology.data_center_app_name, self.topology.saas_app_name, *self.topology.cloud_vpc.active_gateways, self.topology.cloud_vpc.app_name}
    def _run(self, node: str, command: list[str]) -> dict[str, Any]:
        if not self._allowed(node): return {"availability":"UNAVAILABLE","reason":"unknown topology node"}
        result=subprocess.run(["docker","exec","mn."+node,*command],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=False,timeout=5)
        if result.returncode: return {"availability":"UNAVAILABLE","reason":result.stderr.strip()[:240] or "runtime inspection failed"}
        return {"availability":"AVAILABLE","value":result.stdout}
    def json(self,node: str, command: list[str]) -> dict[str, Any]:
        result=self._run(node,command)
        if result["availability"] != "AVAILABLE": return result
        try: return {"availability":"AVAILABLE","value":json.loads(result["value"])}
        except ValueError: return {"availability":"UNAVAILABLE","reason":"runtime returned malformed JSON"}
    def tunnels(self,node: str): return self._run(node,["wg","show"])
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
