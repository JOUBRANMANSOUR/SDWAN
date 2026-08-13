"""JSON-RPC subset exposing only the shared read-only management service."""
from __future__ import annotations
from fastapi import Depends, HTTPException
from pydantic import BaseModel
from ..management.auth import Principal
class MCPRequest(BaseModel):
    method: str
    params: dict = {}
    id: object = None
def install_mcp(app, service, authenticate):
    @app.post("/mcp")
    def mcp(request: MCPRequest, user: Principal = Depends(authenticate)):
        tools={"system_health":service.health,"topology_get":service.topology_view,"sites_list":service.sites,"route_ownership_list":service.ownership,"ztp_devices_list":service.ztp_devices,"events_list":service.events,"dashboard_get":service.dashboard,"topology_nodes_list":service.topology_nodes,"topology_links_list":service.topology_links,"desired_state_summary":service.desired_summary,"policy_versions_list":service.policy_versions}
        if request.method == "initialize": return {"jsonrpc":"2.0","id":request.id,"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"sdwan-v5","version":"1.0"},"capabilities":{"tools":{}}}}
        if request.method == "tools/list": return {"jsonrpc":"2.0","id":request.id,"result":{"tools":[{"name":name,"description":"Read-only SD-WAN management query","inputSchema":{"type":"object","properties":{}}} for name in sorted(tools)]}}
        if request.method == "tools/call":
            action=tools.get(str(request.params.get("name","")))
            if action is None: raise HTTPException(404,"unknown read-only tool")
            return {"jsonrpc":"2.0","id":request.id,"result":{"content":[{"type":"text","text":str(action())}]}}
        raise HTTPException(400,"unsupported MCP method")
