"""FastAPI read-only management REST API and minimal SSE/UI surface."""
from __future__ import annotations
import asyncio, json, uuid
from typing import Dict, List, Optional
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field
from .auth import Principal, allowed, issue, parse_users, scopes_for, verify
from .config import ManagementConfig
from .service import ManagementService
from .agent import OllamaClaudeRunner
from .evidence import EvidenceValidator, render_verified_answer
from .evidence_planner import prepare_route_evidence
from .admin_api import install_management_write_routes

class Login(BaseModel): username: str; password: str
class ChatRequest(BaseModel):
    prompt: str = ""
    message: str = ""
    context: dict = Field(default_factory=dict)
def create_app(config: ManagementConfig | None = None) -> FastAPI:
    config=config or ManagementConfig.from_env(); service=ManagementService(config); runner=OllamaClaudeRunner(config); validator=EvidenceValidator(); app=FastAPI(title="SD-WAN Management", version="1.0.0")
    event_queues: Dict[int, asyncio.Queue] = {}
    active_chat_tasks: Dict[int, asyncio.Task] = {}
    @app.middleware("http")
    async def audit_request(request: Request, call_next):
        request_id = str(uuid.uuid4())
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        actor = getattr(request.state, "actor", None)
        if actor and request.url.path.startswith("/api/v1/") and request.url.path != "/api/v1/auth/login":
            service.audit.add(actor, "API_READ", request.url.path, str(response.status_code), request_id)
        return response
    bearer = HTTPBearer(auto_error=False)
    def principal(request: Request, credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> Principal:
        if credentials is None:
            raise HTTPException(401, "authentication required")
        try:
            user = verify(config.signing_secret, credentials.credentials)
            request.state.actor = user.subject
            return user
        except Exception: raise HTTPException(401, "authentication required")
    def require(scope: str):
        def check(user: Principal = Depends(principal)) -> Principal:
            if not allowed(user,scope): raise HTTPException(403,"scope denied")
            return user
        return check
    install_management_write_routes(app, service, require)

    @app.post("/api/v1/auth/login")
    def login(value: Login):
        record=parse_users(config.users).get(value.username)
        if record is None or record[0] != value.password: raise HTTPException(401,"invalid credentials")
        user=Principal(value.username,record[1],scopes_for(record[1])); service.audit.add(user.subject,"LOGIN","session","ok")
        return {"access_token":issue(config.signing_secret,user),"token_type":"bearer","role":user.role,"scopes":user.scopes}
    @app.get("/healthz")
    def public_health(): return {"status": "ok"}
    @app.get("/api/v1/system")
    def system(user: Principal = Depends(require("network:read"))):
        return {"api_version": "v1", "service_version": "1.0.0", "operational_mode": "typed-administration-and-observability", "health": service.health(), "capabilities": {"management_lifecycle": True, "underlay_read_only": True, "mcp": "local-stdio"}}
    @app.get("/api/v1/system/version")
    def version(user: Principal = Depends(require("network:read"))): return {"api_version":"v1","service_version":"1.0.0","mode":"read-only"}
    @app.get("/api/v1/system/health")
    def health(user: Principal = Depends(require("network:read"))): return service.health()
    @app.get("/api/v1/system/config")
    def system_config(user: Principal = Depends(require("network:read"))): return {"topology_config":str(config.topology),"policy_db_configured":str(config.policy_db),"ztp_db_configured":str(config.ztp_db),"agent_gateway":"configured but fail-closed" if config.agent_command else "disabled"}
    @app.get("/api/v1/system/capabilities")
    def capabilities(user: Principal = Depends(require("network:read"))): return {"read_only":True,"rest":"available","mcp":"available: local stdio only; no HTTP endpoint","agent_gateway":"partially_available","unsupported":["policy writes","ztp writes","routing writes","docker exec from browser"]}
    @app.get("/api/v1/dashboard")
    @app.get("/api/v1/dashboard/summary")
    def dashboard(user: Principal = Depends(require("network:read"))): return service.dashboard()
    @app.get("/api/v1/topology")
    def topology(user: Principal = Depends(require("network:read"))): return service.topology_resource()
    @app.get("/api/v1/topology/nodes")
    def topology_nodes(user: Principal = Depends(require("network:read"))): return service.topology_nodes()
    @app.get("/api/v1/topology/links")
    def topology_links(user: Principal = Depends(require("network:read"))): return service.topology_links()
    @app.get("/api/v1/underlays")
    def underlays(user: Principal = Depends(require("network:read"))):
        return service.underlays()
    @app.get("/api/v1/underlays/{transport}")
    def underlay(transport: str, user: Principal = Depends(require("network:read"))):
        value = service.underlay(transport)
        if value is None: raise HTTPException(404, "underlay not found")
        return value
    @app.get("/api/v1/underlay")
    @app.get("/api/v1/underlay/state")
    def underlay_state(user: Principal = Depends(require("network:read"))): return service.underlay_state()
    @app.get("/api/v1/paths")
    def paths(user: Principal = Depends(require("network:read"))): return service.paths()
    @app.get("/api/v1/path-metrics")
    def path_metrics(user: Principal = Depends(require("network:read"))): return service.path_metrics()
    @app.get("/api/v1/path-decisions")
    def path_decisions(user: Principal = Depends(require("network:read"))): return service.path_decisions()
    @app.get("/api/v1/path-events")
    def path_events(user: Principal = Depends(require("network:read"))): return service.path_events()
    @app.get("/api/v1/graph/components/{component_id:path}")
    def graph_component(component_id: str, user: Principal = Depends(require("network:read"))):
        value = service.graph_component(component_id)
        if not value["available"]: raise HTTPException(404, value["reason"])
        return value
    @app.get("/api/v1/graph/expand/{component_id:path}")
    def graph_expand(component_id: str, direction: str = "outgoing", depth: int = 1, user: Principal = Depends(require("network:read"))):
        value = service.graph_expand(component_id, direction, depth)
        if not value.get("available"): raise HTTPException(404, value.get("reason", "unknown component"))
        return value
    @app.get("/api/v1/graph/path")
    def graph_path(source_id: str, target_id: str, user: Principal = Depends(require("network:read"))):
        return service.graph_path(source_id, target_id)
    @app.get("/api/v1/graph/impact/{component_id:path}")
    def graph_impact(component_id: str, user: Principal = Depends(require("network:read"))):
        value = service.graph_impact(component_id)
        if not value.get("available"): raise HTTPException(404, value.get("reason", "unknown component"))
        return value
    @app.get("/api/v1/graph/evidence")
    def graph_evidence(component_id: List[str] = [], user: Principal = Depends(require("network:read"))):
        return service.graph_evidence(component_id)
    @app.get("/api/v1/workloads")
    def workloads(user: Principal = Depends(require("network:read"))): return service.workloads()
    @app.get("/api/v1/traffic/flows")
    @app.get("/api/v1/hubs/{hub}/flows")
    def traffic_flows(hub: Optional[str] = None, site: Optional[str] = None, user: Principal = Depends(require("network:read"))):
        return {"items": service.hub_flows(hub=hub, site=site), "scope": "hub-transited private flows only"}

    @app.get("/api/v1/sites")
    def sites(user: Principal = Depends(require("network:read"))): return service.sites()
    @app.get("/api/v1/sites/{site}/desired")
    def desired(site: str,user: Principal = Depends(require("network:read"))): return service.desired(site)
    @app.get("/api/v1/sites/{site}")
    def site(site: str,user: Principal = Depends(require("network:read"))):
        rows=[row for row in service.sites() if row["site"] == site]
        if not rows: raise HTTPException(404,"site not found")
        return {"configured":rows[0],"desired":service.desired(site),"observed":service.runtime_view(site)}
    @app.get("/api/v1/sites/{site}/desired-state")
    def desired_state(site: str,user: Principal = Depends(require("network:read"))): return {"availability":"AVAILABLE","state":service.desired(site)}
    @app.get("/api/v1/sites/{site}/applied-state")
    def applied_state(site: str,user: Principal = Depends(require("network:read"))): return {"availability":"AVAILABLE","state":service.desired(site)}
    @app.get("/api/v1/sites/{site}/actual-state")
    def actual_state(site: str,user: Principal = Depends(require("network:read"))): return service.runtime_view(site)
    @app.get("/api/v1/sites/{site}/events")
    def site_events(site: str,user: Principal = Depends(require("network:read"))): return [e for e in service.events() if e.get("target") == site]
    @app.get("/api/v1/sites/{site}/runtime")
    def runtime(site: str,user: Principal = Depends(require("network:read"))): return service.runtime_view(site)
    @app.get("/api/v1/sites/{site}/tunnel")
    @app.get("/api/v1/sites/{site}/tunnels")
    def tunnels(site: str,user: Principal = Depends(require("network:read"))): return service.tunnel_status(site)
    @app.get("/api/v1/sites/{site}/routing")
    def routing(site: str, user: Principal = Depends(require("network:read"))):
        return service.routing(site)
    @app.get("/api/v1/sites/{site}/routes")
    def routes(site: str,user: Principal = Depends(require("network:read"))): return service.route_summary(site)
    @app.get("/api/v1/sites/{site}/rules")
    @app.get("/api/v1/sites/{site}/routing-rules")
    def rules(site: str,user: Principal = Depends(require("network:read"))): return service.route_summary(site).get("routing_rules", [])
    @app.get("/api/v1/sites/{site}/routing-tables")
    def routing_tables(site: str,user: Principal = Depends(require("network:read"))): return service.route_summary(site).get("route_groups", [])
    @app.get("/api/v1/sites/{site}/return-affinity")
    def site_affinity(site: str,user: Principal = Depends(require("network:read"))): return {"available":True,"configuration":"connmark-based return-path affinity; live evidence is included in routing rules"}
    @app.get("/api/v1/hubs")
    def hubs(user: Principal = Depends(require("network:read"))): return [service.hub_view(name) for name in service.topology.hubs]
    @app.get("/api/v1/hubs/{hub}/tunnels")
    def hub_tunnels(hub: str,user: Principal = Depends(require("network:read"))): return service.runtime_view(hub).get("tunnels")
    @app.get("/api/v1/hubs/{hub}/routes")
    def hub_routes(hub: str,user: Principal = Depends(require("network:read"))): return service.runtime_view(hub).get("routes")
    @app.get("/api/v1/hubs/{hub}/return-affinity")
    def hub_affinity(hub: str,user: Principal = Depends(require("network:read"))): return {"availability":"PARTIALLY_AVAILABLE","design":"connmark return-affinity; inspect runtime rules endpoint"}
    @app.get("/api/v1/hubs/{hub}")
    def hub(hub: str,user: Principal = Depends(require("network:read"))): return service.hub_view(hub)
    @app.get("/api/v1/cloud-vpc/gateways")
    def cloud_gateways(user: Principal = Depends(require("network:read"))): return [{"name":name,"availability":"CONFIGURED" if service.topology.cloud_vpc.enabled else "DISABLED"} for name in service.topology.cloud_vpc.gateway_names]
    @app.get("/api/v1/cloud-vpc/gateways/{gateway}")
    def cloud_gateway(gateway: str,user: Principal = Depends(require("network:read"))): return {"gateway":gateway,"runtime":service.runtime_view(gateway) if service.topology.cloud_vpc.enabled else {"availability":"DISABLED"}}
    @app.get("/api/v1/cloud-vpc/gateways/{gateway}/routes")
    def cloud_gateway_routes(gateway: str,user: Principal = Depends(require("network:read"))): return {"availability":"DISABLED" if not service.topology.cloud_vpc.enabled else "UNAVAILABLE","reason":"enable cloud topology for live runtime"}
    @app.get("/api/v1/cloud-vpc/gateways/{gateway}/return-affinity")
    def cloud_gateway_affinity(gateway: str,user: Principal = Depends(require("network:read"))): return {"availability":"PARTIALLY_AVAILABLE","design":"gateway connmark and scoped SNAT when Cloud VPC enabled"}
    @app.get("/api/v1/data-center/routes")
    def dc_routes(user: Principal = Depends(require("network:read"))): return {"availability":"UNAVAILABLE","reason":"no Data Center router runtime adapter"}
    @app.get("/api/v1/data-center/return-affinity")
    def dc_affinity(user: Principal = Depends(require("network:read"))): return {"availability":"PARTIALLY_AVAILABLE","design":"hub scoped SNAT plus connmark"}
    @app.get("/api/v1/data-center")
    def data_center(user: Principal = Depends(require("network:read"))): return service.network_view("data-center")
    @app.get("/api/v1/saas/destinations")
    def saas_destinations(user: Principal = Depends(require("network:read"))):
        return [{"name":service.topology.saas_app_name,"ip":str(service.topology.saas_ip),"type":"public-collaboration-service","egress":"DIRECT_INTERNET","candidate_transports":["bb","lte"]}]
    @app.get("/api/v1/saas/destinations/{destination}")
    def saas_destination(destination: str,user: Principal = Depends(require("network:read"))):
        if destination not in {service.topology.saas_app_name, "public_saas", str(service.topology.saas_ip)}:
            raise HTTPException(404,"SaaS destination not found")
        return {"availability":"CONFIGURED","destination":service.topology.saas_app_name,"ip":str(service.topology.saas_ip),"egress":"DIRECT_INTERNET","candidate_transports":["bb","lte"]}
    @app.get("/api/v1/saas/destinations/{destination}/reachability")
    def saas_reachability(destination: str,user: Principal = Depends(require("network:read"))):
        if destination not in {service.topology.saas_app_name, "public_saas", str(service.topology.saas_ip)}:
            raise HTTPException(404,"SaaS destination not found")
        return service.runtime.workload_health(service.topology.saas_app_name)
    @app.get("/api/v1/saas")
    def saas(user: Principal = Depends(require("network:read"))): return service.network_view("saas")
    @app.get("/api/v1/cloud-vpc")
    def cloud(user: Principal = Depends(require("network:read"))): return service.network_view("cloud-vpc")
    @app.get("/api/v1/routes/ownership")
    def ownership(user: Principal = Depends(require("network:read"))): return service.ownership()
    @app.get("/api/v1/policy")
    def policy(user: Principal = Depends(require("policy:read"))): return service.policy_view()
    @app.get("/api/v1/policy/versions")
    def policy_versions(user: Principal = Depends(require("network:read"))): return service.policy_versions()
    @app.get("/api/v1/policy/destination")
    def destination_policy(user: Principal = Depends(require("network:read"))): return service.destination_policy()
    @app.get("/api/v1/desired-state/summary")
    def desired_summary(user: Principal = Depends(require("network:read"))): return service.desired_summary()
    @app.get("/api/v1/ztp/devices")
    def devices(user: Principal = Depends(require("ztp:read"))): return service.ztp_devices()
    @app.get("/api/v1/ztp/devices/{device_id}")
    def device(device_id: str, user: Principal = Depends(require("ztp:read"))):
        value = service.ztp_device(device_id)
        if value is None: raise HTTPException(404, "device not found")
        return value
    @app.get("/api/v1/events")
    def events(user: Principal = Depends(require("network:read"))): return service.events()
    @app.get("/api/v1/audit")
    @app.get("/api/v1/audit/events")
    def audit(user: Principal = Depends(require("audit:read"))): return service.audit.list()
    @app.post("/api/v1/chat/sessions")
    def create_chat(user: Principal = Depends(require("network:read"))):
        return {"session_id":service.audit.create_session(user.subject),"status":"created"}
    @app.get("/api/v1/chat/sessions/{session_id}")
    def chat_messages(session_id: int,user: Principal = Depends(require("network:read"))):
        if not service.audit.owns_session(session_id,user.subject): raise HTTPException(404,"session not found")
        return service.audit.messages(session_id)
    def event_queue(session_id: int) -> asyncio.Queue:
        if session_id not in event_queues: event_queues[session_id] = asyncio.Queue(maxsize=512)
        return event_queues[session_id]
    @app.post("/api/v1/chat/sessions/{session_id}/messages", status_code=202)
    async def chat(session_id: int,value: ChatRequest,user: Principal = Depends(require("network:read"))):
        if not service.audit.owns_session(session_id,user.subject): raise HTTPException(404,"session not found")
        if session_id in active_chat_tasks and not active_chat_tasks[session_id].done(): raise HTTPException(409,"a message is already running for this session")
        prompt=(value.message or value.prompt).strip()
        if not prompt or len(prompt)>4000: raise HTTPException(422,"message must be 1..4000 characters")
        queue = event_queue(session_id)
        message_id = service.audit.add_message(session_id,user.subject,prompt)
        bundle_id = uuid.uuid4().hex
        service.audit.create_evidence_bundle(bundle_id, session_id, message_id, user.subject)
        async def execute():
            final_text=""
            prepared = prepare_route_evidence(service, prompt)
            if prepared is not None:
                service.audit.append_evidence_tool(bundle_id, prepared.tool, prepared.arguments, prepared.result)
                await queue.put({"type":"evidence_prefetched","data":{"tool":prepared.tool,"arguments":prepared.arguments}})
            async def validate_final(text: str):
                await queue.put({"type":"answer_validation_started","data":{"bundle_id":bundle_id}})
                bundle=service.audit.evidence_bundle(bundle_id,session_id,user.subject)
                try:
                    candidate=text.strip()
                    if candidate.startswith("```"):
                        candidate=candidate.split("\n",1)[-1].rsplit("```",1)[0].strip()
                    parsed=json.loads(candidate)
                except (TypeError, ValueError):
                    parsed={"answer_type":"operational","summary":"","claims":[],"unknowns":[],"limitations":[]}
                outcome=validator.validate(parsed,bundle or {"payload":{}})
                if not outcome.get("valid") and prepared is not None:
                    outcome=validator.validate(prepared.fallback_answer,bundle or {"payload":{}})
                service.audit.finalize_evidence_bundle(bundle_id,session_id,user.subject,outcome)
                if outcome.get("valid") and bundle:
                    rendered=render_verified_answer(outcome,bundle)
                    service.audit.add_message(session_id,"management",rendered)
                    await queue.put({"type":"answer_validation_completed","data":{"bundle_id":bundle_id,"validated_claims":outcome.get("validated_claims",[])}})
                    await queue.put({"type":"verified_answer","data":{"bundle_id":bundle_id,"markdown":rendered}})
                    service.audit.add(user.subject,"CHAT",str(session_id),"verified","evidence-bound response")
                else:
                    fallback="The current evidence is insufficient to provide a verified operational answer."
                    service.audit.add_message(session_id,"management",fallback)
                    await queue.put({"type":"answer_validation_failed","data":{"bundle_id":bundle_id,"errors":outcome.get("errors",[])}})
                    await queue.put({"type":"verified_answer","data":{"bundle_id":bundle_id,"markdown":fallback}})
                    service.audit.add(user.subject,"CHAT",str(session_id),"unavailable","evidence validation failed")
            await queue.put({"type":"session_started","data":{"session_id":session_id,"message_id":message_id}})
            await queue.put({"type":"evidence_bundle_created","data":{"bundle_id":bundle_id,"message_id":message_id}})
            if prepared is not None:
                await queue.put({"type":"server_evidence_answering","data":{"tool":prepared.tool}})
                await validate_final(json.dumps(prepared.fallback_answer))
                await queue.put({"type":"stream_closed","data":{}})
                return
            await queue.put({"type":"agent_starting","data":{}})
            try:
                # A fresh stdio MCP session can occasionally finish after
                # capability discovery without emitting a terminal result.
                # Retry once before finalizing an evidence-unavailable answer.
                for attempt in range(2):
                    final_text=""
                    async for event in runner.run(prompt,str(session_id),user,str(message_id),bundle_id):
                        await queue.put({"type":event.type,"data":event.data})
                        if event.type=="agent_final":
                            final_text=str(event.data.get("text", ""))
                    if final_text:
                        break
                    if attempt == 0:
                        await queue.put({"type":"agent_retrying","data":{"reason":"agent completed without a final result"}})
                await validate_final(final_text)
            except Exception:
                await queue.put({"type":"agent_error","data":{"reason":"agent gateway failed"}})
            finally:
                await queue.put({"type":"stream_closed","data":{}})
        active_chat_tasks[session_id]=asyncio.create_task(execute())
        return {"session_id":session_id,"message_id":message_id,"bundle_id":bundle_id,"accepted":True,"events_url":"/api/v1/chat/sessions/%s/events" % session_id}
    @app.get("/api/v1/chat/sessions/{session_id}/events")
    async def chat_events(session_id: int,user: Principal = Depends(require("network:read"))):
        if not service.audit.owns_session(session_id,user.subject): raise HTTPException(404,"session not found")
        queue=event_queue(session_id)
        async def generate():
            while True:
                try: item=await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield "event: heartbeat\ndata: {}\n\n"; continue
                if item["type"] == "stream_closed": break
                yield "event: %s\ndata: %s\n\n" % (item["type"], json.dumps(item["data"]))
        return StreamingResponse(generate(),media_type="text/event-stream",headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})
    @app.delete("/api/v1/chat/sessions/{session_id}")
    def delete_chat(session_id: int,user: Principal = Depends(require("network:read"))):
        if not service.audit.delete_session(session_id,user.subject): raise HTTPException(404,"session not found")
        return {"deleted":True}
    @app.get("/api/v1/events/stream")
    async def stream(user: Principal = Depends(require("network:read"))):
        async def generate():
            previous = None
            for _ in range(30):
                encoded = json.dumps(service.combined_events())
                yield ("event: snapshot\ndata: " + encoded + "\n\n") if encoded != previous else ": keepalive\n\n"
                previous = encoded
                await asyncio.sleep(2)
        return StreamingResponse(generate(),media_type="text/event-stream")
    @app.get("/", response_class=HTMLResponse)
    def ui(): return """<!doctype html><html><head><title>SD-WAN v5 Management</title><style>body{font-family:system-ui;background:#f3f6fa;color:#172033;max-width:1180px;margin:2rem auto;padding:0 1rem}.panel{background:white;border-radius:12px;padding:1rem;margin:1rem 0;box-shadow:0 1px 5px #ccd}input,button{padding:.6rem;margin:.2rem;border:1px solid #aab;border-radius:6px}button{background:#155eef;color:white}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem}.card{background:#eef4ff;padding:1rem;border-radius:8px}pre{padding:1rem;background:#101828;color:#d0f8d0;overflow:auto;max-height:480px}.warn{color:#9a4d00}</style></head><body><h1>SD-WAN v5 Management</h1><p class=warn>Read-only laboratory observability. No topology, Policy, ZTP, route, tunnel, Docker, or shell control is exposed.</p><div class=panel><input id=u placeholder=username><input id=p type=password placeholder=password><button onclick=login()>Login</button><button onclick=load()>Refresh dashboard</button></div><div id=cards class=grid></div><div class=panel><h2>Read-only assisted diagnosis</h2><input id=q placeholder='Ask for a status summary' size=42><button onclick=chat()>Ask</button><h3>Verified answer</h3><pre id=o>Authenticate, then refresh dashboard.</pre><h3>Agent activity</h3><pre id=a></pre></div><script>let t='',sid=0;const o=document.getElementById('o'),a=document.getElementById('a'),u=document.getElementById('u'),p=document.getElementById('p'),cards=document.getElementById('cards'),q=document.getElementById('q');const hdr=()=>({Authorization:'Bearer '+t,'Content-Type':'application/json'});function card(k,v){return '<div class=card><b>'+k+'</b><br>'+v+'</div>'}async function login(){let r=await fetch('/api/v1/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u.value,password:p.value})});let x=await r.json();t=x.access_token||'';if(!t){o.textContent='Login failed: '+(x.detail||'invalid credentials');return}o.textContent='Authenticated as '+x.role;await load()}async function load(){let r=await fetch('/api/v1/dashboard',{headers:hdr()});let x=await r.json();if(!r.ok){o.textContent='Dashboard error: '+(x.detail||r.status);return}cards.innerHTML=card('Sites',x.sites.length)+card('Route ownership',x.ownership.length)+card('Devices',x.devices.length)+card('Policy DB',x.health.sources.policy_db)+card('ZTP DB',x.health.sources.ztp_db);o.textContent='Dashboard loaded. Ask a read-only SD-WAN question below.'}async function consumeEvents(){let r=await fetch('/api/v1/chat/sessions/'+sid+'/events',{headers:hdr()});if(!r.ok){o.textContent='Event stream error: '+r.status;return}let reader=r.body.getReader(),decoder=new TextDecoder(),buffer='';while(true){let part=await reader.read();if(part.done)break;buffer+=decoder.decode(part.value,{stream:true});let blocks=buffer.split('\\n\\n');buffer=blocks.pop();for(let block of blocks){let name='',data='';for(let line of block.split('\\n')){if(line.startsWith('event:'))name=line.slice(6).trim();if(line.startsWith('data:'))data=line.slice(5).trim()}if(!data)continue;let value=JSON.parse(data);if(name==='assistant_delta')a.textContent+=value.text;if(name==='tool_call_started')a.textContent+='\\n[Requested '+value.tool+']\\n';if(name==='tool_call_completed')a.textContent+='[Tool call completed]\\n';if(name==='answer_validation_started')a.textContent+='\\nValidating MCP evidence...\\n';if(name==='answer_validation_completed')a.textContent+='\\nEvidence validated.\\n';if(name==='answer_validation_failed')a.textContent+='\\nEvidence validation failed.\\n';if(name==='verified_answer')o.textContent=value.markdown;if(name==='agent_error')a.textContent+='\\nError: '+value.reason}}}async function chat(){if(!sid){let r=await fetch('/api/v1/chat/sessions',{method:'POST',headers:hdr()});sid=(await r.json()).session_id}o.textContent='Waiting for verified evidence...';a.textContent='';let events=consumeEvents();let r=await fetch('/api/v1/chat/sessions/'+sid+'/messages',{method:'POST',headers:hdr(),body:JSON.stringify({message:q.value})});if(!r.ok)o.textContent=JSON.stringify(await r.json(),null,2);await events}</script></body></html>"""
    return app
