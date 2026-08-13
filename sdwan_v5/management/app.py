"""FastAPI read-only management REST API and minimal SSE/UI surface."""
from __future__ import annotations
import asyncio, json, uuid
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
from .auth import Principal, allowed, issue, parse_users, scopes_for, verify
from .config import ManagementConfig
from .service import ManagementService
from ..sdwan_mcp.app import install_mcp

class Login(BaseModel): username: str; password: str
class ChatRequest(BaseModel): prompt: str
def create_app(config: ManagementConfig | None = None) -> FastAPI:
    config=config or ManagementConfig.from_env(); service=ManagementService(config); app=FastAPI(title="SD-WAN v5 Management", version="1.0.0")
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
    @app.post("/api/v1/auth/login")
    def login(value: Login):
        record=parse_users(config.users).get(value.username)
        if record is None or record[0] != value.password: raise HTTPException(401,"invalid credentials")
        user=Principal(value.username,record[1],scopes_for(record[1])); service.audit.add(user.subject,"LOGIN","session","ok")
        return {"access_token":issue(config.signing_secret,user),"token_type":"bearer","role":user.role,"scopes":user.scopes}
    @app.get("/api/v1/system/version")
    def version(user: Principal = Depends(require("read:health"))): return {"api_version":"v1","service_version":"1.0.0","mode":"read-only"}
    @app.get("/api/v1/system/health")
    def health(user: Principal = Depends(require("read:health"))): return service.health()
    @app.get("/api/v1/system/config")
    def system_config(user: Principal = Depends(require("read:health"))): return {"topology_config":str(config.topology),"policy_db_configured":str(config.policy_db),"ztp_db_configured":str(config.ztp_db),"agent_gateway":"configured but fail-closed" if config.agent_command else "disabled"}
    @app.get("/api/v1/system/capabilities")
    def capabilities(user: Principal = Depends(require("read:health"))): return {"read_only":True,"rest":True,"mcp":"/mcp","agent_gateway":bool(config.agent_command),"unsupported":["policy writes","ztp writes","routing writes","docker exec from browser"]}
    @app.get("/api/v1/dashboard")
    def dashboard(user: Principal = Depends(require("read:operations"))): return service.dashboard()
    @app.get("/api/v1/topology")
    def topology(user: Principal = Depends(require("read:topology"))): return service.topology_view()
    @app.get("/api/v1/topology/nodes")
    def topology_nodes(user: Principal = Depends(require("read:topology"))): return service.topology_nodes()
    @app.get("/api/v1/topology/links")
    def topology_links(user: Principal = Depends(require("read:topology"))): return service.topology_links()
    @app.get("/api/v1/sites")
    def sites(user: Principal = Depends(require("read:operations"))): return service.sites()
    @app.get("/api/v1/sites/{site}/desired")
    def desired(site: str,user: Principal = Depends(require("read:operations"))): return service.desired(site)
    @app.get("/api/v1/sites/{site}/runtime")
    def runtime(site: str,user: Principal = Depends(require("read:tunnels"))): return service.runtime_view(site)
    @app.get("/api/v1/sites/{site}/tunnels")
    def tunnels(site: str,user: Principal = Depends(require("read:tunnels"))): return service.runtime_view(site).get("tunnels")
    @app.get("/api/v1/sites/{site}/routes")
    def routes(site: str,user: Principal = Depends(require("read:routes"))): return service.runtime_view(site).get("routes")
    @app.get("/api/v1/sites/{site}/rules")
    def rules(site: str,user: Principal = Depends(require("read:routes"))): return service.runtime_view(site).get("rules")
    @app.get("/api/v1/hubs/{hub}")
    def hub(hub: str,user: Principal = Depends(require("read:operations"))): return service.hub_view(hub)
    @app.get("/api/v1/data-center")
    def data_center(user: Principal = Depends(require("read:topology"))): return service.network_view("data-center")
    @app.get("/api/v1/saas")
    def saas(user: Principal = Depends(require("read:topology"))): return service.network_view("saas")
    @app.get("/api/v1/cloud-vpc")
    def cloud(user: Principal = Depends(require("read:topology"))): return service.network_view("cloud-vpc")
    @app.get("/api/v1/routes/ownership")
    def ownership(user: Principal = Depends(require("read:routes"))): return service.ownership()
    @app.get("/api/v1/policy/versions")
    def policy_versions(user: Principal = Depends(require("read:operations"))): return service.policy_versions()
    @app.get("/api/v1/policy/destination")
    def destination_policy(user: Principal = Depends(require("read:operations"))): return service.destination_policy()
    @app.get("/api/v1/desired-state/summary")
    def desired_summary(user: Principal = Depends(require("read:operations"))): return service.desired_summary()
    @app.get("/api/v1/ztp/devices")
    def devices(user: Principal = Depends(require("read:operations"))): return service.ztp_devices()
    @app.get("/api/v1/events")
    def events(user: Principal = Depends(require("read:events"))): return service.events()
    @app.get("/api/v1/audit")
    def audit(user: Principal = Depends(require("read:audit"))): return service.audit.list()
    @app.post("/api/v1/chat/sessions")
    def create_chat(user: Principal = Depends(require("chat:use"))):
        return {"session_id":service.audit.create_session(user.subject)}
    @app.get("/api/v1/chat/sessions/{session_id}")
    def chat_messages(session_id: int,user: Principal = Depends(require("chat:use"))): return service.audit.messages(session_id)
    @app.post("/api/v1/chat/sessions/{session_id}/messages")
    def chat(session_id: int,value: ChatRequest,user: Principal = Depends(require("chat:use"))): return service.chat(user.subject,session_id,value.prompt)
    @app.get("/api/v1/events/stream")
    async def stream(user: Principal = Depends(require("read:events"))):
        async def generate():
            previous = None
            for _ in range(30):
                encoded = json.dumps(service.combined_events())
                yield ("event: snapshot\ndata: " + encoded + "\n\n") if encoded != previous else ": keepalive\n\n"
                previous = encoded
                await asyncio.sleep(2)
        return StreamingResponse(generate(),media_type="text/event-stream")
    @app.get("/", response_class=HTMLResponse)
    def ui(): return """<!doctype html><html><head><title>SD-WAN v5 Management</title><style>body{font-family:system-ui;background:#f3f6fa;color:#172033;max-width:1180px;margin:2rem auto;padding:0 1rem}.panel{background:white;border-radius:12px;padding:1rem;margin:1rem 0;box-shadow:0 1px 5px #ccd}input,button{padding:.6rem;margin:.2rem;border:1px solid #aab;border-radius:6px}button{background:#155eef;color:white}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem}.card{background:#eef4ff;padding:1rem;border-radius:8px}pre{padding:1rem;background:#101828;color:#d0f8d0;overflow:auto;max-height:480px}.warn{color:#9a4d00}</style></head><body><h1>SD-WAN v5 Management</h1><p class=warn>Read-only laboratory observability. No topology, Policy, ZTP, route, tunnel, Docker, or shell control is exposed.</p><div class=panel><input id=u placeholder=username><input id=p type=password placeholder=password><button onclick=login()>Login</button><button onclick=load()>Refresh dashboard</button></div><div id=cards class=grid></div><div class=panel><h2>Read-only assisted diagnosis</h2><input id=q placeholder='Ask for a status summary' size=42><button onclick=chat()>Ask</button><pre id=o>Authenticate, then refresh dashboard.</pre></div><script>let t='',sid=0;const o=document.getElementById('o');const hdr=()=>({Authorization:'Bearer '+t,'Content-Type':'application/json'});function card(k,v){return '<div class=card><b>'+k+'</b><br>'+v+'</div>'}async function login(){let r=await fetch('/api/v1/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u.value,password:p.value})});let x=await r.json();t=x.access_token||'';o.textContent=t?'Authenticated as '+x.role:JSON.stringify(x)}async function load(){let r=await fetch('/api/v1/dashboard',{headers:hdr()});let x=await r.json();if(!r.ok){o.textContent=JSON.stringify(x,null,2);return}cards.innerHTML=card('Sites',x.sites.length)+card('Route ownership',x.ownership.length)+card('Devices',x.devices.length)+card('Policy DB',x.health.sources.policy_db)+card('ZTP DB',x.health.sources.ztp_db);o.textContent=JSON.stringify(x,null,2)}async function chat(){if(!sid){let r=await fetch('/api/v1/chat/sessions',{method:'POST',headers:hdr()});sid=(await r.json()).session_id}let r=await fetch('/api/v1/chat/sessions/'+sid+'/messages',{method:'POST',headers:hdr(),body:JSON.stringify({prompt:q.value})});o.textContent=JSON.stringify(await r.json(),null,2)}</script></body></html>"""
    install_mcp(app, service, principal)
    return app
