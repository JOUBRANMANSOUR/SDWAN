"""Safe Ollama -> Claude Code subprocess runner for the read-only web agent."""
from __future__ import annotations
import asyncio, json, uuid
from dataclasses import dataclass
from typing import AsyncIterator, Dict, List
from .auth import Principal, issue_agent_context
from .config import ManagementConfig
@dataclass(frozen=True)
class AgentEvent:
    type: str
    data: Dict[str, object]
def command_for(config: ManagementConfig, prompt: str, session_id: str, resume: bool = False) -> List[str]:
    session_option = ["--resume", session_id] if resume else ["--session-id", session_id]
    return [config.ollama_executable, "launch", "claude", "--model", config.ollama_model, "--yes", "--", "-p", prompt, "--output-format", "stream-json", "--verbose", "--include-partial-messages", "--mcp-config", str(config.mcp_config), "--strict-mcp-config", "--settings", str(config.claude_settings)] + session_option
def restricted_environment(config: ManagementConfig, context_token: str, session_id: str, message_id: str, bundle_id: str) -> Dict[str, str]:
    return {"HOME": config.claude_home, "PATH": config.agent_path, "SDWAN_PROJECT_ROOT": str(config.project_root), "PYTHONPATH": str(config.project_root.parent), "SDWAN_AGENT_CONTEXT_TOKEN": context_token, "SDWAN_CHAT_SESSION_ID": session_id, "SDWAN_CHAT_MESSAGE_ID": message_id, "SDWAN_EVIDENCE_BUNDLE_ID": bundle_id, "SDWAN_MANAGEMENT_SECRET": config.signing_secret, "SDWAN_AGENT_CONTEXT_AUDIENCE": config.agent_context_audience}
def normalized_event(raw: Dict[str, object]) -> AgentEvent:
    """Expose only text deltas and safe MCP activity; never reasoning events."""
    kind = str(raw.get("type", ""))
    if kind == "result":
        return AgentEvent("ignore", {})
    if kind != "stream_event":
        return AgentEvent("ignore", {})
    event = raw.get("event", {})
    event = event if isinstance(event, dict) else {}
    event_type = str(event.get("type", ""))
    if event_type == "content_block_delta":
        delta = event.get("delta", {})
        delta = delta if isinstance(delta, dict) else {}
        if delta.get("type") == "text_delta" and delta.get("text"):
            return AgentEvent("assistant_delta", {"text": str(delta["text"])[:8192]})
    if event_type == "content_block_start":
        block = event.get("content_block", {})
        block = block if isinstance(block, dict) else {}
        if block.get("type") == "tool_use":
            return AgentEvent("tool_call_started", {"tool": str(block.get("name", "sdwan"))[:120]})
    if event_type == "content_block_stop":
        return AgentEvent("tool_call_completed", {})
    return AgentEvent("ignore", {})

class OllamaClaudeRunner:
    def __init__(self, config: ManagementConfig):
        self.config=config
    async def run(self, prompt: str, session_id: str, principal: Principal, message_id: str = "", bundle_id: str = "") -> AsyncIterator[AgentEvent]:
        token=issue_agent_context(self.config.signing_secret, principal, session_id, self.config.agent_context_audience, self.config.agent_context_ttl_seconds)
        # A stdio MCP server belongs to one agent process.  Use a fresh Claude
        # session for each message so a resumed session can never retain a dead
        # tool connection from a previous subprocess.
        claude_session_id = str(uuid.uuid4())
        factual_prompt = ("You are a read-only SD-WAN diagnostic assistant. Use approved SD-WAN MCP tools for every current-lab claim. "
                          "For a current operational or mixed question, call at least one relevant MCP tool. Never invent facts, values, route types, selected paths, or unavailable fields. "
                          "Your final response MUST be one JSON object matching this schema: {answer_type: conceptual|operational|mixed, summary: string, claims: [{claim_id:string, claim_type:system_health|topology|endpoint|endpoint_route|flow_route|transport|site_status|hub_status|cloud_gateway|data_center|saas|tunnel_status|runtime_interfaces|failover_status|classifier_status|routing_rule|routing_table|route|next_hop|output_interface|selected_hub|selected_transport|route_ownership|desired_state|policy_version|destination_policy|device_enrollment|state_comparison|event|limitation, fact_ids:[string], explanation:string|null}], unknowns:[string], limitations:[string]}. "
                          "Use site_status for configured site listings and site status. Never use invented claim types such as observed, configured, or derived. "
                          "For operational or mixed answers, every claim must reference fact_ids returned by MCP in this message. Do not put operational values in summary or explanation; FastAPI renders values from evidence. "
                          "For conceptual answers, claims must be empty. Never suggest or perform configuration changes. "
                          "The approved MCP tools cover system health, topology nodes and links, transports, configured sites and hubs, Cloud VPC gateways, data center, SaaS, route ownership, desired state, policy versions, destination policy, ZTP devices, observed interfaces, WireGuard tunnels, failover, classifier status, routes, destination-aware route decisions, comparisons, and audit events. For a Cloud gateway IP question, call mcp__sdwan__get_cloud_gateway. For an IP or identity question about one named endpoint, call mcp__sdwan__get_endpoint; use mcp__sdwan__get_endpoint_inventory only when the endpoint name is unknown or ambiguous. "
                          "Use mcp__sdwan__get_site_status for configured site records (including LAN prefixes and hub assignments), mcp__sdwan__get_site_tunnels for a branch-site WireGuard status, mcp__sdwan__get_hub_tunnels for a hub WireGuard status, mcp__sdwan__get_site_routes for installed route data, and mcp__sdwan__explain_route_decision for a specific destination. For a tunnel_status claim, cite tunnel facts only. "
                          "For a question requesting a site route table without a destination, call mcp__sdwan__get_site_routes. For a WireGuard tunnel question, call mcp__sdwan__get_site_tunnels. For a question phrased as a route from the host of a named site (for example 'host of node2'), call mcp__sdwan__explain_site_host_route with site=node2; never substitute the edge endpoint node2 for its host. For a route from one otherwise named endpoint to another, call mcp__sdwan__explain_endpoint_route. For the route actually selected by currently active traffic between named endpoints, call mcp__sdwan__observe_endpoint_flow and use claim_type flow_route. That result also contains configured_path_candidates from the dependency graph; when flow_count is zero, report those only as configured candidates and explicitly state that no runtime path was observed. When using explain_endpoint_route, use claim_type endpoint_route and cite its source, destination, host_access, edge_route, and policy_candidates facts when returned. If its edge_route fact reports available=false or a lookup error and no fwmark was supplied, do not say there is no route: report only that the observed unmarked edge lookup did not produce a selected route. Do not use generic claim_type route for endpoint-route evidence. Do not use a bare tool name and do not claim a tool is unavailable before attempting the relevant approved tool.\n\nUser question: " + prompt)
        resume = False
        cmd=command_for(self.config, factual_prompt, claude_session_id, resume=resume); env=restricted_environment(self.config, token, session_id, message_id, bundle_id)
        if not self.config.mcp_config.is_file() or not self.config.claude_settings.is_file():
            yield AgentEvent("agent_error", {"reason":"agent configuration is unavailable"}); return
        try:
            proc=await asyncio.create_subprocess_exec(*cmd, cwd=str(self.config.project_root), env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except (OSError, ValueError):
            yield AgentEvent("agent_error", {"reason":"agent runtime is unavailable"}); return
        collected=0; saw_text=False; final_text=""; result_received=False
        try:
            while True:
                line=await asyncio.wait_for(proc.stdout.readline(), timeout=self.config.claude_timeout_seconds)
                if not line: break
                collected += len(line)
                if collected > self.config.claude_max_output_bytes: raise RuntimeError("agent output limit exceeded")
                try: raw=json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError): continue
                if not isinstance(raw, dict): continue
                if raw.get("type") == "result":
                    # Assistant records may be interim turns emitted before tool use.
                    # Only the terminal result is eligible for evidence validation.
                    final_text=str(raw.get("result", ""))
                    if final_text:
                        result_received=True
                        yield AgentEvent("agent_final", {"text":final_text[:16384]})
                event = normalized_event(raw)
                if event.type == "assistant_delta": saw_text=True
                if event.type != "ignore": yield event
            stderr=await asyncio.wait_for(proc.stderr.read(self.config.claude_max_output_bytes + 1), timeout=10)
            code=await asyncio.wait_for(proc.wait(), timeout=10)
            if len(stderr) > self.config.claude_max_output_bytes or code != 0: yield AgentEvent("agent_error", {"reason":"agent process did not complete successfully", "exit_code":code})
            else:
                if not result_received:
                    yield AgentEvent("agent_error", {"reason":"agent completed without a final result"})
                yield AgentEvent("agent_completed", {"session_id":session_id})
        except (asyncio.TimeoutError, RuntimeError):
            proc.terminate()
            try: await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError: proc.kill()
            yield AgentEvent("agent_error", {"reason":"agent execution timed out or exceeded bounds"})
