# Evidence-bound MCP accuracy architecture

The management browser still uses REST POST and SSE. Claude Code is launched through
Ollama with `gpt-oss:20b-cloud` and uses the local `sdwan-management-mcp` stdio
subprocess. There is no HTTP `/mcp` endpoint.

For an operational message, FastAPI creates an immutable evidence bundle. MCP tools
return typed `OperationalResult` values with metadata, provenance sources, facts, and
fact IDs. Claude returns an `AgentAnswer` JSON object referencing fact IDs. FastAPI
validates those references and renders operational values from the stored facts. A
failed validation produces an unavailable result rather than model text.

Word blacklists are not used: validity depends on evidence references and fact-kind
compatibility, not a manually maintained vocabulary.
