# MCP

`POST /mcp` is a Python 3.8-compatible validated JSON-RPC fallback because the official MCP Python SDK was not installed/verified for this laboratory. It exposes only shared read-only service queries. It has no write tools and must be called with a bearer token.

## Terminal configuration

Copy `config/mcp.sdwan.example.json` into the Claude Code/Ollama configuration mechanism used by the local installation and set `SDWAN_MCP_TOKEN` to a short-lived user token with `network:read,mcp:read`. Start the Management API first. The MCP endpoint is `/mcp` on port 8090. This configuration is provided but has not been live-tested against Claude Code or Ollama in this environment.
