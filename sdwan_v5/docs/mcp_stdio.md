# Local SD-WAN MCP over stdio

`sdwan-management-mcp` is the only MCP logical server.  It is launched by Claude Code from `config/mcp.sdwan.json`; it has no TCP listener and no HTTP `/mcp` endpoint.  Protocol JSON-RPC is newline-delimited on stdin/stdout; diagnostics stay on stderr.

FastAPI creates a short-lived signed agent context after validating the browser bearer token.  The context is passed only in the restricted local subprocess environment, checked for signature, audience, expiry, and chat session by the MCP server, and never returned to the browser.  REST routes and MCP tools call `ManagementService` and its read-only configuration/database/runtime adapters.

Tools are read-only: dashboard, sites, site status/tunnels/routes, topology, hub/cloud/SaaS state, desired-vs-actual, route explanation, and recent audited events.  Streamable HTTP is deferred so browser and network attack surfaces remain smaller in milestone 1.
