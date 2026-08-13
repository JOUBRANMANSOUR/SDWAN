# MCP structured outputs

The official MCP Python SDK is pinned at `mcp==1.28.1` in
`requirements-management.txt` and runs in `/mnt/data/sdwan-management-venv` with
Python 3.12. It was selected because the official SDK requires Python 3.10+, while
Ryu/Containernet remain on Python 3.8.

`FastMCP` owns stdio protocol negotiation, tool discovery, input validation, output
schemas, structured content, and lifecycle. The project owns RBAC, signed-context
validation, audit logging, service calls, and evidence modeling.

Successful calls publish `outputSchema` and `structuredContent`; serialized JSON is
never sliced. SDK validation and execution failures return `isError: true`.
