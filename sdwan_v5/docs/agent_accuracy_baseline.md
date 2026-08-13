# Agent accuracy baseline

## Inspected components

- MCP server: `sdwan_v5/sdwan_mcp/server.py`
- management API and SSE: `sdwan_v5/management/app.py`
- Claude runner and stream normalization: `sdwan_v5/management/agent.py`
- shared query service and route reporting: `sdwan_v5/management/service.py`
- constrained runtime adapter: `sdwan_v5/management/runtime.py`
- session, chat, and audit persistence: `sdwan_v5/management/repository.py`
- authentication and RBAC: `sdwan_v5/management/auth.py`
- configuration: `sdwan_v5/management/config.py`

## Baseline commands and results

```bash
PYTHONPATH=$PWD /home/joubran/ryu-venv38/bin/python -m unittest discover -s sdwan_v5/tests -v
```

Result: **48 tests passed** on Python 3.8.20.

```bash
/home/joubran/ryu-venv38/bin/python -m pip show mcp
```

Result: no `mcp` package was installed. The existing Ryu environment is Python
3.8.20. The current official MCP Python SDK requires Python 3.10 or newer, so
the migration uses an isolated Python 3.12 management environment and leaves
Ryu/Containernet on Python 3.8 unchanged.

A signed-context stdio test of the pre-migration server completed successfully
for `initialize`, `tools/list`, and `get_dashboard_summary`; stdout contained
manual JSON-RPC responses and stderr was empty.

## Current MCP implementation and contracts

The baseline server manually parses JSON-RPC stdin and manually handles
`initialize`, `tools/list`, `tools/call`, and notifications. Every tool result
is emitted as a JSON document encoded inside a text content block. It slices the
serialized result at 32,768 characters. It publishes input schemas only; it has
no output schemas, structured content, provenance metadata, stable fact IDs,
or structured execution errors.

`tools/list` gives shared generic descriptions to unrelated site tools.
`explain_route_decision` accepts only `site`, so it cannot verify a lookup for a
specific destination. `compare_desired_actual` passes separate dictionaries to
the model rather than performing a typed comparison. A final Claude response is
streamed and displayed without deterministic evidence-reference validation.

## Known unsupported fields and factuality risks

- No observed packet fwmark, connection mark, matched policy rule, or selected
  route can be claimed for a particular packet without a destination-aware
  runtime lookup.
- Fields absent from `ip -j` or `wg show` output cannot be inferred.
- Runtime availability depends on Docker access; unavailable runtime data must
  not be presented as live observation.
- The baseline result text may be invalid JSON after string slicing.
- A final operational answer may be displayed even if no successful MCP tool
  call occurred.

## Baseline factuality example

The prior route explanation was built from a site-wide route summary. It could
state a routing interpretation for an arbitrary destination without observing
that destination, packet source, or fwmark. This is the behavior replaced by
typed destination-aware evidence and deterministic rendering.
