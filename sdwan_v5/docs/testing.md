# Management accuracy testing

Baseline: `PYTHONPATH=$PWD /home/joubran/ryu-venv38/bin/python -m unittest discover -s sdwan_v5/tests -v`.

SDK stdio server: source `sdwan_v5/.env`, create the signed agent context through
the management auth module, then run
`/mnt/data/sdwan-management-venv/bin/python -m sdwan_v5.sdwan_mcp.server`.

The SDK environment is separate from the Python 3.8 Ryu environment. The management
API must be restarted after code changes. SSE emits `session_started`,
`agent_starting`, `tool_call_started`, `tool_call_completed`,
`evidence_bundle_created`, `answer_validation_started`,
`answer_validation_completed`, `answer_validation_failed`, `verified_answer`,
`assistant_delta`, `agent_completed`, `agent_error`, and `heartbeat` as applicable.
