# Answer validation and rendering

Claude must return `AgentAnswer` JSON. Operational and mixed answers require claims;
every claim references facts from the message's evidence bundle. FastAPI rejects
unknown fact IDs, claims without evidence, fact-kind incompatibilities, and
operational answers with no MCP evidence.

The renderer displays facts from the bundle, not values in Claude's `summary` or
`explanation`. Conceptual answers may be shown as conceptual text. Failure emits
`answer_validation_failed` and displays an evidence-insufficient response.
