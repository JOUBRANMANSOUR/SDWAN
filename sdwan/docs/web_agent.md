# Web Agent

Chat sessions are persisted in the isolated management database. The Agent Gateway is disabled by default and never executes the configured external command in this revision. It returns a bounded read-only evidence summary. Enabling external Claude Code/Ollama requires a separately reviewed, least-privilege deployment design.

Chat REST/SSE contracts exist and are tested as a fail-closed management-side implementation. Real Claude Code headless execution through Ollama is deferred until `claude` and `ollama` are installed/configured. It must use the explicit MCP configuration and must not load unrelated MCP servers.
