# Ollama Claude runtime

Primary runtime (no `ANTHROPIC_*` variables):

```bash
/usr/local/bin/ollama launch claude --model gpt-oss:20b-cloud --yes -- \
  -p "List the available SD-WAN sites using only approved MCP tools." \
  --output-format stream-json --verbose --include-partial-messages \
  --mcp-config /mnt/data/sdwan-lab/sdwan/config/mcp.sdwan.json \
  --strict-mcp-config --settings /mnt/data/sdwan-lab/sdwan/config/claude.sdwan.settings.json
```

`--yes` avoids interactive Ollama selection and `--` passes the following flags to Claude. The settings deny Bash, file edit/write, web access, and subagents, while allowing only `mcp__sdwan__*`. FastAPI invokes this exact argv with `asyncio.create_subprocess_exec`, a fixed working directory, and a small allowlisted environment.

Known manual baseline: Ollama and Claude Code 2.1.220 launched interactively with `gpt-oss:20b-cloud`. Headless and MCP integration results must be recorded from actual commands before declaring them successful.
