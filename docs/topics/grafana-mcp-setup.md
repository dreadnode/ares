# Grafana MCP Setup

## Install

```bash
go install github.com/grafana/mcp-grafana/cmd/mcp-grafana@latest
```

## Add to Claude Code

### Without Authentication

```bash
claude mcp add grafana mcp-grafana -e GRAFANA_URL=http://localhost:3000
```

### With Authentication

```bash
claude mcp add grafana mcp-grafana \
  -e GRAFANA_URL=https://grafana.dev.plundr.ai \
  -e GRAFANA_API_KEY=<your-token>
```

### JSON Format

```bash
claude mcp add-json "grafana" '{
  "command": "mcp-grafana",
  "args": [],
  "env": {
    "GRAFANA_URL": "https://grafana.dev.plundr.ai",
    "GRAFANA_API_KEY": "your-token"  # pragma: allowlist secret
  }
}'
```

## Create Service Account Token

1. Grafana → Administration → Service Accounts
2. Add service account → Name it → Assign Editor role
3. Add service account token → Copy token

## Update Configuration

```bash
claude mcp remove grafana
claude mcp add grafana mcp-grafana -e GRAFANA_URL=<url> -e GRAFANA_API_KEY=<token>
```

## Config Location

```text
~/.claude.json
```
