# Grafana MCP Setup

## Install

```bash
go install github.com/grafana/mcp-grafana/cmd/mcp-grafana@latest
```

## Verify Installation

Check where the binary was installed:

```bash
which mcp-grafana
# Or check GOPATH:
ls $(go env GOPATH)/bin/mcp-grafana
```

## Add to Claude Code

### Option 1: Using command name (requires mcp-grafana in PATH)

```bash
claude mcp add grafana mcp-grafana \
  -e GRAFANA_URL=https://grafana.dev.plundr.ai \
  -e GRAFANA_API_KEY=<your-token>
```

### Option 2: Using full path (recommended for reliability)

If `which mcp-grafana` doesn't find the binary or you get connection errors:

```bash
# Find the full path first
GRAFANA_BIN=$(go env GOPATH)/bin/mcp-grafana

# Add using full path
claude mcp add grafana $GRAFANA_BIN \
  -e GRAFANA_URL=https://grafana.dev.plundr.ai \
  -e GRAFANA_API_KEY=<your-token>
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
