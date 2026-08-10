# Grafana MCP

Setup for the Grafana MCP server, and how blue team agents use it to query
Loki and Prometheus during an investigation.

## Setup

### Install

```bash
go install github.com/grafana/mcp-grafana/cmd/mcp-grafana@latest
```

Confirm where it landed:

```bash
which mcp-grafana || ls "$(go env GOPATH)/bin/mcp-grafana"
```

### Create a service account token

1. Grafana → Administration → Service Accounts
2. Add service account, assign the Editor role
3. Add service account token, copy it

### Register with Claude Code

If `mcp-grafana` is on `PATH`:

```bash
claude mcp add grafana mcp-grafana \
  -e GRAFANA_URL=<your-grafana-url> \
  -e GRAFANA_SERVICE_ACCOUNT_TOKEN=<your-token>
```

If it isn't found, or you get connection errors, use the full path and pull
the token from 1Password:

```bash
claude mcp add grafana "$(go env GOPATH)/bin/mcp-grafana" \
  -e GRAFANA_URL=<your-grafana-url> \
  -e GRAFANA_SERVICE_ACCOUNT_TOKEN="$(op item get 'Dev Grafana' --fields api-token --reveal)"
```

Config is written to `~/.claude.json`. To change it, `claude mcp remove grafana`
then re-add.

## How agents query observability data

Blue agents reach Loki and Prometheus over two paths:

1. **Direct HTTP tools** — `query_loki_logs`, `query_logs_around_timestamp`,
   `execute_parallel_queries`, and friends, defined under
   `ares-llm/src/tool_registry/blue/` and executed against the Loki and
   Prometheus APIs.
2. **Native MCP tools** — the `mcp__grafana__*` tools from the MCP server,
   used for label discovery, log stats, dashboard access, and annotations.

Tool descriptions embed their own usage guidance, so the agent knows to check
label stats before issuing a broad query without the prompt spelling it out.
Detection templates cover the common patterns (credential dumping, lateral
movement, Kerberoasting) so agents don't rebuild those queries from scratch.

A typical investigation walks the stages like this:

```text
# TRIAGE — discover what labels exist, then run templates matching the alert
get_loki_label_values(label_name="job")
run_detection_query(technique_id="T1003", time_range="1h")

# CAUSATION — pull context around the alert, fan out to related techniques
query_logs_around_timestamp(
    logql='{job="eventlog"} |= "4662"',
    timestamp="2026-01-15T10:30:00Z",
    window_minutes=15
)
run_parallel_detections(technique_ids=["T1003", "T1003.006", "T1558"])

# LATERAL — pivot by compromised host and suspicious user
get_host_activity(hostname="dc01.contoso.local")
get_user_activity(username="alice")

# SYNTHESIS — mark the investigation complete on the Grafana timeline
post_investigation_completed(investigation_id="inv-xxx", report_url="/reports/inv-xxx.md")
```

## Tool reference

**Loki** (`ares-llm/src/tool_registry/blue/loki.rs`):

| Tool | Purpose |
| ---- | ------- |
| `query_loki_logs` | LogQL query with time range and limit |
| `query_logs_around_timestamp` | Context window around an event |
| `query_logs_progressive` | Iterative query refinement |
| `query_logs_recent` | Quick recent-log lookup |
| `get_loki_label_values` | Label enumeration for filter discovery |
| `execute_parallel_queries` | Concurrent multi-source queries |
| `combine_query_patterns` | Merge multiple query patterns |

**Grafana** (`ares-llm/src/tool_registry/blue/grafana.rs`):

| Tool | Purpose |
| ---- | ------- |
| `get_grafana_alerts` / `get_alert_history` / `get_alerts_in_time_range` | Alert queries |
| `get_grafana_annotations` | Investigation context from annotations |
| `search_grafana_dashboards` / `get_grafana_dashboard` | Dashboard access |
| `create_annotation` | Write investigation markers back to Grafana |
| `create_detection_rule` | Create an alert rule from a LogQL query |
| `post_investigation_started` / `post_investigation_completed` | Lifecycle annotations |

**Detection** (`ares-llm/src/tool_registry/blue/detection.rs`):

| Tool | Purpose |
| ---- | ------- |
| `run_detection_query` / `run_parallel_detections` | Execute MITRE-mapped templates |
| `list_detection_templates` | Browse available templates |
| `get_host_activity` / `get_user_activity` | Pivot by host or user |

Under replay, every one of these is clamped to the replay clock — see
[Benchmark Replay](benchmark-replay.md#clamp-sites).

## Configuration

The datasource UID defaults to `loki` and can be overridden via environment
variables or the `grafana:` / `observability:` sections of `config/ares.yaml`.
Agents need `GRAFANA_URL` and `GRAFANA_SERVICE_ACCOUNT_TOKEN` set.

See [Blue Team Documentation](blue.md) for the investigation lifecycle these
tools serve.
