# Grafana MCP Integration for Ares

This document describes how the Ares SOC agent uses Grafana MCP (Model Context
Protocol) tools to query Loki datasources and investigate security incidents.

## Overview

Ares blue team agents use Grafana MCP (Model Context Protocol) tools to query
observability data during investigations. The tool registry at
`ares-llm/src/tool_registry/blue/grafana.rs` defines individual tool
definitions that wrap the native `mcp__grafana__*` tools. These enable:

- Label discovery (finding available labels and their values)
- Log volume statistics
- LogQL queries for searching logs
- Pre-built queries for common attack indicators

## How Agents Use Grafana MCP

Blue team agents interact with Grafana through two paths:

1. **Direct Loki/Prometheus tools** — `query_loki_logs`, `query_logs_around_timestamp`,
   `execute_parallel_queries`, etc. These are defined in the tool registry and executed
   via HTTP against the Loki/Prometheus APIs.

2. **Native MCP tools** — `mcp__grafana__*` tools provided by the Grafana MCP server.
   These handle label discovery, log stats, dashboard access, and annotation management.

The tool descriptions include usage guidance so the LLM agent knows when to use
each tool and how to construct efficient queries.

## Integration with Investigation Workflow

### Stage 1: TRIAGE

```text
# Discover available data sources and labels
get_loki_label_values(label_name="job")
get_loki_label_values(label_name="host")

# Run detection templates matching the alert
run_detection_query(technique_id="T1003", time_range="1h")
```

### Stage 2: CAUSATION

```text
# Query logs around the alert timestamp
query_logs_around_timestamp(
    logql='{job="eventlog"} |= "4662"',
    timestamp="2024-01-15T10:30:00Z",
    window_minutes=15
)

# Run parallel detections for related techniques
run_parallel_detections(technique_ids=["T1003", "T1003.006", "T1558"])
```

### Stage 3: LATERAL

```text
# Pivot by compromised host
get_host_activity(hostname="dc01.corp.local")

# Check for lateral movement indicators
query_loki_logs(
    logql='{job="eventlog"} |~ "(?i)(psexec|wmiexec|smbexec)"',
    start_time="2024-01-15T00:00:00Z",
    end_time="2024-01-15T23:59:59Z"
)

# Pivot by suspicious user
get_user_activity(username="admin")
```

## Example Investigation Flow

A typical agent investigation follows this pattern (the LLM agent calls
these tools automatically during each investigation stage):

```text
# 1. Discover available labels (TRIAGE stage)
get_loki_label_values(label_name="job")
get_loki_label_values(label_name="host")

# 2. Run detection templates for the alert type
run_parallel_detections(technique_ids=["T1003", "T1003.006"])

# 3. Query logs around the alert timestamp
query_logs_around_timestamp(
    logql='{job="eventlog"} |= "4662"',
    timestamp="2024-01-15T10:30:00Z",
    window_minutes=15
)

# 4. Pivot by host and user (LATERAL stage)
get_host_activity(hostname="dc01.corp.local")
get_user_activity(username="admin")

# 5. Check for attack indicators across hosts
query_loki_logs(
    logql='{job="eventlog"} |~ "(?i)(mimikatz|secretsdump|psexec)"',
    start_time="2024-01-15T00:00:00Z",
    end_time="2024-01-15T23:59:59Z"
)

# 6. Post investigation completion annotation
post_investigation_completed(investigation_id="inv-xxx", report_url="/reports/inv-xxx.md")
```

## Tool Reference

Blue team agents have access to the following tool categories:

**Loki Query Tools** (`ares-llm/src/tool_registry/blue/loki.rs`):

- `query_loki_logs` — LogQL queries with time range and limit
- `query_logs_around_timestamp` — Context-aware log retrieval around an event
- `query_logs_progressive` — Iterative query refinement
- `get_loki_label_values` — Label enumeration for filter discovery
- `execute_parallel_queries` — Concurrent multi-source queries
- `query_logs_recent` — Quick recent log lookup
- `combine_query_patterns` — Merge multiple query patterns

**Grafana Tools** (`ares-llm/src/tool_registry/blue/grafana.rs`):

- `get_grafana_alerts` / `get_alert_history` / `get_alerts_in_time_range` — Alert queries
- `get_grafana_annotations` — Investigation context from annotations
- `search_grafana_dashboards` / `get_grafana_dashboard` — Dashboard access
- `create_annotation` — Write investigation markers back to Grafana
- `create_detection_rule` — Auto-create alert rules from LogQL queries
- `post_investigation_started` / `post_investigation_completed` — Investigation lifecycle annotations

**Detection Tools** (`ares-llm/src/tool_registry/blue/detection.rs`):

- `run_detection_query` / `run_parallel_detections` — Execute MITRE-mapped detection templates
- `list_detection_templates` — Browse available templates
- `get_host_activity` / `get_user_activity` — Pivot investigations by host or user

## Configuration

Grafana tools are registered in the blue team tool registry at
`ares-llm/src/tool_registry/blue/grafana.rs`. The datasource UID defaults to
`"loki"` and can be overridden via environment variables or the config file.

## Benefits

- **Guided Discovery**: Tool definitions include usage guidance to help the
  LLM agent use the native MCP tools correctly
- **Pre-built Queries**: Common security queries are provided for faster
  investigation via detection templates
- **Best Practices**: Tool descriptions include best practices like checking
  stats before querying logs
- **Flexibility**: Agents can use both MCP tools and direct Loki HTTP API calls
- **Integration**: Works alongside the existing investigation workflow

## Next Steps

To use these capabilities:

1. Ensure the Grafana MCP server is configured and running
2. Set the `GRAFANA_URL` and `GRAFANA_SERVICE_ACCOUNT_TOKEN` environment variables
3. Start a blue team investigation: `ares-cli blue from-operation --latest`
4. Agents will automatically use Grafana tools during investigation

For more information, see:

- [Grafana MCP Setup Guide](topics/grafana-mcp-setup.md)
- [Blue Team Documentation](blue.md)
