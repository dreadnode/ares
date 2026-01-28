# Grafana MCP Integration for Ares

This document describes how the Ares SOC agent uses Grafana MCP (Model Context
Protocol) tools to query Loki datasources and investigate security incidents.

## Overview

Ares now includes a `GrafanaMCPTools` toolset that provides guide methods to
help the agent use the native `mcp__grafana__*` tools available in the
environment. These tools enable:

- Label discovery (finding available labels and their values)
- Log volume statistics
- LogQL queries for searching logs
- Pre-built queries for common attack indicators

## Available Tools

### 1. Label Discovery

#### list_loki_label_names_guide()

Returns instructions for listing all available label names in Loki.

**Example Usage by Agent:**

```python
# Agent calls the guide
guide = list_loki_label_names_guide()

# Then uses the native MCP tool
mcp__grafana__list_loki_label_names(
    datasourceUid="loki",
    startRfc3339="2024-01-15T00:00:00Z",  # optional
    endRfc3339="2024-01-15T23:59:59Z"      # optional
)
```

**Returns:** List of label names like
`["environment", "deployment", "host", "job", "namespace"]`

#### list_loki_label_values_guide(label_name)

Returns instructions for listing all values for a specific label.

**Example Usage by Agent:**

```python
# Agent calls the guide with label name
guide = list_loki_label_values_guide("environment")

# Then uses the native MCP tool
mcp__grafana__list_loki_label_values(
    datasourceUid="loki",
    labelName="environment",
    startRfc3339="2024-01-15T00:00:00Z",  # optional
    endRfc3339="2024-01-15T23:59:59Z"      # optional
)
```

**Returns:** List of values like `["staging", "production", "dev"]`

### 2. Log Statistics

#### query_loki_stats_guide(logql_selector)

Returns instructions for getting statistics about log streams.

**Example Usage by Agent:**

```python
# Agent calls the guide with LogQL selector
guide = query_loki_stats_guide('{environment="staging"}')

# Then uses the native MCP tool
mcp__grafana__query_loki_stats(
    datasourceUid="loki",
    logql='{environment="staging"}',
    startRfc3339="2024-01-15T00:00:00Z",  # optional
    endRfc3339="2024-01-15T23:59:59Z"      # optional
)
```

**Returns:**

```json
{
  "streams": 42,
  "chunks": 1500,
  "entries": 50000,
  "bytes": 25000000
}
```

### 3. Log Queries

#### query_loki_logs_guide(logql, limit)

Returns instructions for querying Loki logs with full LogQL support.

**Example Usage by Agent:**

```python
# Agent calls the guide
guide = query_loki_logs_guide('{environment="staging"} |~ "error"', limit=10)

# Then uses the native MCP tool
mcp__grafana__query_loki_logs(
    datasourceUid="loki",
    logql='{environment="staging"} |~ "error"',
    limit=10,
    direction="backward",  # newest first
    startRfc3339="2024-01-15T00:00:00Z",  # optional
    endRfc3339="2024-01-15T23:59:59Z"      # optional
)
```

**Returns:** List of log entries with timestamps, labels, and log lines

### 4. Attack Indicator Searches

#### search_attack_indicators_guide(environment)

Returns pre-built LogQL queries for common attack indicators.

**Example Usage by Agent:**

```python
# Agent calls the guide
guide = search_attack_indicators_guide("staging")
```

**Returns queries for:**

1. General attack indicators (exploit, payload, shell, mimikatz, impacket, etc.)
2. DCSync activity (Event ID 4662)
3. Authentication events (Event ID 4624)
4. Failed authentication (Event ID 4625)
5. PowerShell activity
6. Suspicious network activity

### 5. Environment Discovery

#### discover_environment_guide(environment)

Returns a complete step-by-step guide for discovering environment structure.

**Example Usage by Agent:**

```python
# Agent calls the guide
guide = discover_environment_guide("staging")
```

**Returns a workflow for:**

1. Listing available labels
2. Getting values for important labels (environment, deployment, host, job, namespace)
3. Checking data volume
4. Querying sample logs

## Integration with Investigation Workflow

The agent can use these tools during investigation stages:

### Stage 1: TRIAGE

```python
# Discover environment structure
discover_environment_guide("staging")

# List available labels
mcp__grafana__list_loki_label_names(datasourceUid="loki")

# Get label values
mcp__grafana__list_loki_label_values(datasourceUid="loki", labelName="environment")
```

### Stage 2: CAUSATION

```python
# Check log volume first
mcp__grafana__query_loki_stats(
    datasourceUid="loki",
    logql='{environment="staging"}'
)

# Query logs around alert time
mcp__grafana__query_loki_logs(
    datasourceUid="loki",
    logql='{environment="staging"} |~ "(?i)error"',
    limit=10,
    direction="backward"
)
```

### Stage 3: LATERAL

```python
# Search for attack indicators
mcp__grafana__query_loki_logs(
    datasourceUid="loki",
    logql='{environment="staging"} |~ "(?i)(exploit|payload|shell|mimikatz)"',
    limit=10
)

# Check for DCSync activity
mcp__grafana__query_loki_logs(
    datasourceUid="loki",
    logql='{environment="staging"} | json | event_id="4662"',
    limit=5
)

# Check authentication events
mcp__grafana__query_loki_logs(
    datasourceUid="loki",
    logql='{environment="staging"} | json | event_id="4624"',
    limit=5
)
```

## Example Investigation Flow

```python
# 1. Discover environment
agent.call("discover_environment_guide", environment="staging")

# 2. List labels
labels = mcp__grafana__list_loki_label_names(datasourceUid="loki")

# 3. Get label values for important labels
for label in ["environment", "deployment", "host", "job"]:
    values = mcp__grafana__list_loki_label_values(
        datasourceUid="loki",
        labelName=label
    )
    # Record evidence for each value found

# 4. Check log volume
stats = mcp__grafana__query_loki_stats(
    datasourceUid="loki",
    logql='{environment="staging"}'
)

# 5. Search for attack indicators
indicators = mcp__grafana__query_loki_logs(
    datasourceUid="loki",
    logql='{environment="staging"} |~ "(?i)(exploit|payload|shell)"',
    limit=10
)

# 6. Check specific Windows events
dcsync = mcp__grafana__query_loki_logs(
    datasourceUid="loki",
    logql='{environment="staging"} | json | event_id="4662"',
    limit=5
)

auth = mcp__grafana__query_loki_logs(
    datasourceUid="loki",
    logql='{environment="staging"} | json | event_id="4624"',
    limit=5
)
```

## System Instructions Update

The agent's system instructions now include:

```text
## Grafana MCP Tools (Enhanced Querying)

You have access to enhanced Grafana MCP tools for more powerful querying:

**Discovery Phase:**
1. list_loki_label_names() - Discover available labels
2. list_loki_label_values(label_name) - Get values for specific labels
3. discover_environment(environment) - Get complete environment structure

**Investigation Phase:**
1. query_loki_stats(logql) - Check data volume BEFORE querying
2. query_loki_logs(logql, limit, direction) - Query logs with full LogQL support
3. search_attack_indicators(environment) - Pre-built attack indicator searches
4. check_dcsync_activity(environment) - Look for DCSync (Event ID 4662)
5. check_authentication_events(environment) - Check auth events (Event ID 4624)

**When to use MCP vs Direct Loki:**
- Use MCP tools for: label discovery, stats checks, and convenience methods
- Use direct LokiTools for: custom queries with specific time windows
- Both are valid - choose based on the task
```

## Configuration

The GrafanaMCPTools toolset is configured with:

```python
grafana_mcp_tools = GrafanaMCPTools(datasource_uid="loki")
```

The datasource UID can be changed to target different Loki datasources:

```python
grafana_mcp_tools = GrafanaMCPTools(datasource_uid="custom-loki-ds")
```

## Benefits

1. **Guided Discovery**: The guide tools help the agent understand how to use
   the native MCP tools correctly
2. **Pre-built Queries**: Common security queries are provided for faster
   investigation
3. **Best Practices**: The guides include best practices like checking stats
   before querying logs
4. **Flexibility**: The agent can use both MCP tools and direct Loki API calls
   as needed
5. **Integration**: Seamlessly integrates with the existing investigation
   workflow

## Next Steps

To use these capabilities:

1. Ensure the Grafana MCP server is configured and running
2. Set the `GRAFANA_URL` and `GRAFANA_SERVICE_ACCOUNT_TOKEN` environment variables
3. Run an investigation: `ares investigate`
4. The agent will automatically have access to the GrafanaMCPTools

For more information, see:

- [Grafana MCP Setup Guide](topics/grafana-mcp-setup.md)
- [Home](index.md)
