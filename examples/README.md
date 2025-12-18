# Ares Examples

This directory contains example scripts demonstrating Ares agent capabilities.

## Grafana MCP Windows Attack Query Examples

### Overview

The `grafana_mcp_windows_example.py` script demonstrates the types of queries
the agent can make to Grafana/Loki for Windows security events and attack
indicators.

### Running the Example

```bash
# Using Task
task ares:example:grafana-windows

# Or directly with Python
python examples/grafana_mcp_windows_example.py
```

### Query Examples Demonstrated

The example script demonstrates 9 types of queries the agent can make:

1. **Label Discovery** - Find available labels (environment, host, job, etc.)
2. **Environment Values** - List all environment values
3. **Log Volume** - Check log statistics before querying
4. **Attack Indicators** - Search for mimikatz, impacket, exploit, payload,
   shell, etc.
5. **DCSync Activity** - Event ID 4662 (credential dumping via AD replication)
6. **Authentication Events** - Event ID 4624 (successful logons)
7. **Failed Authentication** - Event ID 4625 (failed logon attempts)
8. **PowerShell Activity** - Detect PowerShell execution
9. **Suspicious Network** - netcat, curl, wget downloading scripts

### Query Examples

#### DCSync Detection (Event ID 4662)

```logql
{environment="staging"} | json | event_id="4662"
```

#### Authentication Events (Event ID 4624)

```logql
{environment="staging"} | json | event_id="4624"
```

#### Attack Indicators

```logql
{environment="staging"} |~ "(?i)(exploit|payload|shell|mimikatz|impacket)"
```

#### PowerShell Activity

```logql
{environment="staging"} |~ "(?i)(powershell|pwsh|invoke-|iex)"
```

### Testing with Real Grafana

To test with actual Grafana/Loki data, the agent needs:

1. **Grafana MCP Server** configured and running
2. **Loki datasource** with UID "loki"
3. **Windows event logs** being ingested into Loki

When running within the agent context (via `task ares:run`), the agent will
have access to the `mcp__grafana__*` tools and can execute these queries
against real data.

### Agent Integration

During investigations, the agent uses the `GrafanaMCPTools` which provides
guide methods:

```python
# Get guide for listing labels
guide = list_loki_label_names_guide()

# Then call the native MCP tool
mcp__grafana__list_loki_label_names(
    datasourceUid="loki",
    startRfc3339="2024-01-15T00:00:00Z",
    endRfc3339="2024-01-15T23:59:59Z"
)
```

### Expected Output

The example script prints:

- The exact queries that will be executed
- Expected output format for each query type
- Context about what each query detects
- Summary of all available capabilities

### Windows Event IDs

Common Windows Security Event IDs the agent queries:

| Event ID | Description | Attack Relevance |
| --- | --- | --- |
| 4662 | Directory Service Access | DCSync (credential dumping) |
| 4624 | Successful Logon | User activity, lateral movement |
| 4625 | Failed Logon | Brute-force attempts |
| 4688 | Process Creation | Command execution, PowerShell |
| 4697 | Service Installation | Persistence |
| 4720 | User Account Created | Persistence |
| 5140 | Network Share Accessed | Lateral movement |

### LogQL Query Patterns

The agent uses these LogQL patterns:

**Label Selectors:**

```logql
{environment="staging"}
{environment="staging", host="web-01"}
{job="windows-events"}
```

**Regex Filters:**

```logql
|~ "(?i)(exploit|payload)"  # Case-insensitive regex match
|= "error"                    # Exact string match
```

**JSON Parsing:**

```logql
| json                        # Parse JSON logs
| json | event_id="4662"     # Filter parsed JSON field
```

### Troubleshooting

**No logs returned:**

- Verify Loki has data for the time range
- Check label values match your environment
- Ensure Windows event logs are being collected

**Permission denied:**

- Verify Grafana API key has correct permissions
- Check datasource UID is correct

**MCP tools not available:**

- Ensure Grafana MCP server is configured
- Verify `GRAFANA_URL` and `GRAFANA_API_KEY` are set
- Check MCP server is running and accessible

### Next Steps

After running this example, you can:

1. **Run a full investigation**: `task ares:run`
2. **Check configuration**: `task ares:config:check`
3. **View the agent instructions**: Read `src/agent.py` INSTRUCTIONS variable

The agent will autonomously use these queries during investigations when it
detects patterns requiring Windows security event analysis.
