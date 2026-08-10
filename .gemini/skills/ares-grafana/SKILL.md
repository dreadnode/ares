---
name: ares-grafana
description: Reference for Grafana dashboards and specific Loki queries used to monitor and debug Ares operations via the grafana MCP server. Use when you need to handily check operation health, errors, agent restarts, or loot discovery.
---
# Ares Grafana Monitoring

Use the `grafana` MCP tools (`query_loki_logs`, `get_dashboard_by_uid`, `search_dashboards`) to monitor Ares operations on `https://grafana.techvomit.xyz`.

## Key Dashboards

Located under the "Attack Simulation" folder (uid: `efqwxzc7grxtsf`):

- **Attack Simulation - Overview** (uid: `attack-simulation-overview`)
- **Ares: Red and Blue Agents** (uid: `ares-agents`)
- **Red Team Agent Logs** (uid: `red-team-agent-logs`)
- **Attack Operation Summary - Deep Dive** (uid: `attack-operation-summary`)

## Common Loki Queries

When querying Loki logs using `query_loki_logs`, use the following LogQL patterns (usually prefixed with `{namespace="attack-simulation"}` for K8s or `{deployment="alpha-operator-range-kali-ares"}` for EC2):

### Errors & Warnings

- All errors: `{namespace="attack-simulation"} |~ "(?i)ERROR"`
- Warnings: `{namespace="attack-simulation"} |~ "(?i)WARN"`

### Orchestrator & Task Executions

- Task execution events: `{namespace="attack-simulation"} |~ "(?i)(executing|completed|task|dispatch)"`
- Orchestrator restarts: `{namespace="attack-simulation", job="orchestrator.log"} |= "starting"`

### Loot Discovery

- Track all loot (hashes, credentials, hosts, domains, DA):
  `{namespace="attack-simulation"} |~ "(DOMAIN ADMIN ACHIEVED|GOLDEN TICKET OBTAINED|Hash added:|Credential added:|Domains \\(|Hosts \\(|Users \\(|Credentials \\(|Hashes \\(|Shares \\(|Weaknesses \\(|has_domain_admin|domain_admin_path|publish_credential|broadcast_credential|new credential|\\[hash\\]|\\[cred\\]|\\[user\\]|\\[host\\]|\\[domain\\])"`

### Connectivity

- Redis connection issues: `{namespace="attack-simulation"} |~ "(?i)(redis|connection|reconnect|disconnect)"`

### Querying Specific Agents

Use the `job` label to filter by agent:

- Orchestrator: `job="orchestrator.log"`
- Recon: `job="recon.log"`
- Credential Access: `job="credential_access.log"`
- Lateral Movement: `job="lateral.log"`
- Privilege Escalation: `job="privesc.log"`
- Coercion: `job="coercion.log"`
- Cracker: `job="cracker.log"`
- ACL: `job="acl.log"`
