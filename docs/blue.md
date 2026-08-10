# Blue Agent Documentation

## Overview

The **Ares Blue Agent** is an autonomous SOC investigation system. It picks up
Grafana alerts, queries Loki logs and Prometheus metrics for evidence, maps
findings to MITRE ATT&CK, and writes investigation reports.

**Key Capabilities:**

- Alert triage and multi-stage investigation (triage → causation → lateral → synthesis)
- LogQL/PromQL query optimization with result caching and retry
- Evidence extraction using the Pyramid of Pain framework
- MITRE ATT&CK technique mapping and gap analysis
- Lateral movement detection and scope expansion
- Attack precursor identification (root cause analysis)
- Historical investigation store for pattern matching and false-positive tracking
- Red-Blue correlation to surface detection gaps
- Markdown report generation with timeline, evidence inventory, and recommendations

## Core Architecture

### Main Components

#### Investigation Orchestrator

**Location:** `ares-cli/src/orchestrator/blue/`

The investigation orchestrator manages the full investigation lifecycle:

- Coordinates LLM-powered investigation agents for Grafana alerts
- Dispatches tasks to specialized sub-agents (triage, threat hunter, lateral analyst, escalation)
- Chains follow-up investigations based on discovered evidence types
- Enforces hard timeout watchdog (1 min/step + 2 min buffer)
- Generates partial reports on timeout
- Handles investigation state persistence via Redis (task queues run on NATS JetStream)

#### Blue Worker Task Loop

**Location:** `ares-cli/src/worker/blue_task_loop.rs`

Runs the worker-side investigation loop with:

- Query optimization and result caching (see [Query Management](#query-management))
- Automatic retry with exponential backoff
- Resilience mechanisms for failed queries

#### Investigation State Model

**Location:** `ares-core/src/models/blue.rs`

The `SharedBlueTeamState` model tracks:

- Investigation ID, alert context, current stage
- Evidence inventory with pyramid level classification
- Timeline of events with MITRE technique mappings
- Investigative questions from question engines
- Query execution log
- Identified MITRE techniques and tactics
- Queried hosts/users for scope tracking
- Lateral movement graph
- Attack synopsis and recommendations
- Escalation status

## Investigation Workflow

### Investigation Stages

#### 1. TRIAGE - "WHAT is happening?"

- Initial alert analysis
- First-level evidence gathering
- IOC extraction (IPs, domains, hashes, processes)
- Basic timeline construction

#### 2. CAUSATION - "WHY did it happen?"

- Root cause analysis
- Precursor attack identification
- Attack chain reconstruction
- Evidence validation and correlation

#### 3. LATERAL - "What is the SCOPE?"

- Lateral movement detection
- Impact assessment across hosts/users
- Scope expansion to compromised assets
- Connection graph construction

#### 4. SYNTHESIS - Report generation

- Evidence consolidation
- MITRE ATT&CK mapping
- Pyramid of Pain assessment
- Recommendations generation
- Markdown report creation

### Investigation Stage Progression

```text
Alert Detected
      ↓
  TRIAGE (query observability data)
      ↓
  CAUSATION (find root cause)
      ↓
  LATERAL (assess scope)
      ↓
  SYNTHESIS (generate report)
      ↓
Report Delivered
```

## Toolsets

### Investigation Tools

**Location:** `ares-tools/src/` (blue feature)

#### Evidence Recording

```text
record_evidence(
    evidence_type: EvidenceType,  // ip, domain, hash, process, file, user, etc.
    value: String,
    pyramid_level: i32,           // 1=Hash Values, 6=TTPs
    mitre_techniques: Vec<String>,
    confidence: f64,              // 0.0-1.0
    description: String,
    source_query: Option<String>
)
```

**Evidence Types:**

- `ip` - IP addresses
- `domain` - Domain names
- `hash` - File hashes
- `process` - Process names/paths
- `file` - File paths
- `user` - User accounts
- `service` - Services/daemons
- `tool` - Attack tools
- `malware` - Malware families
- `technique` - MITRE techniques
- `behavior` - Attack behaviors

**Pyramid of Pain Levels:**

1. Hash Values (trivial to change)
2. IP Addresses
3. Domain Names
4. Network/Host Artifacts
5. Tools
6. TTPs (hard to change)

#### Timeline Management

```text
add_timeline_event(
    timestamp: String,
    description: String,
    mitre_technique: Option<String>,
    evidence_ids: Vec<String>,
    severity: String  // info, low, medium, high, critical
)
```

#### Investigation Tracking

```text
track_host_investigation(hostname: String)
track_user_investigation(username: String)
```

### Completion Tools

```text
complete_investigation(
    attack_synopsis: String,
    recommendations: Vec<String>,
    should_escalate: bool,
    escalation_reason: Option<String>
)
```

Finalizes investigation with:

- Attack summary and recommendations
- Automatic response guidance extraction from alert annotations
- Fallback synopsis generation from collected evidence
- Investigation report generation trigger

### Grafana Integration Tools

```text
get_firing_alerts() -> Vec<Alert>
get_alert_history(alert_name, lookback_hours) -> Vec<Alert>
post_investigation_started(investigation_id, alert_name)
post_investigation_completed(investigation_id, report_url)
```

Features:

- MCP connection management (60s timeout with fallback)
- Multi-endpoint support for different Grafana versions
- Automatic annotation creation on Grafana dashboards

### Observability Tools

#### LokiTools - LogQL Queries

```text
query_loki(
    logql: String,
    start_time: String,
    end_time: String,
    limit: i32 = 100
) -> Vec<LogLine>
```

Features:

- Query validation and optimization
- Regex error detection (catches empty-compatible patterns like `.*`)
- Label matchers, line filters, parsers support
- Result streaming with configurable line limits
- Automatic time range adjustment on timeout

#### PrometheusTools - PromQL Queries

```text
query_prometheus_instant(query: String, time: String)
query_prometheus_range(query: String, start: String, end: String, step: String)
get_metric_metadata(metric: String)
```

### Query Template Tools

Pre-built LogQL queries optimized for detecting red team attack patterns:

- Windows Event ID detection templates
- Pattern-based filters for common attack techniques
- Performance optimization (prefer `|=` over `|~`)
- Optimized selectors to prevent Loki timeouts

Example templates:

- Lateral movement detection (RDP, SMB, WMI, PSExec)
- Privilege escalation events
- Credential dumping patterns
- Suspicious process execution
- Network reconnaissance

### Question Engine Tools

```text
get_combined_questions() -> Vec<InvestigativeQuestion>
```

Generates investigative questions from the two engines described under
[Question Engines](#question-engines), sorted by priority.

### Learning Tools

```text
find_similar_investigations(
    alert_name: String,
    mitre_techniques: Vec<String>,
    severity: String
) -> Vec<Investigation>
```

Features:

- Historical investigation lookup
- Query effectiveness statistics
- False positive pattern learning
- Investigation pattern matching

### MITRE Lookup Tools

- Technique name resolution
- Tactic mapping (Reconnaissance, Initial Access, Execution, etc.)
- Attack lifecycle coverage analysis
- Technique relationship mapping

## Detection & Response Features

### Alert Correlation

**Location:** `ares-core/src/correlation/`

The `AlertCluster` class groups related alerts using similarity scoring:

**Similarity Factors:**

- Common hosts (40% weight)
- Common users (30% weight)
- Common IPs (20% weight)
- Shared MITRE techniques (10% weight)

**Features:**

- Time-window clustering
- Extracts hosts, users, IPs, techniques from alert labels/annotations
- Identifies campaign patterns across multiple alerts

### Lateral Movement Analysis

**Location:** `ares-core/src/state/`

The `LateralGraph` tracks host-to-host connections and attack spread:

**Connection Types:**

- SMB (file shares)
- RDP (remote desktop)
- WMI (Windows Management Instrumentation)
- PSExec (remote execution)
- SSH (secure shell)
- WinRM (Windows Remote Management)
- DCOM (Distributed COM)

**Features:**

- Investigated vs pending hosts tracking
- Pivot suggestions for scope expansion
- Evidence linkage to connections
- MITRE technique associations

### Red-Blue Correlation

**Location:** `ares-core/src/correlation/`

Correlates red team activities with blue team detections to identify gaps:

**Components:**

- `RedTeamActivity` - Captures red team attack actions
- `BlueTeamDetection` - Records blue team alert/investigation results
- `CorrelationMatch` - Links activities to detections
- `DetectionGap` - Identifies undetected red team activities
- `CorrelationReport` - Full correlation analysis

**Match Quality Levels:**

- STRONG - Direct correlation with high confidence
- GOOD - Clear correlation with supporting evidence
- WEAK - Possible correlation with limited evidence
- TENUOUS - Low confidence correlation

### Evidence Validation

**Location:** `ares-core/src/`

Automatic validation of recorded evidence:

- IOC extraction from query results
- Validation against recent query results
- Confidence adjustment based on validation status
- Suggested IOCs from query data
- Source query tracking for provenance

## Query Management

### Budget

An investigation is bounded by **agent steps**, not by a query quota. The
budget is `--max-steps` on the CLI (`MAX_STEPS_BLUE`, default 50 for
watch/poll; `MAX_STEPS_BLUE_ONCE`, default 15 for one-shot runs). The
orchestrator additionally enforces a hard timeout watchdog and emits a partial
report if it fires.

### Caching and retry

Both live in the Loki tool layer (`ares-tools/src/blue/loki.rs`):

- **Result cache** — keyed on `(logql, start_time, end_time)`, 5-minute TTL,
  100 entries max. Historical log data is immutable, so a short TTL is safe and
  it collapses the repeated identical queries an agent tends to issue within one
  investigation.
- **Retry** — up to 3 attempts on transient failures (timeouts, 429/502/503/504)
  with exponential backoff (1s, 2s, 4s), honouring `Retry-After` on 429s.

### LogQL Optimization

**Prevents Broad Selectors:**

```logql
# BAD - Too broad, causes timeouts
{job=~".+"}
{deployment=~".+"}

# GOOD - Specific labels
{job="eventlog"}
{deployment="windows-hosts"}
```

**Filter Recommendations:**

```logql
# PREFER: Fast string contains
{job="eventlog"} |= "4624"

# AVOID: Slow regex when unnecessary
{job="eventlog"} |~ "4624"
```

**Best Practices:**

- Use specific label selectors (job, deployment, namespace)
- Apply line filters (`|=`) before regex patterns (`|~`)
- Limit time ranges for large datasets
- Use streaming aggregations when possible

## Grafana Integration

### MCP (Model Context Protocol) Integration

The blue agent uses MCP to connect to Grafana and access observability data:

**Capabilities:**

- Grafana datasource discovery
- Loki label name and value enumeration
- Prometheus metric discovery
- Alert rule management
- Dashboard and panel access
- Annotation creation and management
- Multi-architecture image rendering

**Setup:**
See [Grafana MCP](grafana-mcp.md) for server installation and the tool reference.

### Markdown Report Generation

**Location:** `ares-core/src/reports/`

Reports are written in this order: executive summary, timeline of events,
MITRE ATT&CK mapping, Pyramid of Pain assessment, evidence inventory, scope
analysis, recommendations, and an appendix carrying the raw query data and a
JSON export.

### Investigation Persistence

Completed investigations are stored for historical lookup, query-effectiveness
statistics, similar-case matching, and false-positive tracking.

## Question Engines

Two engines generate the investigative questions that steer an investigation.
`get_combined_questions` (`ares-tools/src/blue/engines/tools.rs`) runs both and
returns the union sorted by priority — MITRE questions from the identified
techniques, pyramid questions from the recorded evidence. An engine contributes
nothing when its input is empty, so an investigation with no evidence yet gets
MITRE questions only.

- **MITRE Navigator** (`engines/mitre.rs`) — maps evidence to techniques,
  predicts follow-on techniques, and flags tactic gaps. It ranks precursor
  questions highest, so "what came before this?" leads the list.
- **Pyramid Climber** (`engines/pyramid.rs`) — pushes the investigation up the
  Pyramid of Pain, from hashes and IPs toward tools and TTPs.

Two static datasets back these but are *not* engines and generate no questions
of their own — they are lookup tables the agent queries directly:

- **Attack chains** (`engines/data.rs`) — precursor and follow-on technique
  relationships, read by the MITRE engine and exposed as
  `get_attack_chain_precursors`.
- **Detection recipes** (`engines/data.rs`) — Windows Event ID patterns and
  correlation sequences, exposed as `get_detection_recipe` and
  `list_detection_recipes`.

## Response Actions

Blue's response actions are **simulated**. Nothing in ares writes to Active
Directory, resets a krbtgt, revokes a certificate, or touches a host firewall.
There is no responder agent and no privileged path into the lab — blue detects
and decides, and the decision is recorded rather than enforced.

An investigation names an action by calling `confirm_escalation` with a
`containment_action`, one of:

| Action | Meaning |
| ------ | ------- |
| `escalate_to_human` | Default. Raise the incident, take no further action. |
| `disable_ad_account` | Would disable the named principal |
| `isolate_host_firewall` | Would block the named host at the network edge |
| `revoke_krbtgt` | Would rotate the named domain's krbtgt |
| `revoke_certificate` | Would revoke the named certificate |

Each call does two things
(`ares-cli/src/orchestrator/blue/simulated_response.rs`):

1. Emits a span named `blue.simulated_response.<action_type>` tagged
   `attack_team=blue`, which is what the demo dashboard's response panel groups
   on.
2. Publishes the matching op-state event through the recorder, so the red side
   can observe it.

### How red reacts

The loop closes on the red side, and this part is real. Red classifies its own
tool failures into containment signals
(`ares-cli/src/orchestrator/result_processing/containment_recovery.rs`):

| Signal | Triggered by |
| ------ | ------------ |
| `CredentialRevoked` | `STATUS_LOGON_FAILURE`, LDAP `INVALID_CREDENTIALS` |
| `KrbtgtRotated` | `KRB_AP_ERR_MODIFIED` across the realm |
| `HostIsolated` | SMB/WinRM/LDAP all unreachable for one host |
| `CertificateRevoked` | `KDC_ERR_CLIENT_REVOKED` during PKINIT |

When a signal fires, the exploitation queue drops entries whose preconditions
are now invalid rather than retrying the dead credential or host, and the LLM
prompt reflects that the principal, host, certificate, or realm is gone. That
is what stops a containment event from turning into a retry loop.

Because the actions are simulated, a signal in a live run is more often red
invalidating its *own* working credential through cross-realm recon than an
actual lab rotation — verify with netexec before concluding blue caused it.

## Key Files Reference

| Component | Path |
| ----------- | ------ |
| Blue Orchestrator | `ares-cli/src/orchestrator/blue/` |
| Simulated Response | `ares-cli/src/orchestrator/blue/simulated_response.rs` |
| Red Containment Recovery | `ares-cli/src/orchestrator/result_processing/containment_recovery.rs` |
| Blue Worker Task Loop | `ares-cli/src/worker/blue_task_loop.rs` |
| Blue CLI Commands | `ares-cli/src/blue/` |
| Core Models | `ares-core/src/models/` |
| State Management | `ares-core/src/state/` |
| Correlation Engine | `ares-core/src/correlation/` |
| Report Generation | `ares-core/src/reports/` |
| Tool Dispatch | `ares-tools/src/` |
| Configuration | `config/ares.yaml` |

## Configuration

There is no `blue_team:` section in `config/ares.yaml`. What blue reads from
the config file is the backend wiring it needs to reach observability data:

```yaml
observability:
  loki_url: ""
  prometheus_url: "http://localhost:9090"
```

On EC2 the authoritative environment is `/etc/ares/env`, not this file — a
missing `LOKI_URL` there produces an investigation that reports `fired=0`
because it is blind, not because the range was quiet.

Everything else is set per run: the step budget via `--max-steps`, the model
via `MODEL` / `ARES_LLM_MODEL`, and the cache and retry behaviour is compiled
in (see [Caching and retry](#caching-and-retry)).

## Usage

### Prerequisites

- **API keys** in `.env` or 1Password: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
  `GRAFANA_SERVICE_ACCOUNT_TOKEN`, `DREADNODE_API_KEY`
- **Grafana MCP** configured (see [Grafana MCP](grafana-mcp.md))
- **Redis** accessible (K8s in-cluster, or port-forwarded for local/EC2)
- **ares** binary built (`cargo build --release`)

### Quick Start

```bash
# 1. Start a blue investigation from the latest red team operation
task blue:once LATEST=true

# 2. Monitor progress
task blue:multi:status LATEST=true

# 3. View results
task blue:multi:evidence LATEST=true
task blue:multi:techniques LATEST=true
task blue:reports:consolidate LATEST=true
```

### Taskfile Commands

All blue team tasks are invoked via `task blue:<command>`. Most accept
`OPERATION_ID=op-xxx` or `LATEST=true` to identify the target.

#### Starting Investigations

```bash
# Single investigation from a red team operation (local execution)
task blue:once OPERATION_ID=op-xxx
task blue:once LATEST=true

# Submit a specific alert JSON file
task blue:submit ALERT=alert.json
task blue:submit ALERT=alert.json INVESTIGATION_ID=inv-xxx MULTI_AGENT=true

# Continuous poll mode (re-checks every POLL_INTERVAL seconds)
task blue:poll

# Multi-agent from red team operation (K8s remote)
task blue:multi:remote LATEST=true
task blue:multi:remote OPERATION_ID=op-xxx
task blue:multi:remote LATEST=true MAX_STEPS=15   # short run
```

`blue:submit` reads `BLUE_TRANSPORT` like every other blue task: `ec2`
(default, over SSM), `k8s` (`kubectl exec` into the blue orchestrator), or
`local`. The alert is passed by value rather than by path, since under the
remote transports a local file path does not resolve on the far side.

It deliberately does not forward `--grafana-api-key`: the EC2 transport ships
argv through SSM `send-command`, which would persist the token in SSM command
history and CloudTrail. `blue submit` falls back to the remote's own
`GRAFANA_SERVICE_ACCOUNT_TOKEN`, which is what the investigation reads anyway.

#### Monitoring Investigations

```bash
# Investigation status
task blue:multi:status LATEST=true
task blue:multi:status INVESTIGATION_ID=inv-xxx

# Aggregate status for all investigations in an operation
task blue:multi:operation-status LATEST=true
task blue:multi:operation-status LATEST=true WATCH=10  # auto-refresh

# List all investigations
task blue:multi:list

# Runtime info
task blue:multi:runtime LATEST=true

# Triage decision audit trail
task blue:multi:triage-status LATEST=true

# Follow logs (transport-aware)
task blue:multi:logs                          # EC2: blue lines in the orchestrator log
task blue:multi:logs ALL=true                 # EC2: the whole orchestrator log (red+blue)
task blue:multi:logs BLUE_TRANSPORT=k8s ROLE=threat-hunter   # K8s: one role's pods
task blue:multi:logs BLUE_TRANSPORT=k8s ALL=true             # K8s: all blue pods
```

On EC2 blue is not a separate process: `ec2:launch` runs the orchestrator with
`ARES_BLUE_ENABLED=1` and systemd appends both streams to
`/var/log/ares/orchestrator.log`, so blue lines are interleaved with red and
there are no per-role blue pods to select. The default view greps for
`blue|investigation|inv-`, because log lines carry no module target
(telemetry defaults to `show_target=false`).


#### Viewing Results

```bash
# Evidence collected (Pyramid of Pain items)
task blue:multi:evidence LATEST=true
task blue:multi:evidence LATEST=true JSON=true  # machine-readable

# MITRE ATT&CK techniques identified
task blue:multi:techniques LATEST=true
```

#### Reports

```bash
# Generate consolidated report from Redis state
task blue:reports:consolidate LATEST=true
task blue:reports:consolidate OPERATION_ID=op-xxx OUTPUT_DIR=./reports

# Export detection playbook as JSON to ./reports/blue/ (reads RED operation
# state, so under BLUE_TRANSPORT=k8s it targets the red orchestrator)
task blue:playbook LATEST=true
task blue:playbook OPERATION_ID=op-xxx

# The markdown variant is written by the CLI itself, on the box:
#   ares ops export-detection op-xxx --output-dir <dir>
#     -> <dir>/op-xxx/detection_playbook.{json,md}

# List / view local reports
task blue:reports:list
task blue:reports:latest

# Clean up reports
task blue:reports:clean
```

#### Cleanup

```bash
# Delete a single investigation
task blue:multi:delete INVESTIGATION_ID=inv-xxx

# Delete an operation and all its investigations
task blue:multi:delete-operation OPERATION_ID=op-xxx

# Clean up investigations older than N hours
task blue:multi:cleanup MAX_AGE_HOURS=24
task blue:multi:cleanup ALL=true DRY_RUN=true  # preview before deleting
```

### Direct CLI Commands

For environments without Taskfile, or when you need more control, use
`ares` directly. Add `--k8s <NAMESPACE>` for K8s or `--ec2 <NAME>` for
EC2 transport.

```bash
# Submit from red team operation alerts
ares blue from-operation --latest
ares --k8s attack-simulation blue from-operation op-xxx

# Submit a single alert
ares blue submit '{"alert_title":"Suspicious LSASS","severity":"high"}'

# Continuous poll mode
ares blue watch --poll-interval 30 --max-steps 50

# Investigation status and results
ares blue list
ares blue status --latest
ares blue evidence --latest
ares blue evidence --latest --json
ares blue techniques --latest
ares blue runtime --latest
ares blue triage-status --latest
ares blue operation-status --latest --watch 10

# Report generation
ares blue report --latest --output-dir ./reports
ares blue report --operation-id op-xxx --regenerate

# Cleanup
ares blue delete inv-xxx --force
ares blue delete-operation op-xxx --force
ares blue cleanup --max-age-hours 24 --all --force
ares blue cleanup --dry-run
```

### EC2 Deployment

When running on EC2 instead of K8s, port-forward Redis first:

```bash
# Start SSM port-forward (Redis on localhost:16379)
task ec2:redis:forward EC2_NAME=ares-tools

# In another terminal, run blue commands with the forwarded Redis
ARES_REDIS_URL=redis://localhost:16379 ares blue from-operation --latest
```

### Running Blue Alongside Red

Set `BLUE_ENABLED=1` to start blue team investigations automatically when
a red team operation runs:

```bash
task red:ec2:multi TARGET=dreadgoad DOMAIN=contoso.local BLUE_ENABLED=1
```

### Taskfile Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL` | config file | LLM model override |
| `POLL_INTERVAL` | `30` | Seconds between poll cycles |
| `MAX_STEPS_BLUE` | `50` | Max agent steps (watch/poll mode) |
| `MAX_STEPS_BLUE_ONCE` | `15` | Max agent steps (once/investigate mode) |
| `GRAFANA_URL` | *(none - must be set)* | Grafana instance |
| `K8S_NAMESPACE` | `attack-simulation` | K8s namespace for remote commands |
| `REPORT_DIR` | `./reports` | Report output directory |
| `LOG_DIR` | `./logs` | Log output directory |
