# Blue Agent Documentation

## Overview

The **Ares Blue Agent** is an autonomous SOC investigation system. It picks up
Grafana alerts, queries Loki logs and Prometheus metrics for evidence, maps
findings to MITRE ATT&CK, and writes investigation reports.

**Key Capabilities:**

- Automated alert triage and investigation
- Multi-stage investigation workflow (triage → causation → lateral → synthesis)
- Intelligent query optimization and rate limiting
- Evidence extraction using the Pyramid of Pain framework
- MITRE ATT&CK technique mapping and gap analysis
- Lateral movement detection and scope expansion
- Attack precursor identification (root cause analysis)
- Learning from historical investigations
- Red-Blue correlation for detection gap analysis
- Comprehensive markdown report generation

## Core Architecture

### Main Components

#### Investigation Orchestrator

**Location:** `ares-orchestrator/src/blue/`

The investigation orchestrator manages the full investigation lifecycle:

- Coordinates LLM-powered investigation agents for Grafana alerts
- Dispatches tasks to specialized sub-agents (triage, threat hunter, lateral analyst, escalation)
- Chains follow-up investigations based on discovered evidence types
- Enforces hard timeout watchdog (1 min/step + 2 min buffer)
- Generates partial reports on timeout
- Handles investigation state persistence via Redis

#### Blue Worker Task Loop

**Location:** `ares-worker/src/blue_task_loop.rs`

Runs the worker-side investigation loop with:

- Adaptive query limits based on alert severity and stage
- Query optimization and duplicate detection
- Rate limiting to prevent resource abuse
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
- Query limit: 8 queries (12 for critical alerts)

#### 2. CAUSATION - "WHY did it happen?"

- Root cause analysis
- Precursor attack identification
- Attack chain reconstruction
- Evidence validation and correlation
- Query limit: 14 queries

#### 3. LATERAL - "What is the SCOPE?"

- Lateral movement detection
- Impact assessment across hosts/users
- Scope expansion to compromised assets
- Connection graph construction
- Query limit: 20 queries

#### 4. SYNTHESIS - Report generation

- Evidence consolidation
- MITRE ATT&CK mapping
- Pyramid of Pain assessment
- Recommendations generation
- Markdown report creation
- Query limit: 20 queries

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

Generates investigative questions from three engines:

1. **MITRE Navigator Engine**
   - Maps evidence to MITRE techniques
   - Predicts follow-on techniques in attack chains
   - Identifies tactic gaps in coverage

2. **Pyramid Climber Engine**
   - Pushes investigation from IOCs toward TTPs
   - Encourages evidence at higher pyramid levels
   - Guides analysts toward actionable intelligence

3. **Detection Recipes Engine**
   - Windows Security Event patterns
   - Structured investigation workflows
   - Event ID correlation patterns

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

### Query Resilience

**Location:** `ares-core/src/`

Ensures reliable query execution:

- Automatic retry with exponential backoff
- Timeout handling with time range reduction
- Query result caching
- Connection pooling

## Query Management

### Adaptive Query Limits

Query limits scale based on alert severity and investigation stage:

**Base Limits:**

- Normal alerts: 8 queries per investigation
- Critical alerts: 12 queries per investigation

**Stage-Based Limits:**

- Triage: 8 queries
- Causation: 14 queries
- Lateral: 20 queries
- Synthesis: 20 queries

**Bonus Queries:**

- +3 for finding evidence
- +2 for reaching Pyramid level 4+ (Tools/TTPs)

**Hard Limits:**

- Maximum 25 total queries
- Maximum 2 runs of identical query (duplicate detection)
- Free retries for queries returning 0 results

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
See [Grafana MCP Setup](grafana-mcp-setup.md) for MCP server installation instructions.

### Markdown Report Generation

**Location:** `ares-core/src/reports/`

Investigation reports include:

1. **Executive Summary**
   - High-level findings
   - Alert context and severity
   - Key evidence summary

2. **Timeline of Events**
   - Chronological attack progression
   - Pyramid level indicators
   - MITRE technique mappings

3. **MITRE ATT&CK Mapping**
   - Identified techniques and tactics
   - Tactical coverage analysis
   - Attack lifecycle visualization

4. **Pyramid of Pain Assessment**
   - IOC type distribution
   - Progression toward TTPs
   - Actionable intelligence rating

5. **Evidence Inventory**
   - Complete evidence list with sources
   - Confidence ratings
   - Validation status

6. **Scope Analysis**
   - Affected hosts and users
   - Impacted services
   - Lateral movement paths

7. **Recommendations**
   - Immediate response actions
   - Remediation steps
   - Detection improvements

8. **Appendix**
   - Raw query data
   - Investigation metadata
   - JSON export

### Investigation Persistence

Completed investigations are stored for learning and reference:

- Investigation store for historical lookup
- Query effectiveness statistics
- Pattern matching for similar cases
- False positive tracking

## Advanced Investigation Capabilities

### Four Question Engines

The blue agent uses four mandatory question engines to guide investigations:

#### 1. Precursor Attack Chain Engine

Identifies what came BEFORE the detected technique:

- Analyzes MITRE attack phases
- Identifies likely precursor techniques
- Builds complete attack chains
- Focuses on root cause analysis

#### 2. MITRE Navigator Engine

Maps techniques and predicts progression:

- Maps evidence to MITRE techniques
- Predicts follow-on techniques
- Identifies tactical gaps in coverage
- Suggests techniques commonly seen together

#### 3. Pyramid of Pain Climber Engine

Pushes investigation toward actionable intelligence:

- Guides from IOCs (hashes, IPs) toward TTPs
- Encourages evidence at higher pyramid levels
- Focuses on attacker behaviors vs artifacts
- Prioritizes hard-to-change indicators

#### 4. Detection Recipes Engine

Provides structured investigation workflows:

- Windows Event ID patterns
- Event correlation sequences
- Investigation checklists
- Known attack patterns

### Agent Instructions & Anti-Patterns

**Critical Focus Areas:**

- Query efficiency: query → record evidence → complete (minimize query loops)
- Use current time values (not stale alert timestamps)
- Mandatory datasource discovery workflow
- Label value enumeration to prevent timeouts
- Immediate evidence recording after queries
- Precursor investigation emphasis (root cause)
- Lateral scope expansion for high/critical alerts

**Anti-Patterns to Avoid:**

- Multiple queries without recording evidence
- Broad regex patterns in label selectors
- Long time ranges on high-cardinality data
- Duplicate or redundant queries
- Investigation without following question engines
- Ignoring query result validation

## Key Files Reference

| Component | Path |
| ----------- | ------ |
| Blue Orchestrator | `ares-orchestrator/src/blue/` |
| Blue Worker Task Loop | `ares-worker/src/blue_task_loop.rs` |
| Blue CLI Commands | `ares-cli/src/blue/` |
| Core Models | `ares-core/src/models/` |
| State Management | `ares-core/src/state/` |
| Correlation Engine | `ares-core/src/correlation/` |
| Report Generation | `ares-core/src/reports/` |
| Tool Dispatch | `ares-tools/src/` |
| Configuration | `config/ares.yaml` |

## Configuration

### Investigation Configuration

Blue agent configuration in `config/` files:

```yaml
blue_team:
  investigation:
    max_queries: 25  # Hard query limit
    timeout_per_step: 60  # Seconds per investigation step
    timeout_buffer: 120  # Extra seconds before hard timeout
    query_cache_ttl: 300  # Query cache TTL in seconds

  observability:
    loki_timeout: 30  # Loki query timeout
    prometheus_timeout: 30  # Prometheus query timeout
    default_log_limit: 100  # Default log line limit

  reporting:
    format: markdown  # Report format
    include_raw_data: true  # Include appendix with raw data
    export_json: true  # Export JSON alongside markdown
```

## Usage

### Prerequisites

- **API keys** in `.env` or 1Password: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
  `GRAFANA_SERVICE_ACCOUNT_TOKEN`, `DREADNODE_API_KEY`
- **Grafana MCP** configured (see [Grafana MCP Usage](grafana_mcp_usage.md))
- **Redis** accessible (K8s in-cluster, or port-forwarded for local/EC2)
- **ares-cli** binary built (`cargo build --release`)

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

# Single investigation from a red team operation (K8s remote)
task blue:once:remote LATEST=true

# Submit a specific alert JSON file
task blue:investigate ALERT=alert.json

# Continuous poll mode (re-checks every POLL_INTERVAL seconds)
task blue:poll

# Multi-agent investigation via K8s orchestrator
task blue:multi ALERT=alert.json
task blue:multi ALERT=alert.json INVESTIGATION_ID=inv-xxx MULTI_AGENT=true

# Multi-agent from red team operation (K8s remote)
task blue:multi:remote LATEST=true
task blue:multi:remote OPERATION_ID=op-xxx
```

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

# Follow logs
task blue:multi:logs                          # orchestrator only
task blue:multi:logs ALL=true                 # all blue pods
task blue:multi:logs ROLE=threat-hunter       # specific role
```

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

# Export detection playbook (runs on red orchestrator pod)
task blue:playbook LATEST=true
task blue:playbook OPERATION_ID=op-xxx JSON=true

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
`ares-cli` directly. Add `--k8s <NAMESPACE>` for K8s or `--ec2 <NAME>` for
EC2 transport.

```bash
# Submit from red team operation alerts
ares-cli blue from-operation --latest
ares-cli --k8s attack-simulation blue from-operation op-xxx

# Submit a single alert
ares-cli blue submit '{"alert_title":"Suspicious LSASS","severity":"high"}'

# Continuous poll mode
ares-cli blue watch --poll-interval 30 --max-steps 50

# Investigation status and results
ares-cli blue list
ares-cli blue status --latest
ares-cli blue evidence --latest
ares-cli blue evidence --latest --json
ares-cli blue techniques --latest
ares-cli blue runtime --latest
ares-cli blue triage-status --latest
ares-cli blue operation-status --latest --watch 10

# Report generation
ares-cli blue report --latest --output-dir ./reports
ares-cli blue report --operation-id op-xxx --regenerate

# Cleanup
ares-cli blue delete inv-xxx --force
ares-cli blue delete-operation op-xxx --force
ares-cli blue cleanup --max-age-hours 24 --all --force
ares-cli blue cleanup --dry-run
```

### EC2 Deployment

When running on EC2 instead of K8s, port-forward Redis first:

```bash
# Start SSM port-forward (Redis on localhost:16379)
task ec2:redis:forward EC2_NAME=ares-tools

# In another terminal, run blue commands with the forwarded Redis
ARES_REDIS_URL=redis://localhost:16379 ares-cli blue from-operation --latest
```

### Running Blue Alongside Red

Set `BLUE_ENABLED=1` to start blue team investigations automatically when
a red team operation runs:

```bash
task red:ec2:multi TARGET=dreadgoad DOMAIN=sevenkingdoms.local BLUE_ENABLED=1
```

### Taskfile Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL` | config file | LLM model override |
| `POLL_INTERVAL` | `30` | Seconds between poll cycles |
| `MAX_STEPS_BLUE` | `50` | Max agent steps (watch/poll mode) |
| `MAX_STEPS_BLUE_ONCE` | `15` | Max agent steps (once/investigate mode) |
| `GRAFANA_URL` | `https://grafana.dev.plundr.ai` | Grafana instance |
| `K8S_NAMESPACE` | `attack-simulation` | K8s namespace for remote commands |
| `REPORT_DIR` | `./reports` | Report output directory |
| `LOG_DIR` | `./logs` | Log output directory |

## Summary

The **Ares Blue Agent** handles autonomous SOC investigation:

1. Picks up alerts from Grafana
2. Queries Loki and Prometheus with intelligent rate limiting
3. Extracts evidence using the Pyramid of Pain framework
4. Maps to MITRE ATT&CK for tactical context and gap analysis
5. Identifies attack precursors to build complete attack chains
6. Detects lateral movement and expands investigation scope
7. Correlates related alerts to identify campaign patterns
8. Learns from past investigations
9. Generates reports with timelines, recommendations, and evidence
10. Posts annotations back to Grafana

The blue agent cuts investigation time by automating the triage-to-report
pipeline, and the Red-Blue correlation loop surfaces detection gaps that
manual review tends to miss.
