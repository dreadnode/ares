# Blue Agent Documentation

## Overview

The **Ares Blue Agent** is an autonomous SOC (Security Operations Center)
investigation system that ingests Grafana alerts and conducts intelligent,
multi-stage security investigations. It queries observability data (Loki logs,
Prometheus metrics), extracts validated evidence, maps findings to the MITRE
ATT&CK framework, and generates comprehensive investigation reports.

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

**Location:** `src/ares/agents/blue/soc_investigator.py`

The `InvestigationOrchestrator` manages the full investigation lifecycle:

- Creates and configures Dreadnode Agents for investigating Grafana alerts
- Establishes MCP (Model Context Protocol) connections to Grafana
- Enforces hard timeout watchdog (1 min/step + 2 min buffer)
- Generates partial reports on timeout
- Handles investigation state persistence

#### Investigation Agent Factory

**Location:** `src/ares/core/factories/blue_factory.py`

Creates pre-configured investigation agents with:

- Adaptive query limits based on alert severity and stage
- Query optimization and duplicate detection
- Rate limiting to prevent resource abuse
- Automatic retry with exponential backoff
- Resilience mechanisms for failed queries

#### Investigation State Model

**Location:** `src/ares/core/models.py`

The `InvestigationState` model tracks:

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

**Location:** `src/ares/tools/blue/investigation.py`

#### Evidence Recording

```python
record_evidence(
    evidence_type: EvidenceType,  # ip, domain, hash, process, file, user, etc.
    value: str,
    pyramid_level: int,  # 1=Hash Values, 6=TTPs
    mitre_techniques: List[str],
    confidence: float,  # 0.0-1.0
    description: str,
    source_query: Optional[str]
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

```python
add_timeline_event(
    timestamp: str,
    description: str,
    mitre_technique: Optional[str],
    evidence_ids: List[str],
    severity: str  # info, low, medium, high, critical
)
```

#### Investigation Tracking

```python
track_host_investigation(hostname: str)
track_user_investigation(username: str)
```

### Completion Tools

**Location:** `src/ares/tools/blue/actions.py`

```python
complete_investigation(
    attack_synopsis: str,
    recommendations: List[str],
    should_escalate: bool = False,
    escalation_reason: Optional[str] = None
)
```

Finalizes investigation with:

- Attack summary and recommendations
- Automatic response guidance extraction from alert annotations
- Fallback synopsis generation from collected evidence
- Investigation report generation trigger

### Grafana Integration Tools

**Location:** `src/ares/tools/blue/grafana.py`

```python
get_firing_alerts() -> List[Alert]
get_alert_history(alert_name: str, lookback_hours: int) -> List[Alert]
post_investigation_started(investigation_id: str, alert_name: str)
post_investigation_completed(investigation_id: str, report_url: str)
```

Features:

- MCP connection management (60s timeout with fallback)
- Multi-endpoint support for different Grafana versions
- Automatic annotation creation on Grafana dashboards

### Observability Tools

**Location:** `src/ares/tools/blue/observability.py`

#### LokiTools - LogQL Queries

```python
query_loki(
    logql: str,
    start_time: str,
    end_time: str,
    limit: int = 100
) -> List[LogLine]
```

Features:

- Query validation and optimization
- Regex error detection (catches empty-compatible patterns like `.*`)
- Label matchers, line filters, parsers support
- Result streaming with configurable line limits
- Automatic time range adjustment on timeout

#### PrometheusTools - PromQL Queries

```python
query_prometheus_instant(query: str, time: str)
query_prometheus_range(query: str, start: str, end: str, step: str)
get_metric_metadata(metric: str)
```

### Query Template Tools

**Location:** `src/ares/tools/blue/query_templates.py`

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

**Location:** `src/ares/tools/blue/investigation.py`

```python
get_combined_questions() -> List[InvestigativeQuestion]
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

**Location:** `src/ares/tools/blue/learning.py`

```python
find_similar_investigations(
    alert_name: str,
    mitre_techniques: List[str],
    severity: str
) -> List[Investigation]
```

Features:

- Historical investigation lookup
- Query effectiveness statistics
- False positive pattern learning
- Investigation pattern matching

### MITRE Lookup Tools

**Location:** `src/ares/tools/blue/mitre.py`

- Technique name resolution
- Tactic mapping (Reconnaissance, Initial Access, Execution, etc.)
- Attack lifecycle coverage analysis
- Technique relationship mapping

## Detection & Response Features

### Alert Correlation

**Location:** `src/ares/core/alert_correlation.py`

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

**Location:** `src/ares/core/lateral_analyzer.py`

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

**Location:** `src/ares/core/correlation.py`

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

**Location:** `src/ares/core/evidence_validation.py`

Automatic validation of recorded evidence:

- IOC extraction from query results
- Validation against recent query results
- Confidence adjustment based on validation status
- Suggested IOCs from query data
- Source query tracking for provenance

### Query Resilience

**Location:** `src/ares/core/query_resilience.py`

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
See `.claude/CLAUDE.md` for MCP server installation instructions.

### Markdown Report Generation

**Location:** `src/ares/reports/investigation.py`

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
| Investigation Orchestrator | `src/ares/agents/blue/soc_investigator.py` |
| Agent Factory & Query Limits | `src/ares/core/factories/blue_factory.py` |
| Investigation Tools | `src/ares/tools/blue/investigation.py` |
| Completion Tools | `src/ares/tools/blue/actions.py` |
| Grafana Integration | `src/ares/tools/blue/grafana.py` |
| Query Templates | `src/ares/tools/blue/query_templates.py` |
| Learning Tools | `src/ares/tools/blue/learning.py` |
| Observability (Loki/Prometheus) | `src/ares/tools/blue/observability.py` |
| Alert Correlation | `src/ares/core/alert_correlation.py` |
| Lateral Movement Analysis | `src/ares/core/lateral_analyzer.py` |
| Red-Blue Correlation | `src/ares/core/correlation.py` |
| Evidence Validation | `src/ares/core/evidence_validation.py` |
| Report Generation | `src/ares/reports/investigation.py` |
| Investigation Models | `src/ares/core/models.py` |

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

### Running an Investigation

```python
from ares.agents.blue.soc_investigator import InvestigationOrchestrator
from ares.core.models import AlertContext

# Create alert context
alert = AlertContext(
    alert_name="Suspicious PowerShell Execution",
    firing_timestamp="2024-01-27T10:00:00Z",
    severity="high",
    labels={"host": "web-01", "job": "eventlog"},
    annotations={"description": "Encoded PowerShell command detected"}
)

# Run investigation
orchestrator = InvestigationOrchestrator()
result = await orchestrator.investigate(alert)

# Result includes:
# - investigation_id
# - report_path (markdown)
# - report_json_path (JSON)
# - investigation_state (complete state object)
```

### Viewing Investigation Results

Investigation reports are written to the configured output directory and include:

- Markdown report with full analysis
- JSON export for programmatic access
- Grafana annotations linking to the report

## Summary

The **Ares Blue Agent** provides autonomous, intelligent SOC investigation
capabilities that:

1. **Ingest alerts** from Grafana and initiate investigations
2. **Query observability data** (Loki, Prometheus) with intelligent rate limiting
3. **Extract validated evidence** using the Pyramid of Pain framework
4. **Map to MITRE ATT&CK** for tactical context and gap analysis
5. **Identify attack precursors** to build complete attack chains
6. **Detect lateral movement** and expand investigation scope
7. **Correlate related alerts** to identify campaign patterns
8. **Learn from history** using past investigations as guidance
9. **Generate comprehensive reports** with timelines, recommendations, and evidence
10. **Integrate with Grafana** for seamless alert management

The blue agent accelerates SOC workflows, improves detection coverage through
Red-Blue correlation, and provides consistent, thorough investigations at
scale.
