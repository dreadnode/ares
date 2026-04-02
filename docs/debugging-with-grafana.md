# Debugging Ares Operations with Grafana

Step-by-step methodology for diagnosing attack path failures
using Grafana dashboards, Prometheus span metrics, and Loki
logs. This is the primary debugging workflow for understanding
why operations succeed or fail.

## Overview

The Ares system emits OpenTelemetry traces that flow through
Tempo into Prometheus (via span metrics) and logs into Loki.
Grafana ties these together. The debugging workflow is:

1. **Prometheus span metrics** -- quantitative: what happened,
   how much, success/fail rates
2. **Loki logs** -- qualitative: why things failed, error
   messages, orchestrator decisions
3. **Tempo traces** -- deep dive: individual operation trace
   analysis

## Dashboards

| Dashboard                    | UID                          | Use For                      |
| ---------------------------- | ---------------------------- | ---------------------------- |
| Attack Simulation - Overview | `attack-simulation-overview` | Health, agents, error rates  |
| Attack Chain Traces          | `attack-chain-traces`        | Technique breakdown, DA      |
| Attack Operation Summary     | `attack-operation-summary`   | Single operation deep dive   |
| Attack Graph                 | `attack-graph`               | Visual network traversal     |

## Step 1: Assess Overall Health (Prometheus)

Start with high-level metrics to understand the scope of
the problem.

### Active agents and error rate

```promql
-- Active agents
count(count by (service) (rate(traces_spanmetrics_calls_total{
  service_namespace="attack-simulation",
  service=~"ares-.*"
}[5m]) > 0))

-- Error rate (%)
sum(rate(traces_spanmetrics_calls_total{
  service_namespace="attack-simulation",
  status_code="STATUS_CODE_ERROR"
}[5m])) / sum(rate(traces_spanmetrics_calls_total{
  service_namespace="attack-simulation"
}[5m])) * 100 or vector(0)
```

### Agent trace volume (who's busy, who's idle)

```promql
sum by (service) (increase(traces_spanmetrics_calls_total{
  service_namespace="attack-simulation",
  service=~"ares-.*"
}[7d]))
```

Low volume on a specific agent (e.g., `ares-acl-agent`)
may indicate it's not receiving tasks.

## Step 2: Check Attack Milestones (Prometheus)

Determine if the kill chain is completing.

### Domain Admin achievements

```promql
-- Count
sum(increase(traces_spanmetrics_calls_total{
  service_namespace="attack-simulation",
  span_name="discovery.domain_admin"
}[7d])) or vector(0)

-- Breakdown by domain and attack path
sum by (user_name, attack_target_domain, credential_type, attack_path) (
  increase(traces_spanmetrics_calls_total{
    service_namespace="attack-simulation",
    span_name="discovery.domain_admin"
  }[7d])
) > 0
```

### Golden Tickets forged

```promql
-- Count
sum(increase(traces_spanmetrics_calls_total{
  service_namespace="attack-simulation",
  span_name="discovery.golden_ticket"
}[7d])) or vector(0)

-- Breakdown by target domain and forest escalation
sum by (attack_target_domain, source_domain, is_forest_escalation) (
  increase(traces_spanmetrics_calls_total{
    service_namespace="attack-simulation",
    span_name="discovery.golden_ticket"
  }[7d])
) > 0
```

If a domain shows DA but no golden tickets (or vice
versa), there's a gap in the escalation chain.

## Step 3: Analyze Tactic and Technique Distribution (Prometheus)

Understand what the agents are actually doing.

### By MITRE tactic

```promql
sum by (mitre_tactic) (increase(traces_spanmetrics_calls_total{
  service_namespace="attack-simulation",
  mitre_tactic!=""
}[7d]))
```

Expected healthy distribution: discovery > C2 >
credential-access > privilege-escalation >
lateral-movement. If lateral movement is zero,
agents aren't pivoting.

### Top techniques

```promql
topk(15, sum by (mitre_technique_id, mitre_technique_name) (
  increase(traces_spanmetrics_calls_total{
    service_namespace="attack-simulation",
    mitre_technique_id!=""
  }[7d])
))
```

### Tool success/failure

```promql
topk(30, sum by (span_name, tool_status) (
  increase(traces_spanmetrics_calls_total{
    service_namespace="attack-simulation",
    span_name=~"tool\\..*",
    tool_status!=""
  }[7d])
))
```

High failure rates on specific tools point to configuration
issues, missing binaries, or credential problems.

## Step 4: Target and Lateral Movement Analysis (Prometheus)

### What hosts are being targeted

```promql
topk(20, sum by (destination_address, attack_target_type) (
  increase(traces_spanmetrics_calls_total{
    service_namespace="attack-simulation",
    destination_address=~"[a-zA-Z0-9].*\\..*",
    destination_address!~".* .*|.*\\$"
  }[7d])
))
```

If a target domain's hosts don't appear here, agents
aren't reaching them.

### Lateral movement paths

```promql
sum by (destination_address, user_name) (
  increase(traces_spanmetrics_calls_total{
    service_namespace="attack-simulation",
    mitre_tactic="lateral-movement",
    destination_address=~"[a-zA-Z0-9].*\\..*",
    destination_address!~".* .*|.*\\$"
  }[7d])
) > 0
```

### Discoveries (credentials, weaknesses, etc.)

```promql
topk(20, sum by (discovery_type, user_name, weakness_type, attack_target_domain) (
  increase(traces_spanmetrics_calls_total{
    service_namespace="attack-simulation",
    span_name=~"discovery\\..*"
  }[7d])
))
```

## Step 5: Diagnose Failures with Loki Logs

Once Prometheus tells you _what_ is failing, Loki tells
you _why_.

### Common log queries

All queries use namespace `attack-simulation`. Adjust time
range as needed.

```logql
-- Cross-forest / trust related
{namespace="attack-simulation"} |= "essos"
{namespace="attack-simulation"} |= "trust" |= "error"
{namespace="attack-simulation"} |= "cross-forest"
{namespace="attack-simulation"} |= "inter_realm"
{namespace="attack-simulation"} |= "forest" |= "fail"

-- Golden ticket issues
{namespace="attack-simulation"} |= "golden_ticket" |= "error"
{namespace="attack-simulation"} |= "GOLDEN_TICKET"

-- Credential failures
{namespace="attack-simulation"} |= "52e"
{namespace="attack-simulation"} |= "invalidCredentials"

-- Task dispatch and retry loops
{namespace="attack-simulation"} |= "Will retry"
{namespace="attack-simulation"} |= "Maximum steps reached"
{namespace="attack-simulation"} |= "Task timeout"

-- Orchestrator decisions
{namespace="attack-simulation", app="ares-orchestrator"} |= "undominated"
{namespace="attack-simulation", app="ares-orchestrator"} |= "auto_cross_forest"
{namespace="attack-simulation", app="ares-orchestrator"} |= "trust_extraction"

-- Tool execution failures
{namespace="attack-simulation"} |= "Command failed"
{namespace="attack-simulation"} |= "code=127"

-- Specific domain investigation (replace domain as needed)
{namespace="attack-simulation"} |= "essos.local" |= "error"
{namespace="attack-simulation"} |= "essos.local" |= "dispatch"
```

### What to look for in logs

| Pattern | Indicates |
| --- | --- |
| `GOLDEN_TICKET` + `52e` | Credential placeholder auth |
| `SPN target name validation` | Impacket cross-realm bug |
| `Command failed (code=127)` | Missing tool binary |
| `Will retry` in a loop | Repeated task failure |
| `undominated=['domain.local']` | Known but unconquered domain |
| `no DC IP for` | DC not mapped |
| `no DA credentials` | Trust extraction blocked |
| `skipping trust extraction` | Multi-forest off or dedup |

## Step 6: Trace Deep Dive (Tempo)

For individual operation analysis, use the Attack Operation
Summary dashboard with a specific `operation_id`. This shows:

- Full event timeline
- All techniques used in sequence
- Hosts accessed
- Credentials discovered
- Tool pass/fail breakdown

## Step 7: Trend Analysis (Prometheus Range Queries)

To see how attack phases progress over time:

```promql
sum by (attack_phase) (
  rate(traces_spanmetrics_calls_total{
    service_namespace="attack-simulation",
    attack_phase!=""
  }[1h])
) * 60
```

Query as a range (e.g., 7d, step 3600s) to see phase
progression. Healthy operations show:

1. Discovery spike first
2. Credential-theft follows
3. Privilege-escalation ramps up
4. Lateral-movement appears last

If a phase flatlines while earlier phases continue,
something is blocking progression.

## Datasources

| Datasource | UID              | Purpose                    |
| ---------- | ---------------- | -------------------------- |
| Prometheus | `prometheus`     | Span metrics (counts, etc) |
| Loki       | `loki`           | Application logs           |
| Tempo      | (via dashboards) | Distributed traces         |

## Example: Debugging Cross-Forest Failure

Real example of diagnosing why essos.local wasn't being
attacked consistently:

1. **Prometheus showed**: DA achieved ~2x on essos.local
   vs ~103x on north.sevenkingdoms.local. Golden tickets
   forged ~1x for essos vs ~181x for sevenkingdoms.local.
   Massive disparity.

2. **Prometheus tactic breakdown showed**: Lateral movement
   to essos targets was zero in the last 7d.

3. **Loki logs revealed 4 root causes**:
   - `GOLDEN_TICKET` string used as LDAP password,
     causing infinite `52e` retry loops
   - Inter-realm DCSync blocked by SPN target name
     validation (patched DC + impacket limitation)
   - `printerbug.py` missing from worker containers
     (`code=127`), blocking unconstrained delegation
   - Wrong-domain credentials routed to essos.local
     ADCS enumeration

4. **Orchestrator logs confirmed** it knew essos was
   undominated (`undominated=['essos.local']`) and kept
   dispatching tasks, but every path hit a wall.

This combination of quantitative (Prometheus) + qualitative
(Loki) analysis pinpointed the exact blockers in ~10 minutes.
