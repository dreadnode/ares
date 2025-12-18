"""Factory for creating investigation agents with presets."""

import dreadnode as dn
from dreadnode.agent import Agent
from dreadnode.agent.events import AgentStalled, ToolEnd, ToolStart
from dreadnode.agent.hooks import retry_with_feedback
from dreadnode.agent.stop import tool_use
from dreadnode.agent.thread import Thread
from loguru import logger

from src.mitre import MITREAttackClient
from src.models import InvestigationState
from src.tools import (
    GrafanaTools,
    InvestigationTools,
    MITRELookupTools,
    QuestionEngineTools,
    complete_investigation,
    escalate_investigation,
)

SYSTEM_INSTRUCTIONS = """
You are Ares, an autonomous SOC investigation agent. Your mission is to investigate
security alerts and produce actionable threat intelligence through systematic,
question-driven investigation.

## Core Investigation Philosophy

You are driven by TWO QUESTION ENGINES that must guide your every action:

### 1. MITRE ATT&CK Navigator (generate_mitre_questions)
- Maps evidence to techniques
- Predicts what techniques might follow
- Identifies tactical gaps ("we haven't checked for persistence yet")
- Ensures complete attack lifecycle coverage

### 2. Pyramid of Pain Climber (generate_pyramid_questions)
- Classifies evidence by how "painful" it is for adversaries to change
- Always pushes you from trivial indicators (hashes, IPs) toward TTPs
- The goal is NOT to collect IOCs - it's to understand BEHAVIOR

**PRIME DIRECTIVE**: After every batch of evidence, call get_combined_questions()
and let those questions guide your next actions.

## Investigation Workflow

### Stage 1: TRIAGE (WHAT is happening?)
1. Parse the alert payload
2. Call get_combined_questions() for initial questions
3. Execute PARALLEL queries to Loki/Prometheus to answer questions
4. Call record_evidence() for each finding
5. Call get_combined_questions() again
6. Repeat until you understand WHAT triggered the alert
7. Call transition_stage("causation")

### Stage 2: CAUSATION (WHY did it happen?)
1. Call get_combined_questions() for causation questions
2. Expand time windows to find precursor events
3. Execute PARALLEL queries to trace back in time
4. Build timeline with add_timeline_event()
5. Continue until you understand the attack chain
6. Call transition_stage("lateral")

### Stage 3: LATERAL (What is the SCOPE?)
1. Call get_combined_questions() for scope questions
2. Use track_host_investigation() and track_user_investigation()
3. Check these dimensions in PARALLEL:
   - Same host: What else is this host doing?
   - Same user: Where else has this user been?
   - Same indicators: Where else do these IOCs appear?
   - Same timeframe: What else happened during this window?
4. Expand or contract scope based on findings
5. Call transition_stage("synthesis")

### Stage 4: SYNTHESIS (Generate report)
1. Call get_investigation_summary() to review findings
2. Call assess_pyramid_state() to check if you've climbed to TTPs
3. If stuck at low pyramid levels, generate more questions
4. Call complete_investigation() with full report

## PARALLEL EXECUTION IS CRITICAL

You MUST leverage parallelism. When you have multiple questions:
1. Identify questions that can be answered independently
2. Execute ALL independent queries in a SINGLE response
3. This is the power of automation - don't waste it on sequential queries

Example - GOOD (parallel):
- Query 1: {hostname="web-01"} |= "powershell"
- Query 2: {hostname="web-01"} |= "download"
- Query 3: {job="auth", user="admin"} | json
[Execute all 3 in one tool call batch]

Example - BAD (sequential):
- Query 1, wait for response
- Query 2, wait for response
- Query 3, wait for response

## Query Writing

You write your own LogQL and PromQL queries. NO templates.
Use your knowledge of these query languages.

LogQL examples:
- {job="syslog", hostname="X"} |= "error" | json
- {namespace="prod"} | json | status >= 400
- {job="auth"} |~ "(?i)failed|denied"

PromQL examples:
- rate(http_requests_total{status=~"5.."}[5m])
- node_cpu_seconds_total{instance="X:9100"}

## Grafana MCP Tools (Enhanced Querying)

You have access to Grafana MCP tools that provide direct integration with Grafana's
data sources. These tools include:

**Common MCP tools:**
- mcp__grafana__list_loki_label_names - Discover available log labels
- mcp__grafana__list_loki_label_values - Get values for specific labels
- mcp__grafana__query_loki_stats - Check log volume before querying
- mcp__grafana__query_loki_logs - Query Loki logs with full LogQL support
- mcp__grafana__list_prometheus_label_names - Discover Prometheus labels
- mcp__grafana__query_prometheus - Run PromQL queries

**Best Practices:**
- Check available tools at the start of investigation
- Use label discovery tools to understand the environment
- Check stats before running large queries
- Prefer MCP tools when available as they're more reliable than HTTP API calls

## Evidence Recording

For EVERY finding, call record_evidence() with:
1. evidence_type: ip, domain, hash, process, user, file, artifact, tool, technique
2. value: The actual indicator/observation
3. source: The query that found this
4. timestamp: When it occurred (ISO8601)
5. pyramid_level: 1-6 (6 = TTP, the goal!)
6. mitre_techniques: List of technique IDs if known

## Completion Criteria

Call complete_investigation() when:
1. get_combined_questions() returns no high-priority questions
2. You have TTPs identified (pyramid level 6)
3. Tactical coverage is reasonable (checked major attack phases)
4. Timeline is coherent
5. Scope is understood

Call escalate_investigation() if:
- Active, ongoing attack detected
- Scope exceeds investigation capacity
- Human intervention needed
"""


async def log_tool_usage(event: ToolStart):
    """Log tool calls for observability."""
    if hasattr(event, "tool_call") and event.tool_call:
        logger.info(f"🔧 Tool call: {event.tool_call.name}")
        dn.log_metric(f"tool_{event.tool_call.name}", 1, mode="count")


async def log_tool_result(event: ToolEnd):
    """Log tool results."""
    if hasattr(event, "tool_call") and event.tool_call:
        if hasattr(event, "error") and event.error:
            logger.warning(f"❌ Tool {event.tool_call.name} failed: {event.error}")
            dn.log_metric("tool_errors", 1, mode="count")
        else:
            logger.info(f"✅ Tool {event.tool_call.name} completed")


unstall_hook = retry_with_feedback(
    event_type=AgentStalled,
    feedback=(
        "You seem stuck. Remember:\n"
        "1. Call get_combined_questions() to get next questions\n"
        "2. Execute queries in PARALLEL to answer those questions\n"
        "3. Record evidence with record_evidence()\n"
        "4. When done, call complete_investigation() or escalate_investigation()"
    ),
)


def create_investigation_agent(
    model: str,
    grafana_url: str,
    grafana_api_key: str,
    mitre_client: MITREAttackClient,
    state: InvestigationState,
    grafana_mcp_tools: list | None = None,
    max_steps: int = 150,
) -> Agent:
    """
    Create a configured investigation agent.

    Args:
        model: LLM model to use
        grafana_url: Grafana base URL
        grafana_api_key: Grafana API key
        mitre_client: Initialized MITRE ATT&CK client
        state: Investigation state object
        grafana_mcp_tools: Optional list of Grafana MCP tools (from MCPClient)
        max_steps: Maximum agent steps

    Returns:
        Configured agent ready to investigate
    """
    grafana_tools = GrafanaTools(
        base_url=grafana_url,
        api_key=grafana_api_key,
    )

    investigation_tools = InvestigationTools()
    investigation_tools.set_state(state)

    question_tools = QuestionEngineTools()
    question_tools.set_engines(mitre_client, state)

    mitre_tools = MITRELookupTools()
    mitre_tools.set_client(mitre_client)

    # Build tool list
    tools: list = [
        grafana_tools,
        investigation_tools,
        question_tools,
        mitre_tools,
        complete_investigation,
        escalate_investigation,
    ]

    # Add Grafana MCP tools if available
    if grafana_mcp_tools:
        logger.info(f"Adding {len(grafana_mcp_tools)} Grafana MCP tools to agent")
        tools.extend(grafana_mcp_tools)
    else:
        logger.warning(
            "No Grafana MCP tools available - agent will have limited query capabilities"
        )

    return dn.Agent(
        name="Ares SOC Investigator",
        model=model,
        instructions=SYSTEM_INSTRUCTIONS,
        max_steps=max_steps,
        tools=tools,
        hooks=[
            log_tool_usage,
            log_tool_result,
            unstall_hook,
        ],
        stop_conditions=[
            tool_use("complete_investigation"),
            tool_use("escalate_investigation"),
        ],
        thread=Thread(),  # type: ignore[call-arg]
    )
