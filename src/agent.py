"""
Ares SOC Investigation Agent.

Main agent implementation using Dreadnode Agent SDK.
"""

import uuid
from datetime import datetime
from pathlib import Path

import dreadnode as dn
from dreadnode.agent.events import AgentStalled, ToolEnd, ToolStart
from dreadnode.agent.hooks import retry_with_feedback
from dreadnode.agent.stop import stop_on_tool_use
from loguru import logger

from .mitre import MITREAttackClient
from .models import InvestigationState
from .tools import (
    GrafanaTools,
    InvestigationTools,
    LokiTools,
    MITRELookupTools,
    PrometheusTools,
    QuestionEngineTools,
    complete_investigation,
    escalate_investigation,
)

# System instructions for the agent
INSTRUCTIONS = """
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
    logger.debug(f"Tool call: {event.tool_call.name}")
    dn.log_metric(f"tool_{event.tool_call.name}", 1, mode="count")


async def log_tool_result(event: ToolEnd):
    """Log tool results."""
    if event.error:
        logger.warning(f"Tool {event.tool_call.name} failed: {event.error}")
        dn.log_metric("tool_errors", 1, mode="count")


# Hook to handle agent stalling
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


class InvestigationOrchestrator:
    """
    Main orchestrator for SOC investigations.

    Creates and manages Dreadnode Agents for investigating alerts.
    """

    def __init__(
        self,
        model: str,
        grafana_url: str,
        loki_url: str,
        prometheus_url: str,
        grafana_api_key: str,
        mitre_client: MITREAttackClient,
        report_dir: Path,
        max_steps: int = 150,
    ):
        self.model = model
        self.grafana_url = grafana_url
        self.loki_url = loki_url
        self.prometheus_url = prometheus_url
        self.grafana_api_key = grafana_api_key
        self.mitre_client = mitre_client
        self.report_dir = report_dir
        self.max_steps = max_steps

    async def investigate(self, alert: dict) -> dict:
        """
        Run a full investigation on an alert.

        Creates a new agent for this investigation and runs it
        until completion or escalation.
        """
        investigation_id = f"inv-{uuid.uuid4().hex[:8]}"
        alert_name = alert.get("labels", {}).get("alertname", "unknown")

        logger.info(f"Starting investigation {investigation_id} for alert: {alert_name}")

        # Create investigation state
        state = InvestigationState(
            investigation_id=investigation_id,
            alert=alert,
        )

        # Create toolsets with state
        loki_tools = LokiTools(base_url=self.loki_url)
        prometheus_tools = PrometheusTools(base_url=self.prometheus_url)
        grafana_tools = GrafanaTools(
            base_url=self.grafana_url,
            api_key=self.grafana_api_key,
        )

        investigation_tools = InvestigationTools()
        investigation_tools.set_state(state)

        question_tools = QuestionEngineTools()
        question_tools.set_engines(self.mitre_client, state)

        mitre_tools = MITRELookupTools()
        mitre_tools.set_client(self.mitre_client)

        # Build initial prompt with alert context
        initial_prompt = self._build_initial_prompt(alert)

        # Create the agent
        with dn.run(tags=["soc-investigation", alert_name]):
            dn.log_params(
                model=self.model,
                investigation_id=investigation_id,
                alert_name=alert_name,
                alert_severity=alert.get("labels", {}).get("severity", "unknown"),
                max_steps=self.max_steps,
            )
            dn.log_input("alert", alert)

            agent = dn.Agent(
                name="Ares SOC Investigator",
                model=self.model,
                instructions=INSTRUCTIONS,
                tools=[
                    loki_tools,
                    prometheus_tools,
                    grafana_tools,
                    investigation_tools,
                    question_tools,
                    mitre_tools,
                    complete_investigation,
                    escalate_investigation,
                ],
                hooks=[
                    log_tool_usage,
                    log_tool_result,
                    unstall_hook,
                ],
                stop_conditions=[
                    stop_on_tool_use("complete_investigation"),
                    stop_on_tool_use("escalate_investigation"),
                ],
            )

            # Run the investigation
            try:
                result = await agent.run(
                    initial_prompt,
                    max_steps=self.max_steps,
                )

                # Generate report
                report_path = self._generate_report(state, result)

                dn.log_output("report_path", str(report_path))
                dn.log_metric("investigation_success", 1)

                return {
                    "investigation_id": investigation_id,
                    "status": "completed" if not state.escalated else "escalated",
                    "report_path": str(report_path),
                    "evidence_count": len(state.evidence),
                    "techniques_identified": list(state.identified_techniques),
                    "highest_pyramid_level": state.highest_pyramid_level,
                }

            except Exception as e:
                logger.error(f"Investigation failed: {e}")
                dn.log_metric("investigation_failed", 1)
                raise

    def _build_initial_prompt(self, alert: dict) -> str:
        """Build the initial prompt with alert context."""
        labels = alert.get("labels", {})
        annotations = alert.get("annotations", {})

        # Extract key information
        alert_name = labels.get("alertname", "Unknown")
        severity = labels.get("severity", "unknown")
        instance = labels.get("instance", "unknown")
        job = labels.get("job", "unknown")

        summary = annotations.get("summary", "No summary provided")
        description = annotations.get("description", "No description provided")

        starts_at = alert.get("startsAt", datetime.utcnow().isoformat())

        return f"""
ALERT RECEIVED - BEGIN INVESTIGATION

Alert Name: {alert_name}
Severity: {severity}
Instance: {instance}
Job: {job}
Started At: {starts_at}

Summary: {summary}

Description: {description}

Full Alert Labels: {labels}

---

Begin your investigation:

1. First, call get_combined_questions() to generate initial questions
2. Parse the alert to understand what triggered it
3. Query Loki/Prometheus to gather initial evidence around the alert time
4. Record all evidence with record_evidence()
5. Continue following the question engines' guidance

Remember: Execute queries in PARALLEL when they are independent.
The goal is to reach TTPs (Pyramid level 6), not just collect IOCs.
"""

    def _generate_report(self, state: InvestigationState, result) -> Path:
        """Generate the markdown investigation report."""
        from .report import MarkdownReportGenerator

        generator = MarkdownReportGenerator(self.report_dir)
        return generator.generate(state)
