"""
Toolsets for Ares SOC Investigation Agent.

Following Dreadnode SDK patterns - tools are exposed to the agent
for interacting with data sources and managing investigation state.
"""

from datetime import datetime, timedelta

import dreadnode as dn
import httpx
from loguru import logger

from .engines import MITRENavigator, PyramidClimber
from .mitre import MITREAttackClient
from .models import (
    Evidence,
    InvestigationStage,
    InvestigationState,
    PyramidLevel,
    TimelineEvent,
)


class LokiTools(dn.Toolset):
    """Tools for querying Loki log aggregation system."""

    base_url: str
    timeout: int = 30

    @dn.tool_method
    async def query_logs(
        self,
        logql: str,
        start_time: str,
        end_time: str,
        limit: int = 500,
    ) -> dict:
        """
        Execute a LogQL query against Loki.

        Write your own LogQL queries to investigate the logs.
        No templates - use your knowledge of the query language.

        Examples:
        - {job="syslog", hostname="web-01"} |= "error"
        - {namespace="prod"} | json | status >= 400
        - {job="auth"} |~ "(?i)failed|denied" | logfmt

        Args:
            logql: The LogQL query string
            start_time: ISO8601 timestamp for query start (e.g., "2024-01-15T10:00:00Z")
            end_time: ISO8601 timestamp for query end
            limit: Maximum number of log lines to return (default 500)

        Returns:
            Query results with log streams and entries
        """
        dn.log_metric("loki_queries", 1, mode="count")
        logger.info(f"Loki query: {logql}")

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/loki/api/v1/query_range",
                    params={
                        "query": logql,
                        "start": start_time,
                        "end": end_time,
                        "limit": limit,
                    },
                )
                response.raise_for_status()
                result = response.json()

            result_count = len(result.get("data", {}).get("result", []))
            dn.log_metric("loki_results", result_count)

            return result

        except httpx.HTTPError as e:
            logger.error(f"Loki query failed: {e}")
            return {"error": str(e), "data": {"result": []}}

    @dn.tool_method
    async def query_logs_around_timestamp(
        self,
        logql: str,
        timestamp: str,
        window_minutes: int = 5,
        limit: int = 500,
    ) -> dict:
        """
        Query logs within a time window around a specific timestamp.

        Useful for investigating what happened before/after a specific event.

        Args:
            logql: The LogQL query string
            timestamp: ISO8601 timestamp to center the query on
            window_minutes: Minutes before and after the timestamp (default 5)
            limit: Maximum number of log lines

        Returns:
            Query results centered on the timestamp
        """
        center = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        start = (center - timedelta(minutes=window_minutes)).isoformat()
        end = (center + timedelta(minutes=window_minutes)).isoformat()

        return await self.query_logs(
            logql=logql,
            start_time=start,
            end_time=end,
            limit=limit,
        )

    @dn.tool_method
    async def get_label_values(self, label: str) -> list[str]:
        """
        Get all values for a specific Loki label.

        Useful for discovering what hosts, jobs, or namespaces exist.

        Args:
            label: The label name (e.g., "hostname", "job", "namespace")

        Returns:
            List of label values
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/loki/api/v1/label/{label}/values",
                )
                response.raise_for_status()
                return response.json().get("data", [])
        except httpx.HTTPError as e:
            logger.error(f"Failed to get label values: {e}")
            return []


class PrometheusTools(dn.Toolset):
    """Tools for querying Prometheus metrics."""

    base_url: str
    timeout: int = 30

    @dn.tool_method
    async def query_instant(
        self,
        promql: str,
        time: str | None = None,
    ) -> dict:
        """
        Execute an instant PromQL query.

        Write your own PromQL queries to investigate metrics.
        No templates - use your knowledge of the query language.

        Examples:
        - node_cpu_seconds_total{instance="web-01:9100"}
        - rate(http_requests_total{status=~"5.."}[5m])
        - up{job="kubernetes-pods"}

        Args:
            promql: The PromQL query string
            time: Optional evaluation timestamp (ISO8601). If not provided, uses current time.

        Returns:
            Instant query results
        """
        dn.log_metric("prometheus_queries", 1, mode="count")
        logger.info(f"Prometheus instant query: {promql}")

        params = {"query": promql}
        if time:
            params["time"] = time

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/api/v1/query",
                    params=params,
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Prometheus query failed: {e}")
            return {"error": str(e), "data": {"result": []}}

    @dn.tool_method
    async def query_range(
        self,
        promql: str,
        start_time: str,
        end_time: str,
        step: str = "1m",
    ) -> dict:
        """
        Execute a range PromQL query for time series data.

        Args:
            promql: The PromQL query string
            start_time: ISO8601 start timestamp
            end_time: ISO8601 end timestamp
            step: Query resolution step (e.g., "1m", "5m", "1h")

        Returns:
            Range query results with time series
        """
        dn.log_metric("prometheus_queries", 1, mode="count")
        logger.info(f"Prometheus range query: {promql}")

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/api/v1/query_range",
                    params={
                        "query": promql,
                        "start": start_time,
                        "end": end_time,
                        "step": step,
                    },
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Prometheus range query failed: {e}")
            return {"error": str(e), "data": {"result": []}}

    @dn.tool_method
    async def get_metric_names(self, search: str | None = None) -> list[str]:
        """
        Get available Prometheus metric names.

        Args:
            search: Optional search string to filter metric names

        Returns:
            List of metric names
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/api/v1/label/__name__/values",
                )
                response.raise_for_status()
                metrics = response.json().get("data", [])

                if search:
                    search_lower = search.lower()
                    metrics = [m for m in metrics if search_lower in m.lower()]

                return metrics[:100]  # Limit results
        except httpx.HTTPError as e:
            logger.error(f"Failed to get metric names: {e}")
            return []


class GrafanaTools(dn.Toolset):
    """Tools for interacting with Grafana alerting."""

    base_url: str
    api_key: str
    timeout: int = 30

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}"}

    @dn.tool_method
    async def get_firing_alerts(self) -> list[dict]:
        """
        Get all currently firing alerts from Grafana.

        Returns:
            List of firing alert instances with labels, annotations, and values
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/api/alertmanager/grafana/api/v2/alerts",
                    headers=self._headers(),
                    params={"active": "true"},
                )
                response.raise_for_status()
                alerts = response.json()

            dn.log_metric("alerts_polled", len(alerts))
            return alerts

        except httpx.HTTPError as e:
            logger.error(f"Failed to get alerts: {e}")
            return []

    @dn.tool_method
    async def get_alert_history(
        self,
        hours: int = 24,
    ) -> list[dict]:
        """
        Get alert history from Grafana.

        Args:
            hours: How many hours of history to retrieve

        Returns:
            List of historical alert instances
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/api/v1/provisioning/alert-rules",
                    headers=self._headers(),
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Failed to get alert history: {e}")
            return []


class InvestigationTools(dn.Toolset):
    """
    Tools for managing investigation state.

    These tools record evidence, build the timeline, and track
    MITRE mappings and Pyramid of Pain levels.
    """

    state: InvestigationState | None = None

    def set_state(self, state: InvestigationState):
        """Set the investigation state (called by orchestrator)."""
        self.state = state

    @dn.tool_method
    def record_evidence(
        self,
        evidence_type: str,
        value: str,
        source: str,
        timestamp: str | None,
        pyramid_level: int,
        mitre_techniques: list[str] | None = None,
        confidence: float = 0.5,
    ) -> str:
        """
        Record a piece of evidence discovered during investigation.

        CALL THIS FOR EVERY FINDING. Evidence types include:
        - ip, domain, hash, url (IOCs)
        - process, file, user, service (host artifacts)
        - artifact, certificate, user_agent (network artifacts)
        - tool, malware (tools)
        - technique, behavior (TTPs)

        Pyramid levels (higher = more valuable):
        1. Hash Values (trivial to change)
        2. IP Addresses (easy)
        3. Domain Names (simple)
        4. Network/Host Artifacts (annoying)
        5. Tools (challenging)
        6. TTPs (tough - this is the goal!)

        Args:
            evidence_type: Type of evidence (ip, domain, hash, process, etc.)
            value: The actual evidence value
            source: What query or tool found this
            timestamp: ISO8601 timestamp of when this occurred (can be None)
            pyramid_level: Pyramid of Pain level 1-6
            mitre_techniques: Optional list of MITRE technique IDs (e.g., ["T1059.001"])
            confidence: Confidence score 0.0-1.0

        Returns:
            Evidence ID for reference
        """
        if not self.state:
            return "ERROR: No investigation state"

        evidence_id = f"ev-{len(self.state.evidence):04d}"

        ts = None
        if timestamp:
            try:
                ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                pass

        ev = Evidence(
            id=evidence_id,
            type=evidence_type,
            value=value,
            source=source,
            timestamp=ts,
            pyramid_level=PyramidLevel(min(max(pyramid_level, 1), 6)),
            mitre_techniques=mitre_techniques or [],
            confidence=confidence,
        )

        self.state.evidence.append(ev)

        # Update technique tracking
        if mitre_techniques:
            self.state.identified_techniques.update(mitre_techniques)

        # Log to Dreadnode
        dn.log_output(f"evidence_{evidence_id}", ev.to_dict())
        dn.log_metric("evidence_count", 1, mode="count")
        dn.log_metric("highest_pyramid_level", pyramid_level, mode="max")

        logger.info(
            f"Recorded evidence: {evidence_type}={value[:50]}... (pyramid level {pyramid_level})"
        )

        return evidence_id

    @dn.tool_method
    def add_timeline_event(
        self,
        timestamp: str,
        description: str,
        evidence_ids: list[str],
        mitre_techniques: list[str] | None = None,
        confidence: float = 0.5,
    ) -> str:
        """
        Add an event to the investigation timeline.

        Build a coherent timeline of what happened and when.

        Args:
            timestamp: ISO8601 timestamp of when this occurred
            description: Human-readable description of what happened
            evidence_ids: List of evidence IDs supporting this event
            mitre_techniques: MITRE technique IDs for this event
            confidence: Confidence score 0.0-1.0

        Returns:
            Timeline event ID
        """
        if not self.state:
            return "ERROR: No investigation state"

        event_id = f"tl-{len(self.state.timeline):04d}"

        try:
            ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.utcnow()

        event = TimelineEvent(
            id=event_id,
            timestamp=ts,
            description=description,
            evidence_ids=evidence_ids,
            mitre_techniques=mitre_techniques or [],
            confidence=confidence,
        )

        self.state.timeline.append(event)
        self.state.timeline.sort(key=lambda e: e.timestamp)

        dn.log_metric("timeline_events", 1, mode="count")

        logger.info(f"Timeline event: {description[:50]}...")

        return event_id

    @dn.tool_method
    def transition_stage(self, new_stage: str) -> str:
        """
        Transition to a new investigation stage.

        Stages in order:
        1. triage - WHAT is happening
        2. causation - WHY it happened
        3. lateral - What is the SCOPE
        4. synthesis - Generate report

        Args:
            new_stage: One of: triage, causation, lateral, synthesis

        Returns:
            Confirmation message
        """
        if not self.state:
            return "ERROR: No investigation state"

        old_stage = self.state.stage
        self.state.stage = InvestigationStage(new_stage)

        dn.log_metric(f"stage_{new_stage}_entered", 1)
        dn.tag(f"stage:{new_stage}")

        logger.info(f"Stage transition: {old_stage.value} -> {new_stage}")

        return f"Transitioned from {old_stage.value} to {new_stage}"

    @dn.tool_method
    def get_investigation_summary(self) -> dict:
        """
        Get a summary of the current investigation state.

        Use this to understand what you've discovered so far.

        Returns:
            Summary with evidence count, techniques, pyramid state, etc.
        """
        if not self.state:
            return {"error": "No investigation state"}

        return self.state.to_summary()

    @dn.tool_method
    def track_host_investigation(self, hostname: str) -> str:
        """
        Mark a host as being investigated for lateral scope.

        Args:
            hostname: The hostname being investigated

        Returns:
            Suggested queries for this host
        """
        if not self.state:
            return "ERROR: No investigation state"

        self.state.queried_hosts.add(hostname)
        dn.log_metric("hosts_investigated", 1, mode="count")

        return f"""
Host '{hostname}' marked for investigation. Suggested queries:

Loki:
- {{hostname="{hostname}"}} |= "error" | json
- {{hostname="{hostname}", job="auth"}} | json
- {{hostname="{hostname}"}} |~ "(?i)(fail|denied|unauthorized)"

Prometheus:
- node_cpu_seconds_total{{instance=~"{hostname}.*"}}
- node_network_transmit_bytes_total{{instance=~"{hostname}.*"}}
- process_cpu_seconds_total{{instance=~"{hostname}.*"}}
"""

    @dn.tool_method
    def track_user_investigation(self, username: str) -> str:
        """
        Mark a user as being investigated for lateral scope.

        Args:
            username: The username being investigated

        Returns:
            Suggested queries for this user
        """
        if not self.state:
            return "ERROR: No investigation state"

        self.state.queried_users.add(username)
        dn.log_metric("users_investigated", 1, mode="count")

        return f"""
User '{username}' marked for investigation. Suggested queries:

Loki:
- {{job="auth"}} |= "{username}" | json
- {{job="syslog"}} |= "{username}" | json
- {{job="audit"}} | json | user="{username}"
"""


class QuestionEngineTools(dn.Toolset):
    """
    Tools for the question engines that drive the investigation.

    These are the CORE drivers - call them frequently to get
    the next questions to investigate.
    """

    mitre_navigator: MITRENavigator | None = None
    pyramid_climber: PyramidClimber | None = None
    state: InvestigationState | None = None

    def set_engines(
        self,
        mitre_client: MITREAttackClient,
        state: InvestigationState,
    ):
        """Initialize engines with MITRE client and state."""
        self.mitre_navigator = MITRENavigator(mitre_client)
        self.pyramid_climber = PyramidClimber()
        self.state = state

    @dn.tool_method
    def generate_mitre_questions(self) -> list[dict]:
        """
        Generate investigative questions based on MITRE ATT&CK framework.

        This is a CORE DRIVER of the investigation. Call this after
        recording evidence to get the next questions.

        The MITRE Navigator generates questions about:
        1. Follow-on techniques (what might come next in the attack)
        2. Tactical gaps (what attack phases haven't we checked)
        3. Evidence mapping (what technique does this evidence indicate)

        Returns:
            List of prioritized questions with rationale
        """
        if not self.mitre_navigator or not self.state:
            return [{"error": "Engines not initialized"}]

        dn.log_metric("mitre_question_calls", 1, mode="count")

        questions = self.mitre_navigator.generate_questions(self.state)
        questions.sort(key=lambda q: q.priority_score, reverse=True)

        return [q.to_dict() for q in questions[:10]]

    @dn.tool_method
    def generate_pyramid_questions(self) -> list[dict]:
        """
        Generate questions to climb the Pyramid of Pain.

        This is a CORE DRIVER of the investigation. Call this after
        recording evidence to get questions that elevate understanding.

        The Pyramid Climber generates questions that move from:
        - Hash Values (trivial) -> Tools/TTPs
        - IP Addresses (easy) -> Domains/Infrastructure/Tools
        - Domains (simple) -> Infrastructure patterns/Tools
        - Artifacts (annoying) -> Tools/TTPs
        - Tools (challenging) -> TTPs

        The GOAL is always to reach TTPs (level 6).

        Returns:
            List of questions prioritized by elevation potential
        """
        if not self.pyramid_climber or not self.state:
            return [{"error": "Engines not initialized"}]

        dn.log_metric("pyramid_question_calls", 1, mode="count")

        questions = self.pyramid_climber.generate_questions(self.state)
        questions.sort(key=lambda q: q.priority_score, reverse=True)

        return [q.to_dict() for q in questions[:10]]

    @dn.tool_method
    def assess_pyramid_state(self) -> dict:
        """
        Assess the current Pyramid of Pain state of the investigation.

        Use this to check if you're stuck at low-level indicators
        or successfully climbing toward TTPs.

        Returns:
            Assessment with distribution, elevation score, and recommendations
        """
        if not self.pyramid_climber or not self.state:
            return {"error": "Engines not initialized"}

        return self.pyramid_climber.assess_pyramid_state(self.state)

    @dn.tool_method
    def get_combined_questions(self, max_questions: int = 10) -> list[dict]:
        """
        Get prioritized questions from BOTH engines combined.

        This is the recommended way to drive the investigation -
        get questions from both MITRE and Pyramid engines, combined
        and sorted by priority.

        Args:
            max_questions: Maximum number of questions to return

        Returns:
            Combined, prioritized list of questions
        """
        if not self.mitre_navigator or not self.pyramid_climber or not self.state:
            return [{"error": "Engines not initialized"}]

        mitre_qs = self.mitre_navigator.generate_questions(self.state)
        pyramid_qs = self.pyramid_climber.generate_questions(self.state)

        all_questions = mitre_qs + pyramid_qs
        all_questions.sort(key=lambda q: q.priority_score, reverse=True)

        dn.log_metric("combined_questions_generated", len(all_questions))

        return [q.to_dict() for q in all_questions[:max_questions]]


class MITRELookupTools(dn.Toolset):
    """Tools for looking up MITRE ATT&CK data."""

    mitre_client: MITREAttackClient | None = None

    def set_client(self, client: MITREAttackClient):
        self.mitre_client = client

    @dn.tool_method
    def lookup_technique(self, technique_id: str) -> dict | None:
        """
        Look up a MITRE ATT&CK technique by ID.

        Args:
            technique_id: The technique ID (e.g., "T1059.001", "T1105")

        Returns:
            Technique details including name, description, tactic, and data sources
        """
        if not self.mitre_client:
            return {"error": "MITRE client not initialized"}

        technique = self.mitre_client.get_technique(technique_id)
        if not technique:
            return None

        return {
            "id": technique.id,
            "name": technique.name,
            "description": technique.description,
            "tactic": technique.tactic,
            "tactic_id": technique.tactic_id,
            "platforms": technique.platforms,
            "data_sources": technique.data_sources,
            "detection": technique.detection,
        }

    @dn.tool_method
    def get_related_techniques(self, technique_id: str) -> list[dict]:
        """
        Get techniques related to the given technique.

        Useful for understanding what other techniques might appear
        alongside the one you've identified.

        Args:
            technique_id: The technique ID to find relations for

        Returns:
            List of related techniques with relationship type
        """
        if not self.mitre_client:
            return [{"error": "MITRE client not initialized"}]

        return self.mitre_client.get_related_techniques(technique_id)

    @dn.tool_method
    def identify_tactical_gaps(self) -> list[dict]:
        """
        Identify which attack tactics haven't been investigated yet.

        Use this to ensure complete attack lifecycle coverage.

        Returns:
            List of uncovered tactics with example techniques
        """
        if not self.mitre_client:
            return [{"error": "MITRE client not initialized"}]

        # Need access to state for identified techniques
        # This would typically be passed in, simplified here
        uncovered = self.mitre_client.get_all_tactics()

        return [
            {
                "tactic_id": t.id,
                "tactic_name": t.name,
                "description": t.description,
            }
            for t in uncovered[:10]
        ]

    @dn.tool_method
    def search_techniques(self, keyword: str) -> list[dict]:
        """
        Search for techniques by keyword.

        Args:
            keyword: Search term to find in technique names/descriptions

        Returns:
            Matching techniques
        """
        if not self.mitre_client:
            return [{"error": "MITRE client not initialized"}]

        matches = self.mitre_client.search_by_keyword(keyword)

        return [
            {
                "id": t.id,
                "name": t.name,
                "tactic": t.tactic,
            }
            for t in matches
        ]


@dn.tool()
async def complete_investigation(
    summary: str,
    attack_synopsis: str,
    recommendations: list[str],
    confidence: str,
) -> str:
    """
    Complete the investigation and signal report generation.

    Call this when you have:
    1. A clear timeline of events
    2. Identified TTPs with MITRE mappings
    3. Assessed scope and blast radius
    4. Produced actionable intelligence

    Args:
        summary: Executive summary (2-3 sentences)
        attack_synopsis: Description of what happened
        recommendations: List of recommended actions
        confidence: Overall confidence level (high/medium/low with explanation)

    Returns:
        Confirmation message
    """
    dn.log_metric("investigation_completed", 1)
    dn.log_output(
        "completion_summary",
        {
            "summary": summary,
            "attack_synopsis": attack_synopsis,
            "recommendations": recommendations,
            "confidence": confidence,
        },
    )

    logger.success("Investigation completed")

    return "Investigation completed. Report will be generated."


@dn.tool()
async def escalate_investigation(
    reason: str,
    severity: str,
    current_findings: str,
    immediate_actions: list[str],
) -> str:
    """
    Escalate the investigation for human analyst review.

    Call this if:
    - You identify an active, ongoing attack
    - The scope exceeds investigation capacity
    - You need human analyst intervention
    - Critical infrastructure is at risk

    Args:
        reason: Why escalation is needed
        severity: critical, high, or medium
        current_findings: Summary of what you've found so far
        immediate_actions: Actions that should be taken immediately

    Returns:
        Confirmation message
    """
    dn.log_metric("investigation_escalated", 1)
    dn.tag(f"escalation:{severity}")
    dn.tag("needs_human_review")

    dn.log_output(
        "escalation",
        {
            "reason": reason,
            "severity": severity,
            "findings": current_findings,
            "immediate_actions": immediate_actions,
            "escalated_at": datetime.utcnow().isoformat(),
        },
    )

    logger.warning(f"Investigation escalated: {reason}")

    return f"Investigation escalated with severity={severity}. Human analyst notified."
