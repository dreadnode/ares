"""
Ares SOC Investigation Agent.

Main agent implementation using Dreadnode Agent SDK.
"""

import os
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import dreadnode as dn
from loguru import logger

from ares.core.factories.blue_factory import create_investigation_agent, reset_query_tracking
from ares.core.models import InvestigationState, TimelineEvent
from ares.core.persistence import (
    create_stored_investigation_from_state,
    get_investigation_store,
)
from ares.core.templates import get_template_loader
from ares.integrations.mitre import MITREAttackClient
from ares.tools.blue.grafana import GrafanaTools


class InvestigationTimeoutError(Exception):
    """Raised when investigation exceeds hard timeout."""


class WatchdogTimer:
    """Watchdog that generates report and forcefully exits if timeout is exceeded."""

    def __init__(
        self,
        timeout_seconds: int,
        investigation_id: str,
        state: "InvestigationState",
        report_dir: Path,
    ):
        self.timeout = timeout_seconds
        self.investigation_id = investigation_id
        self.state = state
        self.report_dir = report_dir
        self._timer: threading.Timer | None = None
        self._cancelled = False

    def _timeout_handler(self) -> None:
        if self._cancelled:
            return

        logger.critical(
            f"WATCHDOG: Investigation {self.investigation_id} exceeded "
            f"hard timeout of {self.timeout}s"
        )
        logger.warning(
            f"Current state: {len(self.state.evidence)} evidence items, "
            f"{len(self.state.timeline)} timeline events"
        )

        # Generate partial report before dying
        try:
            from ares.reports.investigation import MarkdownReportGenerator

            generator = MarkdownReportGenerator(self.report_dir)
            report_path = generator.generate(self.state)
            logger.warning(f"Partial report saved to: {report_path}")
        except Exception as e:
            logger.error(f"Failed to generate partial report: {e}")

        logger.critical("Forcing exit due to timeout")
        os._exit(1)

    def start(self) -> None:
        self._timer = threading.Timer(self.timeout, self._timeout_handler)
        self._timer.daemon = True
        self._timer.start()
        logger.info(f"Watchdog started: {self.timeout}s ({self.timeout // 60}m)")

    def cancel(self) -> None:
        self._cancelled = True
        if self._timer:
            self._timer.cancel()
        logger.debug("Watchdog cancelled")


def build_initial_prompt(alert: dict, attack_context: dict | None = None) -> str:
    """Build the initial prompt with alert context.

    Args:
        alert: Alert dictionary from Grafana Alertmanager.
        attack_context: Optional red team operation context for focused hunting.
            Contains attack_window_start, attack_window_end, techniques_used, etc.

    Returns:
        Formatted prompt string for agent initialization.

    Example:
        >>> alert = {
        ...     'labels': {'alertname': 'HighCPU', 'severity': 'warning'},
        ...     'annotations': {'summary': 'CPU usage above 80%'}
        ... }
        >>> prompt = build_initial_prompt(alert)
        >>> 'HighCPU' in prompt
        True
    """
    labels = alert.get("labels", {})
    annotations = alert.get("annotations", {})

    # Extract MITRE technique from alert if present
    mitre_technique = None
    for key in ["mitre_technique", "mitre", "technique_id", "technique"]:
        if key in labels:
            mitre_technique = labels[key]
            break
    if not mitre_technique:
        for key in ["mitre_technique", "mitre", "technique_id", "technique"]:
            if key in annotations:
                mitre_technique = annotations[key]
                break

    # Current time for reference
    current_time = datetime.now(timezone.utc)

    # Build attack context for template
    attack_window_start = None
    attack_window_end = None
    techniques_used = []
    priority_queries = []
    operation_id = None

    if attack_context:
        operation_id = attack_context.get("operation_id")
        if attack_context.get("attack_window_start"):
            attack_window_start = (
                attack_context["attack_window_start"].isoformat().replace("+00:00", "Z")
            )
        if attack_context.get("attack_window_end"):
            attack_window_end = (
                attack_context["attack_window_end"].isoformat().replace("+00:00", "Z")
            )
        techniques_used = attack_context.get("techniques_used", [])
        # Convert priority queries to serializable format
        priority_queries = [
            {
                "technique_id": q.technique_id,
                "description": q.description,
                "query": q.logql,
                "priority": q.priority,
            }
            for q in attack_context.get("priority_queries", [])
        ]

    loader = get_template_loader()
    return loader.render(
        "agent/initial_alert_prompt.md.jinja",
        alert_name=labels.get("alertname", "Unknown"),
        severity=labels.get("severity", "unknown"),
        instance=labels.get("instance", "unknown"),
        job=labels.get("job", "unknown"),
        starts_at=alert.get("startsAt", current_time.isoformat()),
        summary=annotations.get("summary", "No summary provided"),
        description=annotations.get("description", "No description provided"),
        labels=labels,
        mitre_technique=mitre_technique,
        current_time=current_time.isoformat().replace("+00:00", "Z"),
        current_time_minus_1h=(current_time - timedelta(hours=1))
        .isoformat()
        .replace("+00:00", "Z"),
        current_time_minus_2h=(current_time - timedelta(hours=2))
        .isoformat()
        .replace("+00:00", "Z"),
        # Red team operation context
        operation_id=operation_id,
        attack_window_start=attack_window_start,
        attack_window_end=attack_window_end,
        techniques_used=techniques_used,
        priority_queries=priority_queries,
    )


class InvestigationOrchestrator:
    """Main orchestrator for SOC investigations.

    Creates and manages Dreadnode Agents for investigating alerts.

    Attributes:
        model: LLM model identifier string.
        grafana_url: Base URL for Grafana instance.
        grafana_api_key: API key for Grafana authentication.
        mitre_client: Client for MITRE ATT&CK data lookups.
        report_dir: Directory path for generated reports.
        max_steps: Maximum number of agent steps per investigation.
        attack_context: Optional red team operation context for focused hunting.
    """

    def __init__(
        self,
        model: str,
        grafana_url: str,
        grafana_api_key: str,
        mitre_client: MITREAttackClient,
        report_dir: Path,
        max_steps: int = 30,
        attack_context: dict | None = None,
    ):
        self.model = model
        self.grafana_url = grafana_url
        self.grafana_api_key = grafana_api_key
        self.mitre_client = mitre_client
        self.report_dir = report_dir
        self.max_steps = max_steps
        self.attack_context = attack_context
        self._mcp_client = None
        self._mcp_tools = None
        # Grafana tools for annotations
        self._grafana_tools = GrafanaTools(
            base_url=grafana_url,
            api_key=grafana_api_key,
        )

    async def _ensure_mcp_connection(self) -> None:
        """Ensure MCP connection is established using connection pool.

        Uses MCPConnectionPool to reuse connections across investigations,
        eliminating the ~60 second connection overhead per investigation.
        """
        import asyncio

        from ares.tools.blue.grafana import MCPConnectionPool, connect_grafana_mcp

        # Check if we already have tools from the pool
        if self._mcp_tools is not None:
            logger.debug("MCP tools already available, skipping connection")
            return

        try:
            logger.info("Getting Grafana MCP connection from pool...")
            # connect_grafana_mcp now uses the connection pool internally
            # Timeout is much shorter since pool reuses existing connections
            timeout = 10.0 if MCPConnectionPool.is_connected() else 60.0
            self._mcp_client = await asyncio.wait_for(  # type: ignore[func-returns-value]
                connect_grafana_mcp(
                    grafana_url=self.grafana_url,
                    grafana_api_key=self.grafana_api_key,
                ),
                timeout=timeout,
            )
            self._mcp_tools = self._mcp_client.tools
            tool_count = len(self._mcp_tools) if self._mcp_tools else 0
            logger.success(f"Grafana MCP ready ({tool_count} tools, pooled)")
        except asyncio.TimeoutError:
            logger.warning(f"Grafana MCP connection timed out after {timeout}s")
            logger.warning("Continuing without MCP tools")
            self._mcp_tools = None
        except Exception as e:
            logger.warning(f"Failed to connect to Grafana MCP: {e}")
            logger.warning("Continuing without MCP tools")
            self._mcp_tools = None

    async def _shutdown_mcp(self) -> None:
        """Clear local MCP references without closing the pooled connection.

        The connection pool manages the actual connection lifecycle.
        We only clear local references here so subsequent investigations
        can get fresh references from the pool.
        """
        # Do NOT close the client - it's managed by MCPConnectionPool
        # Just clear our local references
        self._mcp_client = None
        self._mcp_tools = None
        logger.debug("Cleared local MCP references (pool connection preserved)")

    def _extract_mitre_technique(self, alert: dict, state: InvestigationState) -> None:
        """Extract MITRE technique ID from alert labels or annotations."""
        labels = alert.get("labels", {})
        annotations = alert.get("annotations", {})
        for key in ["mitre_technique", "mitre", "technique_id", "technique"]:
            tech_id = labels.get(key) or annotations.get(key)
            if not tech_id:
                continue
            state.identified_techniques.add(tech_id)
            technique = self.mitre_client.get_technique(tech_id)
            if technique:
                state.technique_names[tech_id] = technique.name
                state.technique_to_tactic[tech_id] = technique.tactic or "Unknown"
                if technique.tactic:
                    state.identified_tactics.add(technique.tactic)
            logger.info(f"Auto-recorded MITRE technique from alert: {tech_id}")
            break

    async def investigate(self, alert: dict, correlation_context: dict | None = None) -> dict:
        """Run a full investigation on an alert.

        Creates a new agent for this investigation and runs it
        until completion or escalation.

        Args:
            alert: The alert dictionary containing labels, annotations, and metadata.
            correlation_context: Optional context from alert correlator with info about
                related alerts (common hosts, users, IPs, techniques).

        Returns:
            A dict containing:
                - investigation_id: Unique identifier for this investigation
                - status: "completed" or "escalated"
                - evidence_count: Number of evidence items collected
                - techniques_identified: List of MITRE ATT&CK technique IDs
                - highest_pyramid_level: Highest Pyramid of Pain level reached (1-6)
                - state: Full InvestigationState for consolidated reporting

        Raises:
            InvestigationTimeoutError: If investigation exceeds the hard timeout.
        """
        investigation_id = f"inv-{uuid.uuid4().hex[:8]}"
        alert_name = alert.get("labels", {}).get("alertname", "unknown")

        logger.info(f"Starting investigation {investigation_id} for alert: {alert_name}")

        # Reset query tracking for this investigation
        reset_query_tracking()

        # Create investigation state early so we can generate partial reports on timeout
        state = InvestigationState(
            investigation_id=investigation_id,
            alert=alert,
            correlation_context=correlation_context,
        )

        # Hard timeout using watchdog thread (works even if event loop is blocked)
        # 1 minute per step + 2 minutes buffer for setup/teardown
        hard_timeout_seconds = (self.max_steps * 60) + 120
        watchdog = WatchdogTimer(
            hard_timeout_seconds,
            investigation_id,
            state,
            self.report_dir,
        )
        watchdog.start()

        try:
            # Ensure MCP connection is ready
            await self._ensure_mcp_connection()

            # Post "investigation started" annotation to Grafana
            await self._post_started_annotation(investigation_id, alert)

            # Auto-extract and record MITRE technique from alert
            self._extract_mitre_technique(alert, state)

            self._create_alert_timeline_event(state, alert)

            initial_prompt = build_initial_prompt(alert, self.attack_context)

            with dn.run(tags=["soc-investigation", alert_name]):
                dn.log_params(
                    model=self.model,
                    investigation_id=investigation_id,
                    alert_name=alert_name,
                    alert_severity=alert.get("labels", {}).get("severity", "unknown"),
                    max_steps=self.max_steps,
                    mcp_tools_available=self._mcp_tools is not None,
                    mcp_tool_count=len(self._mcp_tools) if self._mcp_tools else 0,
                )
                dn.log_input("alert", alert)

                agent = create_investigation_agent(
                    model=self.model,
                    grafana_url=self.grafana_url,
                    grafana_api_key=self.grafana_api_key,
                    mitre_client=self.mitre_client,
                    state=state,
                    grafana_mcp_tools=self._mcp_tools,
                    max_steps=self.max_steps,
                )

                # Run the investigation with asyncio timeout (backup to watchdog)
                try:
                    import asyncio

                    logger.info(f"Starting agent.run() with max_steps={self.max_steps}")

                    # Asyncio timeout as secondary measure
                    timeout_seconds = self.max_steps * 60

                    result = await asyncio.wait_for(
                        agent.run(initial_prompt),
                        timeout=timeout_seconds,
                    )

                    logger.success(f"Agent completed: {result.steps} steps, {result.stop_reason}")
                    if result.error:
                        logger.error(f"Agent error detail: {result.error!r}")

                    status = "completed"
                    if state.escalated:
                        status = "escalated"
                    elif result.stop_reason and "max" in str(result.stop_reason).lower():
                        status = "incomplete"
                        logger.warning(
                            f"Agent reached max_steps ({self.max_steps}) without completion"
                        )

                    # Persist investigation for learning
                    self._persist_investigation(state, status)

                    # Post "investigation completed" annotation to Grafana
                    await self._post_completed_annotation(
                        investigation_id, alert_name, status, state
                    )

                    dn.log_metric("investigation_success", 1)

                    return {
                        "investigation_id": investigation_id,
                        "status": status,
                        "evidence_count": len(state.evidence),
                        "techniques_identified": list(state.identified_techniques),
                        "highest_pyramid_level": state.highest_pyramid_level,
                        "state": state,  # Full state for evaluation framework
                    }

                except asyncio.TimeoutError:
                    logger.error(f"Investigation timed out after {timeout_seconds}s (asyncio)")
                    logger.error(
                        f"Current state: {len(state.evidence)} evidence items, "
                        f"{len(state.timeline)} timeline events"
                    )
                    dn.log_metric("investigation_timeout", 1)

                    # Persist investigation for learning (even on timeout)
                    self._persist_investigation(state, "timeout")

                    # Post "investigation timeout" annotation to Grafana
                    await self._post_completed_annotation(
                        investigation_id, alert_name, "timeout", state
                    )

                    return {
                        "investigation_id": investigation_id,
                        "status": "timeout",
                        "evidence_count": len(state.evidence),
                        "techniques_identified": list(state.identified_techniques),
                        "highest_pyramid_level": state.highest_pyramid_level,
                        "state": state,  # Full state for evaluation framework
                    }

                except Exception as e:
                    import traceback

                    error_msg = str(e)
                    logger.error(f"Investigation failed: {error_msg}")

                    # Log full traceback for ContentText errors (framework bug)
                    if "ContentText" in error_msg:
                        logger.error(f"ContentText error traceback:\n{traceback.format_exc()}")
                        logger.error(f"State alert type: {type(state.alert)}")
                        logger.error(
                            f"State alert keys: {state.alert.keys() if hasattr(state.alert, 'keys') else 'N/A'}"
                        )

                    dn.log_metric("investigation_failed", 1)

                    # Persist failed investigation
                    self._persist_investigation(state, "failed")

                    # Post "investigation failed" annotation to Grafana
                    await self._post_completed_annotation(
                        investigation_id, alert_name, "failed", state
                    )
                    raise

        finally:
            # Always cancel the watchdog on normal completion
            watchdog.cancel()
            # Clear local MCP references (pool connection preserved for next investigation)
            await self._shutdown_mcp()

    async def _post_started_annotation(self, investigation_id: str, alert: dict) -> None:
        """Post investigation started annotation to Grafana.

        Args:
            investigation_id: Unique investigation identifier.
            alert: Alert dictionary.
        """
        try:
            labels = alert.get("labels", {})
            alert_name = labels.get("alertname", "unknown")
            severity = labels.get("severity", "unknown")

            await self._grafana_tools.post_investigation_started(
                investigation_id=investigation_id,
                alert_name=alert_name,
                severity=severity,
            )
        except Exception as e:
            # Don't fail the investigation if annotation fails
            logger.warning(f"Failed to post started annotation: {e}")

    async def _post_completed_annotation(
        self,
        investigation_id: str,
        alert_name: str,
        status: str,
        state: InvestigationState,
    ) -> None:
        """Post investigation completed annotation to Grafana.

        Args:
            investigation_id: Unique investigation identifier.
            alert_name: Name of the alert investigated.
            status: Final status.
            state: Investigation state.
        """
        try:
            # Get summary from state if available
            summary = None
            if state.attack_synopsis:
                summary = state.attack_synopsis
            elif state.recommendations:
                summary = f"Recommendations: {', '.join(state.recommendations[:3])}"

            await self._grafana_tools.post_investigation_completed(
                investigation_id=investigation_id,
                alert_name=alert_name,
                status=status,
                evidence_count=len(state.evidence),
                techniques=list(state.identified_techniques),
                pyramid_level=state.highest_pyramid_level,
                summary=summary,
            )
        except Exception as e:
            # Don't fail the investigation if annotation fails
            logger.warning(f"Failed to post completed annotation: {e}")

    def _create_alert_timeline_event(self, state: InvestigationState, alert: dict) -> None:
        """Create an initial timeline event from the alert."""
        labels = alert.get("labels", {})
        annotations = alert.get("annotations", {})

        starts_at = alert.get("startsAt", "")
        try:
            if starts_at:
                alert_time = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
            else:
                alert_time = datetime.now(timezone.utc)
        except ValueError:
            alert_time = datetime.now(timezone.utc)

        alert_name = labels.get("alertname", "Unknown Alert")
        severity = labels.get("severity", "unknown")
        summary = annotations.get("summary", annotations.get("description", ""))

        description = f"{severity.upper()} alert triggered: {alert_name}"
        if summary:
            description += f" - {summary[:100]}"

        mitre_techniques = []
        for key in ["mitre_technique", "mitre", "technique_id"]:
            if labels.get(key):
                mitre_techniques.append(labels[key])
                break
            if annotations.get(key):
                mitre_techniques.append(annotations[key])
                break

        event = TimelineEvent(
            id="tl-alert-0000",
            timestamp=alert_time,
            description=description,
            evidence_ids=[],
            mitre_techniques=mitre_techniques,
            confidence=0.9,
            source="alert",
        )

        state.timeline.append(event)
        logger.info(f"Created initial timeline event from alert: {description[:50]}...")

    def _generate_report(self, state: InvestigationState, _result) -> Path:
        """Generate the markdown investigation report."""
        from ares.reports.investigation import MarkdownReportGenerator

        generator = MarkdownReportGenerator(self.report_dir)
        return generator.generate(state)

    def _persist_investigation(self, state: InvestigationState, status: str) -> None:
        """Persist investigation results for learning.

        Args:
            state: Investigation state to persist
            status: Final status (completed, escalated, timeout, failed)
        """
        try:
            store = get_investigation_store()

            # Create stored investigation from state
            stored = create_stored_investigation_from_state(state, status)

            # Store the investigation
            store.store_investigation(stored)

            # Update query effectiveness statistics
            alert_name = state.alert.get("labels", {}).get("alertname", "unknown")
            for query in state.executed_queries:
                query_str = query.get("query", "")
                if query_str:
                    # Normalize query for pattern matching
                    pattern = self._normalize_query_pattern(query_str)
                    successful = query.get("result_count", 0) > 0
                    # Check if any evidence was recorded after this query
                    produced_evidence = len(state.evidence) > 0

                    store.update_query_effectiveness(
                        query_pattern=pattern,
                        successful=successful,
                        produced_evidence=produced_evidence,
                        alert_type=alert_name,
                    )

            logger.info(f"Persisted investigation {state.investigation_id} to store")

        except Exception as e:
            # Don't fail the investigation if persistence fails
            logger.warning(f"Failed to persist investigation: {e}")

    def _normalize_query_pattern(self, query: str) -> str:
        """Normalize a query string into a reusable pattern.

        Replaces specific values with placeholders for pattern matching.

        Args:
            query: Raw query string

        Returns:
            Normalized pattern string
        """
        import re

        pattern = query

        # Replace timestamps with placeholder
        pattern = re.sub(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?",
            "<TIMESTAMP>",
            pattern,
        )

        # Replace IP addresses with placeholder
        pattern = re.sub(r"\d+\.\d+\.\d+\.\d+", "<IP>", pattern)

        # Replace UUIDs with placeholder
        pattern = re.sub(
            r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
            "<UUID>",
            pattern,
            flags=re.IGNORECASE,
        )

        # Replace specific hostnames (anything.domain.tld format)
        return re.sub(
            r"\b[a-z0-9-]+\.[a-z0-9-]+\.[a-z]{2,}\b",
            "<HOSTNAME>",
            pattern,
            flags=re.IGNORECASE,
        )
