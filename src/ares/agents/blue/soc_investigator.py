"""
Ares SOC Investigation Agent.

Main agent implementation using Dreadnode Agent SDK.
"""

import signal
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import dreadnode as dn
from loguru import logger

from ares.core.factories.blue_factory import create_investigation_agent
from ares.core.models import InvestigationState
from ares.core.templates import get_template_loader
from ares.integrations.mitre import MITREAttackClient


class InvestigationTimeoutError(Exception):
    """Raised when investigation exceeds hard timeout."""


def build_initial_prompt(alert: dict) -> str:
    """Build the initial prompt with alert context.

    Args:
        alert: Alert dictionary from Grafana Alertmanager.

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
    # Also check annotations
    if not mitre_technique:
        for key in ["mitre_technique", "mitre", "technique_id", "technique"]:
            if key in annotations:
                mitre_technique = annotations[key]
                break

    # Current time for reference
    current_time = datetime.now(timezone.utc)

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
    """

    def __init__(
        self,
        model: str,
        grafana_url: str,
        grafana_api_key: str,
        mitre_client: MITREAttackClient,
        report_dir: Path,
        max_steps: int = 150,
    ):
        self.model = model
        self.grafana_url = grafana_url
        self.grafana_api_key = grafana_api_key
        self.mitre_client = mitre_client
        self.report_dir = report_dir
        self.max_steps = max_steps
        self._mcp_client = None
        self._mcp_tools = None

    async def _ensure_mcp_connection(self) -> None:
        """Ensure MCP connection is established (with 60s timeout)."""
        import asyncio

        if self._mcp_client is None:
            from ares.tools.blue.grafana import connect_grafana_mcp

            try:
                logger.info("Connecting to Grafana MCP server...")
                self._mcp_client = await asyncio.wait_for(  # type: ignore[func-returns-value]
                    connect_grafana_mcp(
                        grafana_url=self.grafana_url,
                        grafana_api_key=self.grafana_api_key,
                    ),
                    timeout=60.0,
                )
                self._mcp_tools = self._mcp_client.tools
                tool_count = len(self._mcp_tools) if self._mcp_tools else 0
                logger.success(f"Grafana MCP connected ({tool_count} tools available)")
            except asyncio.TimeoutError:
                logger.warning("Grafana MCP connection timed out after 60s")
                logger.warning("Continuing without MCP tools")
                self._mcp_tools = None
            except Exception as e:
                logger.warning(f"Failed to connect to Grafana MCP: {e}")
                logger.warning("Continuing without MCP tools")
                self._mcp_tools = None

    async def _shutdown_mcp(self) -> None:
        """Shutdown MCP connection if active."""
        import asyncio

        if self._mcp_client:
            try:
                # Add timeout to prevent hanging on shutdown
                await asyncio.wait_for(
                    self._mcp_client.__aexit__(None, None, None),
                    timeout=10.0,
                )
                logger.info("Grafana MCP connection closed")
            except asyncio.TimeoutError:
                logger.warning("MCP shutdown timed out after 10s, forcing close")
            except Exception as e:
                logger.warning(f"Error closing MCP connection: {e}")
            finally:
                self._mcp_client = None
                self._mcp_tools = None

    async def investigate(self, alert: dict) -> dict:
        """Run a full investigation on an alert.

        Creates a new agent for this investigation and runs it
        until completion or escalation.

        Args:
            alert: The alert dictionary containing labels, annotations, and metadata.

        Returns:
            A dict containing:
                - investigation_id: Unique identifier for this investigation
                - status: "completed" or "escalated"
                - report_path: Path to the generated markdown report
                - evidence_count: Number of evidence items collected
                - techniques_identified: List of MITRE ATT&CK technique IDs
                - highest_pyramid_level: Highest Pyramid of Pain level reached (1-6)

        Raises:
            InvestigationTimeoutError: If investigation exceeds the hard timeout.
        """
        investigation_id = f"inv-{uuid.uuid4().hex[:8]}"
        alert_name = alert.get("labels", {}).get("alertname", "unknown")

        logger.info(f"Starting investigation {investigation_id} for alert: {alert_name}")

        # Hard timeout using signal (works even if event loop is blocked)
        # 1 minute per step + 2 minutes buffer for setup/teardown
        hard_timeout_seconds = (self.max_steps * 60) + 120

        def _timeout_handler(signum, frame):
            raise InvestigationTimeoutError(
                f"Investigation {investigation_id} exceeded hard timeout of {hard_timeout_seconds}s"
            )

        # Set up signal-based hard timeout (Unix only)
        old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(hard_timeout_seconds)
        logger.info(f"Hard timeout set: {hard_timeout_seconds}s ({hard_timeout_seconds // 60}m)")

        # Create investigation state early so we can generate partial reports on timeout
        state = InvestigationState(
            investigation_id=investigation_id,
            alert=alert,
        )

        try:
            # Ensure MCP connection is ready
            await self._ensure_mcp_connection()

            # Auto-extract and record MITRE technique from alert
            labels = alert.get("labels", {})
            annotations = alert.get("annotations", {})
            for key in ["mitre_technique", "mitre", "technique_id", "technique"]:
                if labels.get(key):
                    state.identified_techniques.add(labels[key])
                    logger.info(f"Auto-recorded MITRE technique from alert: {labels[key]}")
                    break
                if annotations.get(key):
                    state.identified_techniques.add(annotations[key])
                    logger.info(f"Auto-recorded MITRE technique from alert: {annotations[key]}")
                    break

            initial_prompt = build_initial_prompt(alert)

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

                # Run the investigation with asyncio timeout (backup to signal timeout)
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

                    # Check if agent hit max_steps without proper completion
                    status = "completed"
                    if state.escalated:
                        status = "escalated"
                    elif result.stop_reason and "max" in str(result.stop_reason).lower():
                        status = "incomplete"
                        logger.warning(
                            f"Agent reached max_steps ({self.max_steps}) without completion"
                        )

                    # Generate report
                    report_path = self._generate_report(state, result)

                    dn.log_output("report_path", str(report_path))
                    dn.log_metric("investigation_success", 1)

                    return {
                        "investigation_id": investigation_id,
                        "status": status,
                        "report_path": str(report_path),
                        "evidence_count": len(state.evidence),
                        "techniques_identified": list(state.identified_techniques),
                        "highest_pyramid_level": state.highest_pyramid_level,
                    }

                except asyncio.TimeoutError:
                    logger.error(f"Investigation timed out after {timeout_seconds}s (asyncio)")
                    logger.error(
                        f"Current state: {len(state.evidence)} evidence items, "
                        f"{len(state.timeline)} timeline events"
                    )
                    dn.log_metric("investigation_timeout", 1)

                    # Still generate a partial report on timeout
                    report_path = self._generate_report(state, None)
                    return {
                        "investigation_id": investigation_id,
                        "status": "timeout",
                        "report_path": str(report_path),
                        "evidence_count": len(state.evidence),
                        "techniques_identified": list(state.identified_techniques),
                        "highest_pyramid_level": state.highest_pyramid_level,
                    }

                except Exception as e:
                    logger.error(f"Investigation failed: {e}")
                    dn.log_metric("investigation_failed", 1)
                    raise

        except InvestigationTimeoutError:
            logger.error(f"Investigation hit HARD TIMEOUT after {hard_timeout_seconds}s")
            logger.error(
                f"Current state: {len(state.evidence)} evidence items, "
                f"{len(state.timeline)} timeline events"
            )
            dn.log_metric("investigation_hard_timeout", 1)

            # Generate partial report
            report_path = self._generate_report(state, None)
            return {
                "investigation_id": investigation_id,
                "status": "hard_timeout",
                "report_path": str(report_path),
                "evidence_count": len(state.evidence),
                "techniques_identified": list(state.identified_techniques),
                "highest_pyramid_level": state.highest_pyramid_level,
            }

        finally:
            # Always cancel the alarm and restore old handler
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
            logger.debug("Hard timeout signal handler cleaned up")

    def _generate_report(self, state: InvestigationState, _result) -> Path:
        """Generate the markdown investigation report."""
        from ares.reports.investigation import MarkdownReportGenerator

        generator = MarkdownReportGenerator(self.report_dir)
        return generator.generate(state)
