"""
Ares SOC Investigation Agent.

Main agent implementation using Dreadnode Agent SDK.
"""

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import dreadnode as dn
from loguru import logger

from ares.core.factories.blue_factory import create_investigation_agent
from ares.core.models import InvestigationState
from ares.core.templates import get_template_loader
from ares.integrations.mitre import MITREAttackClient


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
        """Ensure MCP connection is established."""
        if self._mcp_client is None:
            from ares.tools.blue.grafana import connect_grafana_mcp

            try:
                logger.info("Connecting to Grafana MCP server...")
                self._mcp_client = await connect_grafana_mcp(
                    grafana_url=self.grafana_url,
                    grafana_api_key=self.grafana_api_key,
                )
                self._mcp_tools = self._mcp_client.tools
                tool_count = len(self._mcp_tools) if self._mcp_tools else 0
                logger.success(f"Grafana MCP connected ({tool_count} tools available)")
            except Exception as e:
                logger.warning(f"Failed to connect to Grafana MCP: {e}")
                logger.warning("Continuing without MCP tools")
                self._mcp_tools = None

    async def _shutdown_mcp(self) -> None:
        """Shutdown MCP connection if active."""
        if self._mcp_client:
            try:
                await self._mcp_client.__aexit__(None, None, None)
                logger.info("Grafana MCP connection closed")
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
            TimeoutError: If investigation exceeds the configured timeout.
        """
        investigation_id = f"inv-{uuid.uuid4().hex[:8]}"
        alert_name = alert.get("labels", {}).get("alertname", "unknown")

        logger.info(f"Starting investigation {investigation_id} for alert: {alert_name}")

        # Ensure MCP connection is ready
        await self._ensure_mcp_connection()

        # Create investigation state
        state = InvestigationState(
            investigation_id=investigation_id,
            alert=alert,
        )

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

            # Run the investigation with timeout
            try:
                import asyncio

                logger.info(f"Starting agent.run() with max_steps={self.max_steps}")

                # Add a generous timeout (5 minutes per step)
                timeout_seconds = self.max_steps * 300  # 5 minutes per step

                result = await asyncio.wait_for(
                    agent.run(initial_prompt),
                    timeout=timeout_seconds,
                )

                logger.success(f"Agent completed: {result.steps} steps, {result.stop_reason}")

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

            except asyncio.TimeoutError as timeout_err:
                logger.error(f"Investigation timed out after {timeout_seconds}s")
                logger.error(
                    f"Current state: {len(state.evidence)} evidence items, {len(state.timeline)} timeline events"
                )
                dn.log_metric("investigation_timeout", 1)
                raise TimeoutError(
                    f"Investigation exceeded {timeout_seconds}s timeout"
                ) from timeout_err

            except Exception as e:
                logger.error(f"Investigation failed: {e}")
                dn.log_metric("investigation_failed", 1)
                raise

    def _generate_report(self, state: InvestigationState, _result) -> Path:
        """Generate the markdown investigation report."""
        from ares.reports.investigation import MarkdownReportGenerator

        generator = MarkdownReportGenerator(self.report_dir)
        return generator.generate(state)
