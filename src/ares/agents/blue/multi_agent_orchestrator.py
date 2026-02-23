"""Blue team multi-agent orchestrator.

Coordinates triage, threat hunter, and lateral analyst workers
for investigating security alerts. Workers run in-process via
asyncio.create_task() with shared state in Redis.

The orchestrator LLM decides when to dispatch tasks and how to
synthesize findings. Workers report back via the dispatcher.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import dreadnode as dn
from dreadnode.agent import Agent, Thread
from dreadnode.agent.stop import tool_use
from dreadnode.agent.tools.base import Toolset
from loguru import logger

from ares.agents.blue.soc_investigator import WatchdogTimer, build_initial_prompt
from ares.core.blue_dispatcher import BlueTeamDispatcher
from ares.core.blue_worker import BlueWorkerAgent
from ares.core.factories.blue_agents import (
    create_blue_agent,
    get_blue_stop_conditions,
    load_blue_instructions,
    max_tool_calls_stop,
)
from ares.core.models import (
    BlueRole,
    BlueTaskInfo,
    BlueTaskType,
    InvestigationState,
    SharedBlueTeamState,
)
from ares.core.templates import get_template_loader
from ares.reports.investigation import MarkdownReportGenerator

if TYPE_CHECKING:
    from ares.integrations.mitre import MITREAttackClient


class BlueOrchestratorTools(Toolset):  # type: ignore[misc]
    """Tools available to the orchestrator LLM for dispatching work.

    The orchestrator doesn't query logs directly - it dispatches
    tasks to specialized workers and synthesizes their findings.
    """

    _dispatcher: BlueTeamDispatcher | None = None
    _workers: dict[BlueRole, BlueWorkerAgent] = {}

    def set_dispatcher(self, dispatcher: BlueTeamDispatcher) -> None:
        self._dispatcher = dispatcher

    def set_workers(self, workers: dict[BlueRole, BlueWorkerAgent]) -> None:
        self._workers = workers

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def dispatch_triage(
        self,
        wait_for_result: bool = True,
    ) -> str:
        """Dispatch initial triage of the alert to the triage worker.

        The triage worker will assess the alert severity, check for
        correlated alerts, and record initial evidence.

        This should be your FIRST action for any new alert.

        Args:
            wait_for_result: If True, wait for triage to complete and
                return findings. If False, return task_id immediately.

        Returns:
            Triage findings (if wait_for_result) or task_id.
        """
        if not self._dispatcher:
            return "ERROR: No dispatcher configured"

        alert = self._dispatcher.shared_state.alert
        correlation = self._dispatcher.shared_state.correlation_context

        task = await self._dispatcher.dispatch_triage(alert, correlation)
        worker = self._workers.get(BlueRole.TRIAGE)

        if not worker:
            return f"ERROR: No triage worker available. Task {task.task_id} queued."

        if wait_for_result:
            worker.start_task(task)
            result = await self._dispatcher.wait_for_result(task.task_id, timeout=600)
            return _format_task_result("Triage", task.task_id, result)
        else:
            worker.start_task(task)
            return f"[+] Triage dispatched: task_id={task.task_id}. Use get_task_result() to check."

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def dispatch_threat_hunt(
        self,
        technique_id: str = "",
        detection_method: str = "",
        hostname: str = "",
        username: str = "",
        context: str = "",
        wait_for_result: bool = True,
    ) -> str:
        """Dispatch a threat hunting task to the threat hunter worker.

        The threat hunter will run detection queries, investigate
        specific MITRE techniques, and record evidence.

        Args:
            technique_id: MITRE technique to hunt for (e.g., "T1558.003").
            detection_method: Specific detection query to run (e.g., "detect_kerberoasting").
            hostname: Host to focus investigation on.
            username: User to focus investigation on.
            context: Additional context from prior investigation steps.
            wait_for_result: If True, wait for hunt to complete.

        Returns:
            Hunt findings (if wait_for_result) or task_id.
        """
        if not self._dispatcher:
            return "ERROR: No dispatcher configured"

        task = await self._dispatcher.dispatch_threat_hunt(
            technique_id=technique_id,
            detection_method=detection_method,
            hostname=hostname,
            username=username,
            context=context,
        )
        worker = self._workers.get(BlueRole.THREAT_HUNTER)

        if not worker:
            return f"ERROR: No threat hunter worker available. Task {task.task_id} queued."

        if wait_for_result:
            worker.start_task(task)
            result = await self._dispatcher.wait_for_result(task.task_id, timeout=600)
            return _format_task_result("Threat Hunt", task.task_id, result)
        else:
            worker.start_task(task)
            return f"[+] Threat hunt dispatched: task_id={task.task_id}."

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def dispatch_lateral_analysis(
        self,
        focus_host: str = "",
        focus_user: str = "",
        context: str = "",
        wait_for_result: bool = True,
    ) -> str:
        """Dispatch lateral movement analysis to the lateral analyst.

        The lateral analyst will investigate scope, map lateral paths,
        and identify compromise boundaries.

        Args:
            focus_host: Primary host to analyze lateral movement from/to.
            focus_user: Primary user to analyze activity for.
            context: Additional context from prior investigation steps.
            wait_for_result: If True, wait for analysis to complete.

        Returns:
            Analysis findings (if wait_for_result) or task_id.
        """
        if not self._dispatcher:
            return "ERROR: No dispatcher configured"

        task = await self._dispatcher.dispatch_lateral_analysis(
            focus_host=focus_host,
            focus_user=focus_user,
            context=context,
        )
        worker = self._workers.get(BlueRole.LATERAL_ANALYST)

        if not worker:
            return f"ERROR: No lateral analyst worker available. Task {task.task_id} queued."

        if wait_for_result:
            worker.start_task(task)
            result = await self._dispatcher.wait_for_result(task.task_id, timeout=600)
            return _format_task_result("Lateral Analysis", task.task_id, result)
        else:
            worker.start_task(task)
            return f"[+] Lateral analysis dispatched: task_id={task.task_id}."

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def get_investigation_status(self) -> str:
        """Get current investigation status across all workers.

        Returns summary of evidence collected, techniques found,
        hosts/users investigated, and task status.

        Returns:
            Formatted investigation status.
        """
        if not self._dispatcher:
            return "ERROR: No dispatcher configured"

        summary = await self._dispatcher.get_investigation_summary()
        evidence_summary = await self._dispatcher.get_evidence_summary()

        lines = [
            "=== Investigation Status ===",
            f"Stage: {summary.get('stage', 'unknown')}",
            f"Evidence: {summary.get('evidence_count', 0)} items",
            f"Techniques: {summary.get('technique_count', 0)}",
            f"  IDs: {', '.join(summary.get('techniques_identified', [])[:10])}",
            f"Highest Pyramid Level: {summary.get('highest_pyramid_level', 0)}/6",
            f"Hosts Investigated: {', '.join(summary.get('hosts_investigated', [])[:10])}",
            f"Users Investigated: {', '.join(summary.get('users_investigated', [])[:10])}",
            f"Pending Tasks: {summary.get('pending_tasks', 0)}",
            f"Completed Tasks: {summary.get('completed_tasks', 0)}",
        ]

        if evidence_summary.get("by_type"):
            lines.append(f"Evidence by type: {evidence_summary['by_type']}")
        if evidence_summary.get("by_pyramid_level"):
            lines.append(f"Evidence by pyramid: {evidence_summary['by_pyramid_level']}")
        if summary.get("queued_pivots", 0) > 0 or summary.get("queued_chains", 0) > 0:
            lines.append(
                f"Queued follow-ups: {summary.get('queued_pivots', 0)} pivots, "
                f"{summary.get('queued_chains', 0)} chains"
            )

        return "\n".join(lines)

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def get_task_result(self, task_id: str) -> str:
        """Get the result of a previously dispatched task.

        Use this when you dispatched with wait_for_result=False.

        Args:
            task_id: The task ID returned by a dispatch call.

        Returns:
            Task result or status.
        """
        if not self._dispatcher:
            return "ERROR: No dispatcher configured"

        result = await self._dispatcher.wait_for_result(task_id, timeout=10)
        if result.get("error") and "timed out" in str(result.get("error", "")):
            return f"[*] Task {task_id} still running..."
        return _format_task_result("Task", task_id, result)

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def complete_investigation(
        self,
        summary: str,
        attack_synopsis: str | None = None,
        recommendations: list[str] | None = None,
    ) -> str:
        """Complete the investigation with final synthesis.

        Call this when you have gathered enough evidence and are
        ready to generate the final report.

        Args:
            summary: Executive summary of the investigation.
            attack_synopsis: Narrative of the attack chain.
            recommendations: List of recommended actions.

        Returns:
            Confirmation message.
        """
        if not self._dispatcher:
            return "ERROR: No dispatcher configured"

        backend = self._dispatcher.backend
        await backend.set_meta("attack_synopsis", attack_synopsis or summary)
        await backend.set_meta("stage", "synthesis")

        if recommendations:
            for rec in recommendations:
                await backend.add_recommendation(rec)

        logger.info(f"Investigation completed: {summary[:100]}...")
        return f"[+] Investigation complete. Summary recorded. Report will be generated."

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def escalate_investigation(
        self,
        reason: str,
        severity: str,
        attack_synopsis: str = "",
        recommendations: list[str] | None = None,
    ) -> str:
        """Escalate the investigation for human analyst review.

        Call this when you identify an active attack, critical
        infrastructure at risk, or scope exceeds capacity.

        Args:
            reason: Why escalation is needed.
            severity: Escalation severity: critical, high, medium.
            attack_synopsis: Narrative of the attack chain discovered so far.
            recommendations: List of recommended containment/remediation actions.

        Returns:
            Confirmation message.
        """
        if not self._dispatcher:
            return "ERROR: No dispatcher configured"

        backend = self._dispatcher.backend
        await backend.set_meta("escalated", True)
        await backend.set_meta("escalation_reason", reason)

        if attack_synopsis:
            await backend.set_meta("attack_synopsis", attack_synopsis)

        if recommendations:
            for rec in recommendations:
                await backend.add_recommendation(rec)

        logger.warning(f"Investigation ESCALATED: {reason} (severity={severity})")
        return f"[!] Investigation ESCALATED. Reason: {reason}. Severity: {severity}."


def _format_task_result(task_type: str, task_id: str, result: dict[str, Any]) -> str:
    """Format a task result for display to the orchestrator."""
    lines = [f"=== {task_type} Result (task_id={task_id}) ==="]

    if result.get("error"):
        lines.append(f"Status: FAILED")
        lines.append(f"Error: {result['error']}")
    else:
        lines.append(f"Status: SUCCESS")

    inner = result.get("result", {})
    if isinstance(inner, dict):
        # Format known result fields
        if inner.get("summary") or inner.get("findings_summary") or inner.get("scope_summary"):
            summary = inner.get("summary") or inner.get("findings_summary") or inner.get("scope_summary")
            lines.append(f"Summary: {summary}")

        if inner.get("severity_assessment"):
            lines.append(f"Severity: {inner['severity_assessment']}")

        if inner.get("needs_deep_investigation") is not None:
            lines.append(f"Needs Deep Investigation: {inner['needs_deep_investigation']}")

        if inner.get("techniques_found"):
            lines.append(f"Techniques: {', '.join(inner['techniques_found'])}")

        if inner.get("initial_techniques"):
            lines.append(f"Initial Techniques: {', '.join(inner['initial_techniques'])}")

        if inner.get("evidence_highlights"):
            lines.append("Evidence Highlights:")
            for h in inner["evidence_highlights"][:5]:
                lines.append(f"  - {h}")

        if inner.get("recommended_next_steps"):
            lines.append("Recommended Next Steps:")
            for s in inner["recommended_next_steps"][:5]:
                lines.append(f"  - {s}")

        if inner.get("recommended_pivots"):
            lines.append("Recommended Pivots:")
            for p in inner["recommended_pivots"][:5]:
                lines.append(f"  - {p}")

        if inner.get("hosts_investigated"):
            lines.append(f"Hosts: {', '.join(inner['hosts_investigated'][:10])}")

        if inner.get("users_investigated"):
            lines.append(f"Users: {', '.join(inner['users_investigated'][:10])}")

        if inner.get("lateral_paths"):
            lines.append("Lateral Paths:")
            for p in inner["lateral_paths"][:5]:
                lines.append(f"  - {p}")

        if inner.get("containment_recommendations"):
            lines.append("Containment:")
            for c in inner["containment_recommendations"][:5]:
                lines.append(f"  - {c}")

        if inner.get("detection_gaps"):
            lines.append("Detection Gaps:")
            for g in inner["detection_gaps"][:5]:
                lines.append(f"  - {g}")

    return "\n".join(lines)


class BlueTeamOrchestrator:
    """Multi-agent blue team investigation orchestrator.

    Coordinates triage, threat hunter, and lateral analyst workers
    to investigate security alerts. Uses an LLM-driven orchestrator
    agent that dispatches work to specialized workers.

    Attributes:
        model: LLM model identifier.
        grafana_url: Grafana URL for MCP connection.
        grafana_api_key: Grafana API key.
        mitre_client: MITRE ATT&CK client.
        report_dir: Directory for generated reports.
        max_steps: Max orchestrator steps.
        redis_url: Redis URL for shared state.
        attack_context: Optional red team operation context.
    """

    def __init__(
        self,
        model: str,
        grafana_url: str,
        grafana_api_key: str,
        mitre_client: MITREAttackClient,
        report_dir: Path,
        max_steps: int = 50,
        redis_url: str = "redis://localhost:6379",
        attack_context: dict | None = None,
    ):
        self.model = model
        self.grafana_url = grafana_url
        self.grafana_api_key = grafana_api_key
        self.mitre_client = mitre_client
        self.report_dir = report_dir
        self.max_steps = max_steps
        self.redis_url = redis_url
        self.attack_context = attack_context
        self._mcp_tools: list | None = None

    async def _ensure_mcp_connection(self) -> None:
        """Ensure MCP connection is ready (from pool)."""
        if self._mcp_tools is not None:
            return

        try:
            from ares.tools.blue.grafana import MCPConnectionPool, connect_grafana_mcp

            timeout = 10.0 if MCPConnectionPool.is_connected() else 60.0
            mcp_client = await asyncio.wait_for(
                connect_grafana_mcp(
                    grafana_url=self.grafana_url,
                    grafana_api_key=self.grafana_api_key,
                ),
                timeout=timeout,
            )
            self._mcp_tools = mcp_client.tools
            logger.success(f"Grafana MCP ready ({len(self._mcp_tools or [])} tools)")
        except Exception as e:
            logger.warning(f"Failed to connect to Grafana MCP: {e}")
            self._mcp_tools = None

    async def _shutdown_mcp(self) -> None:
        """Clear local MCP references."""
        self._mcp_tools = None

    async def investigate(
        self,
        alert: dict,
        correlation_context: dict | None = None,
    ) -> dict:
        """Run a multi-agent investigation on an alert.

        1. Connects to Redis and creates dispatcher + shared state
        2. Creates 3 worker agents (triage, hunter, lateral)
        3. Creates orchestrator agent with dispatch tools
        4. Runs orchestrator LLM which dispatches work to workers
        5. Generates report from shared state

        Args:
            alert: The alert dictionary.
            correlation_context: Optional alert correlation context.

        Returns:
            Result dict matching monolithic orchestrator output shape.
        """
        investigation_id = f"inv-{uuid.uuid4().hex[:8]}"
        alert_name = alert.get("labels", {}).get("alertname", "unknown")

        logger.info(f"Starting multi-agent investigation {investigation_id}: {alert_name}")

        # Connect to Redis
        from ares.core.redis_client import create_redis_client

        redis_client = await create_redis_client(self.redis_url)
        await redis_client.ping()

        # Create dispatcher
        dispatcher = BlueTeamDispatcher(redis_client)
        await dispatcher.start(investigation_id, alert, correlation_context)

        # Ensure MCP connection
        await self._ensure_mcp_connection()

        # Create worker agents
        workers: dict[BlueRole, BlueWorkerAgent] = {}

        for role, max_steps in [
            (BlueRole.TRIAGE, 8),
            (BlueRole.THREAT_HUNTER, 20),
            (BlueRole.LATERAL_ANALYST, 15),
        ]:
            agent, callback_tools = create_blue_agent(
                role=role,
                model=self.model,
                backend=dispatcher.backend,
                dispatcher=dispatcher,
                mitre_client=self.mitre_client,
                mcp_tools=self._mcp_tools,
                max_steps=max_steps,
                grafana_url=self.grafana_url,
                alert=alert,
            )
            worker = BlueWorkerAgent(
                role=role,
                agent=agent,
                agent_name=f"{role.value}-{investigation_id[:8]}",
                investigation_id=investigation_id,
                dispatcher=dispatcher,
                callback_tools=callback_tools,
            )
            workers[role] = worker

        # Create orchestrator agent
        orchestrator_tools = BlueOrchestratorTools()
        orchestrator_tools.set_dispatcher(dispatcher)
        orchestrator_tools.set_workers(workers)

        instructions = load_blue_instructions(BlueRole.ORCHESTRATOR)
        stop_conditions = get_blue_stop_conditions(BlueRole.ORCHESTRATOR)

        orchestrator_agent = dn.Agent(
            name="Blue Team Orchestrator",
            model=self.model,
            instructions=instructions,
            max_steps=self.max_steps,
            tools=[orchestrator_tools],
            stop_conditions=stop_conditions,
            thread=Thread(),  # type: ignore[call-arg]
        )

        # Build initial prompt
        initial_prompt = build_initial_prompt(alert, self.attack_context)

        # Watchdog timer
        hard_timeout = (self.max_steps * 60) + 120
        state_for_watchdog = InvestigationState(
            investigation_id=investigation_id,
            alert=alert,
        )
        watchdog = WatchdogTimer(
            hard_timeout, investigation_id, state_for_watchdog, self.report_dir
        )
        watchdog.start()

        try:
            with dn.run(tags=["multi-agent-investigation", alert_name]):
                dn.log_params(
                    model=self.model,
                    investigation_id=investigation_id,
                    alert_name=alert_name,
                    mode="multi_agent",
                    max_steps=self.max_steps,
                )

                # Run orchestrator
                timeout_seconds = self.max_steps * 60
                try:
                    result = await asyncio.wait_for(
                        orchestrator_agent.run(initial_prompt),
                        timeout=timeout_seconds,
                    )
                    logger.success(
                        f"Orchestrator completed: {result.steps} steps, {result.stop_reason}"
                    )
                except asyncio.TimeoutError:
                    logger.error(f"Orchestrator timed out after {timeout_seconds}s")
                except Exception as e:
                    logger.error(f"Orchestrator failed: {e}")

            # Snapshot shared state and convert to InvestigationState
            shared_state = await dispatcher.snapshot_to_shared_state()
            investigation_state = shared_state.to_investigation_state()

            # Determine status
            status = "completed"
            if shared_state.escalated:
                status = "escalated"

            # Generate report
            try:
                report_gen = MarkdownReportGenerator(self.report_dir)
                report_path = report_gen.generate(investigation_state)
                logger.success(f"Report generated: {report_path}")
            except Exception as e:
                logger.error(f"Report generation failed: {e}")

            return {
                "investigation_id": investigation_id,
                "status": status,
                "evidence_count": len(investigation_state.evidence),
                "techniques_identified": list(investigation_state.identified_techniques),
                "highest_pyramid_level": investigation_state.highest_pyramid_level,
                "state": investigation_state,
            }

        finally:
            watchdog.cancel()

            # Stop workers
            for worker in workers.values():
                await worker.stop()

            # Stop dispatcher
            await dispatcher.stop()

            # Close Redis
            try:
                await redis_client.aclose()
            except Exception:
                pass

            logger.info(f"Multi-agent investigation {investigation_id} cleanup complete")
