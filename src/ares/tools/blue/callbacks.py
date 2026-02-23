"""Worker completion callback tools for blue team multi-agent system.

Each worker agent (triage, threat_hunter, lateral_analyst) calls its
corresponding *_complete tool when finished. This sets an asyncio.Event
so the worker loop knows the agent is done and can extract the result.
"""

from __future__ import annotations

import asyncio
from typing import Any

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset
from loguru import logger


class BlueWorkerCallbackTools(Toolset):  # type: ignore[misc]
    """Completion callback tools for blue team worker agents.

    Each worker type calls its role-specific completion method when done.
    The completion sets an asyncio.Event so the worker loop can extract
    the result data and report back to the dispatcher.

    Attributes:
        _completion_event: Set when worker calls a *_complete method.
        _result_data: Populated by the completion call.
    """

    _completion_event: asyncio.Event | None = None
    _result_data: dict[str, Any] = {}

    def set_completion_event(self, event: asyncio.Event) -> None:
        """Set the completion event (called by worker before agent.run)."""
        self._completion_event = event
        self._result_data = {}

    @property
    def result_data(self) -> dict[str, Any]:
        """Get the result data populated by the completion call."""
        return self._result_data

    def _signal_completion(self, data: dict[str, Any]) -> None:
        """Signal completion with result data."""
        self._result_data = data
        if self._completion_event:
            self._completion_event.set()

    @dn.tool_method  # type: ignore[untyped-decorator]
    def triage_complete(
        self,
        summary: str,
        severity_assessment: str,
        initial_techniques: list[str] | None = None,
        recommended_next_steps: list[str] | None = None,
        needs_deep_investigation: bool = True,
    ) -> str:
        """Signal that triage analysis is complete.

        Call this when you have finished the initial triage of the alert.
        Include your assessment of severity and what the alert represents.

        Args:
            summary: Brief summary of triage findings.
            severity_assessment: Your assessment: critical, high, medium, low, or false_positive.
            initial_techniques: MITRE ATT&CK technique IDs identified during triage.
            recommended_next_steps: What should be investigated next.
            needs_deep_investigation: Whether deeper threat hunting is warranted.

        Returns:
            Confirmation message.
        """
        logger.info(f"Triage complete: severity={severity_assessment}, deep={needs_deep_investigation}")
        self._signal_completion({
            "type": "triage",
            "summary": summary,
            "severity_assessment": severity_assessment,
            "initial_techniques": initial_techniques or [],
            "recommended_next_steps": recommended_next_steps or [],
            "needs_deep_investigation": needs_deep_investigation,
        })
        return f"[+] Triage complete. Severity: {severity_assessment}. Findings reported to orchestrator."

    @dn.tool_method  # type: ignore[untyped-decorator]
    def hunt_complete(
        self,
        findings_summary: str,
        techniques_found: list[str] | None = None,
        evidence_highlights: list[str] | None = None,
        detection_gaps: list[str] | None = None,
        recommended_pivots: list[str] | None = None,
    ) -> str:
        """Signal that threat hunting is complete.

        Call this when you have finished investigating the assigned
        detection methods and techniques.

        Args:
            findings_summary: Summary of what was found during hunting.
            techniques_found: MITRE technique IDs confirmed by hunting.
            evidence_highlights: Key evidence items discovered.
            detection_gaps: Areas where detection data was insufficient.
            recommended_pivots: Hosts/users that warrant further investigation.

        Returns:
            Confirmation message.
        """
        logger.info(f"Hunt complete: techniques={len(techniques_found or [])}")
        self._signal_completion({
            "type": "hunt",
            "findings_summary": findings_summary,
            "techniques_found": techniques_found or [],
            "evidence_highlights": evidence_highlights or [],
            "detection_gaps": detection_gaps or [],
            "recommended_pivots": recommended_pivots or [],
        })
        return f"[+] Threat hunt complete. {len(techniques_found or [])} techniques confirmed."

    @dn.tool_method  # type: ignore[untyped-decorator]
    def lateral_complete(
        self,
        scope_summary: str,
        hosts_investigated: list[str] | None = None,
        users_investigated: list[str] | None = None,
        lateral_paths: list[str] | None = None,
        containment_recommendations: list[str] | None = None,
    ) -> str:
        """Signal that lateral movement analysis is complete.

        Call this when you have finished analyzing the scope of
        lateral movement and compromise.

        Args:
            scope_summary: Summary of the lateral movement scope.
            hosts_investigated: Hosts that were analyzed.
            users_investigated: Users that were analyzed.
            lateral_paths: Identified lateral movement paths.
            containment_recommendations: Recommended containment actions.

        Returns:
            Confirmation message.
        """
        logger.info(
            f"Lateral analysis complete: "
            f"hosts={len(hosts_investigated or [])}, users={len(users_investigated or [])}"
        )
        self._signal_completion({
            "type": "lateral",
            "scope_summary": scope_summary,
            "hosts_investigated": hosts_investigated or [],
            "users_investigated": users_investigated or [],
            "lateral_paths": lateral_paths or [],
            "containment_recommendations": containment_recommendations or [],
        })
        return (
            f"[+] Lateral analysis complete. "
            f"{len(hosts_investigated or [])} hosts, {len(users_investigated or [])} users analyzed."
        )
