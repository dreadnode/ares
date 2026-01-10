"""Investigation completion and escalation actions."""

from datetime import datetime, timezone

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset
from loguru import logger

from ares.core.models import InvestigationState


class CompletionTools(Toolset):  # type: ignore[misc]
    """Tools for completing investigations with validation.

    Attributes:
        state: Current investigation state for validation.
    """

    state: InvestigationState | None = None

    def set_state(self, state: InvestigationState):
        """Set the investigation state (called by orchestrator)."""
        self.state = state

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def complete_investigation(
        self,
        summary: str,
        attack_synopsis: str,
        recommendations: list[str],
        confidence: str,
        affected_hosts: list[str],
        affected_users: list[str],
        attack_timeframe: str,
    ) -> str:
        """Complete the investigation and signal report generation.

        REQUIRED before calling:
        1. Must have transitioned through lateral stage
        2. Must have investigated at least one host
        3. Must provide specific affected hosts/users
        4. Must provide attack timeframe

        Args:
            summary: Executive summary (2-3 sentences).
            attack_synopsis: Detailed description of the attack chain.
            recommendations: List of recommended actions.
            confidence: Overall confidence level (high/medium/low with explanation).
            affected_hosts: List of hosts involved in the attack (IPs or hostnames).
            affected_users: List of user accounts involved.
            attack_timeframe: Time range of the attack (e.g., "2024-01-15 14:30-15:45 UTC").

        Returns:
            Confirmation message or error if validation fails.

        Example:
            >>> await complete_investigation(
            ...     summary="Detected Kerberoasting attack targeting service accounts.",
            ...     attack_synopsis="Attacker performed AS-REP roasting against samwell.tarly...",
            ...     recommendations=["Reset passwords for samwell.tarly and jeor.mormont"],
            ...     confidence="High - Multiple corroborating Kerberos events",
            ...     affected_hosts=["10.0.4.186", "WINTERFELL.north.sevenkingdoms.local"],
            ...     affected_users=["samwell.tarly", "jeor.mormont"],
            ...     attack_timeframe="2024-01-08 04:37-04:43 UTC"
            ... )
            'Investigation completed. Report will be generated.'
        """
        warnings = []

        # Validate state exists
        if not self.state:
            return "ERROR: No investigation state. Cannot complete."

        # Log stage warning but don't block
        if self.state.stage.value not in ["lateral", "synthesis"]:
            warnings.append(
                f"Note: Investigation completed at '{self.state.stage.value}' stage "
                f"(ideally should reach 'lateral' stage for thorough analysis)."
            )

        # Log if no hosts were investigated
        if not self.state.queried_hosts and not affected_hosts:
            warnings.append(
                "Note: No specific hosts were investigated. Consider investigating "
                "affected hosts in future investigations."
            )

        # Log warnings (but don't block completion)
        for warning in warnings:
            logger.warning(warning)

        # All validations passed
        dn.log_metric("investigation_completed", 1)
        dn.log_output(
            "completion_summary",
            {
                "summary": summary,
                "attack_synopsis": attack_synopsis,
                "recommendations": recommendations,
                "confidence": confidence,
                "affected_hosts": affected_hosts,
                "affected_users": affected_users,
                "attack_timeframe": attack_timeframe,
                "evidence_count": len(self.state.evidence),
                "timeline_events": len(self.state.timeline),
                "hosts_investigated": list(self.state.queried_hosts),
                "users_investigated": list(self.state.queried_users),
            },
        )

        logger.success("Investigation completed")

        return "Investigation completed. Report will be generated."


@dn.tool()  # type: ignore[untyped-decorator]
async def escalate_investigation(
    reason: str,
    severity: str,
    current_findings: str,
    immediate_actions: list[str],
) -> str:
    """Escalate the investigation for human analyst review.

    Call this if:
    - You identify an active, ongoing attack
    - The scope exceeds investigation capacity
    - You need human analyst intervention
    - Critical infrastructure is at risk

    Args:
        reason: Why escalation is needed.
        severity: critical, high, or medium.
        current_findings: Summary of what you've found so far.
        immediate_actions: Actions that should be taken immediately.

    Returns:
        Confirmation message.

    Example:
        >>> await escalate_investigation(
        ...     reason="Active lateral movement detected across 15+ hosts",
        ...     severity="critical",
        ...     current_findings="Attacker has Domain Admin credentials and is actively "
        ...                      "exfiltrating data from file servers.",
        ...     immediate_actions=[
        ...         "Isolate compromised domain controller",
        ...         "Reset all privileged account passwords",
        ...         "Block C2 IP addresses at firewall"
        ...     ]
        ... )
        'Investigation escalated with severity=critical. Human analyst notified.'

    See Also:
        complete_investigation: For normal investigation completion.
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
            "escalated_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    logger.warning(f"Investigation escalated: {reason}")

    return f"Investigation escalated with severity={severity}. Human analyst notified."
