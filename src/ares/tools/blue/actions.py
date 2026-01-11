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
        attack_synopsis: str | None = None,
        recommendations: list[str] | None = None,
    ) -> str:
        """Complete the investigation and signal report generation.

        Call this when you have:
        - Answered the key questions about the alert
        - Recorded evidence for your findings
        - Built a timeline of events
        - Identified affected hosts/users

        Args:
            summary: Executive summary of the investigation including:
                - What attack/activity was detected
                - Key findings and evidence
                - Affected hosts and users
                - Confidence level (high/medium/low)
            attack_synopsis: Narrative describing the attack chain chronologically.
                Should include specific hostnames, usernames, IPs, and timestamps.
                Explains how the attacker progressed through the attack.
            recommendations: List of recommended actions to take. Should include
                both immediate response actions and long-term improvements.
                Check the alert's 'response' annotation for expert guidance.

        Returns:
            Confirmation message.

        Example:
            >>> await complete_investigation(
            ...     summary="Detected Kerberoasting attack targeting service accounts. "
            ...             "User samwell.tarly requested TGS tickets with RC4 encryption "
            ...             "for multiple SPNs from host 10.0.4.186. Confidence: High.",
            ...     attack_synopsis="At 14:30 UTC, user samwell.tarly from 10.0.4.186 "
            ...                     "began requesting TGS tickets for service accounts. "
            ...                     "12 tickets requested with RC4 encryption over 5 minutes.",
            ...     recommendations=[
            ...         "Reset service account passwords immediately",
            ...         "Enable AES-only Kerberos encryption",
            ...         "Review service account permissions"
            ...     ]
            ... )
            'Investigation completed. Report will be generated.'
        """
        if not self.state:
            return "ERROR: No investigation state. Cannot complete."

        # Log stage info
        if self.state.stage.value not in ["lateral", "synthesis"]:
            logger.info(f"Investigation completed at '{self.state.stage.value}' stage")

        # Store attack synopsis if provided
        if attack_synopsis:
            self.state.attack_synopsis = attack_synopsis
            logger.info(f"Attack synopsis recorded: {attack_synopsis[:100]}...")

        # Process recommendations
        if recommendations:
            self.state.recommendations.extend(recommendations)
            logger.info(f"Added {len(recommendations)} recommendations")

        # Auto-extract recommendations from alert annotations if none provided
        if not self.state.recommendations:
            alert_annotations = self.state.alert.get("annotations", {})
            response_guidance = alert_annotations.get("response", "")
            if response_guidance:
                import re

                steps = re.split(r"\d+\.\s+", response_guidance)
                extracted_recs = [s.strip() for s in steps if s.strip()]
                if extracted_recs:
                    self.state.recommendations.extend(extracted_recs)
                    logger.info(f"Auto-extracted {len(extracted_recs)} recommendations from alert")

        # Auto-generate synopsis if not provided and we have evidence
        if not self.state.attack_synopsis and self.state.evidence:
            self._generate_fallback_synopsis()

        # Record completion
        dn.log_metric("investigation_completed", 1)
        dn.log_output(
            "completion_summary",
            {
                "summary": summary,
                "attack_synopsis": self.state.attack_synopsis,
                "recommendations": self.state.recommendations,
                "evidence_count": len(self.state.evidence),
                "timeline_events": len(self.state.timeline),
                "hosts_investigated": list(self.state.queried_hosts),
                "users_investigated": list(self.state.queried_users),
                "techniques_identified": list(self.state.identified_techniques),
            },
        )

        logger.success(f"Investigation completed: {summary[:100]}...")

        return "Investigation completed. Report will be generated."

    def _generate_fallback_synopsis(self) -> None:
        """Generate a basic synopsis from evidence if none provided."""
        if not self.state:
            return

        parts = []

        alert_name = self.state.alert.get("labels", {}).get("alertname", "Unknown alert")
        severity = self.state.alert.get("labels", {}).get("severity", "unknown")
        starts_at = self.state.alert.get("startsAt", "")

        parts.append(f"{severity.upper()} alert: {alert_name}")

        if starts_at:
            parts.append(f"Alert triggered at {starts_at}.")

        if self.state.identified_techniques:
            techniques = ", ".join(list(self.state.identified_techniques)[:3])
            parts.append(f"MITRE techniques identified: {techniques}.")

        if self.state.queried_hosts:
            hosts = ", ".join(list(self.state.queried_hosts)[:3])
            parts.append(f"Hosts involved: {hosts}.")

        if self.state.queried_users:
            users = ", ".join(list(self.state.queried_users)[:3])
            parts.append(f"Users involved: {users}.")

        if self.state.evidence:
            parts.append(f"{len(self.state.evidence)} evidence items collected.")
            high_level = [e for e in self.state.evidence if e.pyramid_level.value >= 5]
            if high_level:
                parts.append(f"{len(high_level)} high-value indicators (tools/TTPs) identified.")

        self.state.attack_synopsis = " ".join(parts)


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
