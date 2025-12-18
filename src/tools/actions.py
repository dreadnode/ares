"""Investigation completion and escalation actions."""

from datetime import datetime, timezone

import dreadnode as dn
from loguru import logger


@dn.tool()  # type: ignore[untyped-decorator]
async def complete_investigation(
    summary: str,
    attack_synopsis: str,
    recommendations: list[str],
    confidence: str,
) -> str:
    """Complete the investigation and signal report generation.

    Call this when you have:
    1. A clear timeline of events
    2. Identified TTPs with MITRE mappings
    3. Assessed scope and blast radius
    4. Produced actionable intelligence

    Args:
        summary: Executive summary (2-3 sentences).
        attack_synopsis: Description of what happened.
        recommendations: List of recommended actions.
        confidence: Overall confidence level (high/medium/low with explanation).

    Returns:
        Confirmation message.

    Example:
        >>> await complete_investigation(
        ...     summary="Detected PowerShell-based reconnaissance on web-01. "
        ...             "Attack chain progressed to credential access.",
        ...     attack_synopsis="Attacker used PowerShell to enumerate Active Directory...",
        ...     recommendations=[
        ...         "Rotate credentials for compromised accounts",
        ...         "Enable PowerShell script block logging",
        ...         "Review lateral movement paths"
        ...     ],
        ...     confidence="High - Multiple corroborating evidence items with MITRE mappings"
        ... )
        'Investigation completed. Report will be generated.'

    See Also:
        escalate_investigation: For escalating to human analyst when needed.
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
