"""Investigation completion and escalation actions."""

from datetime import datetime, timezone

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset
from loguru import logger

from ares.core.models import InvestigationState

# Formatting constants for consistent UX
STATUS_SUCCESS = "[+]"
STATUS_WARNING = "[!]"
STATUS_INFO = "[*]"
SECTION_SEPARATOR = "=" * 40


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
            ...             "User dave.lee requested TGS tickets with RC4 encryption "
            ...             "for multiple SPNs from host 192.168.58.186. Confidence: High.",
            ...     attack_synopsis="At 14:30 UTC, user dave.lee from 192.168.58.186 "
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

        return self._format_completion_output(summary)

    def _format_completion_output(self, summary: str) -> str:
        """Format the completion output with visual indicators."""
        if not self.state:
            return "→ Report will be generated."

        lines = [
            "📝 INVESTIGATION COMPLETED",
            SECTION_SEPARATOR,
            "",
        ]

        # Final metrics
        evidence_count = len(self.state.evidence)
        timeline_count = len(self.state.timeline)
        technique_count = len(self.state.identified_techniques)

        # Calculate highest pyramid level
        highest_level = max(
            (e.pyramid_level.value for e in self.state.evidence),
            default=0,
        )

        lines.extend(
            [
                "📊 Final Metrics:",
                f"  • Evidence: {evidence_count} items",
                f"  • Timeline: {timeline_count} events",
                f"  • Techniques: {technique_count} identified",
                f"  • Pyramid Level: {highest_level}/6",
                "",
            ]
        )

        # Achievements - build list of achievements then add
        achievements = self._get_completion_achievements(evidence_count, technique_count)
        lines.append("🏆 Achievements:")
        lines.extend(achievements)
        lines.append("")

        # Summary preview
        summary_preview = summary[:150] + "..." if len(summary) > 150 else summary
        lines.extend(
            [
                "📋 Summary:",
                f"  {summary_preview}",
                "",
                "→ Report will be generated.",
            ]
        )

        return "\n".join(lines)

    def _get_completion_achievements(self, evidence_count: int, technique_count: int) -> list[str]:
        """Get list of achievement lines for completion output."""
        if not self.state:
            return []

        achievements = []

        ttp_count = sum(1 for e in self.state.evidence if e.pyramid_level.value == 6)
        tool_count = sum(1 for e in self.state.evidence if e.pyramid_level.value == 5)
        validated_count = sum(1 for e in self.state.evidence if e.validated)

        # Add achievements based on conditions
        if ttp_count > 0:
            achievements.append(f"  ✅ TTP LEVEL REACHED ({ttp_count} TTPs)")
        if tool_count > 0:
            achievements.append(f"  ✅ TOOL IDENTIFICATION COMPLETE ({tool_count} tools)")
        if technique_count >= 3:
            achievements.append("  ✅ COMPREHENSIVE TECHNIQUE COVERAGE")
        if self.state.recommendations:
            achievements.append(f"  ✅ {len(self.state.recommendations)} RECOMMENDATIONS GENERATED")
        if validated_count > 0:
            achievements.append(f"  ✅ VALIDATED EVIDENCE ({validated_count}/{evidence_count})")

        return achievements

    def _generate_fallback_synopsis(self) -> None:  # noqa: PLR0912
        """Generate a comprehensive synopsis from evidence if none provided.

        Creates a structured narrative including:
        - Alert context (name, severity, time)
        - MITRE techniques with names and tactics
        - Hosts and users involved
        - Evidence summary by pyramid level
        - Lateral movement summary
        - Timeline summary
        - Confidence assessment
        """
        if not self.state:
            return

        parts: list[str] = []

        # Alert context
        alert_name = self.state.alert.get("labels", {}).get("alertname", "Unknown alert")
        severity = self.state.alert.get("labels", {}).get("severity", "unknown")
        starts_at = self.state.alert.get("startsAt", "")

        parts.append(f"**Alert:** {severity.upper()} - {alert_name}")
        if starts_at:
            parts.append(f"**Time:** Alert triggered at {starts_at}")

        # Attack techniques identified with names and tactics
        if self.state.identified_techniques:
            technique_details = []
            for tech_id in list(self.state.identified_techniques)[:5]:
                name = self.state.technique_names.get(tech_id, "")
                tactic = self.state.technique_to_tactic.get(tech_id, "")
                if name:
                    technique_details.append(f"{tech_id} ({name}, {tactic})")
                else:
                    technique_details.append(tech_id)
            parts.append(f"**MITRE Techniques:** {', '.join(technique_details)}")

        # Hosts involved
        if self.state.queried_hosts:
            hosts = list(self.state.queried_hosts)[:5]
            parts.append(f"**Hosts Involved:** {', '.join(hosts)}")
            if len(self.state.queried_hosts) > 5:
                parts.append(f"  (and {len(self.state.queried_hosts) - 5} more)")

        # Users involved
        if self.state.queried_users:
            users = list(self.state.queried_users)[:5]
            parts.append(f"**Users Involved:** {', '.join(users)}")

        # Evidence summary by pyramid level
        if self.state.evidence:
            by_level: dict[int, list] = {}
            for ev in self.state.evidence:
                level = ev.pyramid_level.value
                if level not in by_level:
                    by_level[level] = []
                by_level[level].append(ev)

            parts.append(f"**Evidence Collected:** {len(self.state.evidence)} items")

            level_names = {
                1: "Hash Values",
                2: "IP Addresses",
                3: "Domain Names",
                4: "Network/Host Artifacts",
                5: "Tools",
                6: "TTPs",
            }
            for level in sorted(by_level.keys(), reverse=True):
                items = by_level[level]
                level_name = level_names.get(level, f"Level {level}")
                parts.append(f"  - {level_name}: {len(items)} items")
                # Show top 3 values for each level
                for ev in items[:3]:
                    value_preview = ev.value[:50] + "..." if len(ev.value) > 50 else ev.value
                    parts.append(f"    - {ev.type}: {value_preview}")

        # Lateral movement summary
        if (
            hasattr(self.state, "lateral_graph")
            and self.state.lateral_graph
            and self.state.lateral_graph.connections
        ):
            graph = self.state.lateral_graph
            parts.append(f"**Lateral Movement:** {len(graph.connections)} connections detected")
            parts.append(f"  - Hosts investigated: {len(graph.investigated_hosts)}")
            parts.append(f"  - Hosts pending: {len(graph.pending_hosts)}")
            if graph.connections:
                conn_types: dict[str, int] = {}
                for c in graph.connections:
                    conn_types[c.connection_type] = conn_types.get(c.connection_type, 0) + 1
                parts.append(f"  - Connection types: {conn_types}")

        # Timeline summary
        if len(self.state.timeline) > 1:
            sorted_timeline = sorted(self.state.timeline, key=lambda e: e.timestamp)
            first = sorted_timeline[0]
            last = sorted_timeline[-1]
            parts.append(f"**Timeline:** {len(self.state.timeline)} events")
            first_desc = (
                first.description[:50] + "..." if len(first.description) > 50 else first.description
            )
            last_desc = (
                last.description[:50] + "..." if len(last.description) > 50 else last.description
            )
            parts.append(f"  - First event: {first.timestamp.isoformat()} - {first_desc}")
            parts.append(f"  - Last event: {last.timestamp.isoformat()} - {last_desc}")

        # Confidence assessment
        if self.state.evidence:
            avg_confidence = sum(e.confidence for e in self.state.evidence) / len(
                self.state.evidence
            )
            validated_count = sum(1 for e in self.state.evidence if e.validated)
            parts.append(f"**Confidence:** {avg_confidence * 100:.0f}% average")
            parts.append(f"  - Validated evidence: {validated_count}/{len(self.state.evidence)}")

        self.state.attack_synopsis = "\n".join(parts)


@dn.tool  # type: ignore[untyped-decorator]
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

    logger.info(f"Investigation escalated: {reason}")

    # Build formatted escalation output
    severity_upper = severity.upper()
    severity_tag = f"[{severity_upper}]"

    lines = [
        f"⚠️ INVESTIGATION ESCALATED {severity_tag}",
        SECTION_SEPARATOR,
        "",
        "🚨 Escalation Details:",
        f"  Reason: {reason}",
        f"  Severity: {severity}",
        "",
        "📋 Current Findings:",
        f"  {current_findings[:200]}{'...' if len(current_findings) > 200 else ''}",
        "",
    ]

    if immediate_actions:
        lines.append("🔥 Immediate Actions Required:")
        for i, action in enumerate(immediate_actions[:5], 1):
            lines.append(f"  {i}. {action}")
        lines.append("")

    lines.append("→ Human analyst has been notified.")

    return "\n".join(lines)
