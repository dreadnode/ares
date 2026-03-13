"""Tools for triaging escalated investigations.

The escalation triage agent uses these tools to decide whether
an escalated investigation truly requires human review or can
be handled automatically.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset
from loguru import logger

if TYPE_CHECKING:
    import asyncio

    from ares.core.blue_state_backend import BlueStateBackend
    from ares.core.models import SharedBlueTeamState


class EscalationTriageTools(Toolset):  # type: ignore[misc]
    """Tools for making triage decisions on escalated investigations.

    The triage agent evaluates escalated investigations and decides:
    - CONFIRMED: Valid escalation, needs human review
    - DOWNGRADED: False positive or low priority, auto-complete
    - REINVESTIGATE: Need more data before deciding
    - ROUTED: Route to specific team/action

    Attributes:
        _backend: BlueStateBackend for Redis persistence.
        _shared_state: SharedBlueTeamState with investigation data.
        _completion_event: Set when a decision is made.
        _result_data: The decision result.
    """

    _backend: BlueStateBackend | None = None
    _shared_state: SharedBlueTeamState | None = None
    _completion_event: asyncio.Event | None = None
    _result_data: dict[str, Any]

    def __init__(self) -> None:
        super().__init__()
        self._result_data = {}

    def set_backend(self, backend: BlueStateBackend) -> None:
        """Set the Redis state backend."""
        self._backend = backend

    def set_shared_state(self, state: SharedBlueTeamState) -> None:
        """Set the shared investigation state."""
        self._shared_state = state

    def set_completion_event(self, event: asyncio.Event) -> None:
        """Set the completion event (called before agent.run)."""
        self._completion_event = event
        self._result_data = {}

    @property
    def result_data(self) -> dict[str, Any]:
        """Get the decision result data."""
        return self._result_data

    def _signal_completion(self, data: dict[str, Any]) -> None:
        """Signal completion with decision data."""
        self._result_data = data
        if self._completion_event:
            self._completion_event.set()

    def _get_implied_capabilities(self, techniques: set[str]) -> list[str]:
        """Infer attack capabilities from observed techniques.

        Certain techniques imply that other attacks are now possible,
        even if we haven't observed them directly. This is critical for
        triage - we shouldn't downgrade just because we didn't SEE the
        follow-on attack in logs.

        Args:
            techniques: Set of observed MITRE technique IDs.

        Returns:
            List of implied capability warnings.
        """
        implied = []

        # krbtgt hash extraction → Golden Ticket capability
        # T1003.006 = DCSync, T1003.001 = LSASS dump, T1003.003 = NTDS.dit
        credential_dump_techniques = {"T1003.006", "T1003.001", "T1003.003", "T1003"}
        if credential_dump_techniques & techniques:
            implied.append(
                "GOLDEN TICKET CAPABILITY: Credential dumping detected (T1003.x). "
                "If krbtgt hash was obtained, attacker can forge Golden Tickets. "
                "Golden Ticket creation leaves NO log evidence - absence of T1558.001 "
                "detection does NOT mean it wasn't created."
            )

        # Constrained delegation → impersonation to any service on target SPN
        if "T1550.003" in techniques:
            implied.append(
                "PRIVILEGE ESCALATION CAPABILITY: Constrained delegation abuse detected. "
                "Attacker can impersonate ANY user (including Domain Admin) to the "
                "delegated service via S4U2Proxy. This can lead to DC compromise."
            )

        # Unconstrained delegation → TGT theft from any authenticating user
        if any(t in techniques for t in ["T1558", "T1550"]):
            has_delegation = "T1550.003" in techniques or any(
                "delegation" in str(techniques).lower() for _ in [1]
            )
            if has_delegation:
                implied.append(
                    "DOMAIN COMPROMISE RISK: Delegation abuse can lead to domain admin "
                    "access if a privileged user authenticates to the compromised service."
                )

        # Kerberoasting → offline password cracking capability
        if "T1558.003" in techniques:
            implied.append(
                "CREDENTIAL COMPROMISE RISK: Kerberoasting detected. Attacker has "
                "service account password hashes for offline cracking. Weak passwords "
                "can be cracked in minutes."
            )

        # AS-REP Roasting → offline password cracking for pre-auth disabled accounts
        if "T1558.004" in techniques:
            implied.append(
                "CREDENTIAL COMPROMISE RISK: AS-REP Roasting detected. Accounts with "
                "Kerberos pre-auth disabled are vulnerable to offline password cracking."
            )

        # DCSync specifically → full domain compromise
        if "T1003.006" in techniques:
            implied.append(
                "DOMAIN ADMIN ACHIEVED: DCSync (T1003.006) requires Domain Admin or "
                "replication rights. If this technique was successful, the attacker "
                "has DA-equivalent access and can extract ALL domain credentials."
            )

        return implied

    @dn.tool_method  # type: ignore[untyped-decorator]
    def get_investigation_context(self) -> str:
        """Get the full investigation context for triage decision.

        Returns a comprehensive summary of the investigation including:
        - Alert details
        - Escalation reason
        - Evidence collected
        - Techniques identified
        - Attack synopsis
        - Scope (hosts/users investigated)

        Use this FIRST to understand what you're triaging.

        Returns:
            Formatted investigation context.
        """
        if not self._shared_state:
            return "ERROR: No investigation state available"

        state = self._shared_state
        lines = [
            "=" * 60,
            "ESCALATED INVESTIGATION CONTEXT",
            "=" * 60,
            "",
            f"Investigation ID: {state.investigation_id}",
            f"Stage: {state.stage.value}",
            "",
            "--- ALERT ---",
        ]

        # Alert details
        alert = state.alert
        if alert:
            lines.append(f"Name: {alert.get('labels', {}).get('alertname', 'unknown')}")
            lines.append(f"Severity: {alert.get('labels', {}).get('severity', 'unknown')}")
            desc = alert.get("annotations", {}).get("description", "")
            if desc:
                lines.append(f"Description: {desc[:500]}")

        # Escalation reason
        lines.append("")
        lines.append("--- ESCALATION ---")
        lines.append(f"Escalated: {state.escalated}")
        lines.append(f"Reason: {state.escalation_reason or 'Not specified'}")

        # Evidence summary
        lines.append("")
        lines.append("--- EVIDENCE ---")
        lines.append(f"Total evidence items: {len(state.evidence)}")

        if state.evidence:
            # Group by pyramid level
            by_level: dict[int, list] = {}
            for ev in state.evidence:
                level = ev.pyramid_level.value
                if level not in by_level:
                    by_level[level] = []
                by_level[level].append(ev)

            level_names = {
                1: "Hash Values",
                2: "IP Addresses",
                3: "Domain Names",
                4: "Artifacts",
                5: "Tools",
                6: "TTPs",
            }

            for level in sorted(by_level.keys(), reverse=True):
                items = by_level[level]
                lines.append(f"  Level {level} ({level_names.get(level, 'Unknown')}): {len(items)}")
                # Show first 3 items at each level
                for ev in items[:3]:
                    lines.append(f"    - [{ev.type}] {ev.value[:60]}...")

        # Techniques
        lines.append("")
        lines.append("--- MITRE ATT&CK ---")
        lines.append(f"Techniques identified: {len(state.identified_techniques)}")
        if state.identified_techniques:
            techs = list(state.identified_techniques)[:10]
            for tech_id in techs:
                name = state.technique_names.get(tech_id, "")
                lines.append(f"  - {tech_id}: {name}")

        # Scope
        lines.append("")
        lines.append("--- SCOPE ---")
        lines.append(f"Hosts investigated: {len(state.queried_hosts)}")
        if state.queried_hosts:
            for host in list(state.queried_hosts)[:5]:
                lines.append(f"  - {host}")
        lines.append(f"Users investigated: {len(state.queried_users)}")
        if state.queried_users:
            for user in list(state.queried_users)[:5]:
                lines.append(f"  - {user}")

        # Synopsis
        lines.append("")
        lines.append("--- SYNOPSIS ---")
        lines.append(state.attack_synopsis or "No synopsis generated")

        # Attack chain implications - infer capabilities from observed techniques
        lines.append("")
        lines.append("--- ATTACK CHAIN IMPLICATIONS ---")
        implied_capabilities = self._get_implied_capabilities(state.identified_techniques)
        if implied_capabilities:
            for capability in implied_capabilities:
                lines.append(f"  ⚠️  {capability}")
        else:
            lines.append("  No additional implied capabilities")

        # Recommendations
        if state.recommendations:
            lines.append("")
            lines.append("--- RECOMMENDATIONS ---")
            for rec in state.recommendations[:5]:
                lines.append(f"  - {rec}")

        lines.append("")
        lines.append("=" * 60)

        return "\n".join(lines)

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def confirm_escalation(
        self,
        reasoning: str,
        severity: str,
        confidence: float = 0.8,
    ) -> str:
        """Confirm that this escalation requires human review.

        Use when the investigation reveals a genuine threat that needs
        human analyst attention. This keeps the status as "escalated".

        Criteria for confirmation:
        - High-confidence active attack in progress
        - Domain admin or critical system compromise
        - Multiple correlated attack techniques
        - Data exfiltration or ransomware indicators
        - APT-like behavior patterns

        Args:
            reasoning: Detailed explanation of why human review is needed.
            severity: Assessment of severity (critical, high, medium).
            confidence: Confidence in this decision (0.0-1.0).

        Returns:
            Confirmation message.
        """
        if not self._backend:
            return "ERROR: No backend configured"

        await self._backend.set_triage_decision(
            decision="confirmed",
            reasoning=reasoning,
            confidence=confidence,
        )

        logger.info(f"Triage confirmed escalation: severity={severity}, confidence={confidence}")

        self._signal_completion(
            {
                "decision": "confirmed",
                "reasoning": reasoning,
                "severity": severity,
                "confidence": confidence,
            }
        )

        return f"[+] Escalation CONFIRMED ({severity}). Investigation will remain escalated for human review."

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def downgrade_escalation(
        self,
        reasoning: str,
        is_false_positive: bool,
        confidence: float = 0.7,
    ) -> str:
        """Downgrade this escalation - no human review needed.

        Use when the investigation reveals this is not a genuine threat.
        The investigation will be marked as completed instead of escalated.

        Criteria for downgrading:
        - False positive due to benign admin activity
        - Known authorized penetration testing
        - Automated security scanning by IT
        - Log artifact from legitimate software
        - Already remediated incident

        Args:
            reasoning: Detailed explanation of why this is not a threat.
            is_false_positive: True if this is a complete false positive.
            confidence: Confidence in this decision (0.0-1.0).

        Returns:
            Confirmation message.
        """
        if not self._backend:
            return "ERROR: No backend configured"

        await self._backend.set_triage_decision(
            decision="downgraded",
            reasoning=reasoning,
            confidence=confidence,
        )

        fp_label = "FALSE POSITIVE" if is_false_positive else "LOW PRIORITY"
        logger.info(f"Triage downgraded escalation: {fp_label}, confidence={confidence}")

        self._signal_completion(
            {
                "decision": "downgraded",
                "reasoning": reasoning,
                "is_false_positive": is_false_positive,
                "confidence": confidence,
            }
        )

        return f"[+] Escalation DOWNGRADED ({fp_label}). Investigation will be marked completed."

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def request_reinvestigation(
        self,
        reasoning: str,
        focus_areas: list[str],
        confidence: float = 0.5,
    ) -> str:
        """Request additional investigation before making a triage decision.

        Use when you cannot make a confident decision due to missing data.
        This dispatches additional workers to gather more information.

        NOTE: Maximum 2 reinvestigation cycles allowed. After that,
        the escalation will be auto-confirmed.

        Criteria for reinvestigation:
        - Insufficient log data for the time period
        - Need to check related hosts/users
        - Missing context about the environment
        - Ambiguous indicators that need correlation

        Args:
            reasoning: Explanation of what data is missing.
            focus_areas: Specific areas to investigate (e.g., ["check host ws01 for lateral movement", "verify user admin activity"]).
            confidence: How confident you are that more data will help (0.0-1.0).

        Returns:
            Confirmation message or error if max cycles exceeded.
        """
        if not self._backend:
            return "ERROR: No backend configured"

        # Check reinvestigation cycle
        current_cycle = await self._backend.get_reinvestigation_cycle()
        if current_cycle >= 2:
            # Auto-confirm after max cycles
            logger.warning(
                f"Max reinvestigation cycles ({current_cycle}) exceeded, auto-confirming"
            )
            return await self.confirm_escalation(
                reasoning=f"Auto-confirmed after {current_cycle} reinvestigation cycles. Original reason: {reasoning}",
                severity="medium",
                confidence=0.6,
            )

        await self._backend.set_triage_decision(
            decision="reinvestigate",
            reasoning=reasoning,
            confidence=confidence,
            focus_areas=focus_areas,
            reinvestigation_cycle=current_cycle + 1,
        )

        logger.info(
            f"Triage requested reinvestigation: cycle={current_cycle + 1}, focus={focus_areas}"
        )

        self._signal_completion(
            {
                "decision": "reinvestigate",
                "reasoning": reasoning,
                "focus_areas": focus_areas,
                "cycle": current_cycle + 1,
                "confidence": confidence,
            }
        )

        return f"[+] REINVESTIGATION requested (cycle {current_cycle + 1}/2). Focus: {', '.join(focus_areas)}"

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def route_to_team(
        self,
        reasoning: str,
        team: str,
        action: str,
        confidence: float = 0.8,
    ) -> str:
        """Route this investigation to a specific team or trigger an action.

        Use when the investigation should be handled by a specific team
        rather than general SOC escalation.

        Teams:
        - incident_response: Active incident requiring IR team
        - threat_intel: APT indicators need TI analysis
        - forensics: Need disk/memory forensics
        - legal: Insider threat or compliance issue
        - infrastructure: Misconfig needs IT team

        Args:
            reasoning: Explanation of why this routing is appropriate.
            team: Target team (incident_response, threat_intel, forensics, legal, infrastructure).
            action: Specific action for the team (e.g., "isolate host ws01", "analyze malware sample").
            confidence: Confidence in this routing decision (0.0-1.0).

        Returns:
            Confirmation message.
        """
        if not self._backend:
            return "ERROR: No backend configured"

        valid_teams = {"incident_response", "threat_intel", "forensics", "legal", "infrastructure"}
        if team not in valid_teams:
            return f"ERROR: Invalid team '{team}'. Valid teams: {', '.join(sorted(valid_teams))}"

        await self._backend.set_triage_decision(
            decision="routed",
            reasoning=reasoning,
            confidence=confidence,
            routed_to=f"{team}:{action}",
        )

        logger.info(f"Triage routed to {team}: {action}")

        self._signal_completion(
            {
                "decision": "routed",
                "reasoning": reasoning,
                "team": team,
                "action": action,
                "confidence": confidence,
            }
        )

        return f"[+] Investigation ROUTED to {team}. Action: {action}"


__all__ = ["EscalationTriageTools"]
