"""
Markdown Report Generator for red team operations.

Produces detailed penetration testing reports with discovered assets,
credentials, attack paths, and MITRE ATT&CK mapping.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ares.core.templates import get_template_loader

if TYPE_CHECKING:
    from ares.core.models import SharedRedTeamState


class RedTeamReportGenerator:
    """Generates markdown reports from red team operation results.

    Attributes:
        loader: Template loader for rendering report sections.
    """

    def __init__(self):
        self.loader = get_template_loader()

    def generate(self, state: SharedRedTeamState) -> str:
        """Generate the full markdown report.

        Args:
            state: Red team operation state containing all findings.

        Returns:
            Complete markdown report as a string.
        """
        # Use persisted completed_at if available (for SharedRedTeamState)
        completed_at = getattr(state, "completed_at", None) or datetime.now(timezone.utc)
        duration = completed_at - state.started_at
        duration_str = str(duration).split(".")[0]

        executive_summary = self._generate_executive_summary(state)
        vulnerability_count = len(state.discovered_vulnerabilities)
        exploited_count = len(state.exploited_vulnerabilities)

        # Deduplicate users (case-insensitive on domain+username)
        seen_users: set[tuple[str, str]] = set()
        unique_users = []
        for user in state.all_users:
            user_key = (user.domain.lower(), user.username.lower())
            if user_key not in seen_users:
                seen_users.add(user_key)
                unique_users.append(user)

        # Deduplicate credentials (case-insensitive on domain+username+password)
        seen_creds: set[tuple[str, str, str]] = set()
        unique_creds = []
        for cred in state.all_credentials:
            cred_key = (cred.domain.lower(), cred.username.lower(), cred.password)
            if cred_key not in seen_creds:
                seen_creds.add(cred_key)
                unique_creds.append(cred)

        # Calculate counts from SharedRedTeamState
        host_count = len(state.all_hosts)
        credential_count = len(unique_creds)

        # Count admins - check is_admin flag OR known admin usernames
        admin_count = sum(
            1
            for c in unique_creds
            if c.is_admin or c.username.lower() in ("administrator", "krbtgt")
        )

        # Render the report using the template
        return self.loader.render(
            "redteam/reports/operation_summary.md.jinja",
            operation_id=state.operation_id,
            target_ip=state.target.ip if state.target else "Unknown",
            started_at=state.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            completed_at=completed_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            duration=duration_str,
            stage="completed" if (state.completed or state.completed_at) else "in_progress",
            executive_summary=executive_summary,
            has_domain_admin=state.has_domain_admin,
            has_golden_ticket=state.has_golden_ticket,
            host_count=host_count,
            user_count=len(unique_users),
            credential_count=credential_count,
            admin_count=admin_count,
            vulnerability_count=vulnerability_count,
            exploited_count=exploited_count,
            share_count=len(state.all_shares),
            hosts=state.all_hosts,
            users=unique_users,
            credentials=unique_creds,
            shares=state.all_shares,
            weaknesses=state.all_weaknesses,
            timeline=state.operation_timeline,
            techniques_identified=state.identified_techniques,
        )

    def _generate_executive_summary(self, state: SharedRedTeamState) -> str:
        """Generate the executive summary section.

        Args:
            state: Red team operation state.

        Returns:
            Executive summary text.
        """
        if state.report_summary:
            return state.report_summary

        # Calculate counts from SharedRedTeamState
        host_count = len(state.all_hosts)
        credential_count = len(state.all_credentials)
        admin_count = sum(1 for c in state.all_credentials if c.is_admin)
        vulnerability_count = len(state.discovered_vulnerabilities)
        exploited_count = len(state.exploited_vulnerabilities)

        summary_parts = []

        # Operation overview
        target_ip = state.target.ip if state.target else "Unknown"
        summary_parts.append(
            f"Red team operation **{state.operation_id}** was executed against target "
            f"**{target_ip}** in an Active Directory penetration testing engagement."
        )

        # Key achievements
        achievements = []
        if state.has_domain_admin:
            achievements.append("✓ **Domain Administrator access achieved**")
        if state.has_golden_ticket:
            achievements.append("✓ **Golden ticket generated** for persistent access")
        if admin_count > 0:
            achievements.append(f"✓ **{admin_count} administrator account(s)** discovered")
        if credential_count > 0:
            achievements.append(f"✓ **{credential_count} credential(s)** obtained")

        if achievements:
            summary_parts.append("\n\n**Key Achievements:**\n" + "\n".join(achievements))

        # Discovery statistics
        summary_parts.append(
            f"\n\n**Discovery Statistics:**\n"
            f"- Hosts Discovered: {host_count}\n"
            f"- User Accounts: {len(state.all_users)}\n"
            f"- Network Shares: {len(state.all_shares)}\n"
            f"- Password Hashes: {len(state.all_hashes)}\n"
            f"- Vulnerabilities: {vulnerability_count}\n"
            f"- Vulnerabilities Exploited: {exploited_count}"
        )

        # Attack path summary - use actual captured path, not generic text
        if state.has_domain_admin or state.has_golden_ticket:
            if state.domain_admin_path:
                summary_parts.append(f"\n\n**Attack Path:**\n{state.domain_admin_path}")
            else:
                # Fallback only if no path was captured
                summary_parts.append(
                    "\n\n**Attack Path:**\nDomain admin achieved. See timeline below for details."
                )

        # Security posture assessment
        if state.has_domain_admin or state.has_golden_ticket:
            posture = "**CRITICAL**"
            assessment = (
                "The target environment has critical security weaknesses that allowed "
                "full domain compromise. Immediate remediation is required."
            )
        elif admin_count > 0:
            posture = "**HIGH**"
            assessment = (
                "The target environment has significant security weaknesses with administrative "
                "access obtained. Remediation is strongly recommended."
            )
        elif credential_count > 0:
            posture = "**MEDIUM**"
            assessment = (
                "The target environment has moderate security weaknesses with credentials "
                "compromised. Security improvements are recommended."
            )
        else:
            posture = "**LOW**"
            assessment = (
                "The target environment demonstrated resilience against the red team operation. "
                "Continue monitoring and maintain security posture."
            )

        summary_parts.append(f"\n\n**Security Posture:** {posture}\n\n{assessment}")

        return "".join(summary_parts)


def generate_comprehensive_report(state: SharedRedTeamState) -> str:
    """Generate a comprehensive markdown report from SharedRedTeamState.

    This is the main report generator for completed operations. It includes
    the full attack path, all credentials with passwords, hashes, and
    detailed vulnerability information.

    Args:
        state: SharedRedTeamState from Redis containing all operation data.

    Returns:
        Complete markdown report as a string.
    """
    loader = get_template_loader()
    # Use persisted completed_at if available, fallback to now
    completed_at = state.completed_at or datetime.now(timezone.utc)
    duration = completed_at - state.started_at
    duration_str = str(duration).split(".")[0]

    # Deduplicate credentials and hashes
    seen_creds: set[tuple[str, str, str]] = set()
    unique_creds = []
    for cred in state.all_credentials:
        key = (cred.domain.lower(), cred.username.lower(), cred.password)
        if key not in seen_creds:
            seen_creds.add(key)
            unique_creds.append(cred)

    seen_hashes: set[tuple[str, str, str]] = set()
    unique_hashes = []
    for h in state.all_hashes:
        key = (h.domain.lower(), h.username.lower(), h.hash_value.lower())
        if key not in seen_hashes:
            seen_hashes.add(key)
            unique_hashes.append(h)

    # Sort hashes to put important ones first (Administrator, krbtgt)
    def hash_priority(h) -> tuple[int, str]:
        name = h.username.lower()
        if name == "administrator":
            return (0, name)
        if name == "krbtgt":
            return (1, name)
        return (2, name)

    unique_hashes.sort(key=hash_priority)

    # Count DCs
    dc_count = sum(1 for h in state.all_hosts if h.is_dc)

    # Build vulnerability info for template
    discovered_vulns = []
    for vuln_id, vuln in state.discovered_vulnerabilities.items():
        discovered_vulns.append(
            {
                "vuln_id": vuln_id,
                "vuln_type": vuln.vuln_type,
                "target_ip": vuln.target,
                "target_host": vuln.target,
                "priority": vuln.priority,
                "exploited": vuln_id in state.exploited_vulnerabilities,
                "details": vuln.details or "",
            }
        )
    discovered_vulns.sort(key=lambda v: v.get("priority", 999))  # type: ignore[arg-type,return-value]

    # Format timeline events and collect MITRE techniques
    timeline = []
    all_techniques: set[str] = set(state.identified_techniques)
    for event in state.operation_timeline:
        timeline.append(
            {
                "timestamp": event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "description": event.description,
                "mitre_techniques": event.mitre_techniques,
            }
        )
        # Collect techniques from timeline events into the aggregate set
        if event.mitre_techniques:
            all_techniques.update(event.mitre_techniques)

    # Get target info
    target_ip = state.target.ip if state.target else "Unknown"
    target_domain = state.target.domain if state.target else "Unknown"

    # Render the comprehensive report
    return loader.render(
        "redteam/reports/comprehensive_report.md.jinja",
        operation_id=state.operation_id,
        target_ip=target_ip,
        target_domain=target_domain,
        started_at=state.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        completed_at=completed_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        duration=duration_str,
        has_domain_admin=state.has_domain_admin,
        has_golden_ticket=state.has_golden_ticket,
        domain_admin_path=state.domain_admin_path,
        domain_admin_chain=state.build_attack_chain() if state.has_domain_admin else None,
        domains=sorted({d.lower() for d in state.all_domains if d}),
        hosts=state.all_hosts,
        dc_count=dc_count,
        users=state.all_users,
        credentials=unique_creds,
        hashes=unique_hashes,
        weaknesses=state.all_weaknesses,
        timeline=timeline,
        techniques=sorted(all_techniques),
        discovered_vulns=discovered_vulns,
        vulnerabilities_found=len(state.discovered_vulnerabilities),
        vulnerabilities_exploited=len(state.exploited_vulnerabilities),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
