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
    from ares.core.models import RedTeamState, SharedRedTeamState


class RedTeamReportGenerator:
    """Generates markdown reports from red team operation results.

    Attributes:
        loader: Template loader for rendering report sections.
    """

    def __init__(self):
        self.loader = get_template_loader()

    def generate(self, state: RedTeamState) -> str:
        """Generate the full markdown report.

        Args:
            state: Red team operation state containing all findings.

        Returns:
            Complete markdown report as a string.
        """
        duration = datetime.now(timezone.utc) - state.started_at
        duration_str = str(duration).split(".")[0]

        executive_summary = self._generate_executive_summary(state)
        vulnerability_count = getattr(state, "vulnerability_count", None)
        if vulnerability_count is None:
            vulnerability_count = len(state.weaknesses)
        exploited_count = getattr(state, "exploited_count", None)
        if exploited_count is None:
            exploited_count = "unknown"

        # Render the report using the template
        return self.loader.render(
            "redteam/reports/operation_summary.md.jinja",
            operation_id=state.operation_id,
            target_ip=state.target.ip,
            started_at=state.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            completed_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            duration=duration_str,
            stage=state.stage.value,
            executive_summary=executive_summary,
            has_domain_admin=state.has_domain_admin,
            has_golden_ticket=state.has_golden_ticket,
            host_count=state.host_count,
            user_count=len(state.users),
            credential_count=state.credential_count,
            admin_count=state.admin_count,
            vulnerability_count=vulnerability_count,
            exploited_count=exploited_count,
            share_count=len(state.shares),
            hosts=state.hosts,
            users=state.users,
            credentials=state.credentials,
            shares=state.shares,
            weaknesses=state.weaknesses,
            timeline=state.timeline,
            techniques_identified=state.identified_techniques,
        )

    def _generate_executive_summary(self, state: RedTeamState) -> str:
        """Generate the executive summary section.

        Args:
            state: Red team operation state.

        Returns:
            Executive summary text.
        """
        if state.report_summary:
            return state.report_summary

        summary_parts = []

        # Operation overview
        summary_parts.append(
            f"Red team operation **{state.operation_id}** was executed against target "
            f"**{state.target.ip}** in an Active Directory penetration testing engagement."
        )

        # Key achievements
        achievements = []
        if state.has_domain_admin:
            achievements.append("✓ **Domain Administrator access achieved**")
        if state.has_golden_ticket:
            achievements.append("✓ **Golden ticket generated** for persistent access")
        if state.admin_count > 0:
            achievements.append(f"✓ **{state.admin_count} administrator account(s)** discovered")
        if state.credential_count > 0:
            achievements.append(f"✓ **{state.credential_count} credential(s)** obtained")

        if achievements:
            summary_parts.append("\n\n**Key Achievements:**\n" + "\n".join(achievements))

        # Discovery statistics
        vulnerability_count = getattr(state, "vulnerability_count", len(state.weaknesses))
        exploited_count = getattr(state, "exploited_count", None)
        exploited_label = exploited_count if exploited_count is not None else "unknown"
        summary_parts.append(
            f"\n\n**Discovery Statistics:**\n"
            f"- Hosts Discovered: {state.host_count}\n"
            f"- User Accounts: {len(state.users)}\n"
            f"- Network Shares: {len(state.shares)}\n"
            f"- Password Hashes: {len(state.hashes)}\n"
            f"- Vulnerabilities: {vulnerability_count}\n"
            f"- Vulnerabilities Exploited: {exploited_label}"
        )

        # Attack path summary
        if state.has_domain_admin or state.has_golden_ticket:
            summary_parts.append(
                "\n\n**Attack Path:**\n"
                "The operation successfully achieved privileged access through systematic "
                "recon, credential harvesting, and lateral movement techniques. "
                "Detailed attack timeline is provided below."
            )

        # Security posture assessment
        if state.has_domain_admin or state.has_golden_ticket:
            posture = "**CRITICAL**"
            assessment = (
                "The target environment has critical security weaknesses that allowed "
                "full domain compromise. Immediate remediation is required."
            )
        elif state.admin_count > 0:
            posture = "**HIGH**"
            assessment = (
                "The target environment has significant security weaknesses with administrative "
                "access obtained. Remediation is strongly recommended."
            )
        elif state.credential_count > 0:
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
    now = datetime.now(timezone.utc)
    duration = now - state.started_at
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
                "target_ip": vuln.target_ip,
                "target_host": vuln.target_host or vuln.target_ip,
                "priority": vuln.priority,
                "exploited": vuln_id in state.exploited_vulnerabilities,
                "details": vuln.details or "",
            }
        )
    discovered_vulns.sort(key=lambda v: v["priority"])

    # Format timeline events
    timeline = []
    for event in state.operation_timeline:
        timeline.append(
            {
                "timestamp": event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "description": event.description,
                "mitre_techniques": event.mitre_techniques,
            }
        )

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
        completed_at=now.strftime("%Y-%m-%d %H:%M:%S UTC"),
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
        techniques=sorted(state.identified_techniques),
        discovered_vulns=discovered_vulns,
        vulnerabilities_found=len(state.discovered_vulnerabilities),
        vulnerabilities_exploited=len(state.exploited_vulnerabilities),
        generated_at=now.strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
