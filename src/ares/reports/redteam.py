"""
Markdown Report Generator for red team operations.

Produces detailed penetration testing reports with discovered assets,
credentials, attack paths, and MITRE ATT&CK mapping.
"""

from datetime import datetime, timezone

from ares.core.models import RedTeamState
from ares.core.templates import get_template_loader


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
