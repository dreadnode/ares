"""Red Team reporting and documentation tools.

This module provides toolsets for recording findings during
red team operations.
"""

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset

from ares.core.models import SharedRedTeamState


class RedTeamReportingTools(Toolset):
    """Tools for documenting and reporting red team findings.

    Records credentials, weaknesses, and significant events throughout
    the operation.
    """

    state: SharedRedTeamState | None = None

    def set_state(self, state: SharedRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def get_operation_summary(self) -> str:
        """
        Get a summary of the current operation state.

        Returns counts of credentials, hosts, weaknesses, and other
        key metrics for the operation.

        Returns:
            Formatted operation summary

        Example:
            >>> get_operation_summary()
        """
        if not self.state:
            return "[!] No operation state available"

        lines = [
            "📊 OPERATION SUMMARY",
            "=" * 40,
        ]

        if hasattr(self.state, "all_credentials"):
            creds = list(self.state.all_credentials)
        else:
            creds = self.state.credentials
        admin_creds = [c for c in creds if c.is_admin]
        lines.append(f"Credentials: {len(creds)} ({len(admin_creds)} admin)")

        if hasattr(self.state, "all_hashes"):
            hashes = list(self.state.all_hashes)
        else:
            hashes = self.state.hashes
        lines.append(f"Hashes: {len(hashes)}")

        lines.append(f"Hosts: {len(self.state.hosts)}")
        lines.append(f"Users: {len(self.state.users)}")
        lines.append(f"Shares: {len(self.state.shares)}")
        lines.append(f"Weaknesses: {len(self.state.weaknesses)}")

        if hasattr(self.state, "timeline"):
            lines.append(f"Timeline Events: {len(self.state.timeline)}")

        if hasattr(self.state, "has_golden_ticket") and self.state.has_golden_ticket:
            lines.append("\n🎫 Golden Ticket: OBTAINED")

        if hasattr(self.state, "goal_achieved") and self.state.goal_achieved:
            lines.append("\n\u2705 Goal: ACHIEVED")

        return "\n".join(lines)

    @dn.tool_method
    def list_credentials(self) -> str:
        """
        List all discovered credentials.

        Returns:
            Formatted list of credentials

        Example:
            >>> list_credentials()
        """
        if not self.state:
            return "[!] No operation state available"

        if hasattr(self.state, "all_credentials"):
            creds = list(self.state.all_credentials)
        else:
            creds = self.state.credentials

        if not creds:
            return "[*] No credentials discovered yet"

        lines = [
            "🔑 DISCOVERED CREDENTIALS",
            "=" * 40,
        ]

        for cred in creds:
            admin_tag = " [ADMIN]" if cred.is_admin else ""
            password_display = cred.password or "[no password]"
            lines.append(f"- {cred.domain}\\{cred.username}:{password_display}{admin_tag}")
            if cred.source:
                lines.append(f"  Source: {cred.source}")

        return "\n".join(lines)

    @dn.tool_method
    def list_weaknesses(self) -> str:
        """
        List all discovered weaknesses.

        Returns:
            Formatted list of weaknesses

        Example:
            >>> list_weaknesses()
        """
        if not self.state:
            return "[!] No operation state available"

        if not self.state.weaknesses:
            return "[*] No weaknesses recorded yet"

        lines = [
            "\u26a0\ufe0f DISCOVERED WEAKNESSES",
            "=" * 40,
        ]

        for i, weakness in enumerate(self.state.weaknesses, 1):
            lines.append(f"\n{i}. {weakness}")

        return "\n".join(lines)
