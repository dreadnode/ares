"""Red Team reporting and documentation tools.

This module provides toolsets for recording findings during
red team operations.
"""

from datetime import datetime, timezone

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset

from ares.core.models import Credential, Hash, Host, SharedRedTeamState, TimelineEvent
from ares.tools.red.common import format_weakness_block


class RedTeamReportingTools(Toolset):
    """Tools for documenting and reporting red team findings.

    Use these tools to record credentials, weaknesses, and significant
    events throughout the operation.
    """

    state: SharedRedTeamState | None = None

    def set_state(self, state: SharedRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def record_credential(
        self,
        username: str,
        password: str = "",
        hash: str = "",
        domain: str = "",
        source: str = "",
        is_admin: bool = False,
    ) -> str:
        """
        Record a discovered credential in the operation state.

        Use this to manually add credentials that weren't automatically captured.
        Credentials are deduplicated and tracked for the final report.

        Args:
            username: Username discovered
            password: Password if available
            hash: Hash if available (NTLM, Kerberos, etc.)
            domain: Domain for the credential
            source: Where the credential was found (e.g., "secretsdump", "description field")
            is_admin: Whether this is an admin account

        Returns:
            Confirmation of recorded credential

        Example:
            >>> record_credential("admin", password="P@ssw0rd!", domain="contoso.local", source="cracked_hash", is_admin=True)  # pragma: allowlist secret
        """
        if not self.state:
            return "[!] No operation state available"

        if not username:
            return "[!] Username is required"

        cred = Credential(
            username=username,
            password=password,
            domain=domain,
            source=source,
            is_admin=is_admin,
        )

        if hasattr(self.state, "add_credential"):
            self.state.add_credential(cred, source)
        else:
            existing = any(
                c.username == username and c.password == password and c.domain == domain
                for c in self.state.credentials
            )
            if not existing:
                self.state.credentials.append(cred)

        if hash:
            hash_obj = Hash(
                username=username,
                hash_value=hash,
                hash_type="NTLM" if len(hash) == 32 else "Unknown",
                domain=domain,
            )
            if hasattr(self.state, "add_hash"):
                self.state.add_hash(hash_obj, source)
            else:
                self.state.hashes.append(hash_obj)

        admin_str = " [ADMIN]" if is_admin else ""
        return f"[+] Recorded credential: {domain}\\{username}{admin_str}"

    @dn.tool_method
    def record_weakness(
        self,
        title: str,
        vulnerability: str,
        affected_resource: str = "",
        impact: str = "",
        discovery_method: str = "",
    ) -> str:
        """
        Record a security weakness or misconfiguration.

        Use this to document findings that should appear in the final report.
        Weaknesses are deduplicated based on title.

        Args:
            title: Short title for the weakness
            vulnerability: Description of the vulnerability
            affected_resource: What is affected (user, host, service)
            impact: Business/security impact
            discovery_method: How it was discovered

        Returns:
            Confirmation of recorded weakness

        Example:
            >>> record_weakness(
            ...     "Weak Password Policy",
            ...     "Password length requirement is only 7 characters",
            ...     "Domain-wide",
            ...     "Enables password spraying attacks",
            ...     "Password policy enumeration"
            ... )
        """
        if not self.state:
            return "[!] No operation state available"

        details = {}
        if affected_resource:
            details["Affected Resource"] = affected_resource

        block = format_weakness_block(
            title,
            vulnerability,
            details,
            impact,
            discovery_method,
        )

        # Use add_weakness() for proper normalized deduplication
        if self.state.add_weakness(block):
            return f"[+] Recorded weakness: {title}"
        return f"[*] Weakness already recorded: {title}"

    @dn.tool_method
    def record_compromised_host(
        self,
        ip: str,
        hostname: str = "",
        os: str = "",
        access_level: str = "",
        notes: str = "",
    ) -> str:
        """
        Record a compromised host in the operation state.

        Use this to track hosts where you have gained access.
        Important for tracking lateral movement progress.

        Args:
            ip: IP address of the host
            hostname: Hostname if known
            os: Operating system
            access_level: Level of access (user, local_admin, domain_admin)
            notes: Additional notes about the compromise

        Returns:
            Confirmation of recorded host

        Example:
            >>> record_compromised_host("192.168.58.22", "WORKSTATION1", "Windows 10", "local_admin", "Compromised via PsExec")
        """
        if not self.state:
            return "[!] No operation state available"

        host = Host(
            ip=ip,
            hostname=hostname,
            os=os or "Unknown",
            roles=[access_level] if access_level else [],
            services=[],
        )

        if hasattr(self.state, "add_host"):
            self.state.add_host(host)
        else:
            existing = any(h.ip == ip for h in self.state.hosts)
            if not existing:
                self.state.hosts.append(host)

        return f"[+] Recorded compromised host: {ip} ({hostname or 'unknown'}) - {access_level or 'access obtained'}"

    @dn.tool_method
    def record_timeline_event(
        self,
        description: str,
        mitre_techniques: str = "",
        confidence: float = 1.0,
    ) -> str:
        """
        Record a significant event in the operation timeline.

        Use this to document major milestones and attack steps.
        Events are automatically timestamped.

        Args:
            description: Description of the event
            mitre_techniques: Comma-separated MITRE ATT&CK technique IDs
            confidence: Confidence level (0.0-1.0)

        Returns:
            Confirmation of recorded event

        Example:
            >>> record_timeline_event("Gained Domain Admin access", "T1078", 1.0)
        """
        if not self.state:
            return "[!] No operation state available"

        techniques = [t.strip() for t in mitre_techniques.split(",") if t.strip()]

        event = TimelineEvent(
            id=f"evt-{len(self.state.operation_timeline):04d}",
            timestamp=datetime.now(timezone.utc),
            description=description,
            mitre_techniques=techniques,
            confidence=confidence,
            source="manual_recording",
        )
        self.state.operation_timeline.append(event)

        return f"[+] Recorded timeline event: {description}"

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
