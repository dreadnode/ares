"""Red Team reconnaissance and information gathering tools.

This module provides toolsets for network scanning, user enumeration,
security posture validation, and BloodHound collection.
"""

import json
import re
import shlex
import uuid
from typing import Any

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset
from loguru import logger

from ares.core.models import Credential, Host, Share, User
from ares.tools.red.common import (
    AnyRedTeamState,
    add_credential_to_state,
    format_weakness_block,
    is_motd_garbage,
    is_motd_line,
    run_tool,
    write_users_file_remote,
)


class NetworkEnumerationTools(Toolset):
    """Tools for network scanning and recon."""

    state: AnyRedTeamState | None = None
    dispatcher: Any | None = None

    def set_state(self, state: AnyRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    def set_dispatcher(self, dispatcher) -> None:
        self.dispatcher = dispatcher

    def _check_port(self, target: str, port: int, timeout_seconds: int = 5) -> bool:
        cmd = ["nc", "-zv", "-w", str(timeout_seconds), target, str(port)]
        try:
            ssm_timeout = max(30, timeout_seconds + 5)
            _stdout, _stderr, returncode = run_tool(cmd, timeout_seconds=ssm_timeout)
            return returncode == 0
        except Exception:
            return False

    @dn.tool_method
    def check_rdp_reachability(self, target: str, timeout_seconds: int = 5) -> str:
        """
        Check if RDP (3389) is reachable on a target.

        Args:
            target: Target host or IP
            timeout_seconds: Port check timeout

        Returns:
            Reachability status message
        """
        reachable = self._check_port(target, 3389, timeout_seconds)
        if reachable:
            return f"[+] RDP port 3389 reachable on {target}"
        return f"[!] RDP port 3389 not reachable on {target}"

    @dn.tool_method
    def check_winrm_reachability(self, target: str, timeout_seconds: int = 5) -> str:
        """
        Check if WinRM (5985/5986) is reachable on a target.

        Args:
            target: Target host or IP
            timeout_seconds: Port check timeout

        Returns:
            Reachability status message
        """
        http_open = self._check_port(target, 5985, timeout_seconds)
        https_open = self._check_port(target, 5986, timeout_seconds)
        if http_open or https_open:
            open_ports = []
            if http_open:
                open_ports.append("5985")
            if https_open:
                open_ports.append("5986")
            ports = ", ".join(open_ports)
            return f"[+] WinRM reachable on {target} (ports {ports})"
        return f"[!] WinRM not reachable on {target} (ports 5985/5986 closed)"

    def _extract_users_from_outputs(self, outputs: list[tuple[str, str]]) -> set[str]:  # noqa: PLR0912
        users: set[str] = set()
        user_pattern = r"[A-Za-z0-9._$-]+"

        def _add_user(candidate: str) -> None:
            user = candidate.strip()
            if not user or user.endswith("$"):
                return
            if user.lower() == "anonymous":
                return
            # Filter out Kali MOTD garbage and invalid usernames
            if is_motd_garbage(user):
                return
            users.add(user)

        for label, content in outputs:
            if not content:
                continue
            label_lower = label.lower()
            for line in content.splitlines():
                if not line.strip():
                    continue

                # Skip lines that look like Kali MOTD (contain box-drawing characters)
                if is_motd_line(line):
                    continue

                rpc_match = re.search(r"user:\[([^\]]+)\]", line, re.IGNORECASE)
                if rpc_match:
                    _add_user(rpc_match.group(1))
                    continue

                if "netexec smb --users" in label_lower:
                    line_match = re.match(
                        r"^SMB\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+\S+\s+([A-Za-z0-9._-]+)\s+\d{4}-\d{2}-\d{2}",
                        line,
                    )
                    if line_match:
                        _add_user(line_match.group(1))
                        continue
                    backslash_match = re.search(
                        r"\\([A-Za-z0-9._-]+)\\s*\\(SidTypeUser\\)",
                        line,
                    )
                    if backslash_match:
                        _add_user(backslash_match.group(1))
                        continue
                    domain_match = re.search(
                        rf"[A-Za-z0-9._-]+\\({user_pattern})",
                        line,
                    )
                    if domain_match:
                        _add_user(domain_match.group(1))
                        continue
                    rid_match = re.search(r"\bAccount:\s*([A-Za-z0-9._-]+)", line)
                    if rid_match:
                        _add_user(rid_match.group(1))
                        continue

                if "netexec smb --rid-brute" in label_lower:
                    if "SidTypeUser" not in line:
                        continue
                    backslash_match = re.search(
                        r"\\([A-Za-z0-9._-]+)\\s*\\(SidTypeUser\\)",
                        line,
                    )
                    if backslash_match:
                        _add_user(backslash_match.group(1))
                        continue
                    domain_match = re.search(
                        rf"[A-Za-z0-9._-]+\\({user_pattern})",
                        line,
                    )
                    if domain_match:
                        _add_user(domain_match.group(1))
                        continue
                    rid_match = re.search(r"\bAccount:\s*([A-Za-z0-9._-]+)", line)
                    if rid_match:
                        _add_user(rid_match.group(1))
                        continue

                if "smb-enum-users" in label_lower:
                    name_match = re.search(
                        r"\b(?:username|user)\s*[:=]\s*([A-Za-z0-9._-]+)",
                        line,
                        re.IGNORECASE,
                    )
                    if name_match:
                        _add_user(name_match.group(1))
                        continue
                    domain_match = re.search(
                        rf"[A-Za-z0-9._-]+\\({user_pattern})",
                        line,
                    )
                    if domain_match:
                        _add_user(domain_match.group(1))
                        continue

        return users

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
            # Only strip clearly trailing punctuation, not ! which is common in passwords
            password = pass_match.group(1).strip().rstrip(".,;:()")

            username = ""
            account_inline = re.search(r"Account:\s*([A-Za-z0-9_.-]+)", stripped)
            if account_inline:
                username = account_inline.group(1).strip()

            if not username:
                user_inline = re.search(r"user:\[([^\]]+)\]", stripped, re.IGNORECASE)
                if user_inline:
                    username = user_inline.group(1).strip()

            if not username:
                username = current_user

            if not username:
                netexec_match = re.match(
                    r"^SMB\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+\S+\s+([A-Za-z0-9._-]+)\s+\d{4}-\d{2}-\d{2}",
                    stripped,
                )
                if netexec_match:
                    username = netexec_match.group(1).strip()

            if username and password:
                creds.append((username, password))
        return creds

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

    def _run_user_enum_commands(
        self, target: str, username: str, password: str, domain: str
    ) -> list[tuple[str, str]]:
        def _has_user_entries(output: str) -> bool:
            if not output or not output.strip():
                return False
            for line in output.splitlines():
                if re.search(r"\\[^:\\s]+", line):
                    return True
                if re.search(r"\buser(name)?:\s*\S+", line, re.IGNORECASE):
                    return True
                if re.search(r"user:\[[^\]]+\]", line, re.IGNORECASE):
                    return True
            return False

        outputs: list[tuple[str, str]] = []

        cmd = ["netexec", "smb", target]
        if username and password:
            cmd.extend(["-u", username, "-p", password])
            if domain:
                cmd.extend(["-d", domain])
        else:
            cmd.extend(["-u", "", "-p", ""])
        cmd.append("--users")
        stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)
        output = stdout or stderr or ""
        outputs.append(("netexec smb --users", output))

        if not (username and password):
            for rpc_op in ("lsaquery", "enumdomusers", "querydispinfo", "enumdomgroups"):
                rpc_cmd = ["rpcclient", "-U", "", "-N", target, "-c", rpc_op]
                rpc_stdout, rpc_stderr, _ = run_tool(rpc_cmd, timeout_seconds=120)
                rpc_output = rpc_stdout or rpc_stderr or ""
                outputs.append((f"rpcclient null session {rpc_op}", rpc_output))

            combined_output = "\n".join(content for _, content in outputs)
            if not _has_user_entries(combined_output):
                port_cmd = ["nmap", "-Pn", "-p", "445", target]
                port_stdout, port_stderr, _ = run_tool(port_cmd, timeout_seconds=120)
                port_output = port_stdout or port_stderr or ""
                outputs.append(("nmap port 445", port_output))

                nmap_cmd = ["nmap", "-Pn", "-p", "445", "--script", "smb-enum-users", target]
                nmap_stdout, nmap_stderr, _ = run_tool(nmap_cmd, timeout_seconds=180)
                nmap_output = nmap_stdout or nmap_stderr or ""
                outputs.append(("nmap smb-enum-users", nmap_output))

                rid_cmd = ["netexec", "smb", target, "-u", "", "-p", "", "--rid-brute"]
                rid_stdout, rid_stderr, _ = run_tool(rid_cmd, timeout_seconds=120)
                rid_output = rid_stdout or rid_stderr or ""
                outputs.append(("netexec smb --rid-brute", rid_output))

        return outputs

    def _classify_enum_output(self, label: str, output: str) -> str:
        if not output or not output.strip():
            return "no output"
        lower = output.lower()
        if "nt_status_access_denied" in lower or "access denied" in lower:
            return "access denied"
        if "nt_status_logon_failure" in lower or "logon failure" in lower:
            return "auth failed"
        if "filtered" in lower and ("445/tcp" in lower or "port 445" in lower):
            return "445 filtered"
        if any(
            token in lower
            for token in (
                "connection refused",
                "timed out",
                "no route to host",
                "host is down",
                "network is unreachable",
                "nt_status_connection_refused",
                "nt_status_io_timeout",
                "nt_status_host_unreachable",
                "nt_status_network_unreachable",
            )
        ):
            return "connection failed"
        return "ok"

    def _summarize_enum_outputs(self, outputs: list[tuple[str, str]]) -> str:
        lines: list[str] = []
        for label, content in outputs:
            status = self._classify_enum_output(label, content)
            lines.append(f"- {label}: {status}")
        return "\n".join(lines)

    def _format_enum_failure_message(self, outputs: list[tuple[str, str]], raw_output: str) -> str:
        issues = {
            "access_denied": False,
            "auth_failed": False,
            "conn_failed": False,
            "filtered_445": False,
        }
        for label, content in outputs:
            status = self._classify_enum_output(label, content)
            if status == "access denied":
                issues["access_denied"] = True
            elif status == "auth failed":
                issues["auth_failed"] = True
            elif status == "connection failed":
                issues["conn_failed"] = True
            elif status == "445 filtered":
                issues["filtered_445"] = True

        notes: list[str] = []
        if issues["filtered_445"] or issues["conn_failed"]:
            notes.append("Network path to SMB/RPC appears blocked or filtered.")
        if issues["access_denied"]:
            notes.append("RPC/SAMR access denied; anonymous recon may be restricted.")
        if issues["auth_failed"]:
            notes.append("Authentication failed; verify credentials.")
        if not notes:
            notes.append("Target may be non-Windows or recon is blocked.")

        summary = self._summarize_enum_outputs(outputs)
        message = "[!] SMB user enumeration did not return users."
        if summary:
            message += "\nPer-command status:\n" + summary
        if notes:
            message += "\nNotes: " + " ".join(notes)
        if raw_output:
            message += "\nRaw output:\n" + raw_output[:500]
        return message

    @dn.tool_method
    def nmap_scan(self, target: str) -> str:  # noqa: PLR0912
        """
        Scans target IPs to discover services, ports, and host information.

        This tool performs a two-phase network scan for speed and accuracy:
        1. Fast port discovery (no version detection)
        2. Service version detection only on discovered open ports

        Args:
            target: IP addresses to scan (space-separated for multiple targets)

        Returns:
            Detailed nmap scan output showing discovered services and versions

        Example:
            >>> result = nmap_scan("192.168.58.2")
            >>> result = nmap_scan("192.168.58.2 192.168.58.3 192.168.58.4")
        """

        def _parse_nmap_hosts(output: str) -> list[Host]:
            hosts: list[Host] = []
            current_ip = ""
            current_hostname = ""
            current_os = ""
            current_services: list[str] = []

            def _commit_current() -> None:
                if not current_ip:
                    return
                host = Host(
                    ip=current_ip,
                    hostname=current_hostname,
                    os=current_os or "Unknown",
                    roles=[],
                    services=current_services,
                )
                hosts.append(host)

            for line in output.splitlines():
                line = line.strip()  # noqa: PLW2901
                if not line:
                    continue
                report_match = re.match(r"^Nmap scan report for (.+)$", line)
                if report_match:
                    _commit_current()
                    current_ip = ""
                    current_hostname = ""
                    current_os = ""
                    current_services = []

                    host_line = report_match.group(1)
                    ip_match = re.match(r"(.+) \((\d+\.\d+\.\d+\.\d+)\)$", host_line)
                    if ip_match:
                        current_hostname = ip_match.group(1).strip()
                        current_ip = ip_match.group(2)
                    else:
                        ip_only = re.match(r"^(\d+\.\d+\.\d+\.\d+)$", host_line)
                        if ip_only:
                            current_ip = ip_only.group(1)
                        else:
                            current_hostname = host_line
                    continue

                if current_ip:
                    svc_match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+([^\s]+)", line)
                    if svc_match:
                        current_services.append(
                            f"{svc_match.group(1)}/{svc_match.group(2)} {svc_match.group(3)}"
                        )
                    os_match = re.search(r"Service Info: OS: ([^;]+)", line)
                    if os_match and not current_os:
                        current_os = os_match.group(1).strip()

            _commit_current()
            return hosts

        targets = target.split()

        try:
            logger.info(f"[*] Phase 1: Fast port discovery on {len(targets)} target(s)")

            # Phase 1: Fast port scan without version detection
            port_scan_cmd = ["nmap", "-Pn", "-sT", "-T4", "--open", "--top-ports", "100"] + targets
            stdout, stderr, returncode = run_tool(port_scan_cmd, timeout_seconds=120)

            if returncode != 0:
                logger.error(f"[!] Port scan failed: {stderr}")
                return stderr or f"Port scan failed with code {returncode}"

            # Parse open ports from output (format: "22/tcp open ssh")
            open_ports = set()
            for match in re.finditer(r"(\d+)/tcp\s+open", stdout):
                open_ports.add(match.group(1))

            if not open_ports:
                logger.info("[*] No open ports found")
                if self.state:
                    for ip in targets:
                        self.state.queried_hosts.add(ip)
                if self.state:
                    parsed_hosts = _parse_nmap_hosts(stdout)
                    for host in parsed_hosts:
                        if hasattr(self.state, "add_host"):
                            self.state.add_host(host)
                        elif not any(h.ip == host.ip for h in self.state.hosts):
                            self.state.hosts.append(host)
                return stdout

            ports_str = ",".join(sorted(open_ports, key=int))
            logger.info(f"[*] Phase 2: Service detection on {len(open_ports)} ports: {ports_str}")

            # Phase 2: Service version detection only on discovered ports
            svc_scan_cmd = ["nmap", "-Pn", "-sT", "-T4", "--open", "-sV", "-p", ports_str] + targets
            svc_stdout, svc_stderr, svc_returncode = run_tool(svc_scan_cmd, timeout_seconds=300)

            if svc_returncode != 0:
                logger.warning(f"[!] Service scan had issues: {svc_stderr}")
                # Return port scan results if service scan fails
                if self.state:
                    parsed_hosts = _parse_nmap_hosts(stdout)
                    for host in parsed_hosts:
                        if hasattr(self.state, "add_host"):
                            self.state.add_host(host)
                        elif not any(h.ip == host.ip for h in self.state.hosts):
                            self.state.hosts.append(host)
                return stdout

            logger.info(f"[*] Nmap scan completed for {len(targets)} target(s)")

            # Track the scanned hosts
            if self.state:
                for ip in targets:
                    self.state.queried_hosts.add(ip)

                parsed_hosts = _parse_nmap_hosts(svc_stdout)
                for host in parsed_hosts:
                    if hasattr(self.state, "add_host"):
                        self.state.add_host(host)
                    elif not any(h.ip == host.ip for h in self.state.hosts):
                        self.state.hosts.append(host)

            return svc_stdout

        except Exception as e:
            logger.error(f"Scan failed: {e!s}")
            return f"Scan failed: {e!s}"

    @dn.tool_method
    def smb_sweep(self, targets: str) -> str:
        """
        Sweep SMB for Windows hosts using netexec and record host metadata.

        Args:
            targets: Space-separated IPs or CIDR range (e.g., "192.168.58.0/24")

        Returns:
            netexec output for the sweep
        """

        def _parse_netexec_hosts(output_text: str) -> list[Host]:
            hosts: list[Host] = []
            for line in output_text.splitlines():
                if not line.startswith("SMB"):
                    continue
                match = re.match(r"^SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+(.*)$", line)
                if not match:
                    continue
                ip = match.group(1)
                name = match.group(2)
                details = match.group(3)

                os_match = re.search(r"\[\*\]\s+([^(]+)", details)
                os_name = os_match.group(1).strip() if os_match else "Unknown"

                name_match = re.search(r"\(name:([^)]+)\)", details)
                hostname = name_match.group(1) if name_match else name

                domain_match = re.search(r"\(domain:([^)]+)\)", details)
                domain_value = domain_match.group(1).strip() if domain_match else ""
                if domain_value and hostname and "." not in hostname:
                    hostname = f"{hostname.lower()}.{domain_value.lower()}"

                hosts.append(
                    Host(
                        ip=ip,
                        hostname=hostname,
                        os=os_name,
                        roles=[],
                        services=["445/tcp smb"],
                    )
                )
            return hosts

        try:
            target_list = targets.split()
            if not target_list:
                return "[!] No targets provided for SMB sweep."
            cmd = ["netexec", "smb"] + target_list
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=300)
            output = stdout or stderr or ""

            if self.state and output:
                for host in _parse_netexec_hosts(output):
                    if hasattr(self.state, "add_host"):
                        self.state.add_host(host)
                    elif not any(h.ip == host.ip for h in self.state.hosts):
                        self.state.hosts.append(host)

            return output
        except Exception as e:
            logger.error(f"SMB sweep failed: {e!s}")
            return f"SMB sweep failed: {e!s}"

    @dn.tool_method
    def resolve_domain_controllers(self, domain: str, dns_ip: str) -> str:
        """
        Resolve domain controllers via SRV lookup and record them as hosts.

        Args:
            domain: Active Directory domain (e.g., "contoso.local")
            dns_ip: DNS server IP to query

        Returns:
            nslookup output and any resolved controller hostnames
        """

        def _extract_srv_hosts(output_text: str) -> list[str]:
            hosts: list[str] = []
            for raw_line in output_text.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                srv_match = re.search(r"svr hostname = ([^\\s]+)", line, re.IGNORECASE)
                if srv_match:
                    host = srv_match.group(1).rstrip(".")
                    hosts.append(host)
                    continue
                service_match = re.search(
                    r"service = \\d+ \\d+ \\d+ ([^\\s]+)", line, re.IGNORECASE
                )
                if service_match:
                    host = service_match.group(1).rstrip(".")
                    hosts.append(host)
            return hosts

        def _resolve_host(hostname: str) -> str | None:
            getent_cmd = ["getent", "hosts", hostname]
            stdout, stderr, _ = run_tool(getent_cmd, timeout_seconds=60)
            output = stdout or stderr or ""
            match = re.search(r"(\\d+\\.\\d+\\.\\d+\\.\\d+)", output)
            if match:
                return match.group(1)

            nslookup_cmd = ["nslookup", hostname, dns_ip]
            stdout, stderr, _ = run_tool(nslookup_cmd, timeout_seconds=60)
            output = stdout or stderr or ""
            match = re.search(r"Address:\\s*(\\d+\\.\\d+\\.\\d+\\.\\d+)", output)
            if match:
                return match.group(1)
            return None

        try:
            if not domain or not dns_ip:
                return "[!] Domain and dns_ip are required for SRV lookup."
            if self.state and hasattr(self.state, "add_domain"):
                self.state.add_domain(domain)
            query = f"_ldap._tcp.dc._msdcs.{domain}"
            cmd = ["nslookup", "-type=srv", query, dns_ip]
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)
            output = stdout or stderr or ""

            hosts = _extract_srv_hosts(output)
            if self.state and hosts:
                for raw_hostname in hosts:
                    hostname = raw_hostname.strip().rstrip(".")
                    if not hostname:
                        continue
                    ip = _resolve_host(hostname)
                    if not ip:
                        logger.warning(f"[!] Failed to resolve DC hostname: {hostname}")
                        continue
                    host = Host(
                        ip=ip,
                        hostname=hostname,
                        os="Unknown",
                        roles=["AD DC"],
                        services=["389/tcp ldap"],
                    )
                    if hasattr(self.state, "add_host"):
                        self.state.add_host(host)
                    elif not any(h.ip == host.ip for h in self.state.hosts):
                        self.state.hosts.append(host)
            return output
        except Exception as e:
            logger.error(f"SRV lookup failed: {e!s}")
            return f"SRV lookup failed: {e!s}"

    @dn.tool_method
    def enumerate_users(self, target: str, username: str, password: str, domain: str = "") -> str:  # noqa: PLR0912
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
            >>> enumerate_users("192.168.58.100", "user", "pass", "DOMAIN")
            >>> enumerate_users("192.168.58.100", "", "", "")  # null session
        """
        # Import here to avoid circular import
        from ares.tools.red.credential_discovery import CredentialHarvestingTools

        def _has_user_entries(output: str) -> bool:
            if not output or not output.strip():
                return False
            for line in output.splitlines():
                if re.search(r"\\[^:\\s]+", line):
                    return True
                if re.search(r"\buser(name)?:\s*\S+", line, re.IGNORECASE):
                    return True
            return False

        def _parse_netexec_hosts(output_text: str) -> list[Host]:
            hosts: list[Host] = []
            for line in output_text.splitlines():
                if not line.startswith("SMB"):
                    continue
                match = re.match(r"^SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+(.*)$", line)
                if not match:
                    continue
                ip = match.group(1)
                name = match.group(2)
                details = match.group(3)

                os_match = re.search(r"\[\*\]\s+([^(]+)", details)
                os_name = os_match.group(1).strip() if os_match else "Unknown"

                name_match = re.search(r"\(name:([^)]+)\)", details)
                hostname = name_match.group(1) if name_match else name

                domain_match = re.search(r"\(domain:([^)]+)\)", details)
                domain_value = domain_match.group(1).strip() if domain_match else ""
                if (
                    domain_value
                    and hostname
                    and not hostname.lower().endswith(domain_value.lower())
                ):
                    hostname = f"{hostname.lower()}.{domain_value}"

                hosts.append(
                    Host(
                        ip=ip,
                        hostname=hostname,
                        os=os_name,
                        roles=[],
                        services=["445/tcp smb"],
                    )
                )
            return hosts

        try:
            outputs = self._run_user_enum_commands(target, username, password, domain)
            sections = [
                f"===== {label} =====\n{content}" for label, content in outputs if content.strip()
            ]
            output = "\n\n".join(sections).strip()
            logger.info(f"[*] User recon completed for {target} (user:{username}, domain:{domain})")

            # Determine domain early so we can populate state before Kerberos call
            # Priority: 1) Domain from SMB output (most accurate for this target)
            #           2) Task's domain parameter (fallback)
            #           3) State's target domain (last resort)
            domain_from_output = ""
            if output:
                domain_match = re.search(r"\(domain:([^)]+)\)", output, re.IGNORECASE)
                if domain_match:
                    domain_from_output = domain_match.group(1).strip()

            # Use output domain first (it's specific to this target), then task param, then state
            domain_hint = domain_from_output or domain
            if not domain_hint and self.state and self.state.target:
                domain_hint = self.state.target.domain or ""

            effective_domain = domain_hint
            if effective_domain and self.state and hasattr(self.state, "add_domain"):
                self.state.add_domain(effective_domain)

            # Populate hosts and users in state BEFORE Kerberos call so it has users to validate
            found_users = False
            found_passwords = False
            if output and self.state:
                for host in _parse_netexec_hosts(output):
                    if hasattr(self.state, "add_host"):
                        self.state.add_host(host)
                    elif not any(h.ip == host.ip for h in self.state.hosts):
                        self.state.hosts.append(host)

                if effective_domain:
                    users = self._extract_users_from_outputs(outputs)
                    found_users = bool(users)
                    for found_user in sorted(users):
                        if any(
                            u.username == found_user and u.domain == effective_domain
                            for u in self.state.users
                        ):
                            continue
                        self.state.users.append(
                            User(
                                username=found_user,
                                domain=effective_domain,
                                description="",
                                is_admin=False,
                            )
                        )

                    extracted = self._extract_passwords_from_user_enum_output(output)
                    found_passwords = bool(extracted)
                    for found_user, found_password in extracted:
                        pending_key = f"{effective_domain}:{found_user}".lower()
                        if hasattr(self.state, "pending_credential_findings"):
                            self.state.pending_credential_findings.add(pending_key)
                        self._add_credential(
                            found_user,
                            found_password,
                            effective_domain,
                            "user_description",
                        )
                    if "password :" in output.lower() and not extracted:
                        if hasattr(self.state, "pending_credential_findings"):
                            self.state.pending_credential_findings.add(
                                f"{effective_domain}:unknown"
                            )
                        logger.warning("[!] Plaintext password hints found but no usernames parsed")

            # Now run Kerberos user validation with populated state.users
            if not (username and password) and domain_hint:
                cred_tools = CredentialHarvestingTools()
                if self.state is not None:
                    cred_tools.set_state(self.state)
                kerb_output = cred_tools.kerberos_user_enum_noauth(domain_hint, target)
                if kerb_output:
                    output = (output + "\n\n" + kerb_output).strip()

            if output and (_has_user_entries(output) or found_users or found_passwords):
                return output

            raw_output = output or ""
            return self._format_enum_failure_message(outputs, raw_output)

        except Exception as e:
            logger.error(f"User recon failed: {e}")
            return f"User recon failed for {target}: {e}"

    @dn.tool_method
    def enumerate_shares(  # noqa: PLR0912
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
            >>> enumerate_shares("192.168.58.100", "DOMAIN", "user", "pass")
        """

        def _parse_netexec_hosts(output: str) -> list[Host]:
            hosts: list[Host] = []
            for line in output.splitlines():
                if not line.startswith("SMB"):
                    continue
                match = re.match(r"^SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+(.*)$", line)
                if not match:
                    continue
                ip = match.group(1)
                name = match.group(2)
                details = match.group(3)

                os_match = re.search(r"\[\*\]\s+([^(]+)", details)
                os_name = os_match.group(1).strip() if os_match else "Unknown"

                name_match = re.search(r"\(name:([^)]+)\)", details)
                hostname = name_match.group(1) if name_match else name
                domain_match = re.search(r"\(domain:([^)]+)\)", details)
                domain_value = domain_match.group(1).strip() if domain_match else ""
                if domain_value and hostname and "." not in hostname:
                    hostname = f"{hostname.lower()}.{domain_value.lower()}"

                hosts.append(
                    Host(
                        ip=ip,
                        hostname=hostname,
                        os=os_name,
                        roles=[],
                        services=["445/tcp smb"],
                    )
                )
            return hosts

        def _parse_netexec_shares(output: str) -> list[Share]:
            shares: list[Share] = []
            in_table = False
            for line in output.splitlines():
                if not line.startswith("SMB"):
                    continue
                body = re.sub(r"^SMB\s+\S+\s+\d+\s+\S+\s+", "", line).strip()
                if not body:
                    continue
                lower = body.lower()
                if lower.startswith("share") and "permission" in lower:
                    in_table = True
                    continue
                if in_table and set(body) <= {"-", " "}:
                    continue
                if in_table and (body.startswith("[") or lower.startswith("smb")):
                    in_table = False
                    continue
                if not in_table:
                    continue
                parts = body.split(None, 2)
                if not parts:
                    continue
                name = parts[0].strip()
                if not name or name.lower() == "share":
                    continue
                permissions = parts[1].strip() if len(parts) > 1 else ""
                comment = parts[2].strip() if len(parts) > 2 else ""
                shares.append(
                    Share(
                        host=target,
                        name=name,
                        permissions=permissions,
                        comment=comment,
                    )
                )
            return shares

        def _run_share_enum(
            auth_user: str, auth_pass: str, auth_domain: str, auth_desc: str
        ) -> tuple[str, list[Share], bool]:
            """Run share enumeration with given auth, return (output, shares, success)."""
            cmd = ["netexec", "smb", target, "-u", auth_user, "-p", auth_pass]
            if auth_domain:
                cmd.extend(["-d", auth_domain])
            cmd.append("--shares")

            logger.info(f"[enumerate_shares] Trying {auth_desc} on {target}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=120)
            output = stdout or stderr

            # Check for access denied or connection errors
            access_denied = any(
                err in output.lower()
                for err in [
                    "status_access_denied",
                    "status_logon_failure",
                    "error occurs while reading",
                    "connection refused",
                    "error enumerating shares",
                ]
            )

            if access_denied:
                logger.warning(f"[enumerate_shares] {auth_desc} failed on {target}: access denied")
                return output, [], False

            shares = _parse_netexec_shares(output)
            if shares:
                logger.info(
                    f"[enumerate_shares] {auth_desc} found {len(shares)} shares on {target}: "
                    f"{[s.name for s in shares]}"
                )
            else:
                logger.debug(f"[enumerate_shares] {auth_desc} returned no shares on {target}")

            return output, shares, True

        try:
            all_output = ""
            all_shares: list[Share] = []

            if username and password:
                # Use provided credentials
                output, shares, success = _run_share_enum(
                    username, password, domain, f"auth ({username})"
                )
                all_output = output
                all_shares = shares
            else:
                # Try multiple anonymous/guest auth methods
                auth_methods = [
                    ("", "", "", "null session (-u '' -p '')"),
                    ("guest", "", "", "guest account (-u 'guest' -p '')"),
                    ("a", "", "", "anonymous (-u 'a' -p '')"),
                ]

                for auth_user, auth_pass, auth_domain, auth_desc in auth_methods:
                    output, shares, success = _run_share_enum(
                        auth_user, auth_pass, auth_domain, auth_desc
                    )
                    all_output += f"\n--- {auth_desc} ---\n{output}"

                    if shares:
                        all_shares.extend(shares)
                        logger.info(f"[enumerate_shares] Success with {auth_desc} on {target}")
                        break  # Stop on first success with shares

                    if success and not shares:
                        # Auth worked but no shares found, still a valid result
                        logger.debug(
                            f"[enumerate_shares] {auth_desc} worked but no shares on {target}"
                        )
                        break

            # Parse hosts from output
            if self.state and all_output:
                for host in _parse_netexec_hosts(all_output):
                    if hasattr(self.state, "add_host"):
                        self.state.add_host(host)
                    elif not any(h.ip == host.ip for h in self.state.hosts):
                        self.state.hosts.append(host)

            # Add discovered shares to state
            shares_added = 0
            if self.state:
                for share in all_shares:
                    if hasattr(self.state, "add_share"):
                        if self.state.add_share(share):
                            shares_added += 1
                    elif not any(
                        s.host == share.host and s.name == share.name for s in self.state.shares
                    ):
                        self.state.shares.append(share)
                        shares_added += 1

            if shares_added > 0:
                logger.info(
                    f"[enumerate_shares] Added {shares_added} new shares to state for {target}"
                )

            return all_output

        except Exception as e:
            logger.error(f"[enumerate_shares] Failed for {target}: {e}")
            return f"Share recon failed for {target}: {e}"

    @dn.tool_method
    def smbclient_kerberos_shares(self, target: str, target_ip: str = "") -> str:
        """
        Enumerate SMB shares using Kerberos (no password) with smbclient.py.

        Args:
            target: Hostname or IP to query (Kerberos prefers FQDN)
            target_ip: Optional IP to connect to when hostname does not resolve

        Returns:
            smbclient.py output
        """
        try:
            cmd = ["smbclient.py", "-k", "-no-pass"]
            if target_ip:
                cmd.extend(["-target-ip", target_ip])
            cmd.append(f"@{target}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=180)
            output = stdout or stderr or ""

            if self.state and output:
                self._parse_smbclient_shares(output, target)

            return output
        except Exception as e:
            logger.error(f"smbclient share enum failed: {e!s}")
            return f"smbclient share enum failed: {e!s}"

    def _parse_smbclient_shares(self, output: str, target: str) -> None:
        """Parse smbclient share output and add shares to state."""
        if not self.state:
            return
        state = self.state  # Local reference for type narrowing
        in_table = False
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("Sharename"):
                in_table = True
                continue
            if in_table and set(stripped) <= {"-", " "}:
                continue
            if not in_table or not stripped:
                if not stripped:
                    break
                continue
            parts = line.split(None, 2)
            if not parts:
                continue
            name = parts[0].strip()
            if not name:
                continue
            comment = parts[2].strip() if len(parts) > 2 else ""
            share = Share(host=target, name=name, permissions="", comment=comment)
            if hasattr(state, "add_share"):
                state.add_share(share)
            elif not any(s.host == target and s.name == name for s in state.shares):
                state.shares.append(share)

    @dn.tool_method
    def save_users_to_file(
        self, target: str, username: str = "", password: str = "", domain: str = ""
    ) -> str:
        """
        Enumerate users and save them to a file for password attacks.

        This tool enumerates domain users and saves them to /tmp/users.txt,
        which can then be used with username_as_password or password_spray.

        **RUN THIS FIRST** before any password-based attacks.

        Args:
            target: Domain controller IP address
            username: Username for authentication (use empty string for null session)
            password: Password for authentication (use empty string for null session)
            domain: Domain for authentication (optional)

        Returns:
            Path to the users file and count of users saved

        Example:
            >>> save_users_to_file("192.168.58.10", "", "", "")  # null session
            >>> save_users_to_file("192.168.58.10", "user", "pass", "DOMAIN")
        """
        try:
            outputs = self._run_user_enum_commands(target, username, password, domain)
            users = self._extract_users_from_outputs(outputs)

            if not users:
                output = "\n".join(content for _, content in outputs if content).strip()
                return self._format_enum_failure_message(outputs, output)

            # Save to file on recon pod where netexec commands execute
            users_file = "/tmp/users.txt"  # nosec B108  # noqa: S108
            ok, error = write_users_file_remote(sorted(users), users_file, target_role="recon")
            if not ok:
                return f"[!] Failed to write users file on remote: {error}"

            logger.info(f"[+] Saved {len(users)} users to {users_file}")
            return f"[+] Saved {len(users)} users to {users_file}\nUsers: {', '.join(sorted(users)[:20])}{'...' if len(users) > 20 else ''}"

        except Exception as e:
            logger.error(f"Save users to file failed: {e}")
            return f"Save users to file failed: {e}"


class PostureValidationTools(Toolset):
    """Tools for validating AD security posture on compromised hosts."""

    state: AnyRedTeamState | None = None

    def set_state(self, state: AnyRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    def _add_weakness(self, block: str) -> None:
        if not self.state or not block:
            return
        from ares.core.models import SharedRedTeamState

        if isinstance(self.state, SharedRedTeamState):
            self.state.add_weakness(block)
        elif block not in self.state.weaknesses:
            self.state.weaknesses.append(block)

    def _build_netexec_cmd(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
        command: str,
    ) -> list[str]:
        cmd = ["netexec", "smb", target, "-u", username, "-p", password]
        if domain:
            cmd.extend(["-d", domain])
        cmd.extend(["-x", command])
        return cmd

    def _run_netexec_command(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
        command: str,
        timeout_seconds: int = 60,
    ) -> str:
        cmd = self._build_netexec_cmd(target, username, password, domain, command)
        stdout, stderr, _ = run_tool(cmd, timeout_seconds=timeout_seconds)
        return (stdout or "") + ("\n" + stderr if stderr else "")

    @dn.tool_method
    def check_credman_entries(
        self,
        target: str,
        username: str,
        password: str,
        domain: str = "",
    ) -> str:
        """
        Check for Credential Manager entries on a compromised host.

        Args:
            target: Target host
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication (optional)

        Returns:
            cmdkey output with any discovered entries
        """
        output = self._run_netexec_command(
            target, username, password, domain, "cmdkey /list", timeout_seconds=90
        )
        targets = [
            line.strip()
            for line in output.splitlines()
            if line.strip().lower().startswith("target:")
        ]
        if targets:
            block = format_weakness_block(
                "Credential Manager Entries",
                "Stored credentials in Windows Credential Manager",
                {"Targets": ", ".join(targets)},
                "Potential plaintext or reusable credentials",
                "Remote cmdkey recon",
            )
            self._add_weakness(block)
            return "Credential Manager entries found:\n" + output
        return output or "No Credential Manager entries found"

    @dn.tool_method
    def check_autologon_registry(
        self,
        target: str,
        username: str,
        password: str,
        domain: str = "",
    ) -> str:
        """
        Check Autologon registry keys for stored credentials.

        Args:
            target: Target host
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication (optional)

        Returns:
            Registry query output with indicators highlighted
        """
        reg_path = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        cmd = (
            f'reg query "{reg_path}" /v AutoAdminLogon & '
            f'reg query "{reg_path}" /v DefaultUserName & '
            f'reg query "{reg_path}" /v DefaultPassword'
        )
        output = self._run_netexec_command(target, username, password, domain, cmd)
        auto_match = re.search(r"AutoAdminLogon\s+REG_\w+\s+(\S+)", output, re.IGNORECASE)
        auto_value = auto_match.group(1) if auto_match else ""
        auto_enabled = auto_value.strip().lower() in {"1", "0x1", "true", "yes"}
        password_match = re.search(r"DefaultPassword\s+REG_\w+\s*(.*)", output, re.IGNORECASE)
        password_value = password_match.group(1).strip() if password_match else ""
        has_password = bool(password_value) and password_value.lower() not in {"(null)", "null"}
        if has_password:
            block = format_weakness_block(
                "Autologon Credentials",
                "Autologon registry values present",
                {
                    "Registry Path": reg_path,
                    "AutoAdminLogon": auto_value or "unknown",
                },
                "Potential plaintext password exposure",
                "Remote registry query",
            )
            self._add_weakness(block)
            if auto_enabled:
                return "Autologon credentials detected:\n" + output
            return "Autologon password present but AutoAdminLogon disabled:\n" + output
        return output or "No Autologon credentials detected"

    @dn.tool_method
    def check_lm_compatibility_level(
        self,
        target: str,
        username: str,
        password: str,
        domain: str = "",
    ) -> str:
        """
        Check LmCompatibilityLevel for NTLMv1 downgrade risk.

        Args:
            target: Target host
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication (optional)

        Returns:
            Registry query output with interpreted risk
        """
        reg_path = r"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
        cmd = f'reg query "{reg_path}" /v LmCompatibilityLevel'
        output = self._run_netexec_command(target, username, password, domain, cmd)
        match = re.search(
            r"LmCompatibilityLevel\s+REG_DWORD\s+0x([0-9a-fA-F]+)", output, re.IGNORECASE
        )
        if match:
            level = int(match.group(1), 16)
            if level <= 2:
                block = format_weakness_block(
                    "NTLMv1 Downgrade Allowed",
                    "LmCompatibilityLevel permits NTLMv1",
                    {"LmCompatibilityLevel": f"{level}"},
                    "Increases risk of NTLMv1 downgrade attacks",
                    "Remote registry query",
                )
                self._add_weakness(block)
                return f"NTLMv1 allowed (LmCompatibilityLevel={level}):\n" + output
            return f"LmCompatibilityLevel={level} (NTLMv1 restricted):\n" + output
        return output or "LmCompatibilityLevel not found"

    @dn.tool_method
    def check_webclient_service(
        self,
        target: str,
        username: str,
        password: str,
        domain: str = "",
    ) -> str:
        """
        Check WebClient (WebDAV) service status for relay attacks.

        Args:
            target: Target host
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication (optional)

        Returns:
            Service configuration and status output
        """
        cmd = "sc qc WebClient & sc query WebClient"
        output = self._run_netexec_command(target, username, password, domain, cmd)
        if "START_TYPE" in output and "DISABLED" not in output.upper():
            block = format_weakness_block(
                "WebDAV Client Enabled",
                "WebClient service is enabled",
                {"Service": "WebClient"},
                "Enables WebDAV relay/coercion paths",
                "Remote service query",
            )
            self._add_weakness(block)
            return "WebClient service enabled:\n" + output
        return output or "WebClient service not enabled"

    @dn.tool_method
    def check_rdp_sessions(
        self,
        target: str,
        username: str,
        password: str,
        domain: str = "",
    ) -> str:
        """
        Check for active RDP sessions (potential credential theft targets).

        Args:
            target: Target host
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication (optional)

        Returns:
            Session query output
        """
        output = self._run_netexec_command(target, username, password, domain, "quser")
        if "rdp" in output.lower():
            return "RDP sessions detected:\n" + output
        return output or "No RDP sessions detected"

    @dn.tool_method
    def check_sidhistory(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
    ) -> str:
        """
        Check for accounts with SIDHistory (privilege escalation vector).

        Args:
            target: Domain controller IP address
            username: Username for LDAP authentication
            password: Password for authentication
            domain: Target domain (e.g., 'example.local')

        Returns:
            LDAP output listing accounts with sidHistory
        """
        base_dn = ",".join([f"DC={part}" for part in domain.split(".")])
        cmd = [
            "ldapsearch",
            "-x",
            "-H",
            f"ldap://{target}",
            "-D",
            f"{username}@{domain}",
            "-w",
            password,
            "-b",
            base_dn,
            "(sidHistory=*)",
            "sAMAccountName",
            "sidHistory",
        ]
        stdout, stderr, _returncode = run_tool(cmd, timeout_seconds=120)
        output = (stdout or "") + ("\n" + stderr if stderr else "")
        if "sAMAccountName" in output:
            block = format_weakness_block(
                "SIDHistory Enabled",
                "Accounts with SIDHistory present",
                {},
                "Potential SIDHistory abuse for elevated access",
                "LDAP recon",
            )
            self._add_weakness(block)
            return "SIDHistory entries detected:\n" + output
        return output or "No SIDHistory entries detected"

    @dn.tool_method
    def enumerate_domain_netbios_mappings(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
    ) -> str:
        """Query AD Configuration partition for NetBIOS to FQDN domain mappings.

        This queries the crossRef objects in CN=Partitions,CN=Configuration to get
        the authoritative mapping between NetBIOS domain names (e.g., "CORP") and
        their FQDNs (e.g., "corp.contoso.local").

        IMPORTANT: Run this early in enumeration to ensure correct domain resolution
        for credentials discovered in multi-domain forests.

        Args:
            target: Domain controller IP address
            username: Username for LDAP authentication
            password: Password for authentication
            domain: Target domain (e.g., 'contoso.local')

        Returns:
            Summary of discovered NetBIOS to FQDN mappings
        """
        from ares.core.models import SharedRedTeamState

        # Build the Configuration naming context DN
        # For domain "contoso.local", this becomes:
        # CN=Partitions,CN=Configuration,DC=contoso,DC=local
        domain_parts = domain.split(".")
        config_dn = "CN=Partitions,CN=Configuration," + ",".join(
            [f"DC={part}" for part in domain_parts]
        )

        cmd = [
            "ldapsearch",
            "-x",
            "-H",
            f"ldap://{target}",
            "-D",
            f"{username}@{domain}",
            "-w",
            password,
            "-b",
            config_dn,
            "(objectClass=crossRef)",
            "nETBIOSName",
            "dnsRoot",
        ]

        stdout, stderr, returncode = run_tool(cmd, timeout_seconds=60)
        output = (stdout or "") + ("\n" + stderr if stderr else "")

        if returncode != 0 or "ldap_bind" in output.lower():
            return f"[!] LDAP query failed: {output}"

        # Parse the LDIF output for nETBIOSName and dnsRoot pairs
        mappings: list[tuple[str, str]] = []
        current_netbios = None
        current_dnsroot = None

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if line.lower().startswith("netbiosname:"):
                current_netbios = line.split(":", 1)[1].strip()
            elif line.lower().startswith("dnsroot:"):
                current_dnsroot = line.split(":", 1)[1].strip()

            # When we have both values, store the mapping
            if current_netbios and current_dnsroot:
                mappings.append((current_netbios, current_dnsroot))
                current_netbios = None
                current_dnsroot = None

        if not mappings:
            return "[!] No NetBIOS mappings found in crossRef objects"

        # Store mappings in shared state
        added_count = 0
        if self.state and isinstance(self.state, SharedRedTeamState):
            for netbios, fqdn in mappings:
                if self.state.add_netbios_mapping(netbios, fqdn):
                    added_count += 1

        # Format output
        lines = ["NetBIOS to FQDN Domain Mappings (from AD Configuration):"]
        for netbios, fqdn in mappings:
            lines.append(f"  {netbios} -> {fqdn}")

        if added_count > 0:
            lines.append(f"\n✓ Added {added_count} new mappings to shared state")
            lines.append("  Credentials with NetBIOS domains will now resolve correctly")

        return "\n".join(lines)


class BloodHoundTools(Toolset):
    """Tools for ACL recon and privilege escalation path discovery."""

    state: AnyRedTeamState | None = None

    def set_state(self, state: AnyRedTeamState) -> None:
        """Set the operation state for this toolset."""
        self.state = state

    def _parse_bloodhound_output(self, raw_output: str) -> dict[str, Any]:  # noqa: PLR0912
        """Parse BloodHound collection output for actionable attack paths.

        Returns:
            Dictionary with:
            - attack_paths: List of identified attack paths
            - delegation_targets: Accounts with delegation
            - acl_abuse_targets: Accounts vulnerable to ACL abuse
            - high_value_targets: High-value target accounts
            - recommended_actions: Specific next steps
            - discovered_hosts: List of discovered computer hostnames
        """
        result: dict[str, Any] = {
            "attack_paths": [],
            "delegation_targets": [],
            "acl_abuse_targets": [],
            "high_value_targets": [],
            "recommended_actions": [],
            "collection_successful": False,
            "json_files_created": [],
            "discovered_hosts": [],  # Computer hostnames from collection
            "trusted_domains": [],  # Domain trusts discovered
            "computers_found": 0,
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

        # Parse discovered computers/hosts
        # BloodHound outputs: "INFO     Found X computers" or "Found X computers"
        for line in raw_output.split("\n"):
            # Match "Found X computers" patterns
            computer_count_match = re.search(r"Found\s+(\d+)\s+computers?", line, re.IGNORECASE)
            if computer_count_match:
                result["computers_found"] = int(computer_count_match.group(1))

            # Match connecting to host: "Connecting to host: HOSTNAME.domain"
            host_connect_match = re.search(
                r"Connecting\s+to\s+host:\s+([A-Za-z0-9\-\.]+)", line, re.IGNORECASE
            )
            if host_connect_match:
                hostname = host_connect_match.group(1)
                if hostname not in result["discovered_hosts"]:
                    result["discovered_hosts"].append(hostname)

            # Match domain references like "DC01.domain.local" or computer names in output
            # Look for FQDN patterns that appear to be computer names
            fqdn_matches = re.findall(r"\b([A-Za-z0-9\-]+\.[A-Za-z0-9\-\.]+\.local)\b", line)
            for fqdn in fqdn_matches:
                # Skip if it looks like a user principal name (contains @)
                if "@" not in fqdn and fqdn not in result["discovered_hosts"]:
                    # Check if it's a computer-like name (uppercase or ends with $)
                    hostname_part = fqdn.split(".")[0]
                    if hostname_part.isupper() or len(hostname_part) <= 15:
                        result["discovered_hosts"].append(fqdn)

        # Extract trusted domains from BloodHound output
        # BloodHound discovers trusts and outputs domain references
        trust_patterns = [
            r"trust[^\n]*?([a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+\.(?:local|com|net|org))",
            r"domain:\s*([a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+\.(?:local|com|net|org))",
            r"forest[^\n]*?([a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+\.(?:local|com|net|org))",
        ]
        for pattern in trust_patterns:
            trust_matches = re.findall(pattern, raw_output, re.IGNORECASE)
            for trust_domain in trust_matches:
                trust_domain_lower = trust_domain.lower()
                if trust_domain_lower not in result["trusted_domains"]:
                    result["trusted_domains"].append(trust_domain_lower)

        # Also extract domains from discovered host FQDNs (parent/sibling domains)
        for host in result["discovered_hosts"]:
            if "." in host:
                parts = host.lower().split(".", 1)
                if len(parts) > 1:
                    host_domain = parts[1]
                    # Skip common non-domain suffixes and duplicates
                    is_valid = host_domain and host_domain not in result["trusted_domains"]
                    is_not_infra = not any(
                        host_domain.endswith(x) for x in [".internal", ".compute", ".amazonaws.com"]
                    )
                    if is_valid and is_not_infra:
                        result["trusted_domains"].append(host_domain)

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
    def run_bloodhound(  # noqa: PLR0912
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
            domain: Target domain (e.g., 'example.local')
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
            >>> run_bloodhound("example.local", "dave.lee", "ExamplePass123!", "192.168.58.10")
        """
        # DEDUP CHECK: Skip if already ran BloodHound for this domain (prevents duplicate work)
        if self.state:
            domain_key = domain.lower()
            if domain_key in getattr(self.state, "processed_bloodhound_domains", set()):
                return f"[i] BloodHound already completed for {domain} - skipping to save time"

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
        if dc_ip:
            realm = domain.upper()
            krb5_conf = f"/tmp/ares-krb5-{uuid.uuid4().hex}.conf"  # nosec B108  # noqa: S108
            cmd_str = " ".join(shlex.quote(arg) for arg in cmd)

            # Resolve DC hostname to add to /etc/hosts for DNS resolution
            # Query SRV records to discover DC hostnames
            logger.info(f"[*] Resolving domain controllers for {domain}")
            srv_query = f"_ldap._tcp.dc._msdcs.{domain}"
            dc_hostnames = []
            try:
                nslookup_cmd = ["nslookup", "-type=srv", srv_query, dc_ip]
                srv_stdout, srv_stderr, _ = run_tool(
                    nslookup_cmd, timeout_seconds=30, target_role="recon"
                )
                srv_output = srv_stdout or srv_stderr or ""

                # Extract DC hostnames from SRV records
                for line in srv_output.splitlines():
                    # Match patterns like "svr hostname = hostname.domain.local"
                    srv_match = re.search(r"svr hostname = ([^\s]+)", line, re.IGNORECASE)
                    if srv_match:
                        hostname = srv_match.group(1).rstrip(".")
                        dc_hostnames.append(hostname)
                        logger.debug(f"Found DC hostname: {hostname}")
                    # Also match "service = 0 100 389 hostname.domain.local"
                    service_match = re.search(
                        r"service = \d+ \d+ \d+ ([^\s]+)", line, re.IGNORECASE
                    )
                    if service_match and not srv_match:  # Avoid duplicates
                        hostname = service_match.group(1).rstrip(".")
                        dc_hostnames.append(hostname)
                        logger.debug(f"Found DC hostname: {hostname}")

                # Remove duplicates
                dc_hostnames = list(dict.fromkeys(dc_hostnames))
                logger.info(
                    f"[+] Discovered {len(dc_hostnames)} DC hostname(s): {', '.join(dc_hostnames)}"
                )
            except Exception as e:
                logger.warning(f"[!] Failed to resolve DC hostnames via SRV: {e}")
                # Fallback: try reverse DNS lookup
                try:
                    ptr_cmd = ["nslookup", dc_ip, dc_ip]
                    ptr_stdout, ptr_stderr, _ = run_tool(
                        ptr_cmd, timeout_seconds=15, target_role="recon"
                    )
                    ptr_output = ptr_stdout or ptr_stderr or ""
                    # Extract hostname from PTR record: "name = hostname.domain.local"
                    for line in ptr_output.splitlines():
                        ptr_match = re.search(r"name = ([^\s]+)", line, re.IGNORECASE)
                        if ptr_match:
                            hostname = ptr_match.group(1).rstrip(".")
                            dc_hostnames.append(hostname)
                            logger.info(f"[+] Found DC hostname via PTR: {hostname}")
                            break
                except Exception as ptr_e:
                    logger.warning(f"[!] Failed to resolve DC hostname via PTR: {ptr_e}")

            # Build /etc/hosts entries for DC hostnames
            hosts_entries = ""
            if dc_hostnames:
                for hostname in dc_hostnames:
                    hosts_entries += f"echo '{dc_ip} {hostname}' >> /etc/hosts\n"
                logger.info("[*] Adding DC hostname(s) to /etc/hosts for DNS resolution")
            else:
                logger.warning(
                    "[!] No DC hostnames discovered; BloodHound may fail with DNS errors"
                )

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
                f"{hosts_entries}"
                f'env KRB5_CONFIG="$tmp_conf" {cmd_str}\n'
            )
            cmd = ["bash", "-lc", cmd_script]

        try:
            logger.info(f"[*] Running BloodHound collection for {domain}")
            stdout, stderr, _ = run_tool(cmd, timeout_seconds=600, target_role="recon")

            raw_output = stdout + "\n" + (stderr or "")

            # Parse output for actionable intelligence
            parsed = self._parse_bloodhound_output(raw_output)

            # Register discovered hosts in state if available
            if self.state and parsed.get("discovered_hosts"):
                for hostname in parsed["discovered_hosts"]:
                    # Extract short hostname from FQDN
                    short_hostname = hostname.split(".")[0] if "." in hostname else hostname
                    host = Host(
                        ip="",  # IP not available from BloodHound output
                        hostname=short_hostname,
                        os="Windows",  # Assume Windows for AD computers
                        roles=["DC"] if "DC" in short_hostname.upper() else [],
                        services=[],
                    )
                    # Use add_host if available (SharedRedTeamState), else append
                    if hasattr(self.state, "add_host"):
                        self.state.add_host(host)
                    # RedTeamState uses hosts list directly
                    elif not any(h.hostname == short_hostname for h in self.state.hosts):
                        self.state.hosts.append(host)
                    logger.debug(f"Registered host from BloodHound: {short_hostname}")

                logger.info(
                    f"[+] Registered {len(parsed['discovered_hosts'])} hosts from BloodHound collection"
                )

            logger.info("[+] BloodHound collection completed")

            # Build structured response
            output_parts = []
            output_parts.append("=" * 60)
            output_parts.append("BLOODHOUND COLLECTION RESULTS")
            output_parts.append("=" * 60)

            if parsed["collection_successful"]:
                output_parts.append("\n\u2705 Collection successful!")
                if parsed["json_files_created"]:
                    output_parts.append(
                        f"\n📁 JSON files created: {', '.join(parsed['json_files_created'])}"
                    )
            else:
                output_parts.append("\n\u26a0\ufe0f Collection may have encountered issues")

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
                    output_parts.append(f"     \u2192 Use tool: {action['next_tool']}")

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
