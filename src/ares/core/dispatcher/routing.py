"""Task routing methods for dispatching work to specialized agents.

This module provides all request_*() methods for routing tasks to
the appropriate agent roles (crack, lateral, exploit, recon, etc.).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.models import (
    Credential,
    Host,
    TaskInfo,
)

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher


class RoutingMixin:
    """Task routing methods for dispatching work to specialized agents."""

    def _normalize_domain(self: RedTeamDispatcher, domain: str) -> str:
        """Normalize domain to FQDN format.

        Resolves NetBIOS domain names (e.g., "CONTOSO") to their FQDN
        (e.g., "contoso.local") using the shared state's mapping.

        Args:
            domain: Domain name (may be NetBIOS or FQDN)

        Returns:
            Normalized FQDN, or lowercase original if not resolvable
        """
        if not domain:
            return ""
        domain_lower = domain.strip().lower()
        # If already FQDN (contains dot), return as-is
        if "." in domain_lower:
            return domain_lower
        # Try to resolve NetBIOS to FQDN
        return self.shared_state._resolve_netbios_to_fqdn(domain_lower)

    def _find_credential_id(
        self: RedTeamDispatcher,
        username: str,
        domain: str,
        password: str | None = None,
    ) -> tuple[str | None, int]:
        """Find credential ID and attack_step by username/domain/password.

        Returns:
            Tuple of (credential_id, attack_step) or (None, 0) if not found.
        """
        username_lower = username.lower().strip()
        domain_lower = domain.lower().strip() if domain else ""

        for cred in self.shared_state.all_credentials:
            if cred.username.lower().strip() != username_lower:
                continue
            cred_domain = cred.domain.lower().strip() if cred.domain else ""
            if cred_domain != domain_lower and domain_lower not in cred_domain:
                continue
            # If password specified, must match
            if password and cred.password != password:
                continue
            return cred.id, cred.attack_step

        # Also check hashes (for pass-the-hash scenarios)
        for hash_obj in self.shared_state.all_hashes:
            if hash_obj.username.lower().strip() != username_lower:
                continue
            hash_domain = hash_obj.domain.lower().strip() if hash_obj.domain else ""
            if hash_domain != domain_lower and domain_lower not in hash_domain:
                continue
            return hash_obj.id, hash_obj.attack_step

        return None, 0

    def _find_domain_credential(self: RedTeamDispatcher, domain: str) -> Credential | None:
        """Find a credential for the specified domain."""
        domain_lower = domain.lower() if domain else ""
        credential = None
        for cred in self.shared_state.all_credentials:
            cred_domain = cred.domain.lower() if cred.domain else ""
            if cred_domain == domain_lower or domain_lower in cred_domain:
                if cred.password:  # Prefer credentials with passwords
                    return cred
                if not credential:
                    credential = cred
        return credential

    def _find_domain_controller_ip(self: RedTeamDispatcher, domain: str) -> str:
        """Find DC IP for the specified domain.

        Detection priority:
        0. Cached domain_controllers dict (fastest, populated by add_host)
        1. Hosts with explicit DC roles (AD DC, DC, Domain Controller) matching domain
        2. Hosts with "dc" in hostname matching domain (strong indicator)
        3. Hosts with DC-like services (Kerberos 88, LDAP 389) matching domain
        4. Fallback: any host with DC role/services (cross-domain, logged as warning)
        5. DNS SRV lookup (last resort, requires network access)
        """
        domain_lower = domain.lower() if domain else ""

        # Priority 0: Check cached domain_controllers (populated by add_host when DC discovered)
        if domain_lower and domain_lower in self.shared_state.domain_controllers:
            cached_ip = self.shared_state.domain_controllers[domain_lower]
            logger.debug(f"DC IP found in cache: {cached_ip} for {domain}")
            return cached_ip
        # Port tokens must match at start of service string to avoid
        # substring issues (e.g., "389/tcp" matching "3389/tcp")
        dc_port_prefixes = ("88/tcp", "389/tcp")
        dc_service_names = ("kerberos", "ldap")

        def _has_dc_services(host: Host) -> bool:
            """Check if host has DC-specific services (Kerberos, LDAP)."""
            for svc in host.services:
                svc_lower = svc.lower()
                if any(svc_lower.startswith(port) for port in dc_port_prefixes):
                    return True
                if any(name in svc_lower for name in dc_service_names):
                    return True
            return False

        def _has_dc_role(host: Host) -> bool:
            """Check if host has DC role assigned (from SRV lookup or BloodHound)."""
            roles_str = str(host.roles).lower()
            return any(
                marker in roles_str
                for marker in ("dc", "domain controller", "ad dc", "domaincontroller")
            )

        def _hostname_matches_domain(hostname: str, domain: str) -> bool:
            """Check if hostname belongs to the domain."""
            if not hostname or not domain:
                return False
            hostname_lower = hostname.lower()
            domain_lower_check = domain.lower()
            if hostname_lower.endswith(f".{domain_lower_check}"):
                return True
            return hostname_lower == domain_lower_check

        # Check target first (if it belongs to this domain)
        if self.shared_state.target and self.shared_state.target.ip:
            target_ip = self.shared_state.target.ip
            target_hostname = (self.shared_state.target.hostname or "").lower()
            target_domain = (self.shared_state.target.domain or "").lower()

            # If target.domain was explicitly set and matches, use target.ip
            # This is set when user starts operation with --domain, meaning target IS the DC
            if target_domain and target_domain == domain_lower:
                return target_ip

            if target_hostname and _hostname_matches_domain(target_hostname, domain_lower):
                return target_ip
            for host in self.shared_state.all_hosts:
                if host.ip == target_ip:
                    hostname = (host.hostname or "").lower()
                    if _hostname_matches_domain(hostname, domain_lower) and _has_dc_services(host):
                        return host.ip

        # Priority 1: Search hosts with explicit DC roles that belong to this domain
        for host in self.shared_state.all_hosts:
            hostname = (host.hostname or "").lower()
            if _has_dc_role(host) and _hostname_matches_domain(hostname, domain_lower):
                logger.debug(f"DC IP found via role: {host.ip} ({hostname})")
                return host.ip

        # Priority 2: Search hosts with "dc" in hostname that belong to this domain
        for host in self.shared_state.all_hosts:
            hostname = (host.hostname or "").lower()
            if "dc" in hostname and _hostname_matches_domain(hostname, domain_lower):
                logger.debug(f"DC IP found via hostname pattern: {host.ip} ({hostname})")
                return host.ip

        # Priority 3: Infer DC from services on hosts within the domain
        if domain_lower:
            for host in self.shared_state.all_hosts:
                hostname = (host.hostname or "").lower()
                if _hostname_matches_domain(hostname, domain_lower) and _has_dc_services(host):
                    logger.debug(f"DC IP found via services: {host.ip} ({hostname})")
                    return host.ip

        # Priority 3.5: For child domains, find a DC in the same forest
        # e.g., north.sevenkingdoms.local -> find a DC with hostname *.sevenkingdoms.local
        # that is NOT the parent domain's registered DC (prefer child domain's own DC)
        if domain_lower and "." in domain_lower:
            parts = domain_lower.split(".")
            if len(parts) >= 3:  # child.parent.tld has 3+ parts
                parent_domain = ".".join(
                    parts[1:]
                )  # north.sevenkingdoms.local -> sevenkingdoms.local
                parent_dc_ip = self.shared_state.domain_controllers.get(parent_domain)

                # Find all DCs in the same forest (hostname ends with parent domain)
                forest_dcs = [
                    host
                    for host in self.shared_state.all_hosts
                    if _has_dc_role(host)
                    and host.hostname
                    and host.hostname.lower().endswith(f".{parent_domain}")
                ]

                # Prefer a DC that is NOT the parent domain's DC (likely child domain's DC)
                for dc in forest_dcs:
                    if dc.ip != parent_dc_ip:
                        self.shared_state.domain_controllers[domain_lower] = dc.ip
                        logger.info(
                            f"DC IP from forest (not parent): {dc.ip} ({dc.hostname}) -> {domain}"
                        )
                        return dc.ip

                # If only parent DC found, use it as fallback BUT DON'T CACHE
                # Caching the parent DC prevents finding the correct child DC later
                # when host enumeration completes and identifies the real DC
                if parent_dc_ip:
                    logger.info(
                        f"DC IP from parent domain (uncached fallback): {parent_dc_ip} ({parent_domain}) -> {domain}"
                    )
                    return parent_dc_ip

        # Priority 4: DNS SRV lookup (try before generic fallback - more accurate)
        # This correctly finds DCs for child domains like north.sevenkingdoms.local
        # when hostname data is incomplete or missing
        if domain_lower:
            dc_ip = self._dns_lookup_dc(domain_lower)
            if dc_ip:
                # Cache for future lookups
                self.shared_state.domain_controllers[domain_lower] = dc_ip
                logger.info(f"DC IP found via DNS SRV: {dc_ip} for {domain}")
                return dc_ip

        # Priority 4.5: LDAP rootDSE query to determine which DC serves the domain
        # When hostnames are missing, try LDAP against each DC candidate
        candidate_dcs = [h for h in self.shared_state.all_hosts if _has_dc_role(h)]
        if candidate_dcs and domain_lower:
            for dc_candidate in candidate_dcs:
                dc_domain = self._ldap_get_domain(dc_candidate.ip)
                if dc_domain and dc_domain.lower() == domain_lower:
                    self.shared_state.domain_controllers[domain_lower] = dc_candidate.ip
                    logger.info(f"DC IP found via LDAP: {dc_candidate.ip} serves {dc_domain}")
                    return dc_candidate.ip

        # Priority 5: Fallback - hosts with DC roles (any domain) - log warning
        for host in self.shared_state.all_hosts:
            if _has_dc_role(host):
                logger.warning(
                    f"DC IP fallback (no domain match): {host.ip} ({host.hostname}) for domain {domain}"
                )
                return host.ip

        # Priority 6: Any host with DC-like services (risky, may be wrong) - log warning
        for host in self.shared_state.all_hosts:
            if _has_dc_services(host):
                logger.warning(
                    f"DC IP last resort (services only): {host.ip} ({host.hostname}) for domain {domain}"
                )
                return host.ip

        logger.warning(f"No DC IP found for domain {domain}")
        return ""

    def _dns_lookup_dc(self: RedTeamDispatcher, domain: str) -> str:
        """Try DNS SRV record lookup to find DC IP.

        Queries _ldap._tcp.dc._msdcs.{domain} SRV record, then resolves
        the target hostname to an IP address.

        Args:
            domain: The domain to look up (e.g., "contoso.local")

        Returns:
            DC IP address if found, empty string otherwise
        """
        import socket
        import subprocess

        try:
            # Try SRV lookup using nslookup (more reliable in container environments)
            srv_query = f"_ldap._tcp.dc._msdcs.{domain}"
            result = subprocess.run(  # nosec B607
                ["nslookup", "-type=srv", srv_query],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            output = result.stdout + result.stderr

            # Extract hostname from SRV response
            hostname = None
            for raw_line in output.splitlines():
                stripped = raw_line.strip()
                # Match "svr hostname = dc01.contoso.local"
                if "svr hostname" in stripped.lower():
                    match = re.search(r"svr hostname\s*=\s*(\S+)", stripped, re.IGNORECASE)
                    if match:
                        hostname = match.group(1).rstrip(".")
                        break
                # Match "service = 0 100 389 dc01.contoso.local"
                if "service" in stripped.lower() and "389" in stripped:
                    match = re.search(
                        r"service\s*=\s*\d+\s+\d+\s+\d+\s+(\S+)", stripped, re.IGNORECASE
                    )
                    if match:
                        hostname = match.group(1).rstrip(".")
                        break

            if not hostname:
                logger.debug(f"No SRV hostname found for {domain}")
                return ""

            # Resolve hostname to IP
            try:
                ip = socket.gethostbyname(hostname)
                logger.debug(f"Resolved DC hostname {hostname} to {ip}")
                return ip
            except socket.gaierror:
                # Try nslookup as fallback
                result = subprocess.run(  # nosec B607
                    ["nslookup", hostname],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                for ns_line in (result.stdout + result.stderr).splitlines():
                    match = re.search(r"Address:\s*(\d+\.\d+\.\d+\.\d+)", ns_line)
                    if match:
                        ip = match.group(1)
                        # Skip DNS server address (usually first)
                        if ip != "127.0.0.1" and not ip.startswith("127."):
                            logger.debug(f"Resolved DC hostname {hostname} to {ip} via nslookup")
                            return ip
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            logger.debug(f"DNS SRV lookup failed for {domain}: {e}")

        return ""

    def _ldap_get_domain(self: RedTeamDispatcher, dc_ip: str) -> str:
        """Query LDAP rootDSE to get the domain name a DC serves.

        Uses raw socket LDAP to query the defaultNamingContext attribute which
        contains the domain DN (e.g., DC=north,DC=sevenkingdoms,DC=local).

        Args:
            dc_ip: IP address of the DC to query

        Returns:
            Domain name (e.g., "north.sevenkingdoms.local") or empty string on failure
        """
        import socket

        try:
            # LDAP rootDSE search request (precomputed BER encoding)
            # This requests defaultNamingContext from the rootDSE
            ldap_rootdse_request = bytes(
                [
                    0x30,
                    0x25,  # SEQUENCE, length 37
                    0x02,
                    0x01,
                    0x01,  # messageID: 1
                    0x63,
                    0x20,  # SearchRequest, length 32
                    0x04,
                    0x00,  # baseObject: ""
                    0x0A,
                    0x01,
                    0x00,  # scope: baseObject
                    0x0A,
                    0x01,
                    0x00,  # derefAliases: neverDerefAliases
                    0x02,
                    0x01,
                    0x00,  # sizeLimit: 0
                    0x02,
                    0x01,
                    0x00,  # timeLimit: 0
                    0x01,
                    0x01,
                    0x00,  # typesOnly: false
                    0x87,
                    0x0B,
                    0x6F,
                    0x62,
                    0x6A,
                    0x65,
                    0x63,
                    0x74,  # filter: present "objectclass"
                    0x63,
                    0x6C,
                    0x61,
                    0x73,
                    0x73,
                    0x30,
                    0x00,  # attributes: empty (return all)
                ]
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((dc_ip, 389))
            sock.sendall(ldap_rootdse_request)

            # Read all response data (LDAP responses may be fragmented)
            response = b""
            try:
                while True:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    response += chunk
            except TimeoutError:
                pass  # Expected when all data is read
            sock.close()

            # Parse response - look for defaultNamingContext in the raw bytes
            response_str = response.decode("utf-8", errors="replace")

            # Find defaultNamingContext - look for the attribute name followed by DC= pattern
            # The BER encoding puts length bytes between attribute and value, so we use .*? to skip them
            # Use [A-Za-z]+ for the last DC component to avoid capturing BER length bytes (e.g., '0')
            # Pattern handles both "DC=x,DC=local" and "DC=x,DC=y,DC=local" formats
            match = re.search(
                r"defaultNamingContext.*?(DC=[A-Za-z0-9_-]+(?:,DC=[A-Za-z]+)+)",
                response_str,
                re.IGNORECASE | re.DOTALL,
            )
            if match:
                dn = match.group(1)
                # Convert DN to domain name: DC=north,DC=sevenkingdoms,DC=local -> north.sevenkingdoms.local
                parts = []
                for component in dn.split(","):
                    stripped = component.strip()
                    if stripped.upper().startswith("DC="):
                        parts.append(stripped[3:])
                if parts:
                    domain = ".".join(parts)
                    logger.info(f"LDAP rootDSE: {dc_ip} serves domain {domain}")
                    return domain

        except (OSError, TimeoutError, Exception) as e:
            logger.debug(f"LDAP domain lookup failed for {dc_ip}: {e}")

        return ""

    def _extract_ticket_path_from_output(self: RedTeamDispatcher, output: str) -> str:
        """Extract .ccache ticket path from S4U attack or getTGT output.

        Args:
            output: Tool output containing ticket path

        Returns:
            Path to .ccache file, defaults to 'Administrator.ccache' if not found
        """
        if not output:
            return "Administrator.ccache"

        match = re.search(r"Saving ticket in ([^\s]+\.ccache)", output)
        if match:
            return match.group(1)

        match = re.search(r"([A-Za-z0-9_.-]+\.ccache)", output)
        if match:
            return match.group(1)

        return "Administrator.ccache"

    def _extract_host_from_spn(self: RedTeamDispatcher, spn: str) -> str | None:
        """Extract target host from SPN.

        Args:
            spn: Service Principal Name (e.g., 'cifs/DC01.contoso.local')

        Returns:
            Host FQDN (e.g., 'DC01.contoso.local') or None if not extractable
        """
        if not spn or "/" not in spn:
            return None

        parts = spn.split("/", 1)
        if len(parts) == 2:
            return parts[1]
        return None

    def _extract_target_from_ccache_path(
        self: RedTeamDispatcher, ccache_path: str
    ) -> tuple[str | None, str]:
        """Extract target host and domain from ccache ticket path.

        Ticket paths follow format:
        - Administrator@cifs_dc01.contoso.local@CONTOSO.LOCAL.ccache
        - user@service_host.contoso.local@CONTOSO.LOCAL.ccache

        Args:
            ccache_path: Path to the .ccache ticket file

        Returns:
            Tuple of (target_host, domain). Either may be empty if extraction fails.
        """
        if not ccache_path:
            return None, ""

        # Remove .ccache extension and path prefix
        ticket_name = ccache_path.rsplit("/", 1)[-1]
        ticket_name = ticket_name.replace(".ccache", "")

        # Format: user@service_host.domain@REALM
        # Split by @ - last part is realm (domain), middle has service_host
        parts = ticket_name.split("@")
        if len(parts) < 2:
            return None, ""

        domain = parts[-1].lower() if len(parts) >= 2 else ""

        # Middle part has service_host like: cifs_dc01.contoso.local
        if len(parts) >= 2:
            service_host = parts[1] if len(parts) >= 3 else parts[0]
            # Remove service prefix (cifs_, http_, ldap_, host_)
            for prefix in ["cifs_", "http_", "ldap_", "host_", "gc_"]:
                if service_host.lower().startswith(prefix):
                    service_host = service_host[len(prefix) :]
                    break
            return service_host, domain

        return None, domain

    async def _auto_chain_s4u_lateral_movement(
        self: RedTeamDispatcher,
        task_id: str,
        task_info: TaskInfo,
        result: dict[str, Any],
        source_agent: str,
        task_queue: Any = None,
    ) -> int:
        """Auto-chain lateral movement after successful S4U attack.

        When an S4U attack generates an Administrator ticket, this method
        automatically dispatches secretsdump to harvest credentials using
        the generated ticket.

        This function now works for ANY task type (exploit, privesc_enumeration, etc.)
        as long as the output contains a .ccache file. It extracts target info from
        the ticket path itself when task params aren't available.

        Args:
            task_id: ID of the completed task
            task_info: Information about the completed task
            result: Task result containing output
            source_agent: Agent that completed the task
            task_queue: Optional task queue for direct dispatch (threaded consumer passes its own).

        Returns:
            Number of lateral movement tasks dispatched
        """
        output = result.get("output", "") or result.get("stdout", "") or str(result)
        if ".ccache" not in output:
            return 0

        ticket_path = self._extract_ticket_path_from_output(output)

        # Try to get target info from task params first
        params = task_info.params or {}
        target_spn = params.get("target_spn", "")
        target_host = self._extract_host_from_spn(target_spn) if target_spn else None
        domain = params.get("domain", "")

        # If params missing, extract from ccache ticket path
        # Format: Administrator@cifs_dc01.contoso.local@CONTOSO.LOCAL.ccache
        if not target_host or not domain:
            target_host, domain = self._extract_target_from_ccache_path(ticket_path)

        if not target_host:
            logger.warning(
                f"Could not extract target host from output or ccache path: {ticket_path}"
            )
            return 0

        target_ip: str | None = None
        for host in self.shared_state.all_hosts:
            if host.hostname and target_host.lower() in host.hostname.lower():
                target_ip = host.ip
                break

        target_for_secretsdump = target_ip or target_host

        dc_ip = self._find_domain_controller_ip(domain)

        logger.info(f"🎫 S4U SUCCESS! Auto-chaining secretsdump: {ticket_path} -> {target_host}")

        await self.request_credential_access(
            domain=domain,
            source_agent="auto_s4u_chain",
            target_ips=[target_for_secretsdump],
            username="Administrator",
            techniques=["secretsdump"],
            reason="auto_s4u_chain",
            extra_params={
                "ticket_path": ticket_path,
                "no_pass": True,  # nosec B105 - not a password, it's a flag
                "dc_ip": dc_ip,
            },
            task_queue=task_queue,
        )
        return 1

    def _record_exploit_weakness(
        self: RedTeamDispatcher, vuln_type: str, target: str, payload: dict[str, Any]
    ) -> None:
        """Record an exploited vulnerability as a weakness for the report."""
        domain = payload.get("domain", "")
        hostname = payload.get("target_hostname", target)
        account = payload.get("account_name") or payload.get("account", "")

        weakness_map = {
            "constrained_delegation": (
                f"### Constrained Delegation — {account}@{domain}\n"
                f"**Vulnerability:** Account {account} has constrained delegation rights "
                f"(msDS-AllowedToDelegateTo), allowing S4U impersonation of any user "
                f"to the target service.\n"
                f"- **Affected Resource:** {hostname} ({target})\n"
                f"- **Discovery Method:** Injected/findDelegation enumeration\n"
                f"- **Impact:** Attacker can impersonate Administrator via S4U attack, "
                f"then use the ticket for secretsdump or remote execution on the target."
            ),
            "mssql_impersonation": (
                f"### MSSQL Impersonation — sa on {hostname}\n"
                f"**Vulnerability:** A domain user can EXECUTE AS LOGIN = 'sa' on the "
                f"MSSQL instance, escalating to sysadmin.\n"
                f"- **Affected Resource:** {hostname} ({target})\n"
                f"- **Discovery Method:** MSSQL enum_impersonate\n"
                f"- **Impact:** Full SQL Server control, xp_cmdshell for OS command execution."
            ),
            "esc8": (
                f"### ADCS ESC8 — Web Enrollment Relay on {hostname}\n"
                f"**Vulnerability:** ADCS web enrollment endpoint is vulnerable to "
                f"NTLM relay (ESC8).\n"
                f"- **Affected Resource:** {hostname} ({target})\n"
                f"- **Discovery Method:** certipy find\n"
                f"- **Impact:** Relay authentication to obtain certificates for domain accounts."
            ),
        }

        block = weakness_map.get(vuln_type)
        if block:
            self.shared_state.add_weakness(block)

    async def request_crack(
        self: RedTeamDispatcher,
        hash_value: str,
        hash_type: str,
        source_agent: str,
        username: str = "",
        domain: str = "",
        priority: int = 5,
        wordlist: str = "rockyou.txt",
    ) -> str:
        """
        Route hash to CrackerAgent for cracking.

        Uses Redis task queue for cross-pod communication when available,
        falls back to in-memory queue for same-process communication.

        Args:
            hash_value: The hash to crack.
            hash_type: Type (NTLM, NetNTLMv2, Kerberos, etc.).
            source_agent: Agent making the request.
            username: Associated username.
            domain: Associated domain.
            priority: 1=urgent (krbtgt), 5=normal, 10=low.
            wordlist: Wordlist to use.

        Returns:
            Task ID for tracking.
        """
        # Skip new crack tasks if DA already achieved (allow in-progress to complete)
        if self.shared_state.has_domain_admin:
            logger.debug(f"Skipping crack request for {username} - DA already achieved")
            return ""
        # Normalize domain to FQDN format
        domain = self._normalize_domain(domain)
        # Find the hash object to get its ID for attack chain tracking
        parent_hash_id = None
        parent_attack_step = 0
        normalized_domain = domain.lower().strip()
        normalized_user = username.lower().strip()
        for h in self.shared_state.all_hashes:
            if h.hash_value == hash_value or (
                h.username.lower() == normalized_user
                and h.domain.lower() == normalized_domain
                and h.hash_type.upper() == hash_type.upper()
            ):
                parent_hash_id = h.id
                parent_attack_step = h.attack_step
                break

        payload = {
            "hash_value": hash_value,
            "hash_type": hash_type,
            "username": username,
            "domain": domain,
            "wordlist": wordlist,
            "parent_credential_id": parent_hash_id,  # Hash ID for attack chain
            "parent_attack_step": parent_attack_step,
        }

        if self._task_queue:
            task_id = await self._throttled_submit_task(
                task_type="crack",
                target_role="cracker",
                payload=payload,
                source_agent=source_agent,
                priority=priority,
            )
            if not task_id:
                return ""

            # Task queued for main loop dispatch or deferred - don't create TaskInfo here
            # The main loop's _process_pending_dispatches will create TaskInfo when it submits
            if task_id in ("deferred", "queued"):
                logger.info(f"Crack task {task_id} to background/main loop queue")
                return task_id

            task_info = TaskInfo(
                task_id=task_id,
                task_type="crack",
                assigned_agent="cracker",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info

            logger.info(f"Crack task {task_id} submitted to Redis queue")
            return task_id

        # No Redis task queue - cannot dispatch
        logger.warning("No task queue available, cannot route crack request")
        return ""

    async def request_lateral_movement(
        self: RedTeamDispatcher,
        target_host: str,
        username: str,
        source_agent: str,
        password: str | None = None,
        hash_value: str | None = None,
        domain: str = "",
        method: str | None = None,
    ) -> str:
        """
        Route lateral movement request to LateralAgent.

        Uses Redis task queue for cross-pod communication when available.

        Args:
            target_host: IP or hostname to move to.
            username: Username to authenticate.
            source_agent: Agent making the request.
            password: Password (if available).
            hash_value: NTLM hash (if available).
            domain: Domain for authentication.
            method: Specific method (psexec, winrm, wmi) or None for auto.

        Returns:
            Task ID for tracking.
        """
        # Skip lateral movement if DA already achieved
        if self.shared_state.has_domain_admin:
            logger.debug(f"Skipping lateral movement to {target_host} - DA already achieved")
            return ""

        if not target_host or not target_host.strip():
            logger.warning(f"Skipping lateral movement for {domain}\\{username}: empty target_host")
            return ""

        # Normalize domain to FQDN format
        domain = self._normalize_domain(domain)

        resolved_password = password
        resolved_hash = hash_value
        resolved_domain = domain

        if not resolved_password and not resolved_hash:
            username_key = username.strip().lower()
            domain_key = domain.strip().lower() if domain else ""

            matching_creds = [
                cred
                for cred in self.shared_state.all_credentials
                if cred.username.strip().lower() == username_key
                and (not domain_key or cred.domain.strip().lower() == domain_key)
            ]

            if matching_creds:
                cred = matching_creds[0]
                resolved_password = cred.password
                if not resolved_domain:
                    resolved_domain = cred.domain
                logger.debug(
                    f"Filled lateral auth from credential store for {resolved_domain or domain}\\{username}"
                )

            if not resolved_password:
                matching_hashes = [
                    h
                    for h in self.shared_state.all_hashes
                    if h.username.strip().lower() == username_key
                    and (not domain_key or h.domain.strip().lower() == domain_key)
                ]
                if matching_hashes:
                    h = matching_hashes[0]
                    resolved_hash = h.hash_value
                    if h.cracked_password:
                        resolved_password = h.cracked_password
                    if not resolved_domain:
                        resolved_domain = h.domain
                    logger.debug(
                        f"Filled lateral auth from hash store for {resolved_domain or domain}\\{username}"
                    )

        self._ensure_credential_in_state(
            username=username,
            domain=resolved_domain or domain,
            password=resolved_password,
            hash_value=resolved_hash,
            source="lateral_movement",
        )

        # Track attack chain - find credential ID
        parent_id, parent_step = self._find_credential_id(
            username, resolved_domain or domain, resolved_password
        )

        payload = {
            "target_host": target_host,
            "username": username,
            "password": resolved_password,
            "hash_value": resolved_hash,
            "domain": resolved_domain,
            "method": method,
            "parent_credential_id": parent_id,
            "parent_attack_step": parent_step,
        }

        if not resolved_password and not resolved_hash:
            logger.warning(
                f"Skipping lateral movement for {resolved_domain or domain}\\{username} -> {target_host}: missing credentials"
            )
            return ""

        if self._task_queue:
            task_id = await self._throttled_submit_task(
                task_type="lateral",
                target_role="lateral",
                payload=payload,
                source_agent=source_agent,
            )
            if not task_id:
                return ""

            # Task queued for main loop dispatch or deferred - don't create TaskInfo here
            if task_id in ("deferred", "queued"):
                logger.info(f"Lateral movement task {task_id} to background/main loop queue")
                return task_id

            task_info = TaskInfo(
                task_id=task_id,
                task_type="lateral_movement",
                assigned_agent="lateral",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info

            logger.info(f"Lateral movement task {task_id} submitted to Redis queue")
            return task_id

        # No Redis task queue - cannot dispatch
        logger.warning("No task queue available, cannot route lateral movement request")
        return ""

    async def request_acl_analysis(
        self: RedTeamDispatcher,
        target_user: str,
        domain: str,
        source_agent: str,
        find_path_to: str = "Domain Admins",
    ) -> str:
        """
        Request ACLAgent to analyze attack paths for target.

        Uses Redis task queue for cross-pod communication when available.

        Args:
            target_user: User to find paths to.
            domain: Target domain.
            source_agent: Agent making the request.
            find_path_to: Target group/user for path finding.

        Returns:
            Task ID for tracking.
        """
        # Skip ACL analysis if DA already achieved
        if self.shared_state.has_domain_admin:
            logger.debug(f"Skipping ACL analysis for {target_user} - DA already achieved")
            return ""

        # Normalize domain to FQDN format
        domain = self._normalize_domain(domain)

        # PREREQUISITE CHECK: ACL analysis requires BloodHound data
        # The ACL agent only has exploitation tools, not collection capability.
        # If BloodHound hasn't run for this domain, dispatch it first and defer ACL analysis.
        domain_lower = domain.lower()
        if domain_lower not in self.shared_state.processed_bloodhound_domains:
            logger.info(
                f"ACL analysis for {target_user}@{domain} deferred - BloodHound not yet run. "
                f"Dispatching BloodHound collection first."
            )
            # Find credential for BloodHound collection
            credential = self._find_domain_credential(domain)
            if credential and credential.password:
                await self.request_recon(
                    source_agent=source_agent,
                    domain=domain,
                    username=credential.username,
                    password=credential.password,
                    reason="bloodhound",
                    techniques=["run_bloodhound"],
                )
            else:
                logger.warning(
                    f"Cannot dispatch BloodHound for {domain} - no password credential available. "
                    f"ACL analysis will remain blocked until BloodHound data is collected."
                )
            # Return empty - ACL analysis will be retried by orchestrator after BloodHound completes
            return ""

        credential = self._find_domain_credential(domain)
        dc_ip = self._find_domain_controller_ip(domain)

        payload = {
            "target_user": target_user,
            "domain": domain,
            "find_path_to": find_path_to,
            "dc_ip": dc_ip,
        }
        if credential:
            payload["username"] = credential.username
            payload["password"] = credential.password or ""
            payload["parent_credential_id"] = credential.id  # Track attack chain
            payload["parent_attack_step"] = (
                str(credential.attack_step) if credential.attack_step else ""
            )
            if not credential.password:
                for h in self.shared_state.all_hashes:
                    if h.username == credential.username:
                        payload["hash"] = h.hash_value
                        break

        if self._task_queue:
            task_id = await self._throttled_submit_task(
                task_type="acl_analysis",
                target_role="acl",
                payload=payload,
                source_agent=source_agent,
            )
            if not task_id:
                return ""

            # Task queued for main loop dispatch or deferred - don't create TaskInfo here
            if task_id in ("deferred", "queued"):
                logger.info(f"ACL analysis task {task_id} to background/main loop queue")
                return task_id

            task_info = TaskInfo(
                task_id=task_id,
                task_type="acl_analysis",
                assigned_agent="acl",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info

            logger.info(f"ACL analysis task {task_id} submitted to Redis queue")
            return task_id

        # No Redis task queue - cannot dispatch
        logger.warning("No task queue available, cannot route ACL analysis request")
        return ""

    async def request_recon(
        self: RedTeamDispatcher,
        source_agent: str,
        domain: str,
        target_ips: list[str] | None = None,
        username: str = "",
        password: str | None = None,
        hash_value: str | None = None,
        reason: str | None = None,
        techniques: list[str] | None = None,
    ) -> str:
        """
        Request reconnaissance actions (nmap, user enumeration, BloodHound).

        Uses Redis task queue for cross-pod communication when available.

        Args:
            source_agent: Agent making the request.
            domain: Target domain.
            target_ips: Target IPs for scanning/enumeration.
            username: Optional username for authenticated enumeration.
            password: Optional password for authenticated enumeration.
            hash_value: Optional NTLM hash for pass-the-hash.
            reason: Reason for the recon request (e.g., "network_scan", "bloodhound").
            techniques: Optional list of techniques to prioritize.

        Returns:
            Task ID for tracking.
        """
        # Skip new recon tasks if DA already achieved
        if self.shared_state.has_domain_admin:
            logger.debug(f"Skipping recon request ({reason}) - DA already achieved")
            return ""

        # Skip nmap if all targets have already been scanned
        if reason == "network_scan" and techniques and "nmap_scan" in techniques:
            scan_targets = set(target_ips or [])
            already_scanned = scan_targets & self.shared_state.scanned_targets
            if scan_targets and scan_targets == already_scanned:
                logger.info(f"Skipping nmap - all {len(scan_targets)} targets already scanned")
                return ""

        # PREREQUISITE: Non-nmap recon tasks require targets to be scanned first
        # This ensures nmap runs before SMB enumeration, user enumeration, etc.
        # We dispatch nmap (priority 1) AND continue to dispatch enumeration (priority 5).
        # Priority-based insertion ensures nmap runs first.
        is_nmap_task = reason == "network_scan" or (techniques and "nmap_scan" in techniques)
        if not is_nmap_task and target_ips and self._task_queue:
            unscanned = set(target_ips) - self.shared_state.scanned_targets
            if unscanned:
                logger.info(
                    f"Dispatching nmap for {len(unscanned)} unscanned targets before {reason} "
                    f"(targets: {list(unscanned)[:3]}{'...' if len(unscanned) > 3 else ''})"
                )
                # Dispatch nmap with high priority - it will run before the enumeration task
                await self._throttled_submit_task(
                    task_type="recon",
                    target_role="recon",
                    payload={
                        "domain": domain,
                        "target_ips": list(unscanned),
                        "reason": "network_scan",
                        "techniques": ["nmap_scan"],
                    },
                    source_agent="dispatcher",
                    priority=1,  # Urgent - runs first due to priority-based queue insertion
                )
                # DON'T return - continue to dispatch the enumeration task with lower priority
                # It will be queued behind nmap and run after nmap completes

        # Normalize domain to FQDN format
        domain = self._normalize_domain(domain)

        self._ensure_credential_in_state(
            username=username,
            domain=domain,
            password=password,
            hash_value=hash_value,
            source=f"recon_{reason or 'task'}",
        )

        dc_ip = self._find_domain_controller_ip(domain)

        # Track attack chain
        parent_id, parent_step = self._find_credential_id(username, domain, password)

        payload = {
            "domain": domain,
            "target_ips": target_ips or [],
            "dc_ip": dc_ip,
            "username": username,
            "password": password,
            "hash_value": hash_value,
            "reason": reason,
            "techniques": techniques or [],
            "parent_credential_id": parent_id,
            "parent_attack_step": parent_step,
        }

        if self._task_queue:
            # Nmap tasks get high priority to ensure they run before enumeration
            priority = 1 if is_nmap_task else 5
            task_id = await self._throttled_submit_task(
                task_type="recon",
                target_role="recon",
                payload=payload,
                source_agent=source_agent,
                priority=priority,
            )
            if not task_id:
                return ""

            # Task queued for main loop dispatch or deferred - don't create TaskInfo here
            if task_id in ("deferred", "queued"):
                logger.info(f"Recon task {task_id} to background/main loop queue")
                return task_id

            task_info = TaskInfo(
                task_id=task_id,
                task_type="recon",
                assigned_agent="recon",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info

            cred_label = username or "unauthenticated"
            if hash_value and not password:
                cred_label = f"{cred_label} (hash)"
            if password:
                cred_label = f"{cred_label} (password)"
            reason_label = f" reason={reason}" if reason else ""
            logger.info(
                f"Recon task {task_id} submitted to Redis queue for {cred_label}{reason_label}"
            )
            return task_id

        # No Redis task queue - cannot dispatch
        logger.warning("No task queue available, cannot route recon request")
        return ""

    async def request_credential_access(
        self: RedTeamDispatcher,
        source_agent: str,
        domain: str,
        target_ips: list[str] | None = None,
        username: str = "",
        password: str | None = None,
        hash_value: str | None = None,
        hash_type: str | None = None,
        credential_source: str | None = None,
        reason: str | None = None,
        techniques: list[str] | None = None,
        extra_params: dict[str, Any] | None = None,
        task_queue: Any = None,
    ) -> str:
        """
        Request credential access actions (AS-REP roast, Kerberoast, secretsdump, LSASS).

        Uses Redis task queue for cross-pod communication when available.

        Args:
            source_agent: Agent making the request.
            domain: Target domain.
            target_ips: Target IPs for credential access actions.
            username: Optional username for authenticated actions.
            password: Optional password for authenticated actions.
            hash_value: Optional NTLM hash for pass-the-hash actions.
            techniques: Optional list of techniques to prioritize.
            extra_params: Optional additional parameters to pass (e.g., ticket_path, no_pass).
            task_queue: Optional task queue for direct dispatch (threaded consumer passes its own).

        Returns:
            Task ID for tracking.
        """
        # Skip new credential access tasks if DA already achieved
        if self.shared_state.has_domain_admin:
            logger.debug(f"Skipping credential access request ({reason}) - DA already achieved")
            return ""

        # Normalize domain to FQDN format
        domain = self._normalize_domain(domain)

        self._ensure_credential_in_state(
            username=username,
            domain=domain,
            password=password,
            hash_value=hash_value,
            source=f"credential_access_{reason or 'task'}",
        )

        dc_ip = self._find_domain_controller_ip(domain)

        # Track attack chain
        parent_id, parent_step = self._find_credential_id(username, domain, password)

        payload: dict[str, Any] = {
            "domain": domain,
            "target_ips": target_ips or [],
            "dc_ip": dc_ip,
            "username": username,
            "password": password,
            "hash_value": hash_value,
            "hash_type": hash_type,
            "credential_source": credential_source,
            "reason": reason,
            "techniques": techniques or [],
            "parent_credential_id": parent_id,
            "parent_attack_step": parent_step,
        }

        if extra_params:
            payload.update(extra_params)

        # Use provided task_queue (from threaded consumer) or fall back to self._task_queue
        effective_task_queue = task_queue if task_queue is not None else self._task_queue
        if effective_task_queue:
            task_id = await self._throttled_submit_task(
                task_type="credential_access",
                target_role="credential_access",
                payload=payload,
                source_agent=source_agent,
                task_queue=effective_task_queue,
            )
            if not task_id:
                return ""

            # Task queued for main loop dispatch or deferred - don't create TaskInfo here
            if task_id in ("deferred", "queued"):
                logger.info(f"Credential access task {task_id} to background/main loop queue")
                return task_id

            task_info = TaskInfo(
                task_id=task_id,
                task_type="credential_access",
                assigned_agent="credential_access",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info

            cred_label = username or "no-cred"
            if hash_value and not password:
                cred_label = f"{cred_label} (hash)"
            if password:
                cred_label = f"{cred_label} (password)"
            reason_label = f" reason={reason}" if reason else ""
            source_label = f" source={credential_source}" if credential_source else ""
            hash_label = f" hash_type={hash_type}" if hash_type else ""
            logger.info(
                f"Credential access task {task_id} submitted to Redis queue for {cred_label}{reason_label}{source_label}{hash_label}"
            )
            return task_id

        # No Redis task queue - cannot dispatch
        logger.warning("No task queue available, cannot route credential access request")
        return ""

    def _enrich_delegation_payload(
        self: RedTeamDispatcher, payload: dict[str, Any], vuln_type: str
    ) -> None:
        """Enrich delegation exploit payload with credentials from state if missing."""
        if vuln_type not in ("constrained_delegation", "unconstrained_delegation"):
            return
        if payload.get("password"):
            return
        account = payload.get("account_name") or payload.get("account", payload.get("target", ""))
        account_lower = account.lower().rstrip("$") if account else ""
        for cred in self.shared_state.all_credentials:
            if cred.username.lower() == account_lower and cred.password:
                payload["password"] = cred.password
                if not payload.get("domain") and cred.domain:
                    payload["domain"] = cred.domain
                logger.info(f"Enriched {vuln_type} payload with credential for {account}")
                break

    def _resolve_dc_ip_for_payload(
        self: RedTeamDispatcher, payload: dict[str, Any], vuln_type: str
    ) -> None:
        """Resolve dc_ip for exploit payload if not already set."""
        if payload.get("dc_ip") or not payload.get("domain"):
            return
        dc_ip = self._find_domain_controller_ip(payload["domain"]) or payload.get("target_ip", "")
        if not dc_ip and self.shared_state.target:
            dc_ip = self.shared_state.target.ip
        if dc_ip:
            payload["dc_ip"] = dc_ip
            logger.info(f"Resolved dc_ip={dc_ip} for exploit {vuln_type}")

    async def request_exploit(
        self: RedTeamDispatcher,
        vuln_type: str,
        vuln_id: str,
        target: str,
        source_agent: str,
        params: dict[str, Any] | None = None,
        task_queue: Any = None,
    ) -> str:
        """Request PrivEscAgent to exploit vulnerability."""
        if self.shared_state.has_domain_admin:
            logger.debug(f"Skipping exploit {vuln_type} on {target} - DA already achieved")
            return ""

        params = params or {}
        if "domain" in params:
            params["domain"] = self._normalize_domain(params["domain"])

        payload = {"vuln_type": vuln_type, "vuln_id": vuln_id, "target": target, **params}

        # Enrich with credentials and resolve DC IP
        self._enrich_delegation_payload(payload, vuln_type)
        self._resolve_dc_ip_for_payload(payload, vuln_type)

        # Track attack chain
        username = payload.get("username") or payload.get("account_name", "")
        if username:
            parent_id, parent_step = self._find_credential_id(
                username, payload.get("domain", ""), payload.get("password", "")
            )
            payload["parent_credential_id"] = parent_id
            payload["parent_attack_step"] = parent_step

        effective_task_queue = task_queue if task_queue is not None else self._task_queue
        if not effective_task_queue:
            logger.warning("No task queue available, cannot route exploit request")
            return ""

        task_id = await self._throttled_submit_task(
            task_type="exploit",
            target_role="privesc",
            payload=payload,
            source_agent=source_agent,
            priority=1,
            task_queue=effective_task_queue,
        )
        if not task_id:
            return ""

        if task_id in ("deferred", "queued"):
            logger.info(f"Exploit task for {vuln_type} {task_id} to background/main loop queue")
            self._record_exploit_weakness(vuln_type, target, payload)
            return "deferred"

        task_info = TaskInfo(
            task_id=task_id, task_type="exploit", assigned_agent="privesc", params=payload
        )
        self.shared_state.pending_tasks[task_id] = task_info
        logger.info(f"Exploit task {task_id} for {vuln_type} submitted to Redis queue")
        self._record_exploit_weakness(vuln_type, target, payload)
        return task_id

    async def request_privesc_enumeration(
        self: RedTeamDispatcher,
        source_agent: str,
        domain: str,
        username: str,
        password: str,
        techniques: list[str] | None = None,
        task_queue: Any = None,
    ) -> str:
        """
        Request PRIVESC agent to run enumeration tasks (e.g., find_delegation).

        This routes enumeration tasks that require PRIVESC tools (like DelegationTools)
        to the correct agent, rather than RECON which doesn't have these tools.

        Args:
            source_agent: Agent making the request.
            domain: Target domain.
            username: Username for authenticated enumeration.
            password: Password for authentication.
            techniques: List of enumeration techniques (e.g., ["find_delegation"]).

        Returns:
            Task ID for tracking.
        """
        # Skip new privesc enumeration tasks if DA already achieved
        if self.shared_state.has_domain_admin:
            logger.debug(f"Skipping privesc enumeration ({techniques}) - DA already achieved")
            return ""

        # Normalize domain to FQDN format
        domain = self._normalize_domain(domain)

        # Deduplication: check if already processed or pending for this credential
        cred_key = f"{domain.lower()}:{username.lower()}"
        technique_key = f"{cred_key}:{','.join(sorted(techniques or ['find_delegation']))}"

        # Skip if already successfully processed
        if cred_key in self.shared_state.processed_delegation_creds:
            logger.debug(f"Skipping privesc enumeration for {cred_key} - already processed")
            return ""

        # Skip if there's already a pending task for same credential + techniques
        for task in self.shared_state.pending_tasks.values():
            if task.task_type != "privesc_enumeration":
                continue
            task_domain = (task.params.get("domain") or "").lower()
            task_user = (task.params.get("username") or "").lower()
            task_techniques = task.params.get("techniques") or ["find_delegation"]
            pending_key = f"{task_domain}:{task_user}:{','.join(sorted(task_techniques))}"
            if pending_key == technique_key:
                logger.debug(
                    f"Skipping privesc enumeration for {cred_key} - already pending (task {task.task_id})"
                )
                return ""

        self._ensure_credential_in_state(
            username=username,
            domain=domain,
            password=password,
            source="privesc_enumeration",
        )

        dc_ip = self._find_domain_controller_ip(domain)
        if not dc_ip and self.shared_state.target and self.shared_state.target.ip:
            dc_ip = self.shared_state.target.ip
            logger.warning(f"DC IP fallback: using primary target IP {dc_ip} for {domain}")

        # Track attack chain
        parent_id, parent_step = self._find_credential_id(username, domain, password)

        payload = {
            "domain": domain,
            "dc_ip": dc_ip,
            "username": username,
            "password": password,
            "techniques": techniques or [],
            "parent_credential_id": parent_id,
            "parent_attack_step": parent_step,
        }

        # Use provided task_queue (from threaded consumer) or fall back to self._task_queue
        effective_task_queue = task_queue if task_queue is not None else self._task_queue
        if effective_task_queue:
            # Use priority=1 (highest) for delegation enumeration - these are critical
            # for discovering constrained delegation paths to Domain Admin
            task_id = await self._throttled_submit_task(
                task_type="privesc_enumeration",
                target_role="privesc",
                payload=payload,
                source_agent=source_agent,
                priority=1,  # Highest priority - delegation discovery is critical path
                task_queue=effective_task_queue,
            )
            if not task_id:
                return ""

            # Task queued for main loop dispatch or deferred - don't create TaskInfo here
            if task_id in ("deferred", "queued"):
                logger.info(f"Privesc enumeration task {task_id} to background/main loop queue")
                return task_id

            task_info = TaskInfo(
                task_id=task_id,
                task_type="privesc_enumeration",
                assigned_agent="privesc",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info

            logger.info(
                f"Privesc enumeration task {task_id} submitted to Redis queue "
                f"for {domain}\\{username}, techniques={techniques}"
            )
            return task_id

        # No Redis task queue - cannot dispatch
        logger.warning("No task queue available, cannot route privesc enumeration request")
        return ""

    async def request_coercion(
        self: RedTeamDispatcher,
        source_agent: str,
        interface: str = "",
        techniques: list[str] | None = None,
        duration: int = 300,
        payload_override: dict[str, Any] | None = None,
    ) -> str:
        """
        Request the coercion agent to start network coercion.

        Uses Redis task queue for cross-pod communication when available.

        Args:
            source_agent: Agent making the request.
            interface: Network interface (auto-detected if not specified).
            techniques: Coercion techniques to use.
            duration: How long to run (seconds).
            payload_override: Optional dict to merge/override default payload.
                             Use for ESC8-specific coercion (petitpotam, coercer).

        Returns:
            Task ID for tracking.
        """
        # Skip new coercion tasks if DA already achieved
        if self.shared_state.has_domain_admin:
            logger.debug(f"Skipping coercion request ({techniques}) - DA already achieved")
            return ""

        techniques = techniques or ["LLMNR", "NBT-NS", "mDNS"]

        # NOTE: Do NOT detect interface here on the orchestrator side.
        # Pass empty string and let the coercion worker detect the interface locally,
        # since the worker pod has the correct ARES_NETWORK_INTERFACE env var set.
        # The orchestrator and worker pods may have different network interfaces.

        payload: dict[str, Any] = {
            "interface": interface,
            "techniques": techniques,
            "duration": duration,
        }

        if payload_override:
            payload.update(payload_override)

        if self._task_queue:
            task_id = await self._throttled_submit_task(
                task_type="coercion",
                target_role="coercion",
                payload=payload,
                source_agent=source_agent,
            )
            if not task_id:
                return ""

            # Task queued for main loop dispatch or deferred - don't create TaskInfo here
            if task_id in ("deferred", "queued"):
                logger.info(f"Coercion task {task_id} to background/main loop queue")
                return task_id

            task_info = TaskInfo(
                task_id=task_id,
                task_type="coercion",
                assigned_agent="coercion",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info

            logger.info(f"Coercion task {task_id} submitted to Redis queue")
            return task_id

        # No Redis task queue - cannot dispatch
        logger.warning("No task queue available, cannot route coercion request")
        return ""


__all__ = ["RoutingMixin"]
