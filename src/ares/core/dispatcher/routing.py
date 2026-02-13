"""Task routing methods for dispatching work to specialized agents.

This module provides all request_*() methods for routing tasks to
the appropriate agent roles (crack, lateral, exploit, recon, etc.).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.messages import (
    ACLAnalysisRequest,
    CoercionRequest,
    CrackRequest,
    CredentialAccessRequest,
    ExploitRequest,
    LateralMovementRequest,
    ReconRequest,
    generate_task_id,
)
from ares.core.models import (
    AgentRole,
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

    def _find_domain_controller_ip(self: RedTeamDispatcher, domain: str) -> str:  # noqa: PLR0912
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

        # Priority 4: Fallback - hosts with DC roles (any domain) - log warning
        for host in self.shared_state.all_hosts:
            if _has_dc_role(host):
                logger.warning(
                    f"DC IP fallback (no domain match): {host.ip} ({host.hostname}) for domain {domain}"
                )
                return host.ip

        # Priority 5: Any host with DC-like services (risky, may be wrong) - log warning
        for host in self.shared_state.all_hosts:
            if _has_dc_services(host):
                logger.warning(
                    f"DC IP last resort (services only): {host.ip} ({host.hostname}) for domain {domain}"
                )
                return host.ip

        # Priority 6: DNS SRV lookup (last resort, requires network access)
        if domain_lower:
            dc_ip = self._dns_lookup_dc(domain_lower)
            if dc_ip:
                # Cache for future lookups
                self.shared_state.domain_controllers[domain_lower] = dc_ip
                logger.info(f"DC IP found via DNS SRV: {dc_ip} for {domain}")
                return dc_ip

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
            spn: Service Principal Name (e.g., 'cifs/DC01.domain.local')

        Returns:
            Host FQDN (e.g., 'DC01.domain.local') or None if not extractable
        """
        if not spn or "/" not in spn:
            return None

        parts = spn.split("/", 1)
        if len(parts) == 2:
            return parts[1]
        return None

    async def _auto_chain_s4u_lateral_movement(
        self: RedTeamDispatcher,
        task_id: str,
        task_info: TaskInfo,
        result: dict[str, Any],
        source_agent: str,
    ) -> int:
        """Auto-chain lateral movement after successful S4U attack.

        When an S4U attack generates an Administrator ticket, this method
        automatically dispatches secretsdump to harvest credentials using
        the generated ticket.

        Args:
            task_id: ID of the completed task
            task_info: Information about the completed task
            result: Task result containing output
            source_agent: Agent that completed the task

        Returns:
            Number of lateral movement tasks dispatched
        """
        if task_info.task_type != "exploit":
            return 0

        params = task_info.params or {}
        if params.get("vuln_type") != "constrained_delegation":
            return 0

        output = result.get("output", "") or result.get("stdout", "") or str(result)
        if ".ccache" not in output:
            logger.debug(f"No .ccache found in S4U output for task {task_id}")
            return 0

        ticket_path = self._extract_ticket_path_from_output(output)
        target_spn = params.get("target_spn", "")
        target_host = self._extract_host_from_spn(target_spn)
        domain = params.get("domain", "")

        if not target_host:
            logger.warning(f"Could not extract host from SPN: {target_spn}")
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

            task_info = TaskInfo(
                task_id=task_id,
                task_type="crack",
                assigned_agent="cracker",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info
            self._redis_task_ids.add(task_id)

            logger.info(f"Crack task {task_id} submitted to Redis queue")
            return task_id

        task_id = generate_task_id()
        cracker_agent = self._role_queues.get(AgentRole.CRACKER)

        if not cracker_agent:
            logger.warning("No cracker agent registered, cannot route crack request")
            return ""

        task_info = TaskInfo(
            task_id=task_id,
            task_type="crack",
            assigned_agent=cracker_agent,
            params=payload,
        )
        self.shared_state.pending_tasks[task_id] = task_info

        await self._message_queues[cracker_agent].put(
            CrackRequest(
                source_agent=source_agent,
                task_id=task_id,
                hash_value=hash_value,
                hash_type=hash_type,
                username=username,
                domain=domain,
                callback_agent=source_agent,
                wordlist=wordlist,
                priority=priority,
            )
        )

        logger.info(f"Crack request {task_id} sent to {cracker_agent}")
        return task_id

    async def request_lateral_movement(  # noqa: PLR0912
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

            task_info = TaskInfo(
                task_id=task_id,
                task_type="lateral_movement",
                assigned_agent="lateral",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info
            self._redis_task_ids.add(task_id)

            logger.info(f"Lateral movement task {task_id} submitted to Redis queue")
            return task_id

        task_id = generate_task_id()
        lateral_agent = self._role_queues.get(AgentRole.LATERAL)

        if not lateral_agent:
            logger.warning("No lateral agent registered, cannot route lateral request")
            return ""

        task_info = TaskInfo(
            task_id=task_id,
            task_type="lateral_movement",
            assigned_agent=lateral_agent,
            params=payload,
        )
        self.shared_state.pending_tasks[task_id] = task_info

        await self._message_queues[lateral_agent].put(
            LateralMovementRequest(
                source_agent=source_agent,
                task_id=task_id,
                target_host=target_host,
                username=username,
                password=password,
                hash_value=hash_value,
                domain=domain,
                method=method,
                callback_agent=source_agent,
            )
        )

        logger.info(f"Lateral movement request {task_id} sent to {lateral_agent}")
        return task_id

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

            task_info = TaskInfo(
                task_id=task_id,
                task_type="acl_analysis",
                assigned_agent="acl",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info
            self._redis_task_ids.add(task_id)

            logger.info(f"ACL analysis task {task_id} submitted to Redis queue")
            return task_id

        task_id = generate_task_id()
        acl_agent = self._role_queues.get(AgentRole.ACL)

        if not acl_agent:
            logger.warning("No ACL agent registered, cannot route ACL request")
            return ""

        task_info = TaskInfo(
            task_id=task_id,
            task_type="acl_analysis",
            assigned_agent=acl_agent,
            params=payload,
        )
        self.shared_state.pending_tasks[task_id] = task_info

        await self._message_queues[acl_agent].put(
            ACLAnalysisRequest(
                source_agent=source_agent,
                task_id=task_id,
                target_user=target_user,
                domain=domain,
                find_path_to=find_path_to,
                callback_agent=source_agent,
            )
        )

        logger.info(f"ACL analysis request {task_id} sent to {acl_agent}")
        return task_id

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
            task_id = await self._throttled_submit_task(
                task_type="recon",
                target_role="recon",
                payload=payload,
                source_agent=source_agent,
            )
            if not task_id:
                return ""

            task_info = TaskInfo(
                task_id=task_id,
                task_type="recon",
                assigned_agent="recon",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info
            self._redis_task_ids.add(task_id)

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

        task_id = generate_task_id()
        recon_agent = self._role_queues.get(AgentRole.RECON)

        if not recon_agent:
            logger.warning("No recon agent registered, cannot route request")
            return ""

        task_info = TaskInfo(
            task_id=task_id,
            task_type="recon",
            assigned_agent=recon_agent,
            params=payload,
        )
        self.shared_state.pending_tasks[task_id] = task_info

        await self._message_queues[recon_agent].put(
            ReconRequest(
                source_agent=source_agent,
                task_id=task_id,
                domain=domain,
                target_ips=payload["target_ips"],
                dc_ip=dc_ip,
                username=username,
                password=password,
                hash_value=hash_value,
                reason=reason,
                techniques=payload["techniques"],
                callback_agent=source_agent,
            )
        )

        logger.info(f"Recon request {task_id} sent to {recon_agent}")
        return task_id

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

        if self._task_queue:
            task_id = await self._throttled_submit_task(
                task_type="credential_access",
                target_role="credential_access",
                payload=payload,
                source_agent=source_agent,
            )
            if not task_id:
                return ""

            task_info = TaskInfo(
                task_id=task_id,
                task_type="credential_access",
                assigned_agent="credential_access",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info
            self._redis_task_ids.add(task_id)

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

        task_id = generate_task_id()
        credential_agent = self._role_queues.get(AgentRole.CREDENTIAL_ACCESS)

        if not credential_agent:
            logger.warning("No credential access agent registered, cannot route request")
            return ""

        task_info = TaskInfo(
            task_id=task_id,
            task_type="credential_access",
            assigned_agent=credential_agent,
            params=payload,
        )
        self.shared_state.pending_tasks[task_id] = task_info

        await self._message_queues[credential_agent].put(
            CredentialAccessRequest(
                source_agent=source_agent,
                task_id=task_id,
                domain=domain,
                target_ips=payload["target_ips"],
                dc_ip=dc_ip,
                username=username,
                password=password,
                hash_value=hash_value,
                techniques=payload["techniques"],
                callback_agent=source_agent,
            )
        )

        logger.info(f"Credential access request {task_id} sent to {credential_agent}")
        return task_id

    async def request_exploit(
        self: RedTeamDispatcher,
        vuln_type: str,
        vuln_id: str,
        target: str,
        source_agent: str,
        params: dict[str, Any] | None = None,
    ) -> str:
        """
        Request PrivEscAgent to exploit vulnerability.

        Uses Redis task queue for cross-pod communication when available.

        Args:
            vuln_type: ADCS_ESC1, DELEGATION_UNCONSTRAINED, etc.
            vuln_id: Vulnerability ID.
            target: Target to exploit.
            source_agent: Agent making the request.
            params: Vulnerability-specific parameters.

        Returns:
            Task ID for tracking.
        """
        # Skip new exploit tasks if DA already achieved
        if self.shared_state.has_domain_admin:
            logger.debug(f"Skipping exploit {vuln_type} on {target} - DA already achieved")
            return ""

        # Normalize domain to FQDN format in params
        params = params or {}
        if "domain" in params:
            params["domain"] = self._normalize_domain(params["domain"])

        payload = {
            "vuln_type": vuln_type,
            "vuln_id": vuln_id,
            "target": target,
            **params,
        }

        # Track attack chain - look up credential from params
        username = payload.get("username") or payload.get("account_name", "")
        domain = payload.get("domain", "")
        password = payload.get("password", "")
        if username:
            parent_id, parent_step = self._find_credential_id(username, domain, password)
            payload["parent_credential_id"] = parent_id
            payload["parent_attack_step"] = parent_step

        # Ensure dc_ip is resolved for exploit tasks that need it
        if not payload.get("dc_ip") and payload.get("domain"):
            dc_ip = self._find_domain_controller_ip(payload["domain"])
            if not dc_ip:
                dc_ip = payload.get("target_ip", "")
            if not dc_ip and self.shared_state.target:
                dc_ip = self.shared_state.target.ip
            if dc_ip:
                payload["dc_ip"] = dc_ip
                logger.info(f"Resolved dc_ip={dc_ip} for exploit {vuln_type}")

        if self._task_queue:
            # Use priority=1 (highest) - exploit tasks are the actual DA path.
            # Combined with phase adjustment (-2 in privilege_escalation),
            # exploits will have effective priority -1 → clamped to 1,
            # beating discovery tasks (priority=2 after +1 adjustment).
            task_id = await self._throttled_submit_task(
                task_type="exploit",
                target_role="privesc",
                payload=payload,
                source_agent=source_agent,
                priority=1,
            )
            if not task_id:
                return ""

            task_info = TaskInfo(
                task_id=task_id,
                task_type="exploit",
                assigned_agent="privesc",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info
            self._redis_task_ids.add(task_id)

            logger.info(f"Exploit task {task_id} for {vuln_type} submitted to Redis queue")

            self._record_exploit_weakness(vuln_type, target, payload)

            return task_id

        task_id = generate_task_id()
        privesc_agent = self._role_queues.get(AgentRole.PRIVESC)

        if not privesc_agent:
            logger.warning("No privesc agent registered, cannot route exploit request")
            return ""

        task_info = TaskInfo(
            task_id=task_id,
            task_type="exploit",
            assigned_agent=privesc_agent,
            params=payload,
        )
        self.shared_state.pending_tasks[task_id] = task_info

        await self._message_queues[privesc_agent].put(
            ExploitRequest(
                source_agent=source_agent,
                task_id=task_id,
                vuln_type=vuln_type,
                vuln_id=vuln_id,
                target=target,
                params=params or {},
                callback_agent=source_agent,
            )
        )

        logger.info(f"Exploit request {task_id} for {vuln_type} sent to {privesc_agent}")
        return task_id

    async def request_privesc_enumeration(
        self: RedTeamDispatcher,
        source_agent: str,
        domain: str,
        username: str,
        password: str,
        techniques: list[str] | None = None,
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

        if self._task_queue:
            # Use priority=1 (highest) for delegation enumeration - these are critical
            # for discovering constrained delegation paths to Domain Admin
            task_id = await self._throttled_submit_task(
                task_type="privesc_enumeration",
                target_role="privesc",
                payload=payload,
                source_agent=source_agent,
                priority=1,  # Highest priority - delegation discovery is critical path
            )
            if not task_id:
                return ""

            task_info = TaskInfo(
                task_id=task_id,
                task_type="privesc_enumeration",
                assigned_agent="privesc",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info
            self._redis_task_ids.add(task_id)

            logger.info(
                f"Privesc enumeration task {task_id} submitted to Redis queue "
                f"for {domain}\\{username}, techniques={techniques}"
            )
            return task_id

        task_id = generate_task_id()
        privesc_agent = self._role_queues.get(AgentRole.PRIVESC)

        if not privesc_agent:
            logger.warning("No privesc agent registered, cannot route enumeration request")
            return ""

        task_info = TaskInfo(
            task_id=task_id,
            task_type="privesc_enumeration",
            assigned_agent=privesc_agent,
            params=payload,
        )
        self.shared_state.pending_tasks[task_id] = task_info

        await self._message_queues[privesc_agent].put(
            ExploitRequest(
                source_agent=source_agent,
                task_id=task_id,
                vuln_type="PRIVESC_ENUMERATION",
                vuln_id=f"enum-{task_id}",
                target=dc_ip or domain,
                params={
                    "domain": domain,
                    "username": username,
                    "password": password,
                    "techniques": techniques or [],
                },
                callback_agent=source_agent,
            )
        )

        logger.info(f"Privesc enumeration request {task_id} sent to {privesc_agent}")
        return task_id

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

            task_info = TaskInfo(
                task_id=task_id,
                task_type="coercion",
                assigned_agent="coercion",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info
            self._redis_task_ids.add(task_id)

            logger.info(f"Coercion task {task_id} submitted to Redis queue")
            return task_id

        task_id = generate_task_id()
        coercion_agent = self._role_queues.get(AgentRole.COERCION)

        if not coercion_agent:
            logger.warning("No coercion agent registered, cannot route coercion request")
            return ""

        task_info = TaskInfo(
            task_id=task_id,
            task_type="coercion",
            assigned_agent=coercion_agent,
            params=payload,
        )
        self.shared_state.pending_tasks[task_id] = task_info

        await self._message_queues[coercion_agent].put(
            CoercionRequest(
                source_agent=source_agent,
                task_id=task_id,
                interface=interface,
                techniques=techniques,
                duration=duration,
                callback_agent=source_agent,
            )
        )

        logger.info(f"Coercion request {task_id} sent to {coercion_agent}")
        return task_id


__all__ = ["RoutingMixin"]
