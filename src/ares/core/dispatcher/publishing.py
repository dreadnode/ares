"""Discovery publishing for credentials, hosts, shares, and vulnerabilities.

This module provides methods to publish discoveries to all agents and update
shared state. Includes MSSQL auto-detection and ADCS enumeration support.

NOTE: When called from the threaded result consumer (non-main thread), dispatch
operations are skipped because the task queue is bound to the main event loop.
The main orchestrator loop handles dispatches through normal processing.
"""

from __future__ import annotations

import asyncio
import threading
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.models import (
    Credential,
    Hash,
    Host,
    Share,
    TaskInfo,
    TimelineEvent,
    VulnerabilityInfo,
)

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher


class PublishingMixin:
    """Discovery publishing for credentials, hosts, shares, and vulnerabilities."""

    async def publish_credential(  # noqa: PLR0912
        self: RedTeamDispatcher,
        credential: Credential,
        source_agent: str,
        is_admin: bool = False,
        task_queue: Any = None,
    ) -> bool:
        """
        Broadcast new credential to all agents.

        Args:
            credential: The discovered credential.
            source_agent: Agent that discovered it.
            is_admin: Whether this is an admin credential.

        Returns:
            True if credential was new and added.
        """
        self._add_user(credential.username, credential.domain, source_agent)
        added = self.shared_state.add_credential(credential, source_agent)

        if added:
            self.signal_credential_access()
            # Add timeline event for credential discovery
            import uuid
            from datetime import datetime, timezone

            self.shared_state.operation_timeline.append(
                TimelineEvent(
                    id=f"evt-cred-{uuid.uuid4().hex[:8]}",
                    timestamp=datetime.now(timezone.utc),
                    source=source_agent,
                    description=f"Credential discovered: {credential.domain}\\{credential.username} via {credential.source}",
                    mitre_techniques=["T1078"] if is_admin else ["T1552"],
                )
            )
            is_main_thread = threading.current_thread() is threading.main_thread()
            if is_main_thread:
                await self._checkpoint()
            else:
                self._checkpoint_requested.set()
                logger.info(
                    f"⚡ Checkpoint requested for credential: {credential.domain}\\{credential.username}"
                )
            logger.info(f"Credential published: {credential.domain}\\{credential.username}")

            # Immediate delegation check for high-value credentials (cracked hashes)
            # Cracked Kerberoast/AS-REP hashes may have constrained delegation rights
            is_cracked = credential.source and (
                "cracker" in credential.source.lower()
                or "cracked" in credential.source.lower()
                or "kerberoast" in credential.source.lower()
                or "asrep" in credential.source.lower()
            )
            if is_cracked and credential.password and credential.domain:
                cred_key = f"{credential.domain.lower()}:{credential.username.lower()}"
                if cred_key not in self.shared_state.processed_delegation_creds:
                    # Dispatch delegation check directly using effective task queue
                    # When called from threaded consumer, task_queue is passed in
                    # When called from main thread, task_queue is None and we use self._task_queue
                    effective_task_queue = (
                        task_queue if task_queue is not None else self._task_queue
                    )
                    if effective_task_queue:
                        logger.info(
                            f"🚀 Immediate delegation check for cracked credential: "
                            f"{credential.domain}\\{credential.username}"
                        )
                        try:
                            task_id = await asyncio.wait_for(
                                self.request_privesc_enumeration(
                                    source_agent="orchestrator",
                                    domain=credential.domain,
                                    username=credential.username,
                                    password=credential.password,
                                    techniques=["find_delegation"],
                                    task_queue=effective_task_queue,
                                ),
                                timeout=30.0,
                            )
                            if task_id:
                                logger.info(
                                    f"🚀 Immediate delegation task {task_id} dispatched for "
                                    f"{credential.domain}\\{credential.username}"
                                )
                        except asyncio.TimeoutError:
                            logger.error(
                                f"Timeout dispatching delegation check for {credential.domain}\\{credential.username}"
                            )
                        except Exception as e:
                            logger.warning(f"Failed to dispatch immediate delegation check: {e}")

                        # Check for pending constrained delegation vulnerabilities we can now exploit
                        try:
                            await asyncio.wait_for(
                                self._exploit_delegation_with_credential(
                                    credential, source_agent, effective_task_queue
                                ),
                                timeout=30.0,
                            )
                        except asyncio.TimeoutError:
                            logger.error(
                                f"Timeout in _exploit_delegation_with_credential for "
                                f"{credential.domain}\\{credential.username}"
                            )
                        except Exception as e:
                            logger.warning(f"Error exploiting delegation with credential: {e}")
                    else:
                        logger.warning(
                            f"Cannot dispatch delegation enum - no task_queue available: "
                            f"{credential.domain}\\{credential.username}"
                        )
        else:
            logger.debug(
                f"Credential not published (duplicate/invalid): {credential.domain}\\{credential.username}"
            )

        return added

    async def publish_hash(
        self: RedTeamDispatcher,
        hash_obj: Hash,
        source_agent: str,
        priority: int = 5,
    ) -> bool:
        """
        Broadcast new hash to all agents.

        Args:
            hash_obj: The discovered hash.
            source_agent: Agent that discovered it.
            priority: Priority for cracking (1=krbtgt, 2=admin, 5=normal).

        Returns:
            True if hash was new and added.
        """
        added = self.shared_state.add_hash(hash_obj, source_agent)

        if added:
            self.signal_credential_access()
            # Add timeline event for hash discovery
            import uuid
            from datetime import datetime, timezone

            is_critical = hash_obj.username.lower() in ("krbtgt", "administrator")
            event_desc = (
                f"Hash discovered: {hash_obj.domain}\\{hash_obj.username} ({hash_obj.hash_type})"
            )
            if is_critical:
                event_desc = f"CRITICAL: {event_desc}"
            self.shared_state.operation_timeline.append(
                TimelineEvent(
                    id=f"evt-hash-{uuid.uuid4().hex[:8]}",
                    timestamp=datetime.now(timezone.utc),
                    source=source_agent,
                    description=event_desc,
                    mitre_techniques=["T1003"],  # OS Credential Dumping
                )
            )
            if threading.current_thread() is threading.main_thread():
                await self._checkpoint()
            else:
                self._checkpoint_requested.set()
            logger.info(
                f"Hash published: {hash_obj.domain}\\{hash_obj.username} ({hash_obj.hash_type})"
            )
        else:
            logger.debug(
                f"Hash not published (duplicate): {hash_obj.domain}\\{hash_obj.username} ({hash_obj.hash_type})"
            )

        return added

    async def publish_share(self: RedTeamDispatcher, share: Share, source_agent: str) -> bool:
        """
        Record share discovery in shared state.

        Args:
            share: The discovered share.
            source_agent: Agent that discovered it.

        Returns:
            True if share was new and added.
        """
        added = self.shared_state.add_share(share)
        if added:
            if threading.current_thread() is threading.main_thread():
                await self._checkpoint()
            else:
                self._checkpoint_requested.set()
            logger.info(f"Share recorded: {share.host}/{share.name}")
        else:
            logger.debug(f"Share not published (duplicate/invalid): {share.host}/{share.name}")
        return added

    def signal_credential_access(self: RedTeamDispatcher) -> None:
        """Wake credential access loop when new credentials or hashes appear."""
        self._credential_access_event.set()

    async def wait_for_credential_access_signal(self: RedTeamDispatcher, timeout: float) -> None:
        """Wait for new credential activity or a timeout."""
        if self._credential_access_event.is_set():
            self._credential_access_event.clear()
            return
        try:
            await asyncio.wait_for(self._credential_access_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return
        finally:
            self._credential_access_event.clear()

    async def publish_host(self: RedTeamDispatcher, host: Host, source_agent: str) -> bool:
        """
        Broadcast new host to all agents.

        Args:
            host: The discovered host.
            source_agent: Agent that discovered it.

        Returns:
            True if host was new and added.
        """
        added = self.shared_state.add_host(host)

        if added:
            if threading.current_thread() is threading.main_thread():
                await self._checkpoint()
            else:
                self._checkpoint_requested.set()
            logger.info(f"Host published: {host.ip} ({host.hostname})")

            # Auto-detect MSSQL and queue vulnerability for exploitation
            await self._auto_detect_mssql(host, source_agent)
        else:
            logger.debug(f"Host not published (duplicate/merged): {host.ip} ({host.hostname})")

        return added

    async def _auto_detect_mssql(self: RedTeamDispatcher, host: Host, source_agent: str) -> None:
        """
        Auto-detect MSSQL service on host and queue vulnerability for exploitation.

        Checks for MSSQL indicators in services list and automatically queues
        an mssql_linked_server vulnerability for the privesc agent to exploit.
        """
        services_lower = [s.lower() for s in host.services]

        # Check for MSSQL indicators
        has_mssql = any(
            indicator in svc
            for svc in services_lower
            for indicator in ("mssql", "1433", "ms-sql", "sqlserver")
        )

        if not has_mssql:
            return

        # Check if we already have an MSSQL vuln queued for this host
        existing_vulns = self.shared_state.discovered_vulnerabilities.values()
        for vuln in existing_vulns:
            if vuln.target == host.ip and vuln.vuln_type.startswith("mssql_"):
                logger.debug(f"MSSQL vulnerability already queued for {host.ip}")
                return

        # Find any SQL-related credentials we have
        sql_creds = self._find_sql_credentials()

        # Only queue MSSQL vulnerability if we have valid credentials
        if not sql_creds:
            logger.info(
                f"Skipping MSSQL vulnerability for {host.ip} ({host.hostname}) - "
                "no valid SQL credentials available yet"
            )
            return

        # Queue MSSQL vulnerability for exploitation
        details: dict[str, Any] = {
            "hostname": host.hostname,
            "services": host.services,
            "available_credentials": sql_creds,
            "note": f"Auto-detected MSSQL service with {len(sql_creds)} potential SQL credential(s). "
            "Check for linked servers and impersonation.",
        }

        await self.queue_vulnerability(
            vuln_type="mssql_linked_server",
            target=host.ip,
            details=details,
            discovered_by=source_agent,
        )
        logger.info(
            f"Auto-queued MSSQL vulnerability for {host.ip} ({host.hostname}) - "
            f"found {len(sql_creds)} potential SQL creds"
        )

        # Proactively dispatch MSSQL impersonation enumeration for each credential
        # This discovers sa/sysadmin impersonation rights early, triggering priority boost
        await self._dispatch_mssql_enum(host, sql_creds, source_agent)

    async def _dispatch_mssql_enum(
        self: RedTeamDispatcher,
        host: Host,
        sql_creds: list[dict[str, str]],
        source_agent: str,
    ) -> None:
        """Proactively dispatch MSSQL impersonation enumeration for discovered MSSQL host."""
        if not self._task_queue:
            return

        # Skip dispatch when in non-main thread (threaded consumer) - main loop handles it
        if threading.current_thread() is not threading.main_thread():
            return

        # Track which creds we've already dispatched enum for this host
        enum_key = f"mssql_enum:{host.ip}"
        if not hasattr(self, "_mssql_enum_dispatched"):
            self._mssql_enum_dispatched: set[str] = set()

        # Dispatch enumeration for up to 2 credentials (avoid flooding)
        dispatched = 0
        for cred in sql_creds[:2]:
            cred_key = f"{enum_key}:{cred.get('domain', '')}\\{cred.get('username', '')}"
            if cred_key in self._mssql_enum_dispatched:
                continue

            self._mssql_enum_dispatched.add(cred_key)

            payload = {
                "target": host.ip,
                "hostname": host.hostname,
                "username": cred.get("username", ""),
                "password": cred.get("password", ""),
                "domain": cred.get("domain", ""),
                "action": "mssql_enum_impersonation",
                "note": "Proactive MSSQL impersonation enumeration - check for sa/sysadmin access",
            }

            task_id = await self._throttled_submit_task(
                task_type="lateral",  # Uses LateralMovementTools which has mssql_enum_impersonation
                target_role="lateral",
                payload=payload,
                source_agent=source_agent,
                priority=5,  # Medium-high priority
            )

            if task_id:
                task_info = TaskInfo(
                    task_id=task_id,
                    task_type="mssql_enum",
                    assigned_agent="lateral",
                    params=payload,
                )
                self.shared_state.pending_tasks[task_id] = task_info
                self._redis_task_ids.add(task_id)
                dispatched += 1
                logger.info(
                    f"🔍 Dispatched proactive MSSQL enum for {host.ip} "
                    f"with {cred.get('domain', '')}\\{cred.get('username', '')}"
                )

        if dispatched > 0:
            logger.warning(
                f"📊 Auto-dispatched {dispatched} MSSQL enumeration task(s) for {host.ip}"
            )

    def _find_sql_credentials(self: RedTeamDispatcher) -> list[dict[str, str]]:
        """
        Find credentials that might work for MSSQL authentication.

        Returns credentials for:
        - Users with 'sql' in username (e.g., sql_svc)
        - Domain users (can auth to SQL via Windows auth)

        Note: Only returns credentials WITH passwords - MSSQL Windows auth
        requires a password, not just a hash.
        """
        sql_creds: list[dict[str, str]] = []
        seen: set[str] = set()

        for cred in self.shared_state.all_credentials:
            # Skip credentials without passwords - MSSQL needs actual passwords
            if not cred.password:
                continue

            key = f"{cred.domain}\\{cred.username}"
            if key in seen:
                continue
            seen.add(key)

            # Prioritize SQL service accounts
            is_sql_account = "sql" in cred.username.lower()

            sql_creds.append(
                {
                    "username": cred.username,
                    "password": cred.password,
                    "domain": cred.domain,
                    "is_sql_account": str(is_sql_account),
                }
            )

        # Sort to prioritize SQL accounts
        sql_creds.sort(key=lambda x: x.get("is_sql_account", "False") != "True")
        return sql_creds[:5]  # Return top 5 candidates

    def _ensure_credential_in_state(
        self: RedTeamDispatcher,
        username: str,
        domain: str,
        password: str | None = None,
        hash_value: str | None = None,
        source: str = "task_dispatch",
    ) -> bool:
        """
        Ensure a credential is saved to shared state when dispatching tasks.

        This prevents credentials from being "lost" when they're only in task payloads
        but not in the shared state that other agents can see.

        Args:
            username: Username for the credential.
            domain: Domain for the credential.
            password: Optional password.
            hash_value: Optional NTLM hash.
            source: Source identifier for the credential.

        Returns:
            True if credential was added, False if it already existed or was invalid.
        """
        if not username:
            return False
        # Only create Credential if we have a password (Credential requires password field)
        # Hash-only credentials are tracked separately in all_hashes
        if not password:
            return False

        # Create credential object
        credential = Credential(
            username=username,
            domain=domain or "",
            password=password,
            source=source,
        )

        # add_credential handles deduplication
        added = self.shared_state.add_credential(credential, source)
        if added:
            logger.info(
                f"Auto-saved credential to shared state: {domain}\\{username} (source={source})"
            )
        return added

    async def scan_hosts_for_mssql(self: RedTeamDispatcher) -> int:
        """
        Scan all known hosts for MSSQL services and queue vulnerabilities.

        This method should be called periodically by the orchestrator to catch
        MSSQL hosts discovered by worker agents that didn't go through publish_host.

        Returns:
            Number of new MSSQL vulnerabilities queued.
        """
        queued = 0
        for host in self.shared_state.all_hosts:
            services_lower = [s.lower() for s in host.services]

            # Check for MSSQL indicators
            has_mssql = any(
                indicator in svc
                for svc in services_lower
                for indicator in ("mssql", "1433", "ms-sql", "sqlserver")
            )

            if not has_mssql:
                continue

            # Check if we already have an MSSQL vuln queued for this host
            already_queued = any(
                vuln.target == host.ip and vuln.vuln_type.startswith("mssql_")
                for vuln in self.shared_state.discovered_vulnerabilities.values()
            )

            if already_queued:
                continue

            # Find SQL credentials
            sql_creds = self._find_sql_credentials()

            # Only queue if we have valid credentials
            if not sql_creds:
                logger.debug(
                    f"Periodic scan: skipping MSSQL vulnerability for {host.ip} ({host.hostname}) - "
                    "no valid SQL credentials available"
                )
                continue

            # Queue MSSQL vulnerabilities (both linked server and impersonation)
            details: dict[str, Any] = {
                "hostname": host.hostname,
                "services": host.services,
                "available_credentials": sql_creds,
                "note": f"Auto-detected MSSQL service with {len(sql_creds)} potential SQL credential(s). "
                "Check for linked servers and impersonation.",
            }

            # Queue mssql_linked_server vulnerability
            await self.queue_vulnerability(
                vuln_type="mssql_linked_server",
                target=host.ip,
                details=details,
                discovered_by="mssql_scanner",
            )

            # Also queue mssql_impersonation vulnerability
            # This checks for sa/dbo impersonation rights which can lead to privilege escalation
            impersonation_details: dict[str, Any] = {
                "hostname": host.hostname,
                "services": host.services,
                "available_credentials": sql_creds,
                "note": f"Auto-detected MSSQL service with {len(sql_creds)} potential SQL credential(s). "
                "Check for impersonation rights (EXECUTE AS) to sa, dbo, or other privileged logins.",
            }
            await self.queue_vulnerability(
                vuln_type="mssql_impersonation",
                target=host.ip,
                details=impersonation_details,
                discovered_by="mssql_scanner",
            )

            queued += 2  # Queued both linked_server and impersonation
            logger.info(
                f"Periodic scan: queued MSSQL vulnerabilities (linked_server + impersonation) for "
                f"{host.ip} ({host.hostname}) with {len(sql_creds)} SQL credentials"
            )

        return queued

    def find_adcs_servers(self: RedTeamDispatcher) -> list[tuple[str, str]]:
        """
        Find ADCS servers from discovered shares (CertEnroll indicator).

        Returns:
            List of (ip, hostname) tuples for hosts with CertEnroll shares.
        """
        adcs_servers: list[tuple[str, str]] = []
        seen_hosts: set[str] = set()

        for share in self.shared_state.all_shares:
            if share.name and share.name.lower() == "certenroll":
                host_ip = share.host
                if host_ip and host_ip not in seen_hosts:
                    # Find hostname from all_hosts
                    hostname = ""
                    for h in self.shared_state.all_hosts:
                        if h.ip == host_ip:
                            hostname = h.hostname or ""
                            break
                    adcs_servers.append((host_ip, hostname))
                    seen_hosts.add(host_ip)

        return adcs_servers

    async def request_adcs_enumeration(
        self: RedTeamDispatcher,
        source_agent: str,
        target_ip: str,
        domain: str,
        username: str,
        password: str,
    ) -> str:
        """
        Request ADCS enumeration (certipy_find) on a target CA server.

        This dispatches a task to the PRIVESC agent to run certipy_find
        and discover ADCS vulnerabilities (ESC1-ESC15).

        Args:
            source_agent: Agent making the request.
            target_ip: IP of the ADCS server (CA).
            domain: Target domain.
            username: Username for authentication.
            password: Password for authentication.

        Returns:
            Task ID for tracking.
        """
        # Auto-save credential to shared state so other agents can use it
        self._ensure_credential_in_state(
            username=username,
            domain=domain,
            password=password,
            source="adcs_enumeration",
        )

        dc_ip = self._find_domain_controller_ip(domain)

        # Track attack chain
        parent_id, parent_step = self._find_credential_id(username, domain, password)

        payload = {
            "vuln_type": "adcs_enumerate",
            "vuln_id": f"adcs_enumerate_{target_ip}_{hash(f'{domain}{username}') % 10000:04d}",
            "target": target_ip,
            "domain": domain,
            "dc_ip": dc_ip or target_ip,
            "username": username,
            "password": password,
            "note": "Auto-detected ADCS server (CertEnroll share). Run certipy_find to enumerate ESC1-ESC15 vulnerabilities.",
            "parent_credential_id": parent_id,
            "parent_attack_step": parent_step,
        }

        # Use Redis task queue if available (Kubernetes multi-pod mode)
        if self._task_queue:
            task_id = await self._throttled_submit_task(
                task_type="exploit",
                target_role="privesc",
                payload=payload,
                source_agent=source_agent,
                priority=1,  # Exploit tasks get highest priority
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

            logger.info(f"ADCS enumeration task {task_id} submitted to Redis queue for {target_ip}")
            return task_id

        # No Redis task queue - cannot dispatch
        logger.warning("No task queue available, cannot route ADCS enumeration")
        return ""

    async def publish_vulnerability(
        self: RedTeamDispatcher,
        vuln: VulnerabilityInfo,
        source_agent: str,
    ) -> bool:
        """
        Record new vulnerability in shared state.

        Args:
            vuln: The discovered vulnerability.
            source_agent: Agent that discovered it.

        Returns:
            True if vulnerability was new and added.
        """
        added = self.shared_state.add_vulnerability(vuln)

        if added:
            if threading.current_thread() is threading.main_thread():
                await self._checkpoint()
            else:
                self._checkpoint_requested.set()
            logger.info(f"Vulnerability published: {vuln.vuln_type} on {vuln.target}")

        return added

    async def _exploit_delegation_with_credential(
        self: RedTeamDispatcher,
        credential: Credential,
        source_agent: str,
        task_queue: Any = None,
    ) -> None:
        """Check for pending delegation vulnerabilities matching this credential and exploit.

        When a credential is cracked, check if we have a pending constrained/unconstrained
        delegation vulnerability for this account and dispatch the actual exploit.

        Args:
            credential: The credential to check for delegation vulnerabilities.
            source_agent: Agent that discovered the credential.
            task_queue: Optional task queue for direct dispatch (threaded consumer passes its own).
        """
        cred_user = credential.username.lower().rstrip("$")

        for vuln_id, vuln in list(self.shared_state.discovered_vulnerabilities.items()):
            if vuln.vuln_type not in ("constrained_delegation", "unconstrained_delegation"):
                continue

            # Check if this vulnerability is for the same account
            vuln_account = vuln.details.get("account_name", vuln.target).lower().rstrip("$")
            if vuln_account != cred_user:
                continue

            # Check if already exploited (vuln_id tracked in exploited_vulnerabilities set)
            if vuln_id in self.shared_state.exploited_vulnerabilities:
                continue

            # We have credentials for a delegation vulnerability - exploit it!
            target_spn = vuln.details.get("target_spn", "")
            domain = vuln.details.get("domain", credential.domain)
            dc_ip = vuln.details.get("dc_ip", "")

            if vuln.vuln_type == "constrained_delegation" and target_spn:
                logger.warning(
                    f"🚀 Auto-exploiting constrained delegation: {credential.username} -> {target_spn} "
                    f"(vuln_id: {vuln_id})"
                )
                try:
                    await asyncio.wait_for(
                        self.request_exploit(
                            vuln_type="constrained_delegation",
                            vuln_id=vuln_id,
                            target=credential.username,
                            source_agent="auto_delegation",
                            params={
                                "account": credential.username,
                                "account_name": credential.username,
                                "password": credential.password,
                                "domain": domain,
                                "target_spn": target_spn,
                                "dc_ip": dc_ip,
                                "impersonate": "Administrator",
                                "action": "s4u_attack",
                            },
                            task_queue=task_queue,
                        ),
                        timeout=30.0,
                    )
                except asyncio.TimeoutError:
                    logger.error(
                        f"Timeout auto-exploiting constrained delegation: {credential.username} -> {target_spn}"
                    )
                except Exception as e:
                    logger.error(f"Failed to auto-exploit constrained delegation: {e}")


__all__ = ["PublishingMixin"]
