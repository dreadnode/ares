"""Discovery publishing for credentials, hosts, shares, and vulnerabilities.

This module provides methods to publish discoveries to all agents and update
shared state. Includes MSSQL auto-detection and ADCS enumeration support.

NOTE: When called from the threaded result consumer (non-main thread), dispatch
operations are skipped because the task queue is bound to the main event loop.
The main orchestrator loop handles dispatches through normal processing.

IMPORTANT: Credentials and hashes are persisted directly to Redis when called
from the threaded consumer (using task_queue.redis) to avoid waiting for the
main-thread checkpoint which may be blocked by LLM API calls.
"""

from __future__ import annotations

import asyncio
import hashlib
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
from ares.core.tracing import trace_discovery

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher


class PublishingMixin:
    """Discovery publishing for credentials, hosts, shares, and vulnerabilities."""

    async def publish_credential(
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
            # Signal credential access - use thread-safe event from non-main thread
            if threading.current_thread() is threading.main_thread():
                self.signal_credential_access()
            else:
                # Thread-safe signal - maintenance loop will transfer to asyncio.Event
                self._credential_access_requested.set()
            # Add timeline event for credential discovery
            import uuid
            from datetime import datetime, timezone

            # Determine MITRE techniques based on credential source
            mitre_techniques = ["T1078"] if is_admin else ["T1552"]
            cred_source_lower = (credential.source or "").lower()
            if "kerberoast" in cred_source_lower:
                mitre_techniques.append("T1558.003")  # Kerberoasting
            if "asrep" in cred_source_lower or "as-rep" in cred_source_lower:
                mitre_techniques.append("T1558.004")  # AS-REP Roasting
            if "cracked" in cred_source_lower:
                mitre_techniques.append("T1110")  # Brute Force (password cracking)
            timeline_event = TimelineEvent(
                id=f"evt-cred-{uuid.uuid4().hex[:8]}",
                timestamp=datetime.now(timezone.utc),
                source=source_agent,
                description=f"Credential discovered: {credential.domain}\\{credential.username} via {credential.source}",
                mitre_techniques=mitre_techniques,
            )
            self.shared_state.operation_timeline.append(timeline_event)
            # Add techniques to identified_techniques set for MITRE mapping in report
            self.shared_state.identified_techniques.update(mitre_techniques)
            # Persist timeline event to Redis
            await self._persist_timeline_event(timeline_event, task_queue)
            is_main_thread = threading.current_thread() is threading.main_thread()
            if is_main_thread:
                await self._checkpoint()
            # CRITICAL: Persist directly to Redis using the threaded consumer's client.
            # The main-thread checkpoint may be blocked by LLM API calls for minutes,
            # causing credentials to be stuck in memory and not visible to CLI.
            elif task_queue is not None:
                try:
                    from ares.core.state_backend import RedisStateBackend

                    backend = RedisStateBackend(task_queue.redis, self.shared_state.operation_id)
                    await backend.add_credential(credential)
                    logger.info(
                        f"✅ Credential persisted directly to Redis: "
                        f"{credential.domain}\\{credential.username}"
                    )
                except Exception as e:
                    # Fallback to checkpoint on failure
                    logger.warning(f"Direct Redis persist failed, falling back to checkpoint: {e}")
                    self._checkpoint_requested.set()
            else:
                # No task_queue available, fall back to checkpoint request
                self._checkpoint_requested.set()
                logger.info(
                    f"⚡ Checkpoint requested for credential: "
                    f"{credential.domain}\\{credential.username}"
                )
            logger.info(f"Credential published: {credential.domain}\\{credential.username}")

            # Trace the credential discovery
            trace_discovery(
                discovery_type="credential",
                source_agent=source_agent,
                operation_id=self.shared_state.operation_id,
                target_user=credential.username,
                target_domain=credential.domain,
            )

            # Check if this credential has golden ticket capability
            # (e.g., is local admin on a DC we already know about)
            if credential.domain:
                self.shared_state.update_golden_ticket_capability(
                    credential.username, credential.domain, source_agent
                )

            # Immediate actions for ANY credential with password
            # This includes cracked hashes AND credentials from username_as_password, etc.
            if credential.password and credential.domain:
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
                            f"🚀 Immediate delegation check for credential: "
                            f"{credential.domain}\\{credential.username}"
                        )
                        try:
                            # Skip asyncio.wait_for when in threaded consumer to avoid
                            # "Future attached to different loop" errors. The threaded
                            # consumer has its own event loop and the timeout wrapper
                            # can cause cross-loop Future issues.
                            is_threaded = threading.current_thread() is not threading.main_thread()
                            if is_threaded:
                                task_id = await self.request_privesc_enumeration(
                                    source_agent="orchestrator",
                                    domain=credential.domain,
                                    username=credential.username,
                                    password=credential.password,
                                    techniques=["find_delegation"],
                                    task_queue=effective_task_queue,
                                )
                            else:
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
                                # Mark as processed to prevent _auto_credential_access from
                                # dispatching the same delegation check again (duplicate)
                                self.shared_state.processed_delegation_creds.add(cred_key)
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
                            if is_threaded:
                                await self._exploit_delegation_with_credential(
                                    credential, source_agent, effective_task_queue
                                )
                            else:
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
                        # NOTE: Secretsdump handled by _auto_credential_access (~15s interval, signaled on new creds)
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
        task_queue: Any = None,
    ) -> bool:
        """
        Broadcast new hash to all agents.

        Args:
            hash_obj: The discovered hash.
            source_agent: Agent that discovered it.
            priority: Priority for cracking (1=krbtgt, 2=admin, 5=normal).
            task_queue: Optional task queue for threaded dispatch.

        Returns:
            True if hash was new and added.
        """
        added = self.shared_state.add_hash(hash_obj, source_agent)

        if added:
            # Signal credential access - use thread-safe event from non-main thread
            is_main_thread = threading.current_thread() is threading.main_thread()
            if is_main_thread:
                self.signal_credential_access()
            else:
                # Thread-safe signal - maintenance loop will transfer to asyncio.Event
                self._credential_access_requested.set()
            # Add timeline event for hash discovery
            import uuid
            from datetime import datetime, timezone

            is_critical = hash_obj.username.lower() in ("krbtgt", "administrator")
            event_desc = (
                f"Hash discovered: {hash_obj.domain}\\{hash_obj.username} ({hash_obj.hash_type})"
            )
            if is_critical:
                event_desc = f"CRITICAL: {event_desc}"

            # Determine MITRE techniques based on hash type and source
            mitre_techniques = ["T1003"]  # OS Credential Dumping
            hash_value_lower = (hash_obj.hash_value or "").lower()
            hash_type_lower = (hash_obj.hash_type or "").lower()
            hash_source_lower = (hash_obj.source or "").lower()

            # Kerberoasting: TGS-REP hashes
            if (
                "$krb5tgs$" in hash_value_lower
                or hash_type_lower in ("kerberoast", "krb5tgs", "tgs-rep", "tgs")
                or "kerberoast" in hash_source_lower
            ):
                mitre_techniques.append("T1558.003")  # Kerberoasting

            # AS-REP Roasting: AS-REP hashes
            if (
                "$krb5asrep$" in hash_value_lower
                or hash_type_lower in ("asrep", "as-rep", "krb5asrep")
                or "asrep" in hash_source_lower
                or "as-rep" in hash_source_lower
            ):
                mitre_techniques.append("T1558.004")  # AS-REP Roasting

            # DCSync or secretsdump for NTLM hashes
            if hash_type_lower == "ntlm" and (
                "secretsdump" in hash_source_lower or "dcsync" in hash_source_lower
            ):
                mitre_techniques.append("T1003.006")  # DCSync

            timeline_event = TimelineEvent(
                id=f"evt-hash-{uuid.uuid4().hex[:8]}",
                timestamp=datetime.now(timezone.utc),
                source=source_agent,
                description=event_desc,
                mitre_techniques=mitre_techniques,
            )
            self.shared_state.operation_timeline.append(timeline_event)
            # Add techniques to identified_techniques set for MITRE mapping in report
            self.shared_state.identified_techniques.update(mitre_techniques)
            # Persist timeline event to Redis
            await self._persist_timeline_event(timeline_event, task_queue)
            if is_main_thread:
                await self._checkpoint()
                # CRITICAL: Also dispatch trust key extraction on main thread for multi-forest mode
                # Triggered by EITHER krbtgt OR Administrator NTLM hash to ensure extraction runs
                # even if krbtgt was first published with Unknown type
                username_lower = hash_obj.username.lower()
                hash_type_lower = (hash_obj.hash_type or "").lower()
                is_ntlm = hash_type_lower == "ntlm"
                is_da_hash = username_lower in ("krbtgt", "administrator") and is_ntlm

                if is_da_hash and self.shared_state.has_domain_admin:
                    from ares.core.config import get_multi_forest_mode

                    if get_multi_forest_mode() and not self.shared_state.all_forests_dominated():
                        undominated = self.shared_state.get_undominated_forests()
                        if undominated:
                            await self._auto_dispatch_trust_key_extraction(
                                da_domain=hash_obj.domain or "",
                                da_username="Administrator",
                                undominated_forests=undominated,
                                source_agent=source_agent,
                            )
            # CRITICAL: Persist directly to Redis using the threaded consumer's client.
            # The main-thread checkpoint may be blocked by LLM API calls for minutes,
            # causing hashes to be stuck in memory and not visible to CLI.
            elif task_queue is not None:
                try:
                    from ares.core.state_backend import RedisStateBackend

                    backend = RedisStateBackend(task_queue.redis, self.shared_state.operation_id)
                    await backend.add_hash(hash_obj)
                    # CRITICAL: Also persist DA status if krbtgt hash was found
                    # add_hash() sets has_domain_admin=True in memory but skips Redis
                    # persist due to event loop check. We MUST persist DA to Redis here
                    # so the orchestrator can see it and exit promptly.
                    username_lower = hash_obj.username.lower()
                    hash_type_lower = (hash_obj.hash_type or "").lower()
                    is_ntlm = hash_type_lower == "ntlm"
                    is_da_hash = username_lower in ("krbtgt", "administrator") and is_ntlm

                    logger.debug(
                        f"publish_hash DA check: user={username_lower}, type={hash_type_lower}, "
                        f"is_da_hash={is_da_hash}, has_domain_admin={self.shared_state.has_domain_admin}"
                    )

                    if is_da_hash and self.shared_state.has_domain_admin:
                        # Persist DA to Redis if krbtgt found
                        if username_lower == "krbtgt":
                            da_domain = hash_obj.domain.lower() if hash_obj.domain else None
                            await backend.set_domain_admin(
                                achieved=True,
                                path=self.shared_state.domain_admin_path,
                                da_hash_id=self.shared_state.da_hash_id,
                                domain=da_domain,
                            )
                            logger.success(
                                f"✅ Domain Admin status persisted directly to Redis (krbtgt found for {da_domain})"
                            )
                        # Auto-dispatch trust key extraction for multi-forest mode
                        # Triggered by EITHER krbtgt OR Administrator NTLM hash
                        # This ensures extraction runs even if krbtgt was first with Unknown type
                        await self._auto_dispatch_trust_key_extraction_threaded(
                            da_domain=hash_obj.domain or "",
                            task_queue=task_queue,
                            source_agent=source_agent,
                        )
                    logger.debug(
                        f"✅ Hash persisted directly to Redis: "
                        f"{hash_obj.domain}\\{hash_obj.username}"
                    )
                except Exception as e:
                    # Fallback to checkpoint on failure
                    logger.warning(
                        f"Direct Redis persist failed for hash, falling back to checkpoint: {e}"
                    )
                    self._checkpoint_requested.set()
            else:
                # No task_queue available, fall back to checkpoint request
                self._checkpoint_requested.set()
            logger.info(
                f"Hash published: {hash_obj.domain}\\{hash_obj.username} ({hash_obj.hash_type}) "
                f"[source: {hash_obj.source or 'unknown'}]"
            )

            # Trace the hash discovery
            trace_discovery(
                discovery_type="hash",
                source_agent=source_agent,
                operation_id=self.shared_state.operation_id,
                target_user=hash_obj.username,
                target_domain=hash_obj.domain,
                additional_attrs={
                    "hash.type": hash_obj.hash_type or "unknown",
                    "hash.cracked": bool(hash_obj.cracked_password),
                },
            )

            # If hash has cracked password, create credential via publish_credential()
            # This triggers immediate dispatch (delegation checks, secretsdump, etc.)
            # IMPORTANT: This is the ONLY place credentials are created for cracked hashes.
            # add_hash() no longer creates credentials to avoid duplicate detection issues.
            if hash_obj.cracked_password:
                cracked_cred = Credential(
                    username=hash_obj.username,
                    password=hash_obj.cracked_password,
                    domain=hash_obj.domain,
                    source=f"cracked:{hash_obj.hash_type or 'unknown'}",
                    parent_id=hash_obj.id,
                    attack_step=(hash_obj.attack_step or 0) + 1,
                )
                logger.info(
                    f"🔓 Hash cracked, publishing credential: {hash_obj.domain}\\{hash_obj.username}"
                )
                await self.publish_credential(cracked_cred, source_agent, task_queue=task_queue)

            # IMMEDIATE: Dispatch crack task for crackable hashes
            # This saves ~30s vs waiting for _auto_crack_dispatch loop
            if not hash_obj.cracked_password:
                await self._immediate_crack_dispatch(
                    hash_obj, source_agent, task_queue, is_main_thread
                )
        else:
            logger.debug(
                f"Hash not published (duplicate): {hash_obj.domain}\\{hash_obj.username} ({hash_obj.hash_type})"
            )

        return added

    async def _immediate_crack_dispatch(
        self: RedTeamDispatcher,
        hash_obj: Hash,
        source_agent: str,
        task_queue: Any,
        is_main_thread: bool,
    ) -> None:
        """Dispatch crack task immediately when a new hash is published."""
        # Build crack key for deduplication (same as _auto_crack_dispatch)
        crack_key = (
            f"{(hash_obj.domain or '').lower()}:"
            f"{hash_obj.username.lower()}:"
            f"{hash_obj.hash_value[:32]}:"
            f"{(hash_obj.hash_type or '').upper()}"
        )

        if crack_key in self.shared_state.processed_crack_requests:
            return  # Already dispatched

        # Determine priority based on hash type
        hash_value_lower = hash_obj.hash_value.lower()
        hash_type_upper = (hash_obj.hash_type or "").upper()

        if "$krb5tgs$" in hash_value_lower or "KERBEROAST" in hash_type_upper:
            crack_priority = 2  # High priority - service accounts
        elif "$krb5asrep$" in hash_value_lower or "ASREP" in hash_type_upper:
            crack_priority = 3  # Medium-high priority
        else:
            crack_priority = 5  # Normal priority

        effective_task_queue = task_queue if task_queue is not None else self._task_queue
        if not effective_task_queue:
            logger.debug(
                f"No task queue available for immediate crack dispatch: "
                f"{hash_obj.domain}\\{hash_obj.username}"
            )
            return

        try:
            if is_main_thread:
                crack_task_id = await asyncio.wait_for(
                    self.request_crack(
                        hash_value=hash_obj.hash_value,
                        hash_type=hash_obj.hash_type or "unknown",
                        source_agent="orchestrator",
                        username=hash_obj.username,
                        domain=hash_obj.domain or "",
                        priority=crack_priority,
                        task_queue=effective_task_queue,
                    ),
                    timeout=30.0,
                )
            else:
                crack_task_id = await self.request_crack(
                    hash_value=hash_obj.hash_value,
                    hash_type=hash_obj.hash_type or "unknown",
                    source_agent="orchestrator",
                    username=hash_obj.username,
                    domain=hash_obj.domain or "",
                    priority=crack_priority,
                    task_queue=effective_task_queue,
                )

            # Mark as processed to prevent duplicate dispatch from _auto_crack_dispatch
            self.shared_state.processed_crack_requests.add(crack_key)

            if crack_task_id:
                logger.info(
                    f"🔨 Immediate crack dispatched for "
                    f"{hash_obj.domain}\\{hash_obj.username} ({hash_obj.hash_type}): {crack_task_id}"
                )
        except asyncio.TimeoutError:
            logger.warning(
                f"Timeout dispatching immediate crack for {hash_obj.domain}\\{hash_obj.username}"
            )
        except Exception as e:
            logger.warning(f"Failed to dispatch immediate crack: {e}")

    async def publish_share(
        self: RedTeamDispatcher,
        share: Share,
        source_agent: str,
        task_queue: Any = None,
    ) -> bool:
        """
        Record share discovery in shared state.

        Args:
            share: The discovered share.
            source_agent: Agent that discovered it.
            task_queue: Task queue for direct Redis persistence from threaded consumers.

        Returns:
            True if share was new and added.
        """
        added = self.shared_state.add_share(share)
        if added:
            is_main_thread = threading.current_thread() is threading.main_thread()
            if is_main_thread:
                await self._checkpoint()
            elif task_queue is not None:
                # Persist directly to Redis using the threaded consumer's client
                try:
                    from ares.core.state_backend import RedisStateBackend

                    backend = RedisStateBackend(task_queue.redis, self.shared_state.operation_id)
                    await backend.add_share(share)
                    logger.debug(f"Share persisted directly to Redis: {share.host}/{share.name}")
                except Exception as e:
                    logger.warning(f"Direct Redis persist failed for share: {e}")
                    self._checkpoint_requested.set()
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
            True if host was new or had meaningful data merged (services, roles, etc).
        """
        updated = self.shared_state.add_host(host)

        if updated:
            if threading.current_thread() is threading.main_thread():
                await self._checkpoint()
            else:
                self._checkpoint_requested.set()
            logger.info(f"Host updated: {host.ip} ({host.hostname})")

            # Auto-detect MSSQL and queue vulnerability for exploitation
            await self._auto_detect_mssql(host, source_agent)

            # If this is a DC, re-check all credentials for golden ticket capability
            # A credential with local_admin on this DC can now dump NTDS.dit
            if host.is_dc:
                await self._recheck_golden_ticket_on_dc_discovery(host, source_agent)
        else:
            logger.debug(f"Host unchanged (exact duplicate): {host.ip} ({host.hostname})")

        return updated

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
        # Snapshot to avoid "dict changed size during iteration" from threaded consumer
        existing_vulns = list(self.shared_state.discovered_vulnerabilities.values())
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
        # Use Redis-backed tracking if available, fallback to in-memory
        enum_key = f"mssql_enum:{host.ip}"
        if not hasattr(self, "_mssql_enum_dispatched"):
            self._mssql_enum_dispatched: set[str] = set()

        # Dispatch enumeration for up to 2 credentials (avoid flooding)
        dispatched = 0
        for cred in sql_creds[:2]:
            cred_key = f"{enum_key}:{cred.get('domain', '')}\\{cred.get('username', '')}"

            # Check Redis first if backend available, else check in-memory
            backend = getattr(self.shared_state, "_backend", None)
            if backend:
                try:
                    if await backend.is_mssql_enum_dispatched(cred_key):
                        continue
                except Exception:
                    pass  # Fall through to in-memory check

            if cred_key in self._mssql_enum_dispatched:
                continue

            # Mark as dispatched in both in-memory and Redis
            self._mssql_enum_dispatched.add(cred_key)
            if backend:
                try:
                    await backend.add_mssql_enum_dispatched(cred_key)
                except Exception as e:
                    logger.debug(f"Failed to persist MSSQL enum dispatch to Redis: {e}")

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

            # Skip if task was queued for main loop or deferred - don't create TaskInfo here
            if task_id and task_id not in ("deferred", "queued"):
                task_info = TaskInfo(
                    task_id=task_id,
                    task_type="mssql_enum",
                    assigned_agent="lateral",
                    params=payload,
                )
                # Write to Redis FIRST (source of truth), then cache in memory
                await self._persist_task_info_to_redis(task_id, task_info)
                self.shared_state.pending_tasks[task_id] = task_info
                dispatched += 1
                logger.info(
                    f"Dispatched proactive MSSQL enum for {host.ip} "
                    f"with {cred.get('domain', '')}\\{cred.get('username', '')}"
                )
            elif task_id in ("deferred", "queued"):
                dispatched += 1
                logger.info(f"MSSQL enum for {host.ip} {task_id} to background/main loop queue")

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

    async def _recheck_golden_ticket_on_dc_discovery(
        self: RedTeamDispatcher,
        host: Host,
        source_agent: str,
    ) -> None:
        """Re-check all credentials for golden ticket capability when a DC is discovered.

        When a new DC is identified, any existing credential with local_admin on that
        DC now has golden ticket capability (can dump NTDS.dit to get krbtgt hash).

        Args:
            host: The newly discovered DC host.
            source_agent: Agent that discovered the DC.
        """
        # Only process if this is a DC
        if not host.is_dc:
            return

        found_capable = False

        # Check all credentials to see if they have admin access on this DC
        for cred in self.shared_state.all_credentials:
            if cred.domain and self.shared_state.update_golden_ticket_capability(
                cred.username, cred.domain, source_agent
            ):
                found_capable = True

        # Also check cracked hashes that have passwords
        for hash_obj in self.shared_state.all_hashes:
            if (
                hash_obj.cracked_password
                and hash_obj.domain
                and self.shared_state.update_golden_ticket_capability(
                    hash_obj.username, hash_obj.domain, source_agent
                )
            ):
                found_capable = True

        # Checkpoint if we found new capabilities
        if found_capable:
            if threading.current_thread() is threading.main_thread():
                await self._checkpoint()
            else:
                self._checkpoint_requested.set()

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
            # Snapshot to avoid "dict changed size during iteration" from threaded consumer
            already_queued = any(
                vuln.target == host.ip and vuln.vuln_type.startswith("mssql_")
                for vuln in list(self.shared_state.discovered_vulnerabilities.values())
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
            "vuln_id": f"adcs_enumerate_{target_ip}_{hashlib.md5(f'{domain}{username}'.encode(), usedforsecurity=False).hexdigest()[:4]}",
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

            # Task queued for main loop dispatch or deferred - don't create TaskInfo here
            if task_id in ("deferred", "queued"):
                logger.info(
                    f"ADCS enumeration task {task_id} to background/main loop queue for {target_ip}"
                )
                return task_id

            task_info = TaskInfo(
                task_id=task_id,
                task_type="exploit",
                assigned_agent="privesc",
                params=payload,
            )
            # Write to Redis FIRST (source of truth), then cache in memory
            await self._persist_task_info_to_redis(task_id, task_info)
            self.shared_state.pending_tasks[task_id] = task_info

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

            # Check for golden ticket capability when local_admin vuln is discovered
            if vuln.vuln_type == "local_admin":
                await self._check_golden_ticket_on_local_admin(vuln, source_agent)

        return added

    async def _check_golden_ticket_on_local_admin(
        self: RedTeamDispatcher,
        vuln: VulnerabilityInfo,
        source_agent: str,
    ) -> None:
        """Check if a local_admin vulnerability enables golden ticket capability.

        When a user has local admin on a DC, they can dump NTDS.dit to get krbtgt hash.

        Args:
            vuln: The local_admin vulnerability.
            source_agent: Agent that discovered it.
        """
        # Extract principal info from the vulnerability
        details = vuln.details if isinstance(vuln.details, dict) else {}
        username = details.get("username", "")
        domain = details.get("domain", "")

        if not username:
            return

        # Check if this grants golden ticket capability
        if self.shared_state.update_golden_ticket_capability(username, domain, source_agent):
            # Checkpoint to persist the updated capability tracking
            if threading.current_thread() is threading.main_thread():
                await self._checkpoint()
            else:
                self._checkpoint_requested.set()

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

            # Defensive: ensure vuln.details is a dict before calling .get()
            vuln_details = vuln.details if isinstance(vuln.details, dict) else {}

            # Check if this vulnerability is for the same account
            vuln_account = vuln_details.get("account_name", vuln.target).lower().rstrip("$")
            if vuln_account != cred_user:
                continue

            # Check if already exploited (vuln_id tracked in exploited_vulnerabilities set)
            if vuln_id in self.shared_state.exploited_vulnerabilities:
                continue

            # We have credentials for a delegation vulnerability - exploit it!
            target_spn = vuln_details.get("target_spn", "")
            domain = vuln_details.get("domain", credential.domain)
            dc_ip = vuln_details.get("dc_ip", "")

            if vuln.vuln_type == "constrained_delegation" and target_spn:
                logger.warning(
                    f"🚀 Auto-exploiting constrained delegation: {credential.username} -> {target_spn} "
                    f"(vuln_id: {vuln_id})"
                )
                try:
                    # Skip asyncio.wait_for when in threaded consumer to avoid
                    # "Future attached to different loop" errors. The threaded
                    # consumer has its own event loop and the timeout wrapper
                    # can cause cross-loop Future issues.
                    is_threaded = threading.current_thread() is not threading.main_thread()
                    if is_threaded:
                        await self.request_exploit(
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
                        )
                    else:
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

    async def _persist_timeline_event(
        self: RedTeamDispatcher,
        event: TimelineEvent,
        task_queue: Any = None,
    ) -> None:
        """Persist a timeline event to Redis.

        Works from both main thread (using backend) and threaded consumer
        (using task_queue.redis).

        Args:
            event: The TimelineEvent to persist.
            task_queue: Optional task queue for threaded dispatch.
        """
        # Serialize TimelineEvent to dict (use to_dict() for consistent serialization)
        event_dict = event.to_dict()
        # Ensure timestamp is serialized as ISO string
        if hasattr(event.timestamp, "isoformat"):
            event_dict["timestamp"] = event.timestamp.isoformat()

        is_main_thread = threading.current_thread() is threading.main_thread()
        backend = getattr(self.shared_state, "_backend", None)

        if is_main_thread and backend:
            # Main thread: use the shared state backend
            try:
                await backend.add_timeline_event(event_dict)
            except Exception as e:
                logger.warning(f"Failed to persist timeline event via backend: {e}")
        elif task_queue is not None:
            # Threaded consumer: use task_queue.redis directly
            try:
                from ares.core.state_backend import RedisStateBackend

                threaded_backend = RedisStateBackend(
                    task_queue.redis, self.shared_state.operation_id
                )
                await threaded_backend.add_timeline_event(event_dict)
            except Exception as e:
                logger.warning(f"Failed to persist timeline event via task_queue: {e}")

    async def _load_mssql_enum_dispatched(self: RedTeamDispatcher) -> None:
        """Load MSSQL enum dispatch tracking from Redis backend.

        Called during dispatcher initialization to restore state after restart.
        """
        backend = getattr(self.shared_state, "_backend", None)
        if not backend:
            return

        try:
            dispatched = await backend.get_mssql_enum_dispatched()
            if not hasattr(self, "_mssql_enum_dispatched"):
                self._mssql_enum_dispatched = set()
            self._mssql_enum_dispatched.update(dispatched)
            if dispatched:
                logger.info(f"Loaded {len(dispatched)} MSSQL enum dispatch entries from Redis")
        except Exception as e:
            logger.warning(f"Failed to load MSSQL enum dispatch tracking: {e}")

    async def _auto_dispatch_trust_key_extraction_threaded(
        self: RedTeamDispatcher,
        da_domain: str,
        task_queue: Any,
        source_agent: str,
    ) -> None:
        """Auto-dispatch trust key extraction for multi-forest mode (from threaded consumer).

        When DA is achieved on a domain and other forests remain undominated,
        this dispatches trust key extraction tasks directly to Redis.

        This is called from the threaded result consumer when krbtgt hash is found.
        Since we're not on the main thread, we dispatch directly to Redis queue
        instead of using the dispatcher's _throttled_submit_task().

        Args:
            da_domain: Domain where we just achieved DA.
            task_queue: Task queue with Redis client for direct dispatch.
            source_agent: Agent that found the krbtgt hash.
        """
        from ares.core.config import get_multi_forest_mode

        logger.info(f"🌲 _auto_dispatch_trust_key_extraction_threaded called for {da_domain}")

        if not get_multi_forest_mode():
            logger.debug("🌲 Multi-forest mode disabled, skipping trust extraction")
            return

        if not task_queue:
            logger.warning("🌲 Cannot dispatch trust key extraction: no task_queue available")
            return

        # Deduplicate: only dispatch once per DA domain
        # This prevents multiple dispatches when both krbtgt and Administrator hashes trigger
        if not hasattr(self, "_trust_extraction_dispatched"):
            self._trust_extraction_dispatched: set[str] = set()

        da_domain_lower = da_domain.lower()
        if da_domain_lower in self._trust_extraction_dispatched:
            logger.debug(f"MULTI_FOREST_MODE: Trust extraction already dispatched for {da_domain}")
            return

        # Check undominated forests
        if self.shared_state.all_forests_dominated():
            logger.info("MULTI_FOREST_MODE: All forests dominated, no trust key extraction needed")
            return

        undominated = self.shared_state.get_undominated_forests()
        if not undominated:
            return

        # Mark as dispatched BEFORE actual dispatch (fail-safe)
        self._trust_extraction_dispatched.add(da_domain_lower)

        logger.info(f"MULTI_FOREST_MODE: {len(undominated)} forest(s) remaining: {undominated}")

        # Get DC IP for the domain where we have DA
        da_domain_lower = da_domain.lower()
        dc_ip = self.shared_state.domain_controllers.get(da_domain_lower)
        if not dc_ip:
            logger.warning(f"Cannot dispatch trust key extraction: no DC IP for {da_domain}")
            return

        # Find DA credential (Administrator NTLM hash preferred)
        da_hash = None
        da_password = None
        da_username = "Administrator"

        # Look for Administrator hash
        for h in self.shared_state.all_hashes:
            if (
                h.username.lower() == "administrator"
                and h.domain
                and h.domain.lower() == da_domain_lower
                and (h.hash_type or "").lower() == "ntlm"
            ):
                da_hash = h.hash_value
                break

        # Fallback to password credential
        if not da_hash:
            for cred in self.shared_state.all_credentials:
                if (
                    cred.domain
                    and cred.domain.lower() == da_domain_lower
                    and cred.password
                    and cred.username.lower() == "administrator"
                ):
                    da_password = cred.password
                    da_username = cred.username
                    break

        if not da_hash and not da_password:
            logger.warning(
                f"Cannot dispatch trust key extraction: no DA credentials for {da_domain}"
            )
            return

        # Dispatch trust key extraction for each undominated forest
        import json
        import uuid

        # Check if we should extract from parent domain (forest root) instead of child
        # Trust accounts like ESSOS$ exist at the forest level, so we need forest root DA
        extraction_domain = da_domain_lower
        extraction_dc_ip = dc_ip

        # If DA domain is a child, ALWAYS use forest root for trust extraction
        # IMPORTANT: Child domain credentials do NOT work on parent DC via PTH!
        # We need to wait for golden ticket with ExtraSid to get parent domain creds.
        domain_parts = da_domain_lower.split(".")
        if len(domain_parts) >= 3:  # child.parent.tld
            parent_domain = ".".join(domain_parts[1:])
            # Try to get parent DC from state
            parent_dc_ip = self.shared_state.domain_controllers.get(parent_domain)

            # DNS fallback if parent DC not in state
            if not parent_dc_ip:
                logger.info(
                    f"MULTI_FOREST_MODE: Parent DC not in state, trying DNS for {parent_domain}"
                )
                try:
                    import subprocess

                    # Query SRV record for parent DC
                    dns_cmd = ["dig", "+short", f"_ldap._tcp.dc._msdcs.{parent_domain}", "SRV"]
                    result = subprocess.run(  # noqa: ASYNC221
                        dns_cmd, capture_output=True, text=True, timeout=10, check=False
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        for line in result.stdout.strip().split("\n"):
                            parts = line.split()
                            if len(parts) >= 4:
                                dc_hostname = parts[3].rstrip(".")
                                a_cmd = ["dig", "+short", dc_hostname, "A"]
                                a_result = subprocess.run(  # noqa: ASYNC221
                                    a_cmd, capture_output=True, text=True, timeout=10, check=False
                                )
                                if a_result.returncode == 0 and a_result.stdout.strip():
                                    parent_dc_ip = a_result.stdout.strip().split("\n")[0]
                                    logger.info(
                                        f"MULTI_FOREST_MODE: Resolved parent DC via DNS: "
                                        f"{dc_hostname} -> {parent_dc_ip}"
                                    )
                                    # Cache for future use
                                    self.shared_state.domain_controllers[parent_domain] = (
                                        parent_dc_ip
                                    )
                                    break
                except Exception as dns_err:
                    logger.warning(f"MULTI_FOREST_MODE: DNS resolution failed: {dns_err}")

            if parent_dc_ip:
                extraction_domain = parent_domain
                extraction_dc_ip = parent_dc_ip

                # For child domains, we need PARENT domain Administrator hash
                # Child domain hash won't work on parent DC (PTH doesn't cross domain boundary)
                # Check if we have parent Administrator hash from golden ticket DCSync
                parent_admin_hash = None
                for h in self.shared_state.all_hashes:
                    if (
                        h.username.lower() == "administrator"
                        and h.domain
                        and h.domain.lower() == parent_domain.lower()
                        and (h.hash_type or "").lower() == "ntlm"
                    ):
                        parent_admin_hash = h.hash_value
                        break

                if parent_admin_hash:
                    # Use parent domain hash
                    da_hash = parent_admin_hash
                    logger.info(
                        f"MULTI_FOREST_MODE: Using parent domain hash for trust extraction "
                        f"({parent_domain}\\Administrator)"
                    )
                else:
                    # Don't have parent hash yet - golden ticket with ExtraSid needs to
                    # DCSync the parent domain first. Skip dispatch, will retry later.
                    logger.warning(
                        f"MULTI_FOREST_MODE: Child domain {da_domain} detected but no parent "
                        f"Administrator hash found for {parent_domain}. Waiting for golden ticket "
                        f"flow to DCSync parent domain. Trust extraction deferred."
                    )
                    # Clear the dedup flag so this can be retried when parent hash appears
                    self._trust_extraction_dispatched.discard(da_domain_lower)
                    return
            else:
                logger.warning(
                    f"MULTI_FOREST_MODE: Cannot find parent DC for {parent_domain}, "
                    f"using child DC {da_domain_lower} (may not find trust accounts)"
                )

        for target_forest in undominated:
            target_forest_lower = target_forest.lower()

            # Dedup key to prevent re-dispatch on restart
            dedup_key = f"{extraction_domain}:{target_forest_lower}"
            if dedup_key in self.shared_state.processed_trust_extractions:
                logger.debug(f"Trust key extraction already dispatched: {dedup_key}")
                continue

            self.shared_state.processed_trust_extractions.add(dedup_key)

            # Build task payload (must match exploit prompt format)
            # Use extraction_domain/extraction_dc_ip which may be parent (forest root) if
            # we have Enterprise Admin via ExtraSid
            task_payload = {
                "vuln_type": "trust_key_extraction",
                "target": extraction_dc_ip,
                "domain": extraction_domain,
                "username": da_username,
                "password": da_hash or da_password,
                "dc_ip": extraction_dc_ip,
                "trusted_domain": target_forest,
                "use_hash": bool(da_hash),
                # Original DA domain for credential context (cross-domain auth via trust)
                "auth_domain": da_domain,
            }

            task_id = f"trust_extraction_{uuid.uuid4().hex[:12]}"
            task_data = {
                "task_id": task_id,
                "task_type": "exploit",
                "target_agent": "privesc",
                "payload": task_payload,
                "source_agent": "auto_trust_extraction",
                "priority": 1,  # High priority
            }

            logger.warning(
                f"🌲 Auto-dispatching trust key extraction: {extraction_domain} → {target_forest} "
                f"(DC: {extraction_dc_ip}, using {'hash' if da_hash else 'password'})"
            )

            try:
                # Submit directly to privesc queue (where KerberosTools lives)
                # Use RPUSH for priority <= 2 (urgent) tasks - workers BRPOP from right,
                # so RPUSH items are processed immediately (front of queue)
                task_json = json.dumps(task_data)
                logger.debug(f"🌲 Trust extraction task payload: {task_json[:200]}...")
                result = await task_queue.redis.rpush(
                    "ares:tasks:privesc",
                    task_json,
                )
                logger.warning(
                    f"🌲 Trust key extraction task {task_id} submitted to privesc queue "
                    f"(rpush result: {result})"
                )
            except Exception as e:
                logger.error(f"🌲 Failed to dispatch trust key extraction: {e}", exc_info=True)


__all__ = ["PublishingMixin"]
