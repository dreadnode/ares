"""Operation recovery manager for multi-agent red team operations.

This module provides recovery capabilities for handling pod restarts
and operation recovery in a Kubernetes environment.

State is stored directly in Redis using native data structures via RedisStateBackend.
Recovery loads state from Redis - no JSON checkpoint deserialization or merge logic needed.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from loguru import logger

from ares.core.config import get_default_max_retries
from ares.core.models import SharedRedTeamState, TaskStatus, TimelineEvent
from ares.core.redis_client import create_redis_client
from ares.core.task_queue import RedisTaskQueue

if TYPE_CHECKING:
    from redis.asyncio import Redis

    from ares.core.k8s_executor import KubernetesPodExecutor


class RecoveryError(Exception):
    """Raised when recovery fails."""


class OperationRecoveryManager:
    """
    Handle pod restarts and operation recovery.

    Provides recovery functionality using Redis-native state storage
    to enable recovery from pod crashes in Kubernetes environments.

    Usage:
        manager = OperationRecoveryManager(
            k8s_executor=executor,
            redis_url="redis://..."
        )

        # Recover after pod restart
        state, requeued_task_ids = await manager.recover_operation(operation_id)
    """

    # Connection error keywords to detect stale/failed connections
    _CONNECTION_ERROR_KEYWORDS = (
        "connection",
        "connect",
        "closed",
        "timeout",
        "broken pipe",
        "reset",
        "reading from",
    )

    def __init__(
        self,
        k8s_executor: KubernetesPodExecutor | None = None,
        redis_url: str | None = None,
        checkpoint_interval: int = 60,
    ):
        """
        Initialize the recovery manager.

        Args:
            k8s_executor: Kubernetes executor for pod management.
            redis_url: Redis URL for state persistence.
            checkpoint_interval: Deprecated - checkpoints are no longer periodic.
        """
        self._k8s = k8s_executor
        self._redis_url = redis_url
        self._redis_client: Redis | None = None
        self._connected = False
        self._checkpoint_interval = checkpoint_interval
        self._checkpoint_task: asyncio.Task | None = None
        self._running = False

    @property
    def redis_client(self) -> Redis:
        """Get the Redis client. Raises RuntimeError if not connected."""
        if self._redis_client is None:
            raise RuntimeError("Redis not connected. Call _ensure_connected() first.")
        return self._redis_client

    def _is_connection_error(self, error: Exception) -> bool:
        """Check if an exception is a connection-related error."""
        error_str = str(error).lower()
        return any(keyword in error_str for keyword in self._CONNECTION_ERROR_KEYWORDS)

    def _handle_connection_error(self, error: Exception) -> None:
        """
        Handle Redis connection errors by resetting connection state.

        This allows the next operation to attempt reconnection via Sentinel,
        which will discover the current master (handles pod restarts/failover).
        """
        self._connected = False
        if self._redis_client:
            # Don't await close here - just drop the stale client reference
            # The client will be recreated on next _ensure_connected()
            self._redis_client = None
        logger.warning(f"Redis connection error, will reconnect: {error}")

    async def _ensure_connected(self) -> bool:
        """
        Ensure Redis client is connected, reconnecting if needed.

        Returns:
            True if connected, False if connection failed.
        """
        # If client already exists (e.g., set directly in tests), consider connected
        if self._redis_client is not None:
            if not self._connected:
                # Mark as connected if client was set directly
                self._connected = True
            return True

        if not self._redis_url:
            return False

        try:
            self._redis_client = await create_redis_client(self._redis_url)
            await self._redis_client.ping()
            self._connected = True
            logger.info("Recovery manager reconnected to Redis")
            return True
        except Exception as e:
            logger.warning(f"Failed to connect to Redis: {e}")
            # Close the client if it was created before setting to None
            if self._redis_client:
                try:
                    await self._redis_client.aclose()
                except Exception:
                    pass
            self._redis_client = None
            self._connected = False
            return False

    async def start(self) -> None:
        """Initialize Redis connection."""
        if self._redis_url:
            try:
                self._redis_client = await create_redis_client(self._redis_url)
                await self._redis_client.ping()
                self._connected = True
                logger.info(f"Recovery manager connected to Redis: {self._redis_url}")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}")
                # Close the client if it was created
                if self._redis_client:
                    try:
                        await self._redis_client.aclose()
                    except Exception:
                        pass
                    self._redis_client = None

    async def stop(self) -> None:
        """Cleanup resources."""
        self._running = False

        if self._checkpoint_task:
            self._checkpoint_task.cancel()
            try:
                await self._checkpoint_task
            except asyncio.CancelledError:
                pass

        if self._redis_client:
            await self._redis_client.close()
            self._redis_client = None
            self._connected = False

    async def recover_operation(
        self,
        operation_id: str,
        auto_requeue: bool = True,
    ) -> tuple[SharedRedTeamState, list[str]]:
        """
        Recover state from Redis-native storage.

        Args:
            operation_id: The operation ID to recover.
            auto_requeue: If True, automatically requeue interrupted tasks.

        Returns:
            Tuple of (recovered state, list of requeued task IDs).
            Requeued tasks are already in pending_tasks which the result
            consumer polls automatically.

        Raises:
            RecoveryError: If no state found or recovery fails.
        """
        if not await self._ensure_connected():
            raise RecoveryError("Redis not available for recovery")

        # Check if Redis-native keys exist for this operation
        meta_key = f"ares:op:{operation_id}:meta"
        has_data = await self.redis_client.exists(meta_key)

        if not has_data:
            raise RecoveryError(f"No state found for operation {operation_id}")

        try:
            from ares.core.state_backend import RedisStateBackend

            # Create state with backend - data is already in Redis
            state = SharedRedTeamState(operation_id=operation_id)
            backend = RedisStateBackend(self.redis_client, operation_id)
            state.set_backend(backend)

            # Load all data from Redis into memory for sync access
            await self._load_state_from_backend(state, backend)

            # Handle task requeuing
            requeued_task_ids = await self._requeue_interrupted_tasks(
                state, operation_id, auto_requeue
            )

            logger.info(f"Recovered state from Redis for {operation_id}")
            return state, requeued_task_ids

        except RecoveryError:
            raise
        except Exception as e:
            raise RecoveryError(f"Failed to recover operation: {e}") from e

    async def _load_state_from_backend(
        self,
        state: SharedRedTeamState,
        backend,  # RedisStateBackend, but avoid circular import
    ) -> None:
        """Load all state data from Redis backend into memory."""
        # Load collections
        state.all_credentials.extend(await backend.get_credentials())
        state.all_hashes.extend(await backend.get_hashes())
        # Safety net dedup (HASH storage with HSETNX prevents dupes, but handles legacy data)
        state.all_hashes = self._dedupe_hashes(state.all_hashes)
        state.all_hosts.extend(await backend.get_hosts())
        state.all_users.extend(await backend.get_users())
        state.all_shares.extend(await backend.get_shares())
        # Load weaknesses and populate dedup keys for proper deduplication
        weaknesses = await backend.get_weaknesses()
        for weakness in weaknesses:
            state.all_weaknesses.append(weakness)
            # Populate dedup keys set from loaded weaknesses
            dedup_key = state._extract_weakness_dedup_key(weakness)
            state._weakness_dedup_keys.add(dedup_key)
        state.all_domains.extend(await backend.get_domains())

        # Load vulnerabilities (get_vulnerabilities returns dict[str, VulnerabilityInfo])
        state.discovered_vulnerabilities.update(await backend.get_vulnerabilities())

        # Load exploited vulnerabilities
        state.exploited_vulnerabilities.update(await backend.get_exploited_vulnerabilities())

        # Load processed sets
        await state.load_processed_sets_from_backend()

        # Load persistence tracking (golden tickets, backdoors, ACL chains, gMSA accounts)
        await state.load_persistence_tracking_from_backend()

        # Load meta fields
        (
            state.has_domain_admin,
            state.domain_admin_path,
            state.da_hash_id,
        ) = await backend.get_domain_admin()
        state.has_golden_ticket = await backend.get_meta("has_golden_ticket", default=False)
        completed_at_str = await backend.get_meta("completed_at")
        if completed_at_str:
            try:
                state.completed_at = datetime.fromisoformat(completed_at_str)
            except (ValueError, TypeError):
                pass

        # Load DC map
        dc_map = await backend.get_all_dcs()
        state.domain_controllers.update(dc_map)

        # Reconstruct Target from meta for environment tracking
        target_ip = await backend.get_meta("target_ip", default="")
        target_domain = await backend.get_meta("target_domain", default="")
        target_env = await backend.get_meta("target_environment", default="")
        if target_ip or target_domain:
            from ares.core.models import Target

            state.target = Target(
                ip=target_ip or "",
                domain=target_domain or "",
                environment=target_env or "",
            )

        # Load NetBIOS map
        netbios_map = await backend.get_all_netbios_mappings()
        state.netbios_to_fqdn.update(netbios_map)

        # Load artifacts
        artifacts = await backend.get_all_artifacts()
        state.downloaded_artifacts.update(artifacts)

        # Load timeline events
        timeline_events = await backend.get_timeline_events()
        for event_dict in timeline_events:
            try:
                event = TimelineEvent(
                    id=event_dict.get("id", ""),
                    timestamp=datetime.fromisoformat(event_dict["timestamp"]),
                    description=event_dict.get("description", ""),
                    evidence_ids=event_dict.get("evidence_ids", []),
                    mitre_techniques=event_dict.get("mitre_techniques", []),
                    confidence=event_dict.get("confidence", 0.5),
                    source=event_dict.get("source", "investigation"),
                )
                state.operation_timeline.append(event)
            except (KeyError, ValueError) as e:
                logger.warning(f"Failed to deserialize timeline event: {e}")
        if timeline_events:
            logger.info(f"Loaded {len(state.operation_timeline)} timeline events from Redis")

        # Load MITRE techniques
        techniques = await backend.get_techniques()
        state.identified_techniques.update(techniques)
        if techniques:
            logger.info(f"Loaded {len(techniques)} MITRE techniques from Redis")

    def _dedupe_hashes(self, hashes: list) -> list:
        """Deduplicate hashes, keeping first occurrence.

        For AS-REP hashes: dedupe by (domain, username) since each AS-REP request
        generates a different hash but cracks to the same password.

        For Kerberoast hashes: dedupe by (domain, username, spn, etype).

        For other hashes: dedupe by exact hash value.

        Args:
            hashes: List of Hash objects

        Returns:
            Deduplicated list of Hash objects
        """
        seen_asrep: set[tuple[str, str]] = set()  # (domain, username)
        seen_kerberoast: set[tuple[str, str, str]] = set()  # (domain, username, spn_key)
        seen_other: set[str] = set()  # hash_value
        result = []

        for h in hashes:
            hash_type = (h.hash_type or "").strip().lower()
            hash_value = h.hash_value or ""
            username = (h.username or "").strip().lower()
            domain = (h.domain or "").strip().lower()

            is_asrep = hash_type in {"as-rep", "asrep", "krb5asrep"} or hash_value.startswith(
                "$krb5asrep$"
            )
            is_kerberoast = hash_type in {
                "kerberoast",
                "krb5tgs",
                "tgs-rep",
                "tgs",
            } or hash_value.startswith("$krb5tgs$")

            if is_asrep:
                asrep_key = (domain, username)
                if asrep_key in seen_asrep:
                    continue
                seen_asrep.add(asrep_key)
            elif is_kerberoast:
                spn_key = self._extract_kerberoast_spn_key(hash_value) or ""
                kerb_key = (domain, username, spn_key)
                if kerb_key in seen_kerberoast:
                    continue
                seen_kerberoast.add(kerb_key)
            else:
                if hash_value in seen_other:
                    continue
                seen_other.add(hash_value)

            result.append(h)

        if len(result) < len(hashes):
            logger.info(f"Deduplicated {len(hashes) - len(result)} duplicate hashes")

        return result

    def _extract_kerberoast_spn_key(self, hash_value: str) -> str | None:
        """Extract SPN and encryption type from Kerberoast hash for deduplication."""
        if not hash_value.startswith("$krb5tgs$"):
            return None
        try:
            parts = hash_value.split("$")
            if len(parts) < 4:
                return None
            etype = parts[2]
            asterisk_parts = hash_value.split("*")
            if len(asterisk_parts) < 2:
                return None
            inner = asterisk_parts[1]
            inner_parts = inner.split("$")
            if len(inner_parts) < 3:
                return None
            spn = inner_parts[2]
            return f"{etype}:{spn}"
        except Exception:
            return None

    async def _requeue_interrupted_tasks(
        self,
        state: SharedRedTeamState,
        operation_id: str,
        auto_requeue: bool,
    ) -> list[str]:
        """Requeue tasks that were interrupted by pod restart."""
        interrupted_count = 0
        requeued_count = 0
        failed_count = 0
        requeued_task_ids: list[str] = []

        task_queue = RedisTaskQueue(self._redis_url) if auto_requeue else None
        if task_queue:
            await task_queue.connect()

        try:
            for task_id, task in list(state.pending_tasks.items()):
                if task.status in (
                    TaskStatus.PENDING,
                    TaskStatus.IN_PROGRESS,
                    TaskStatus.RETRYING,
                ):
                    interrupted_count += 1

                    if task.status == TaskStatus.IN_PROGRESS:
                        task.retry_count += 1

                    max_retries = getattr(task, "max_retries", get_default_max_retries())
                    if auto_requeue and task.retry_count <= max_retries:
                        task.status = TaskStatus.RETRYING
                        if task.retry_count > 0:
                            task.error = f"Pod restart during execution (retry {task.retry_count}/{max_retries})"
                        else:
                            task.error = "Requeued after pod restart (task was pending)"

                        if task_queue:
                            await task_queue.requeue_task(
                                task_type=task.task_type,
                                target_role=task.assigned_agent,
                                payload=task.params,
                                task_id=task_id,
                                retry_count=task.retry_count,
                            )
                            requeued_count += 1
                            requeued_task_ids.append(task_id)
                            logger.info(
                                f"Task {task_id} requeued for retry "
                                f"({task.retry_count}/{max_retries})"
                            )
                    else:
                        task.status = TaskStatus.FAILED
                        task.error = (
                            f"Pod restart during execution (max retries {max_retries} exceeded)"
                        )
                        task.completed_at = datetime.now(timezone.utc)
                        failed_count += 1
                        logger.error(
                            f"Task {task_id} permanently failed after {task.retry_count} retries"
                        )
        finally:
            if task_queue:
                await task_queue.disconnect()

        if interrupted_count:
            logger.warning(
                f"Recovery: {interrupted_count} interrupted tasks - "
                f"{requeued_count} requeued, {failed_count} permanently failed"
            )

        return requeued_task_ids

    async def has_checkpoint(self, operation_id: str) -> bool:
        """
        Check if state exists for an operation.

        Args:
            operation_id: The operation ID.

        Returns:
            True if state exists.
        """
        if not await self._ensure_connected():
            return False

        try:
            key = f"ares:op:{operation_id}:meta"
            return await self.redis_client.exists(key) > 0
        except Exception as e:
            if self._is_connection_error(e):
                self._handle_connection_error(e)
            return False

    async def delete_checkpoint(self, operation_id: str) -> bool:
        """
        Delete state for an operation.

        Args:
            operation_id: The operation ID.

        Returns:
            True if deleted successfully.
        """
        if not await self._ensure_connected():
            return False

        try:
            from ares.core.state_backend import RedisStateBackend

            backend = RedisStateBackend(self.redis_client, operation_id)
            deleted = await backend.delete_all_keys()
            logger.info(f"Deleted {deleted} keys for operation {operation_id}")
            return deleted > 0
        except Exception as e:
            if self._is_connection_error(e):
                self._handle_connection_error(e)
            logger.error(f"Failed to delete state: {e}")
            return False

    async def ensure_pods_ready(
        self,
        roles: list[str] | None = None,
        timeout: int = 120,
    ) -> dict[str, bool]:
        """
        Wait for all required pods to be ready.

        Args:
            roles: List of roles to wait for (default: all standard roles).
            timeout: Maximum time to wait in seconds.

        Returns:
            Dict mapping role to ready status.
        """
        if self._k8s is None:
            logger.warning("No Kubernetes executor configured")
            return {}

        if roles is None:
            roles = ["orchestrator", "cracker", "acl", "privesc", "lateral", "coercion"]

        return await self._k8s.wait_for_all_pods(roles, timeout)

    async def list_operations(self) -> list[dict]:
        """
        List all operations with state in Redis.

        Returns:
            List of operation info dicts.
        """
        if not await self._ensure_connected():
            return []

        try:
            # Scan for operation meta keys
            operations = []
            async for key in self.redis_client.scan_iter("ares:op:*:meta"):
                # Extract operation ID from key
                key_str = key.decode() if isinstance(key, bytes) else key
                parts = key_str.split(":")
                if len(parts) >= 3:
                    op_id = parts[2]
                    operations.append({"operation_id": op_id})

            return operations

        except Exception as e:
            if self._is_connection_error(e):
                self._handle_connection_error(e)
            logger.error(f"Failed to list operations: {e}")
            return []

    async def cleanup_old_checkpoints(self, max_age_hours: int = 24) -> int:
        """
        Clean up old operation state from Redis.

        With Redis-native state backend, keys have TTL and auto-expire.
        This method provides explicit cleanup for operations older than max_age_hours.

        Args:
            max_age_hours: Delete operations older than this many hours.

        Returns:
            Number of operations cleaned up.
        """
        if not await self._ensure_connected():
            return 0

        cleaned = 0
        cutoff = datetime.now(timezone.utc) - __import__("datetime").timedelta(hours=max_age_hours)

        try:
            # Scan for operation meta keys
            async for key in self.redis_client.scan_iter("ares:op:*:meta"):
                key_str = key.decode() if isinstance(key, bytes) else key
                parts = key_str.split(":")
                if len(parts) >= 3:
                    op_id = parts[2]

                    # Check operation timestamp from ID (format: op-YYYYMMDD-HHMMSS)
                    try:
                        if op_id.startswith("op-") and len(op_id) >= 18:
                            date_str = op_id[3:11]  # YYYYMMDD
                            time_str = op_id[12:18]  # HHMMSS
                            op_time = datetime.strptime(
                                f"{date_str}{time_str}", "%Y%m%d%H%M%S"
                            ).replace(tzinfo=timezone.utc)

                            if op_time < cutoff and await self.delete_checkpoint(op_id):
                                cleaned += 1
                                logger.info(f"Cleaned up old operation: {op_id}")
                    except (ValueError, IndexError):
                        # Can't parse timestamp, skip
                        continue

            return cleaned

        except Exception as e:
            if self._is_connection_error(e):
                self._handle_connection_error(e)
            logger.error(f"Failed to cleanup old checkpoints: {e}")
            return cleaned


class OperationResumeHelper:
    """
    Helper for resuming operations after recovery.

    Provides utilities for picking up where an operation left off.
    """

    def __init__(
        self,
        state: SharedRedTeamState,
        recovery_manager: OperationRecoveryManager,
    ):
        self.state = state
        self.recovery = recovery_manager

    def get_interrupted_tasks(self) -> list[dict]:
        """
        Get tasks that were interrupted during recovery and permanently failed.

        Note: Tasks with RETRYING status are being auto-requeued and don't need
        manual intervention.

        Returns:
            List of task info for permanently failed tasks.
        """
        interrupted = []

        # Snapshot to avoid "dict changed size during iteration"
        for task_id, task in list(self.state.pending_tasks.items()):
            # Only return permanently failed tasks (max retries exceeded)
            if task.status == TaskStatus.FAILED and task.error and "Pod restart" in task.error:
                interrupted.append(
                    {
                        "task_id": task_id,
                        "task_type": task.task_type,
                        "params": task.params,
                        "assigned_agent": task.assigned_agent,
                        "retry_count": getattr(task, "retry_count", 0),
                        "error": task.error,
                    }
                )

        return interrupted

    def get_retrying_tasks(self) -> list[dict]:
        """
        Get tasks that are currently being retried.

        Returns:
            List of task info for tasks being auto-retried.
        """
        retrying = []

        # Snapshot to avoid "dict changed size during iteration"
        for task_id, task in list(self.state.pending_tasks.items()):
            if task.status == TaskStatus.RETRYING:
                retrying.append(
                    {
                        "task_id": task_id,
                        "task_type": task.task_type,
                        "params": task.params,
                        "assigned_agent": task.assigned_agent,
                        "retry_count": getattr(task, "retry_count", 0),
                        "max_retries": getattr(task, "max_retries", get_default_max_retries()),
                    }
                )

        return retrying

    def get_unexploited_vulnerabilities(self) -> list[dict]:
        """
        Get vulnerabilities that still need exploitation.

        Returns:
            List of vulnerability info sorted by priority.
        """
        unexploited = self.state.get_unexploited_vulnerabilities()

        return sorted(
            [
                {
                    "vuln_id": v.vuln_id,
                    "vuln_type": v.vuln_type,
                    "target": v.target,
                    "priority": v.priority,
                    "recommended_agent": v.recommended_agent,
                }
                for v in unexploited
            ],
            key=lambda x: x["priority"],
        )

    def get_uncracked_hashes(self) -> list[dict]:
        """
        Get hashes that still need cracking.

        Returns:
            List of hash info.
        """
        return [
            {
                "username": h.username,
                "domain": h.domain,
                "hash_type": h.hash_type,
                "hash_value": h.hash_value,
            }
            for h in self.state.all_hashes
            if not h.cracked_password
        ]

    def get_resume_prompt(self) -> str:
        """
        Generate a prompt summarizing what needs to be done after recovery.

        Returns:
            Formatted prompt for the orchestrator.
        """
        lines = [
            "OPERATION RESUMED AFTER RECOVERY",
            "=" * 50,
            "",
            f"Operation ID: {self.state.operation_id}",
            f"Credentials found: {len(self.state.all_credentials)}",
            f"Hosts discovered: {len(self.state.all_hosts)}",
            f"Domain admin: {'YES' if self.state.has_domain_admin else 'NO'}",
            "",
        ]

        # Retrying tasks (auto-handled)
        retrying = self.get_retrying_tasks()
        if retrying:
            lines.append(f"[RETRYING] {len(retrying)} tasks auto-requeued:")
            for task in retrying[:5]:
                lines.append(
                    f"  - {task['task_type']} -> {task['assigned_agent']} "
                    f"(retry {task['retry_count']}/{task['max_retries']})"
                )
            lines.append("")

        # Permanently failed tasks (need manual attention)
        interrupted = self.get_interrupted_tasks()
        if interrupted:
            lines.append(f"[FAILED] {len(interrupted)} tasks exceeded max retries:")
            for task in interrupted[:5]:
                lines.append(
                    f"  - {task['task_type']} -> {task['assigned_agent']} "
                    f"(retried {task['retry_count']}x)"
                )
            lines.append("")

        # Unexploited vulnerabilities
        unexploited = self.get_unexploited_vulnerabilities()
        if unexploited:
            lines.append(f"[PENDING] {len(unexploited)} unexploited vulnerabilities:")
            for vuln in unexploited[:5]:
                lines.append(
                    f"  - {vuln['vuln_type']}: {vuln['target']} (priority {vuln['priority']})"
                )
            lines.append("")

        # Uncracked hashes
        uncracked = self.get_uncracked_hashes()
        if uncracked:
            lines.append(f"[PENDING] {len(uncracked)} uncracked hashes")
            lines.append("")

        if not retrying and not interrupted:
            lines.append("[OK] No interrupted tasks - clean recovery")
            lines.append("")

        return "\n".join(lines)


__all__ = [
    "OperationRecoveryManager",
    "OperationResumeHelper",
    "RecoveryError",
]
