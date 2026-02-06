"""Operation recovery manager for multi-agent red team operations.

This module provides recovery capabilities for handling pod restarts
and operation recovery in a Kubernetes environment.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from loguru import logger

from ares.core.models import DEFAULT_MAX_RETRIES, SharedRedTeamState, TaskStatus
from ares.core.redis_client import create_redis_client
from ares.core.task_queue import RedisTaskQueue

if TYPE_CHECKING:
    from ares.core.dispatcher import RedTeamDispatcher
    from ares.core.k8s_executor import KubernetesPodExecutor


class RecoveryError(Exception):
    """Raised when recovery fails."""


def _merge_state(target: SharedRedTeamState, existing: SharedRedTeamState) -> None:
    """Merge existing checkpoint data into current state to prevent regressions."""
    # Hosts, domains, users (using built-in dedup methods)
    for host in existing.all_hosts:
        target.add_host(host)
    for domain in getattr(existing, "all_domains", []):
        target.add_domain(domain)
    for user in existing.all_users:
        target.add_user(user.username, user.domain)

    # Credentials (preserve original source fields)
    _merge_credentials(target, existing)
    _merge_hashes(target, existing)
    _merge_shares(target, existing)
    _merge_weaknesses(target, existing)

    # Vulnerabilities and techniques
    for vuln_id, vuln in existing.discovered_vulnerabilities.items():
        target.discovered_vulnerabilities.setdefault(vuln_id, vuln)
    target.exploited_vulnerabilities |= existing.exploited_vulnerabilities
    target.identified_techniques |= existing.identified_techniques

    # Timeline
    _merge_timeline(target, existing)

    # Domain Admin / Golden Ticket flags (OR logic - once achieved, never regress)
    if existing.has_domain_admin and not target.has_domain_admin:
        target.has_domain_admin = True
        target.domain_admin_path = existing.domain_admin_path or target.domain_admin_path
    if existing.has_golden_ticket and not target.has_golden_ticket:
        target.has_golden_ticket = True

    # Safety net: scan merged hashes for DA indicators if flag not yet set
    if not target.has_domain_admin:
        for h in target.all_hashes:
            ht = (h.hash_type or "").strip().lower()
            un = (h.username or "").strip().lower()
            if ht == "ntlm" and un in ("krbtgt", "administrator"):
                target.has_domain_admin = True
                target.domain_admin_path = (
                    f"secretsdump → {un} NTLM hash found in state (detected during merge)"
                )
                break

    # Merge dynamic tracking attributes (set via object.__setattr__)
    for dynamic_attr in ("_queried_hosts", "_tested_credentials"):
        existing_value = getattr(existing, dynamic_attr, None)
        if existing_value is not None:
            target_value: set = getattr(target, dynamic_attr, set())
            object.__setattr__(target, dynamic_attr, target_value | existing_value)


def _merge_credentials(target: SharedRedTeamState, existing: SharedRedTeamState) -> None:
    """Merge credentials from existing state into target."""
    seen = {
        f"{c.domain.strip()}:{c.username.strip()}:{c.password.strip()}".lower()
        for c in target.all_credentials
    }
    for cred in existing.all_credentials:
        key = f"{cred.domain.strip()}:{cred.username.strip()}:{cred.password.strip()}".lower()
        if cred.username and key not in seen:
            seen.add(key)
            target.all_credentials.append(cred)


def _merge_hashes(target: SharedRedTeamState, existing: SharedRedTeamState) -> None:
    """Merge hashes from existing state into target."""
    seen = {h.hash_value for h in target.all_hashes}
    for h in existing.all_hashes:
        if h.hash_value not in seen:
            seen.add(h.hash_value)
            target.all_hashes.append(h)


def _merge_shares(target: SharedRedTeamState, existing: SharedRedTeamState) -> None:
    """Merge shares from existing state into target."""
    seen = {(s.host, s.name) for s in target.all_shares}
    for s in existing.all_shares:
        key = (s.host, s.name)
        if key not in seen:
            seen.add(key)
            target.all_shares.append(s)


def _merge_weaknesses(target: SharedRedTeamState, existing: SharedRedTeamState) -> None:
    """Merge weaknesses from existing state into target."""
    seen = set(target.all_weaknesses)
    for w in existing.all_weaknesses:
        if w not in seen:
            seen.add(w)
            target.all_weaknesses.append(w)


def _merge_timeline(target: SharedRedTeamState, existing: SharedRedTeamState) -> None:
    """Merge timeline events from existing state into target."""
    seen = {e.id for e in target.operation_timeline}
    for event in existing.operation_timeline:
        if event.id not in seen:
            seen.add(event.id)
            target.operation_timeline.append(event)


class OperationRecoveryManager:
    """
    Handle pod restarts and operation recovery.

    Provides checkpoint/restore functionality using Redis to enable
    recovery from pod crashes in Kubernetes environments.

    Usage:
        manager = OperationRecoveryManager(
            k8s_executor=executor,
            # redis_url defaults to config value from ares.core.config
        )

        # Regular checkpoints during operation
        await manager.checkpoint(state)

        # Recover after pod restart
        state = await manager.recover_operation(operation_id)
    """

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
            checkpoint_interval: Seconds between automatic checkpoints.
        """
        self._k8s = k8s_executor
        self._redis_url = redis_url
        self._redis_client = None
        self._checkpoint_interval = checkpoint_interval
        self._checkpoint_task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> None:
        """Initialize Redis connection."""
        if self._redis_url:
            try:
                self._redis_client = await create_redis_client(self._redis_url)
                await self._redis_client.ping()
                logger.info(f"Recovery manager connected to Redis: {self._redis_url}")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}")

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

    async def checkpoint(self, state: SharedRedTeamState) -> bool:
        """
        Save state checkpoint to Redis.

        Args:
            state: The shared state to checkpoint.

        Returns:
            True if checkpoint was saved successfully.
        """
        if self._redis_client is None:
            return False

        try:
            key = f"ares:operation:{state.operation_id}:state"
            existing_data = await self._redis_client.get(key)
            if existing_data:
                try:
                    existing_state = SharedRedTeamState.from_bytes(existing_data)
                    _merge_state(state, existing_state)
                except Exception as exc:
                    logger.warning(f"Failed to merge existing checkpoint state: {exc}")
            # Debug: log state counts before checkpoint
            logger.info(
                f"Checkpointing state: hosts={len(state.all_hosts)}, "
                f"users={len(state.all_users)}, creds={len(state.all_credentials)}, "
                f"hashes={len(state.all_hashes)}, domain_admin={state.has_domain_admin}"
            )
            await self._redis_client.set(key, state.to_bytes())

            # Set checkpoint timestamp
            time_key = f"ares:operation:{state.operation_id}:checkpoint_time"
            await self._redis_client.set(
                time_key,
                datetime.now(timezone.utc).isoformat(),
            )

            # Set 24 hour TTL
            await self._redis_client.expire(key, 86400)
            await self._redis_client.expire(time_key, 86400)

            logger.debug(f"Checkpoint saved for operation {state.operation_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")
            return False

    async def recover_operation(  # noqa: PLR0912
        self,
        operation_id: str,
        auto_requeue: bool = True,
    ) -> SharedRedTeamState:
        """
        Recover state from last checkpoint.

        By default, automatically requeues interrupted tasks for retry.
        Tasks that exceed max_retries are marked as permanently failed.

        Args:
            operation_id: The operation ID to recover.
            auto_requeue: If True, automatically requeue interrupted tasks.

        Returns:
            Recovered SharedRedTeamState.

        Raises:
            RecoveryError: If no checkpoint found or recovery fails.
        """
        if self._redis_client is None:
            raise RecoveryError("Redis not available for recovery")

        try:
            key = f"ares:operation:{operation_id}:state"
            data = await self._redis_client.get(key)

            if not data:
                raise RecoveryError(f"No checkpoint found for operation {operation_id}")

            state = SharedRedTeamState.from_bytes(data)

            # Handle in-progress tasks that were interrupted
            interrupted_count = 0
            requeued_count = 0
            failed_count = 0

            # Create task queue for requeuing
            task_queue = RedisTaskQueue(self._redis_url) if auto_requeue else None
            if task_queue:
                await task_queue.connect()

            try:
                for task_id, task in list(state.pending_tasks.items()):
                    # PENDING/RETRYING tasks may have been submitted to Redis but not yet picked up
                    # when pods restarted, so they need to be requeued.
                    if task.status in (
                        TaskStatus.PENDING,
                        TaskStatus.IN_PROGRESS,
                        TaskStatus.RETRYING,
                    ):
                        interrupted_count += 1

                        # IN_PROGRESS tasks were running, so they count as a retry. PENDING/RETRYING
                        # tasks were never started, so they shouldn't increment.
                        if task.status == TaskStatus.IN_PROGRESS:
                            task.retry_count += 1

                        max_retries = getattr(task, "max_retries", DEFAULT_MAX_RETRIES)
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
                                f"Task {task_id} permanently failed after "
                                f"{task.retry_count} retries"
                            )
            finally:
                if task_queue:
                    await task_queue.disconnect()

            if interrupted_count:
                logger.warning(
                    f"Recovery: {interrupted_count} interrupted tasks - "
                    f"{requeued_count} requeued, {failed_count} permanently failed"
                )

            # Get checkpoint time for logging
            time_key = f"ares:operation:{operation_id}:checkpoint_time"
            checkpoint_time = await self._redis_client.get(time_key)
            if checkpoint_time:
                checkpoint_str = (
                    checkpoint_time.decode()
                    if isinstance(checkpoint_time, (bytes, bytearray))
                    else str(checkpoint_time)
                )
                logger.info(f"Recovered state from checkpoint at {checkpoint_str}")

            return state

        except RecoveryError:
            raise
        except Exception as e:
            raise RecoveryError(f"Failed to recover operation: {e}") from e

    async def get_checkpoint_time(self, operation_id: str) -> datetime | None:
        """
        Get the timestamp of the last checkpoint.

        Args:
            operation_id: The operation ID.

        Returns:
            Datetime of last checkpoint, or None if not found.
        """
        if self._redis_client is None:
            return None

        try:
            time_key = f"ares:operation:{operation_id}:checkpoint_time"
            data = await self._redis_client.get(time_key)
            if data:
                return datetime.fromisoformat(data.decode())
        except Exception as e:
            logger.warning(f"Failed to get checkpoint time: {e}")

        return None

    async def has_checkpoint(self, operation_id: str) -> bool:
        """
        Check if a checkpoint exists for an operation.

        Args:
            operation_id: The operation ID.

        Returns:
            True if checkpoint exists.
        """
        if self._redis_client is None:
            return False

        try:
            key = f"ares:operation:{operation_id}:state"
            return await self._redis_client.exists(key) > 0
        except Exception:
            return False

    async def delete_checkpoint(self, operation_id: str) -> bool:
        """
        Delete checkpoint for an operation.

        Args:
            operation_id: The operation ID.

        Returns:
            True if deleted successfully.
        """
        if self._redis_client is None:
            return False

        try:
            key = f"ares:operation:{operation_id}:state"
            time_key = f"ares:operation:{operation_id}:checkpoint_time"
            await self._redis_client.delete(key, time_key)
            logger.info(f"Deleted checkpoint for operation {operation_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete checkpoint: {e}")
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

    async def start_auto_checkpoint(
        self,
        state: SharedRedTeamState,
        interval: int | None = None,
    ) -> None:
        """
        Start automatic periodic checkpointing.

        Args:
            state: The state to checkpoint periodically.
            interval: Checkpoint interval in seconds (uses default if None).
        """
        if self._checkpoint_task is not None:
            logger.warning("Auto checkpoint already running")
            return

        interval = interval or self._checkpoint_interval
        self._running = True

        async def _checkpoint_loop():
            while self._running:
                await asyncio.sleep(interval)
                if self._running:
                    await self.checkpoint(state)

        self._checkpoint_task = asyncio.create_task(_checkpoint_loop())
        logger.info(f"Started auto checkpoint every {interval} seconds")

    async def stop_auto_checkpoint(self) -> None:
        """Stop automatic periodic checkpointing."""
        self._running = False

        if self._checkpoint_task:
            self._checkpoint_task.cancel()
            try:
                await self._checkpoint_task
            except asyncio.CancelledError:
                pass
            self._checkpoint_task = None

        logger.info("Stopped auto checkpoint")

    async def start_periodic_checkpoint(
        self,
        dispatcher: RedTeamDispatcher,
        interval: int | None = None,
    ) -> None:
        """
        Start automatic periodic checkpointing using dispatcher's shared state.

        This method runs as a coroutine and should be used with asyncio.create_task().

        Args:
            dispatcher: The RedTeamDispatcher to checkpoint state from.
            interval: Checkpoint interval in seconds (uses default if None).
        """

        interval = interval or self._checkpoint_interval
        self._running = True

        logger.info(f"Starting periodic checkpoint every {interval} seconds")

        # Immediate checkpoint on start so workers can discover the operation
        if dispatcher._shared_state:
            success = await self.checkpoint(dispatcher.shared_state)
            if success:
                logger.info("Initial checkpoint saved - workers can now discover operation")
            else:
                logger.warning("Failed to save initial checkpoint")

        while self._running:
            await asyncio.sleep(interval)
            if self._running and dispatcher._shared_state:
                success = await self.checkpoint(dispatcher.shared_state)
                if success:
                    logger.debug("Periodic checkpoint saved")
                else:
                    logger.warning("Failed to save periodic checkpoint")

    async def list_operations(self) -> list[dict]:
        """
        List all operations with checkpoints.

        Returns:
            List of operation info dicts.
        """
        if self._redis_client is None:
            return []

        try:
            # Scan for operation keys
            operations = []
            async for key in self._redis_client.scan_iter("ares:operation:*:state"):
                # Extract operation ID from key
                parts = key.decode().split(":")
                if len(parts) >= 3:
                    op_id = parts[2]
                    checkpoint_time = await self.get_checkpoint_time(op_id)
                    operations.append(
                        {
                            "operation_id": op_id,
                            "checkpoint_time": checkpoint_time.isoformat()
                            if checkpoint_time
                            else None,
                        }
                    )

            return operations

        except Exception as e:
            logger.error(f"Failed to list operations: {e}")
            return []

    async def cleanup_old_checkpoints(self, max_age_hours: int = 24) -> int:
        """
        Remove checkpoints older than specified age.

        Args:
            max_age_hours: Maximum age in hours.

        Returns:
            Number of checkpoints removed.
        """
        if self._redis_client is None:
            return 0

        try:
            removed = 0
            cutoff = datetime.now(timezone.utc)

            operations = await self.list_operations()
            for op in operations:
                if op["checkpoint_time"]:
                    checkpoint_time = datetime.fromisoformat(op["checkpoint_time"])
                    age_hours = (cutoff - checkpoint_time).total_seconds() / 3600

                    if age_hours > max_age_hours:
                        await self.delete_checkpoint(op["operation_id"])
                        removed += 1

            if removed:
                logger.info(f"Cleaned up {removed} old checkpoints")

            return removed

        except Exception as e:
            logger.error(f"Failed to cleanup checkpoints: {e}")
            return 0


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

        for task_id, task in self.state.pending_tasks.items():
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

        for task_id, task in self.state.pending_tasks.items():
            if task.status == TaskStatus.RETRYING:
                retrying.append(
                    {
                        "task_id": task_id,
                        "task_type": task.task_type,
                        "params": task.params,
                        "assigned_agent": task.assigned_agent,
                        "retry_count": getattr(task, "retry_count", 0),
                        "max_retries": getattr(task, "max_retries", DEFAULT_MAX_RETRIES),
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
