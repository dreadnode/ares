"""Operation recovery manager for multi-agent red team operations.

This module provides recovery capabilities for handling pod restarts
and operation recovery in a Kubernetes environment.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from loguru import logger

from ares.core.models import SharedRedTeamState, TaskStatus

if TYPE_CHECKING:
    from ares.core.dispatcher import RedTeamDispatcher
    from ares.core.k8s_executor import KubernetesPodExecutor


class RecoveryError(Exception):
    """Raised when recovery fails."""


class OperationRecoveryManager:
    """
    Handle pod restarts and operation recovery.

    Provides checkpoint/restore functionality using Redis to enable
    recovery from pod crashes in Kubernetes environments.

    Usage:
        manager = OperationRecoveryManager(
            redis_url="redis://redis.attack-simulation.svc.cluster.local:6379",
            k8s_executor=executor,
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
                import redis.asyncio as redis

                self._redis_client = redis.from_url(self._redis_url)
                await self._redis_client.ping()
                logger.info(f"Recovery manager connected to Redis: {self._redis_url}")
            except ImportError:
                logger.warning("redis package not installed, recovery disabled")
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

    async def recover_operation(self, operation_id: str) -> SharedRedTeamState:
        """
        Recover state from last checkpoint.

        Marks in-progress tasks as failed since they were interrupted.

        Args:
            operation_id: The operation ID to recover.

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
                raise RecoveryError(f"No checkpoint found for operation {operation_id}")  # noqa: TRY301

            state = SharedRedTeamState.from_bytes(data)

            # Mark in-progress tasks as failed (they were interrupted)
            interrupted_count = 0
            for _task_id, task in list(state.pending_tasks.items()):
                if task.status == TaskStatus.IN_PROGRESS:
                    task.status = TaskStatus.FAILED
                    task.error = "Pod restart during execution"
                    task.completed_at = datetime.now(timezone.utc)
                    interrupted_count += 1

            if interrupted_count:
                logger.warning(f"Marked {interrupted_count} in-progress tasks as failed")

            # Get checkpoint time for logging
            time_key = f"ares:operation:{operation_id}:checkpoint_time"
            checkpoint_time = await self._redis_client.get(time_key)
            if checkpoint_time:
                logger.info(f"Recovered state from checkpoint at {checkpoint_time.decode()}")

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
            roles = ["orchestrator", "cracker", "acl", "privesc", "lateral", "poisoner"]

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
        Get tasks that were interrupted during recovery.

        Returns:
            List of task info for tasks that need to be retried.
        """
        interrupted = []

        for task_id, task in self.state.pending_tasks.items():
            if task.status == TaskStatus.FAILED and task.error == "Pod restart during execution":
                interrupted.append(
                    {
                        "task_id": task_id,
                        "task_type": task.task_type,
                        "params": task.params,
                        "assigned_agent": task.assigned_agent,
                    }
                )

        return interrupted

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
            "🔄 OPERATION RESUMED AFTER RECOVERY",
            "=" * 50,
            "",
            f"Operation ID: {self.state.operation_id}",
            f"Credentials found: {len(self.state.all_credentials)}",
            f"Hosts discovered: {len(self.state.all_hosts)}",
            f"Domain admin: {'YES ✅' if self.state.has_domain_admin else 'NO ⏳'}",
            "",
        ]

        # Interrupted tasks
        interrupted = self.get_interrupted_tasks()
        if interrupted:
            lines.append(f"⚠️ {len(interrupted)} INTERRUPTED TASKS (may need retry):")
            for task in interrupted[:5]:
                lines.append(f"  • {task['task_type']} -> {task['assigned_agent']}")
            lines.append("")

        # Unexploited vulnerabilities
        unexploited = self.get_unexploited_vulnerabilities()
        if unexploited:
            lines.append(f"🎯 {len(unexploited)} UNEXPLOITED VULNERABILITIES:")
            for vuln in unexploited[:5]:
                lines.append(
                    f"  • {vuln['vuln_type']}: {vuln['target']} (priority {vuln['priority']})"
                )
            lines.append("")

        # Uncracked hashes
        uncracked = self.get_uncracked_hashes()
        if uncracked:
            lines.append(f"#️⃣ {len(uncracked)} UNCRACKED HASHES")
            lines.append("")

        lines.extend(
            [
                "📋 RECOMMENDED ACTIONS:",
                "1. Review agent status with get_agent_status()",
                "2. Check pending tasks with get_pending_tasks()",
                "3. Continue exploitation of pending vulnerabilities",
                "4. Dispatch crack requests for any new hashes",
            ]
        )

        return "\n".join(lines)


__all__ = [
    "OperationRecoveryManager",
    "OperationResumeHelper",
    "RecoveryError",
]
