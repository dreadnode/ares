"""Redis-based task queue for multi-agent communication.

Replaces in-memory asyncio.Queue with Redis Lists for cross-pod messaging.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from loguru import logger
from pydantic import BaseModel


class TaskMessage(BaseModel):
    """Task message structure for Redis queues."""

    task_id: str
    task_type: str  # crack, lateral, acl_analysis, exploit, poison
    source_agent: str
    target_agent: str  # Role: cracker, lateral, acl, privesc, poisoning
    payload: dict[str, Any]
    priority: int = 5  # 1=urgent, 5=normal, 10=low
    created_at: datetime | None = None
    callback_queue: str | None = None  # Where to send results

    def __init__(self, **data):
        if data.get("created_at") is None:
            data["created_at"] = datetime.now(timezone.utc)
        super().__init__(**data)


class TaskResult(BaseModel):
    """Task result structure."""

    task_id: str
    success: bool
    result: dict[str, Any] | None = None
    error: str | None = None
    completed_at: datetime | None = None
    worker_pod: str | None = None

    def __init__(self, **data):
        if data.get("completed_at") is None:
            data["completed_at"] = datetime.now(timezone.utc)
        super().__init__(**data)


class RedisTaskQueue:
    """
    Redis-based task queue for inter-pod communication.

    Queue naming convention:
        - ares:tasks:{role}        - Task queue per role (List)
        - ares:results:{task_id}   - Result queue per task (List, TTL)
        - ares:tasks:priority:{role} - Priority sorted set (for future use)
        - ares:heartbeat:{agent}   - Agent heartbeat (String, TTL)

    Usage (Orchestrator):
        queue = RedisTaskQueue(redis_url)
        await queue.connect()

        task_id = await queue.submit_task(
            task_type="crack",
            target_role="cracker",
            payload={"hash": "...", "type": "NTLM"},
        )

        result = await queue.wait_for_result(task_id, timeout=300)

    Usage (Worker):
        queue = RedisTaskQueue(redis_url)
        await queue.connect()

        while True:
            task = await queue.poll_task(role="cracker", timeout=5)
            if task:
                result = await process_task(task)
                await queue.send_result(task.task_id, result)
    """

    # Queue key prefixes
    TASK_QUEUE_PREFIX = "ares:tasks"
    RESULT_QUEUE_PREFIX = "ares:results"
    HEARTBEAT_PREFIX = "ares:heartbeat"
    LOCK_PREFIX = "ares:lock"

    # TTLs
    # Task results kept 24 hours for long operations, recovery, and debugging
    RESULT_TTL = 86400  # 24 hours
    HEARTBEAT_TTL = 60  # 60 seconds

    def __init__(self, redis_url: str = "redis://redis.attack-simulation.svc.cluster.local:6379"):
        self.redis_url = redis_url
        self._client = None
        self._connected = False

    async def connect(self) -> None:
        """Connect to Redis."""
        if self._connected:
            return

        try:
            import redis.asyncio as redis

            self._client = redis.from_url(
                self.redis_url,
                decode_responses=True,  # Auto-decode to strings
            )
            await self._client.ping()
            self._connected = True
            logger.info(f"TaskQueue connected to Redis at {self.redis_url}")

        except ImportError as e:
            raise RuntimeError("redis package required: pip install redis") from e
        except Exception as e:
            raise RuntimeError(f"Failed to connect to Redis: {e}") from e

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._client:
            await self._client.aclose()
            self._connected = False
            logger.info("TaskQueue disconnected")

    def _handle_connection_error(self, error: Exception) -> None:
        """
        Handle Redis connection errors by resetting connection state.

        This allows the next operation to attempt reconnection.
        """
        self._connected = False
        if self._client:
            # Don't await here since we're in a sync context
            # The client will be recreated on next connect()
            self._client = None
        logger.warning(f"Redis connection error, will retry: {error}")

    def _task_queue_key(self, role: str) -> str:
        """Get task queue key for a role."""
        return f"{self.TASK_QUEUE_PREFIX}:{role}"

    def _result_queue_key(self, task_id: str) -> str:
        """Get result queue key for a task."""
        return f"{self.RESULT_QUEUE_PREFIX}:{task_id}"

    def _heartbeat_key(self, agent_name: str) -> str:
        """Get heartbeat key for an agent."""
        return f"{self.HEARTBEAT_PREFIX}:{agent_name}"

    # === Orchestrator Methods ===

    async def submit_task(
        self,
        task_type: str,
        target_role: str,
        payload: dict[str, Any],
        source_agent: str = "orchestrator",
        priority: int = 5,
        task_id: str | None = None,
    ) -> str:
        """
        Submit a task to a role's queue.

        Args:
            task_type: Type of task (crack, lateral, exploit, etc.)
            target_role: Role to handle the task (cracker, lateral, privesc, etc.)
            payload: Task-specific data
            source_agent: Agent submitting the task
            priority: Task priority (1=urgent, 10=low)
            task_id: Optional task ID (generated if not provided)

        Returns:
            Task ID for tracking

        Raises:
            Exception: Re-raises connection errors after marking connection as failed
        """
        if not self._connected:
            await self.connect()

        task_id = task_id or f"{task_type}_{uuid.uuid4().hex[:12]}"

        task = TaskMessage(
            task_id=task_id,
            task_type=task_type,
            source_agent=source_agent,
            target_agent=target_role,
            payload=payload,
            priority=priority,
            callback_queue=self._result_queue_key(task_id),
        )

        queue_key = self._task_queue_key(target_role)

        try:
            # LPUSH for FIFO (workers use BRPOP from right)
            await self._client.lpush(queue_key, task.model_dump_json())

            logger.info(f"Task {task_id} submitted to {queue_key}")
            return task_id

        except Exception as e:
            error_str = str(e).lower()
            if any(
                keyword in error_str
                for keyword in [
                    "connection",
                    "connect",
                    "closed",
                    "timeout",
                    "broken pipe",
                    "reset",
                ]
            ):
                self._handle_connection_error(e)
            raise

    async def wait_for_result(
        self,
        task_id: str,
        timeout: float = 300.0,
    ) -> TaskResult | None:
        """
        Wait for a task result.

        Args:
            task_id: Task ID to wait for
            timeout: Maximum wait time in seconds

        Returns:
            TaskResult or None if timeout

        Raises:
            Exception: Re-raises connection errors after marking connection as failed
        """
        if not self._connected:
            await self.connect()

        result_key = self._result_queue_key(task_id)

        try:
            # BRPOP blocks until result available or timeout
            result = await self._client.brpop(result_key, timeout=int(timeout))

            if result is None:
                logger.warning(f"Timeout waiting for task {task_id}")
                return None

            # result is (key, value) tuple
            _, data = result
            return TaskResult.model_validate_json(data)

        except Exception as e:
            error_str = str(e).lower()
            if any(
                keyword in error_str
                for keyword in [
                    "connection",
                    "connect",
                    "closed",
                    "timeout",
                    "broken pipe",
                    "reset",
                ]
            ):
                self._handle_connection_error(e)
            raise

    async def check_result(self, task_id: str) -> TaskResult | None:
        """
        Non-blocking check for task result.

        Args:
            task_id: Task ID to check

        Returns:
            TaskResult or None if not ready
        """
        if not self._connected:
            await self.connect()

        result_key = self._result_queue_key(task_id)
        data = await self._client.rpop(result_key)

        if data is None:
            return None

        return TaskResult.model_validate_json(data)

    # === Worker Methods ===

    async def poll_task(
        self,
        role: str,
        timeout: float = 5.0,
    ) -> TaskMessage | None:
        """
        Poll for next task (blocking).

        Args:
            role: Worker role to poll for
            timeout: How long to block waiting

        Returns:
            TaskMessage or None if timeout

        Raises:
            Exception: Re-raises connection errors after marking connection as failed
        """
        if not self._connected:
            await self.connect()

        queue_key = self._task_queue_key(role)

        try:
            # BRPOP from right for FIFO order
            result = await self._client.brpop(queue_key, timeout=int(timeout))

            if result is None:
                return None

            _, data = result
            return TaskMessage.model_validate_json(data)

        except Exception as e:
            # Check if it's a connection error
            error_str = str(e).lower()
            if any(
                keyword in error_str
                for keyword in [
                    "connection",
                    "connect",
                    "closed",
                    "timeout",
                    "broken pipe",
                    "reset",
                ]
            ):
                self._handle_connection_error(e)
            raise

    async def send_result(
        self,
        task_id: str,
        success: bool,
        result: dict[str, Any] | None = None,
        error: str | None = None,
        worker_pod: str | None = None,
    ) -> None:
        """
        Send task result back to orchestrator.

        Args:
            task_id: Task ID
            success: Whether task succeeded
            result: Task result data
            error: Error message if failed
            worker_pod: Pod that processed the task

        Raises:
            Exception: Re-raises connection errors after marking connection as failed
        """
        if not self._connected:
            await self.connect()

        task_result = TaskResult(
            task_id=task_id,
            success=success,
            result=result,
            error=error,
            worker_pod=worker_pod,
        )

        result_key = self._result_queue_key(task_id)

        try:
            # Push result and set TTL
            await self._client.lpush(result_key, task_result.model_dump_json())
            await self._client.expire(result_key, self.RESULT_TTL)

            logger.info(f"Result sent for task {task_id}: success={success}")

        except Exception as e:
            error_str = str(e).lower()
            if any(
                keyword in error_str
                for keyword in [
                    "connection",
                    "connect",
                    "closed",
                    "timeout",
                    "broken pipe",
                    "reset",
                ]
            ):
                self._handle_connection_error(e)
            raise

    # === Health/Heartbeat Methods ===

    async def send_heartbeat(
        self,
        agent_name: str,
        status: str = "idle",
        current_task: str | None = None,
        pod_name: str | None = None,
    ) -> None:
        """
        Send agent heartbeat.

        Args:
            agent_name: Agent name
            status: Current status (idle, busy, offline)
            current_task: Current task ID if busy
            pod_name: Kubernetes pod name

        Raises:
            Exception: Re-raises connection errors after marking connection as failed
        """
        if not self._connected:
            await self.connect()

        heartbeat_key = self._heartbeat_key(agent_name)
        data = json.dumps(
            {
                "status": status,
                "current_task": current_task,
                "pod_name": pod_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        try:
            await self._client.set(heartbeat_key, data, ex=self.HEARTBEAT_TTL)
        except Exception as e:
            error_str = str(e).lower()
            if any(
                keyword in error_str
                for keyword in [
                    "connection",
                    "connect",
                    "closed",
                    "timeout",
                    "broken pipe",
                    "reset",
                ]
            ):
                self._handle_connection_error(e)
            raise

    async def get_heartbeat(self, agent_name: str) -> dict[str, Any] | None:
        """
        Get agent heartbeat data.

        Raises:
            Exception: Re-raises connection errors after marking connection as failed
        """
        if not self._connected:
            await self.connect()

        heartbeat_key = self._heartbeat_key(agent_name)

        try:
            data = await self._client.get(heartbeat_key)

            if data is None:
                return None

            return json.loads(data)

        except Exception as e:
            error_str = str(e).lower()
            if any(
                keyword in error_str
                for keyword in [
                    "connection",
                    "connect",
                    "closed",
                    "timeout",
                    "broken pipe",
                    "reset",
                ]
            ):
                self._handle_connection_error(e)
            raise

    async def get_all_heartbeats(self, pattern: str = "*") -> dict[str, dict]:
        """Get all agent heartbeats matching pattern."""
        if not self._connected:
            await self.connect()

        result = {}
        async for key in self._client.scan_iter(f"{self.HEARTBEAT_PREFIX}:{pattern}"):
            agent_name = key.split(":")[-1]
            data = await self._client.get(key)
            if data:
                result[agent_name] = json.loads(data)

        return result

    # === Queue Stats ===

    async def get_queue_length(self, role: str) -> int:
        """Get number of pending tasks for a role."""
        if not self._connected:
            await self.connect()

        queue_key = self._task_queue_key(role)
        return await self._client.llen(queue_key)

    async def get_all_queue_stats(self) -> dict[str, int]:
        """Get queue lengths for all roles."""
        if not self._connected:
            await self.connect()

        roles = ["cracker", "lateral", "acl", "privesc", "poisoning", "atomic", "enum"]
        stats = {}

        for role in roles:
            stats[role] = await self.get_queue_length(role)

        return stats

    # === Operation Locking ===

    async def acquire_operation_lock(
        self,
        operation_id: str,
        ttl_seconds: int = 7200,
    ) -> bool:
        """
        Acquire exclusive lock for an operation using SETNX.

        Args:
            operation_id: The operation to lock
            ttl_seconds: Lock expiry time (default: 2 hours)

        Returns:
            True if lock acquired, False if already held by another process
        """
        if not self._connected:
            await self.connect()

        key = f"{self.LOCK_PREFIX}:{operation_id}"
        # SETNX-style: only set if not exists
        result = await self._client.set(key, "locked", nx=True, ex=ttl_seconds)

        if result:
            logger.info(f"Acquired operation lock for {operation_id}")
            return True

        logger.warning(f"Failed to acquire lock for {operation_id} - already held")
        return False

    async def release_operation_lock(self, operation_id: str) -> None:
        """Release the operation lock."""
        if not self._connected:
            await self.connect()

        key = f"{self.LOCK_PREFIX}:{operation_id}"
        await self._client.delete(key)
        logger.info(f"Released operation lock for {operation_id}")

    async def extend_operation_lock(
        self,
        operation_id: str,
        ttl_seconds: int = 7200,
    ) -> bool:
        """
        Extend the lock TTL to prevent expiry during long operations.

        Args:
            operation_id: The operation ID
            ttl_seconds: New TTL in seconds

        Returns:
            True if lock was extended, False if lock not held
        """
        if not self._connected:
            await self.connect()

        key = f"{self.LOCK_PREFIX}:{operation_id}"
        result = await self._client.expire(key, ttl_seconds)
        return bool(result)


__all__ = [
    "RedisTaskQueue",
    "TaskMessage",
    "TaskResult",
]
