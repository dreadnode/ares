"""Redis-based task queue for multi-agent communication.

Replaces in-memory asyncio.Queue with Redis Lists for cross-pod messaging.
"""

from __future__ import annotations

import asyncio
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from loguru import logger
from pydantic import BaseModel

from ares.core.config import get_agent_heartbeat_timeout, get_redis_url
from ares.core.redis_client import (
    create_redis_client,
    get_redis_sentinel_config,
    invalidate_sentinel_client,
)


class TaskMessage(BaseModel):
    """Task message structure for Redis queues."""

    task_id: str
    task_type: str  # crack, lateral, acl_analysis, exploit, coercion
    source_agent: str
    target_agent: str  # Role: credential_access, cracker, lateral, acl, privesc, coercion
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
    agent_name: str | None = None

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
    TASK_STATUS_PREFIX = "ares:task_status"
    TASK_STATUS_TTL = 60 * 60 * 24  # 24 hours
    LOCK_PREFIX = "ares:lock"
    STATE_UPDATE_CHANNEL_PREFIX = "ares:state:updates"

    # TTLs
    # Task results kept 24 hours for long operations, recovery, and debugging
    RESULT_TTL = 86400  # 24 hours
    HEARTBEAT_TTL = 60  # 60 seconds

    def __init__(self, redis_url: str | None = None):
        self.redis_url = redis_url or get_redis_url()
        self._client = None
        self._connected = False
        self._heartbeat_ttl = max(self.HEARTBEAT_TTL, get_agent_heartbeat_timeout() * 2)

    @property
    def redis(self):
        """Expose the underlying Redis client for legacy call sites."""
        return self._client

    async def connect(self) -> None:
        """Connect to Redis.

        When called from a non-main thread (e.g., threaded result consumer),
        uses direct connection to avoid SentinelConnectionPool's cross-loop
        Future issues.
        """
        if self._connected:
            return

        # Use direct connection when in a non-main thread to avoid
        # SentinelConnectionPool's async state being shared across event loops
        is_main_thread = threading.current_thread() is threading.main_thread()
        direct_connection = not is_main_thread

        try:
            self._client = await create_redis_client(
                self.redis_url,
                decode_responses=True,  # Auto-decode to strings
                direct_connection=direct_connection,
            )
            await self._client.ping()
            self._connected = True
            if get_redis_sentinel_config():
                conn_type = "direct" if direct_connection else "via Sentinel"
                logger.info(f"TaskQueue connected to Redis {conn_type}")
            else:
                logger.info(f"TaskQueue connected to Redis at {self.redis_url}")

        except Exception as e:
            raise RuntimeError(f"Failed to connect to Redis: {e}") from e

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._client:
            await self._client.aclose()
            self._connected = False
            logger.info("TaskQueue disconnected")

    async def ping_or_reconnect(self, timeout: float = 5.0) -> bool:
        """Ping Redis and reconnect if the connection is stale.

        This should be called periodically to detect stale connections caused by
        Sentinel pod restarts. When a Sentinel pod restarts with a new IP, existing
        connections may hang indefinitely.

        Args:
            timeout: Max seconds to wait for ping response

        Returns:
            True if ping succeeded, False if reconnection was needed
        """
        if not self._client:
            await self.connect()
            return False

        try:
            import asyncio

            await asyncio.wait_for(self._client.ping(), timeout=timeout)
            return True
        except Exception as e:
            logger.warning(f"Redis ping failed ({type(e).__name__}: {e}), forcing reconnection")
            # Invalidate Sentinel client to force fresh DNS resolution
            invalidate_sentinel_client()
            self._connected = False
            try:
                if self._client:
                    await self._client.aclose()
            except Exception:
                pass
            self._client = None
            # Reconnect with fresh Sentinel IPs
            await self.connect()
            logger.info("Reconnected to Redis after ping failure")
            return False

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

    def _task_status_key(self, task_id: str) -> str:
        """Get task status key for a task."""
        return f"{self.TASK_STATUS_PREFIX}:{task_id}"

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
            # Priority-based insertion:
            # - priority <= 2 (urgent): RPUSH to front of queue (processed first)
            # - priority > 2 (normal): LPUSH to back of queue (FIFO order)
            # Workers use BRPOP from right, so RPUSH items are processed immediately.
            if priority <= 2:
                await self._client.rpush(queue_key, task.model_dump_json())
                logger.info(
                    f"Task {task_id} URGENT (priority={priority}) submitted to front of {queue_key}"
                )
            else:
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

    async def check_results_batch(self, task_ids: list[str]) -> dict[str, TaskResult | None]:
        """
        Batch check for task results using Redis pipeline.

        This is significantly faster than sequential check_result calls when
        checking many tasks, as it performs all operations in a single round-trip.
        With N tasks and 30s socket timeout, sequential checking can take up to
        N * 30s during connectivity issues. Pipeline batching reduces this to
        a single timeout window regardless of N.

        Args:
            task_ids: List of task IDs to check

        Returns:
            Dict mapping task_id -> TaskResult (or None if not ready)
        """
        if not task_ids:
            return {}

        if not self._connected:
            await self.connect()

        # Use pipeline for single round-trip
        pipe = self._client.pipeline()
        for task_id in task_ids:
            result_key = self._result_queue_key(task_id)
            pipe.rpop(result_key)

        results: dict[str, TaskResult | None] = {}
        try:
            raw_results = await pipe.execute()
            for task_id, data in zip(task_ids, raw_results, strict=False):
                if data is None:
                    results[task_id] = None
                else:
                    try:
                        results[task_id] = TaskResult.model_validate_json(data)
                    except Exception as e:
                        logger.warning(f"Failed to parse result for {task_id}: {e}")
                        results[task_id] = None
        except Exception as e:
            # On pipeline failure, return empty results (caller will retry)
            logger.warning(f"Pipeline check_results_batch failed: {e}")
            return dict.fromkeys(task_ids)

        return results

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
            # Wrap in asyncio.wait_for to catch hung connections.
            # The Redis timeout parameter only works if the request reaches the server.
            # On a stale/dead TCP connection, the await hangs forever without this.
            result = await asyncio.wait_for(
                self._client.brpop(queue_key, timeout=int(timeout)),
                timeout=timeout + 2.0,  # Extra margin for network latency
            )

            if result is None:
                return None

            _, data = result
            return TaskMessage.model_validate_json(data)

        except asyncio.TimeoutError:
            # asyncio.wait_for timed out but Redis BRPOP didn't return
            # This indicates a stale connection (e.g., Sentinel pod restarted)
            logger.warning(
                f"BRPOP hung for {timeout + 2.0}s on queue {queue_key} - "
                "possible stale Sentinel connection, forcing reconnection"
            )
            invalidate_sentinel_client()
            self._handle_connection_error(
                TimeoutError("BRPOP hung - possible stale Sentinel connection")
            )
            return None

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
        agent_name: str | None = None,
    ) -> None:
        """
        Send task result back to orchestrator.

        Args:
            task_id: Task ID
            success: Whether task succeeded
            result: Task result data
            error: Error message if failed
            worker_pod: Pod that processed the task
            agent_name: Logical agent name (e.g., 'ares-enum')

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
            agent_name=agent_name,
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
        role: str | None = None,
        operation_id: str | None = None,
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
                "role": role,
                "operation_id": operation_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        try:
            await self._client.set(heartbeat_key, data, ex=self._heartbeat_ttl)
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

    async def set_task_status(
        self,
        task_id: str,
        status: str,
        **fields: Any,
    ) -> None:
        """Persist task status with a TTL for debugging/insight."""
        if not self._connected:
            await self.connect()

        data = {"status": status, "updated_at": datetime.now(timezone.utc).isoformat()}
        data.update(fields)
        key = self._task_status_key(task_id)

        try:
            await self._client.set(key, json.dumps(data, default=str), ex=self.TASK_STATUS_TTL)
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

        roles = [
            "cracker",
            "lateral",
            "acl",
            "privesc",
            "coercion",
            "recon",
            "credential_access",
        ]
        stats = {}

        for role in roles:
            stats[role] = await self.get_queue_length(role)

        return stats

    # === Operation Locking ===

    async def acquire_operation_lock(
        self,
        operation_id: str,
        ttl_seconds: int = 7200,
        force: bool = False,
    ) -> bool:
        """
        Acquire exclusive lock for an operation using SETNX.

        Args:
            operation_id: The operation to lock
            ttl_seconds: Lock expiry time (default: 2 hours)
            force: If True, forcefully acquire lock (for resume scenarios)

        Returns:
            True if lock acquired, False if already held by another process
        """
        if not self._connected:
            await self.connect()

        key = f"{self.LOCK_PREFIX}:{operation_id}"

        if force:
            # Force acquire: delete existing lock and set new one
            await self._client.delete(key)
            await self._client.set(key, "locked", ex=ttl_seconds)
            logger.info(f"Force-acquired operation lock for {operation_id}")
            return True

        # SETNX-style: only set if not exists
        result = await self._client.set(key, "locked", nx=True, ex=ttl_seconds)

        if result:
            logger.info(f"Acquired operation lock for {operation_id}")
            return True

        logger.warning(f"Failed to acquire lock for {operation_id} - already held")
        return False

    async def release_operation_lock(self, operation_id: str) -> None:
        """Release the operation lock and clear active pointer if it matches."""
        if not self._connected:
            await self.connect()

        key = f"{self.LOCK_PREFIX}:{operation_id}"
        await self._client.delete(key)
        logger.info(f"Released operation lock for {operation_id}")

        # Clear the active operation pointer if it points to this operation
        try:
            active_op = await self._client.get("ares:op:active")
            if active_op:
                active_op_str = (
                    active_op.decode() if isinstance(active_op, bytes) else str(active_op)
                )
                if active_op_str == operation_id:
                    await self._client.delete("ares:op:active")
                    logger.info(f"Cleared active operation pointer for {operation_id}")
        except Exception as e:
            logger.warning(f"Failed to clear active operation pointer: {e}")

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

    # === Task Retry ===

    async def requeue_task(
        self,
        task_type: str,
        target_role: str,
        payload: dict[str, Any],
        task_id: str,
        retry_count: int = 0,
        source_agent: str = "orchestrator",
        priority: int = 1,  # High priority for retries
    ) -> str:
        """
        Requeue a failed task for retry.

        Unlike submit_task, this pushes to the front of the queue (RPUSH)
        to prioritize retries over new tasks. The task_id is preserved
        so results are correctly tracked.

        Args:
            task_type: Type of task
            target_role: Role to handle the task
            payload: Task-specific data
            task_id: Original task ID (preserved for tracking)
            retry_count: Current retry count
            source_agent: Agent requeuing the task
            priority: Task priority (default 1 = high for retries)

        Returns:
            Task ID (same as input task_id)
        """
        if not self._connected:
            await self.connect()

        # Add retry metadata to payload so workers know this is a retry
        payload_with_retry = {
            **payload,
            "_retry_count": retry_count,
            "_is_retry": True,
        }

        # Keep the same task_id so results are tracked correctly
        task = TaskMessage(
            task_id=task_id,
            task_type=task_type,
            source_agent=source_agent,
            target_agent=target_role,
            payload=payload_with_retry,
            priority=priority,
            callback_queue=self._result_queue_key(task_id),
        )

        queue_key = self._task_queue_key(target_role)

        try:
            # RPUSH to front of queue (workers use BRPOP from right)
            # This prioritizes retried tasks over new ones
            await self._client.rpush(queue_key, task.model_dump_json())

            logger.info(f"Task {task_id} requeued to {queue_key} (retry {retry_count})")
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

    # === Pub/Sub Methods for Real-Time State Updates ===

    def _state_update_channel(self, operation_id: str) -> str:
        """Get the pub/sub channel for state updates."""
        return f"{self.STATE_UPDATE_CHANNEL_PREFIX}:{operation_id}"

    async def publish_state_update(self, operation_id: str) -> int:
        """
        Publish a state update notification to subscribers.

        Workers subscribed to this channel will refresh their shared state
        from Redis when they receive this notification.

        Args:
            operation_id: The operation ID

        Returns:
            Number of subscribers that received the message
        """
        if not self._connected:
            await self.connect()

        channel = self._state_update_channel(operation_id)
        message = json.dumps(
            {
                "type": "state_update",
                "operation_id": operation_id,
                "ts": datetime.now(timezone.utc).isoformat(),
            }
        )

        try:
            count = await self._client.publish(channel, message)
            logger.debug(f"State update published to {channel} ({count} subscribers)")
            return count
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
            # Don't raise - pub/sub failures shouldn't break the main flow
            logger.warning(f"Failed to publish state update: {e}")
            return 0

    async def subscribe_state_updates(self, operation_id: str):
        """
        Subscribe to state update notifications for an operation.

        This returns a pubsub object that can be used to listen for messages.
        The caller is responsible for iterating over messages and closing.

        Args:
            operation_id: The operation ID to subscribe to

        Returns:
            Redis pubsub object with active subscription

        Example:
            pubsub = await queue.subscribe_state_updates(operation_id)
            async for message in pubsub.listen():
                if message["type"] == "message":
                    # Refresh state from Redis
                    ...
            await pubsub.unsubscribe()
            await pubsub.aclose()
        """
        if not self._connected:
            await self.connect()

        channel = self._state_update_channel(operation_id)
        pubsub = self._client.pubsub()
        await pubsub.subscribe(channel)
        logger.info(f"Subscribed to state updates on {channel}")
        return pubsub

    # === Real-Time Discovery Queue ===
    #
    # Workers publish discoveries (credentials, hashes, vulnerabilities) immediately
    # during task execution. The orchestrator polls this queue and can dispatch
    # follow-up tasks (e.g., exploit tasks) without waiting for task completion.

    DISCOVERY_QUEUE_PREFIX = "ares:discoveries"
    DISCOVERY_TTL = 3600  # 1 hour - discoveries also in final result, this is for speed

    def _discovery_queue_key(self, operation_id: str) -> str:
        """Get discovery queue key for an operation."""
        return f"{self.DISCOVERY_QUEUE_PREFIX}:{operation_id}"

    async def publish_discovery(
        self,
        operation_id: str,
        discovery_type: str,
        data: dict,
        source_agent: str = "",
        task_id: str = "",
    ) -> bool:
        """
        Publish a discovery for immediate processing by orchestrator.

        Workers call this when they discover credentials, hashes, vulnerabilities, etc.
        The orchestrator can then dispatch follow-up tasks immediately.

        Args:
            operation_id: The operation ID
            discovery_type: Type of discovery (credential, hash, vulnerability, delegation, etc.)
            data: Discovery data (varies by type)
            source_agent: Agent that made the discovery
            task_id: Task ID that produced this discovery

        Returns:
            True if published successfully
        """
        if not self._connected:
            await self.connect()

        queue_key = self._discovery_queue_key(operation_id)
        message = json.dumps(
            {
                "type": discovery_type,
                "data": data,
                "source_agent": source_agent,
                "task_id": task_id,
                "ts": datetime.now(timezone.utc).isoformat(),
            }
        )

        try:
            await self._client.lpush(queue_key, message)
            await self._client.expire(queue_key, self.DISCOVERY_TTL)
            logger.debug(f"Published {discovery_type} discovery to {queue_key}")
            return True
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
            logger.warning(f"Failed to publish discovery: {e}")
            return False

    async def poll_discoveries(self, operation_id: str, max_items: int = 100) -> list[dict]:
        """
        Poll for pending discoveries (non-blocking).

        Args:
            operation_id: The operation ID
            max_items: Maximum discoveries to retrieve per poll

        Returns:
            List of discovery dicts
        """
        if not self._connected:
            await self.connect()

        queue_key = self._discovery_queue_key(operation_id)
        discoveries = []

        try:
            # Use pipeline for efficiency
            pipe = self._client.pipeline()
            for _ in range(max_items):
                pipe.rpop(queue_key)
            results = await pipe.execute()

            for data in results:
                if data is None:
                    break
                try:
                    discoveries.append(json.loads(data))
                except json.JSONDecodeError:
                    logger.warning(f"Invalid discovery JSON: {data}")

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
            logger.warning(f"Failed to poll discoveries: {e}")

        return discoveries


__all__ = [
    "RedisTaskQueue",
    "TaskMessage",
    "TaskResult",
]
