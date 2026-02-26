"""Redis-based task queue for blue team multi-agent communication.

Enables distributed blue team workers to poll Redis for tasks and report
results, similar to the red team RedisTaskQueue.

Queue naming convention:
    - ares:blue:tasks:{investigation_id}:{role}  - Task queue per role (List)
    - ares:blue:results:{task_id}                - Result queue per task (List, TTL)
    - ares:blue:heartbeat:{agent}                - Agent heartbeat (String, TTL)
    - ares:blue:active_investigations            - Active investigation IDs (Set)
    - ares:blue:investigation:{id}:meta          - Investigation metadata (Hash)
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from loguru import logger
from pydantic import BaseModel

from ares.core.config import get_agent_heartbeat_timeout, get_redis_url
from ares.core.redis_client import (
    create_redis_client,
    get_redis_sentinel_config,
    invalidate_sentinel_client,
)

if TYPE_CHECKING:
    from redis.asyncio import Redis


class BlueTaskMessage(BaseModel):
    """Task message structure for blue team Redis queues."""

    task_id: str
    task_type: str  # triage_alert, threat_hunt, lateral_analysis, etc.
    investigation_id: str
    assigned_role: str  # triage, threat_hunter, lateral_analyst
    params: dict[str, Any]
    created_at: datetime | None = None

    def __init__(self, **data):
        if data.get("created_at") is None:
            data["created_at"] = datetime.now(timezone.utc)
        super().__init__(**data)


class BlueTaskResult(BaseModel):
    """Task result structure for blue team."""

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


class BlueTaskQueue:
    """Redis-based task queue for blue team inter-pod communication.

    Supports two modes:
    1. Per-investigation queues (legacy): Tasks queued per investigation
    2. Global queues (default): Single queue per role, tasks include investigation_id

    Queue naming convention:
        - ares:blue:tasks:global:{role}              - Global task queue per role (List)
        - ares:blue:tasks:{investigation_id}:{role}  - Per-investigation queue (legacy)
        - ares:blue:results:{task_id}                - Result queue per task (List, TTL)
        - ares:blue:heartbeat:{agent}                - Agent heartbeat (String, TTL)
        - ares:blue:active_investigations            - Active investigation IDs (Set)
        - ares:blue:investigation:{id}:meta          - Investigation metadata (Hash)

    Usage (Orchestrator):
        queue = BlueTaskQueue(redis_url, use_global_queue=True)
        await queue.connect()

        task_id = await queue.submit_task(
            investigation_id="inv-xxx",
            task_type="threat_hunt",
            target_role="threat_hunter",
            params={"technique_id": "T1558.003"},
        )

        result = await queue.wait_for_result(task_id, timeout=300)

    Usage (Worker with global queue):
        queue = BlueTaskQueue(redis_url, use_global_queue=True)
        await queue.connect()

        while True:
            task = await queue.poll_global_task(role="threat_hunter", timeout=5)
            if task:
                result = await process_task(task)
                await queue.send_result(task.task_id, result)
    """

    # Queue key prefixes
    TASK_QUEUE_PREFIX = "ares:blue:tasks"
    GLOBAL_TASK_QUEUE_PREFIX = "ares:blue:tasks:global"
    RESULT_QUEUE_PREFIX = "ares:blue:results"
    HEARTBEAT_PREFIX = "ares:blue:heartbeat"
    INVESTIGATIONS_KEY = "ares:blue:active_investigations"
    INVESTIGATION_META_PREFIX = "ares:blue:investigation"

    # TTLs
    RESULT_TTL = 86400  # 24 hours
    HEARTBEAT_TTL = 60  # 60 seconds
    INVESTIGATION_TTL = 86400  # 24 hours

    def __init__(self, redis_url: str | None = None, use_global_queue: bool = True):
        self.redis_url = redis_url or get_redis_url()
        self.use_global_queue = use_global_queue
        self._client: Redis | None = None
        self._connected = False
        self._heartbeat_ttl = max(self.HEARTBEAT_TTL, get_agent_heartbeat_timeout() * 2)

    @property
    def redis(self) -> Redis:
        """Expose the underlying Redis client for legacy call sites."""
        if self._client is None:
            raise RuntimeError("Not connected to Redis")
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
                decode_responses=True,
                direct_connection=direct_connection,
            )
            await self._client.ping()
            self._connected = True
            if get_redis_sentinel_config():
                conn_type = "direct" if direct_connection else "via Sentinel"
                logger.info(f"BlueTaskQueue connected to Redis {conn_type}")
            else:
                logger.info(f"BlueTaskQueue connected to Redis at {self.redis_url}")

        except Exception as e:
            raise RuntimeError(f"Failed to connect to Redis: {e}") from e

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._client:
            await self._client.aclose()
            self._connected = False
            logger.info("BlueTaskQueue disconnected")

    async def ping_or_reconnect(self, timeout: float = 5.0) -> bool:
        """Ping Redis and reconnect if the connection is stale.

        Args:
            timeout: Max seconds to wait for ping response

        Returns:
            True if ping succeeded, False if reconnection was needed
        """
        if not self._client:
            await self.connect()
            return False

        try:
            await asyncio.wait_for(self._client.ping(), timeout=timeout)
            return True
        except Exception as e:
            logger.warning(f"Redis ping failed ({type(e).__name__}: {e}), forcing reconnection")
            invalidate_sentinel_client()
            self._connected = False
            try:
                if self._client:
                    await self._client.aclose()
            except Exception:
                pass
            self._client = None
            await self.connect()
            logger.info("Reconnected to Redis after ping failure")
            return False

    def _handle_connection_error(self, error: Exception) -> None:
        """Handle Redis connection errors by resetting connection state."""
        self._connected = False
        if self._client:
            self._client = None
        logger.warning(f"Redis connection error, will retry: {error}")

    def _task_queue_key(self, investigation_id: str, role: str) -> str:
        """Get task queue key for a role within an investigation."""
        return f"{self.TASK_QUEUE_PREFIX}:{investigation_id}:{role}"

    def _result_queue_key(self, task_id: str) -> str:
        """Get result queue key for a task."""
        return f"{self.RESULT_QUEUE_PREFIX}:{task_id}"

    def _heartbeat_key(self, agent_name: str) -> str:
        """Get heartbeat key for an agent."""
        return f"{self.HEARTBEAT_PREFIX}:{agent_name}"

    def _investigation_meta_key(self, investigation_id: str) -> str:
        """Get metadata key for an investigation."""
        return f"{self.INVESTIGATION_META_PREFIX}:{investigation_id}:meta"

    # === Investigation Discovery ===

    async def register_investigation(
        self,
        investigation_id: str,
        alert: dict[str, Any],
        model: str | None = None,
        credentials: dict[str, str] | None = None,
    ) -> None:
        """Register an active investigation for workers to discover.

        Args:
            investigation_id: Unique investigation identifier.
            alert: The alert JSON that triggered the investigation.
            model: LLM model to use for workers.
            credentials: API credentials to pass to workers.
        """
        if not self._connected:
            await self.connect()

        # Add to active investigations set
        await self.redis.sadd(self.INVESTIGATIONS_KEY, investigation_id)

        # Store metadata
        meta_key = self._investigation_meta_key(investigation_id)
        meta = {
            "investigation_id": investigation_id,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "alert": json.dumps(alert),
        }
        if model:
            meta["model"] = model
        if credentials:
            meta["credentials"] = json.dumps(credentials)

        await self.redis.hset(meta_key, mapping=meta)
        await self.redis.expire(meta_key, self.INVESTIGATION_TTL)
        await self.redis.expire(self.INVESTIGATIONS_KEY, self.INVESTIGATION_TTL)

        logger.info(f"Registered investigation {investigation_id} for worker discovery")

    async def unregister_investigation(self, investigation_id: str) -> None:
        """Remove an investigation from the active set and delete metadata.

        This triggers workers to stop polling for this investigation's tasks
        and re-discover a new active investigation.
        """
        if not self._connected:
            await self.connect()

        # Remove from active set
        await self.redis.srem(self.INVESTIGATIONS_KEY, investigation_id)

        # Delete metadata so workers detect investigation is no longer active
        meta_key = self._investigation_meta_key(investigation_id)
        await self.redis.delete(meta_key)

        logger.info(f"Unregistered investigation {investigation_id}")

    async def discover_active_investigation(
        self,
        max_wait: int | None = None,
        poll_interval: float = 5.0,
    ) -> str | None:
        """Discover an active investigation to work on.

        Args:
            max_wait: Maximum seconds to wait (None = wait forever).
            poll_interval: Seconds between checks.

        Returns:
            Investigation ID or None if timeout.
        """
        if not self._connected:
            await self.connect()

        start = datetime.now(timezone.utc)

        while True:
            # Get all active investigations
            inv_ids = await self.redis.smembers(self.INVESTIGATIONS_KEY)
            if inv_ids:
                # Return the first one (could prioritize by start time)
                inv_id = next(iter(inv_ids))
                logger.info(f"Discovered active investigation: {inv_id}")
                return inv_id

            # Check timeout
            if max_wait is not None:
                elapsed = (datetime.now(timezone.utc) - start).total_seconds()
                if elapsed >= max_wait:
                    logger.warning(f"No investigation found within {max_wait}s")
                    return None

            await asyncio.sleep(poll_interval)

    async def get_investigation_model(self, investigation_id: str) -> str | None:
        """Get the model configured for an investigation."""
        if not self._connected:
            await self.connect()

        meta_key = self._investigation_meta_key(investigation_id)
        return await self.redis.hget(meta_key, "model")

    async def get_investigation_credentials(self, investigation_id: str) -> dict[str, str]:
        """Get worker credentials for an investigation."""
        if not self._connected:
            await self.connect()

        meta_key = self._investigation_meta_key(investigation_id)
        creds_json = await self.redis.hget(meta_key, "credentials")
        if creds_json:
            try:
                return json.loads(creds_json)
            except json.JSONDecodeError:
                pass
        return {}

    async def get_investigation_alert(self, investigation_id: str) -> dict[str, Any]:
        """Get the alert for an investigation."""
        if not self._connected:
            await self.connect()

        meta_key = self._investigation_meta_key(investigation_id)
        alert_json = await self.redis.hget(meta_key, "alert")
        if alert_json:
            try:
                return json.loads(alert_json)
            except json.JSONDecodeError:
                pass
        return {}

    # === Orchestrator Methods ===

    async def submit_task(
        self,
        investigation_id: str,
        task_type: str,
        target_role: str,
        params: dict[str, Any],
        task_id: str | None = None,
    ) -> str:
        """Submit a task to a role's queue.

        Args:
            investigation_id: Investigation this task belongs to.
            task_type: Type of task (triage_alert, threat_hunt, etc.).
            target_role: Role to handle the task (triage, threat_hunter, etc.).
            params: Task-specific parameters.
            task_id: Optional task ID (generated if not provided).

        Returns:
            Task ID for tracking.
        """
        if not self._connected:
            await self.connect()

        task_id = task_id or f"{task_type}_{uuid.uuid4().hex[:8]}"

        task = BlueTaskMessage(
            task_id=task_id,
            task_type=task_type,
            investigation_id=investigation_id,
            assigned_role=target_role,
            params=params,
        )

        queue_key = self._task_queue_key(investigation_id, target_role)

        try:
            await self.redis.lpush(queue_key, task.model_dump_json())
            await self.redis.expire(queue_key, self.INVESTIGATION_TTL)
            logger.info(f"Task {task_id} submitted to {queue_key}")
            return task_id

        except Exception as e:
            error_str = str(e).lower()
            if any(
                keyword in error_str
                for keyword in ["connection", "closed", "timeout", "broken pipe", "reset"]
            ):
                self._handle_connection_error(e)
            raise

    async def wait_for_result(
        self,
        task_id: str,
        timeout: float = 300.0,
    ) -> BlueTaskResult | None:
        """Wait for a task result.

        Args:
            task_id: Task ID to wait for.
            timeout: Maximum wait time in seconds.

        Returns:
            BlueTaskResult or None if timeout.
        """
        if not self._connected:
            await self.connect()

        result_key = self._result_queue_key(task_id)

        try:
            result = await self.redis.brpop(result_key, timeout=int(timeout))

            if result is None:
                logger.warning(f"Timeout waiting for task {task_id}")
                return None

            _, data = result
            return BlueTaskResult.model_validate_json(data)

        except Exception as e:
            error_str = str(e).lower()
            if any(
                keyword in error_str
                for keyword in ["connection", "closed", "timeout", "broken pipe", "reset"]
            ):
                self._handle_connection_error(e)
            raise

    # === Worker Methods ===

    async def poll_task(
        self,
        investigation_id: str,
        role: str,
        timeout: float = 5.0,
    ) -> BlueTaskMessage | None:
        """Poll for next task (blocking).

        Args:
            investigation_id: Investigation to poll tasks for.
            role: Worker role to poll for.
            timeout: How long to block waiting.

        Returns:
            BlueTaskMessage or None if timeout.
        """
        if not self._connected:
            await self.connect()

        queue_key = self._task_queue_key(investigation_id, role)

        try:
            result = await asyncio.wait_for(
                self.redis.brpop(queue_key, timeout=int(timeout)),
                timeout=timeout + 2.0,
            )

            if result is None:
                return None

            _, data = result
            return BlueTaskMessage.model_validate_json(data)

        except asyncio.TimeoutError:
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
            error_str = str(e).lower()
            if any(
                keyword in error_str
                for keyword in ["connection", "closed", "timeout", "broken pipe", "reset"]
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
        """Send task result back to orchestrator.

        Args:
            task_id: Task ID.
            success: Whether task succeeded.
            result: Task result data.
            error: Error message if failed.
            worker_pod: Pod that processed the task.
            agent_name: Logical agent name.
        """
        if not self._connected:
            await self.connect()

        task_result = BlueTaskResult(
            task_id=task_id,
            success=success,
            result=result,
            error=error,
            worker_pod=worker_pod or os.environ.get("HOSTNAME"),
            agent_name=agent_name,
        )

        result_key = self._result_queue_key(task_id)

        try:
            await self.redis.lpush(result_key, task_result.model_dump_json())
            await self.redis.expire(result_key, self.RESULT_TTL)
            logger.info(f"Result sent for task {task_id}: success={success}")

        except Exception as e:
            error_str = str(e).lower()
            if any(
                keyword in error_str
                for keyword in ["connection", "closed", "timeout", "broken pipe", "reset"]
            ):
                self._handle_connection_error(e)
            raise

    # === Heartbeat Methods ===

    async def heartbeat(
        self,
        agent_name: str,
        status: str = "idle",
        current_task: str | None = None,
    ) -> None:
        """Send worker heartbeat.

        Args:
            agent_name: Agent sending the heartbeat.
            status: Current status (idle, busy).
            current_task: Task ID being processed.
        """
        if not self._connected:
            await self.connect()

        key = self._heartbeat_key(agent_name)
        data = json.dumps(
            {
                "agent_name": agent_name,
                "status": status,
                "current_task": current_task,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "pod": os.environ.get("HOSTNAME", "unknown"),
            }
        )
        await self.redis.setex(key, self._heartbeat_ttl, data)

    async def get_worker_status(self, agent_name: str) -> dict[str, Any] | None:
        """Get status of a worker.

        Args:
            agent_name: Agent to check.

        Returns:
            Status dict or None if no heartbeat.
        """
        if not self._connected:
            await self.connect()

        key = self._heartbeat_key(agent_name)
        data = await self.redis.get(key)
        if data:
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                pass
        return None


__all__ = [
    "BlueTaskMessage",
    "BlueTaskQueue",
    "BlueTaskResult",
]
