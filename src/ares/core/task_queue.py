"""Redis-based task queue for multi-agent communication.

Uses Redis Streams with consumer groups for reliable cross-pod task distribution.
Result queues and discovery queues remain List-based (point-to-point, one-shot).
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from loguru import logger
from pydantic import BaseModel

from ares.core.base_task_queue import BaseTaskQueue
from ares.core.circuit_breaker import (
    CircuitBreakerError,
    get_error_debouncer,
    get_redis_circuit,
)
from ares.core.config import (
    get_redis_retry_base_delay,
    get_redis_retry_max_delay,
)
from ares.core.redis_client import (
    get_retry_delay,
    invalidate_sentinel_client,
    is_connection_error,
    timed_redis_write,
)
from ares.core.tracing import IP_PATTERN, is_likely_fqdn, producer_span

# Optional: trace context propagation for cross-process tracing
try:
    from opentelemetry.propagate import inject as otel_inject

    _OTEL_PROPAGATE_AVAILABLE = True
except ImportError:
    _OTEL_PROPAGATE_AVAILABLE = False


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
    # Stream metadata (populated by poll_task, not serialized to Redis)
    stream_entry_id: str | None = None  # Redis Stream entry ID for XACK
    _stream_urgent: bool = False  # Whether consumed from the urgent stream

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


class RedisTaskQueue(BaseTaskQueue):
    """
    Redis-based task queue for inter-pod communication using Streams.

    Queue naming convention:
        - ares:stream:tasks:{role}:urgent  - Urgent task stream (priority <= 2, retries)
        - ares:stream:tasks:{role}:normal  - Normal task stream (priority > 2)
        - ares:cg:tasks:{role}             - Consumer group per role
        - ares:results:{task_id}           - Result queue per task (List, TTL)
        - ares:heartbeat:{agent}           - Agent heartbeat (String, TTL)

    Workers use consumer groups (XREADGROUP) to consume tasks. After processing,
    tasks are acknowledged (XACK). Unacknowledged tasks from crashed consumers
    can be reclaimed via XAUTOCLAIM.

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
            task = await queue.poll_task(role="cracker", timeout=5, consumer_name="worker-0")
            if task:
                result = await process_task(task)
                await queue.send_result(task.task_id, result)
                await queue.ack_task("cracker", task.stream_entry_id, task._stream_urgent)
    """

    # Queue key prefixes
    TASK_QUEUE_PREFIX = "ares:tasks"
    TASK_STREAM_PREFIX = "ares:stream:tasks"
    TASK_GROUP_PREFIX = "ares:cg:tasks"
    RESULT_QUEUE_PREFIX = "ares:results"
    HEARTBEAT_PREFIX = "ares:heartbeat"
    TASK_STATUS_PREFIX = "ares:task_status"
    TASK_STATUS_TTL = 60 * 60 * 24  # 24 hours
    LOCK_PREFIX = "ares:lock"
    STATE_UPDATE_CHANNEL_PREFIX = "ares:state:updates"
    # Stream trimming: approximate max entries per stream to bound memory
    STREAM_MAXLEN = 10000

    def __init__(self, redis_url: str | None = None, use_circuit_breaker: bool = True):
        super().__init__(redis_url)
        self._use_circuit_breaker = use_circuit_breaker
        # Shared circuit breaker and debouncer across all task queue instances
        self._circuit = get_redis_circuit() if use_circuit_breaker else None
        self._debouncer = get_error_debouncer() if use_circuit_breaker else None

    async def connect(self) -> None:
        """Connect to Redis with circuit breaker protection.

        When called from a non-main thread (e.g., threaded result consumer),
        uses direct connection to avoid SentinelConnectionPool's cross-loop
        Future issues.

        Uses socket_timeout=None to allow blocking operations (XREADGROUP, BRPOP)
        to wait for extended periods without hitting socket timeout. Timeout
        control is handled at the application level via asyncio.wait_for.

        Circuit breaker: If the circuit is open, fails fast without attempting
        connection. This prevents thundering herd when Redis is unavailable.
        """
        if self._connected:
            return

        # Check circuit breaker FIRST - fail fast if Redis is known to be down
        if self._circuit and not self._circuit.allow_request_sync():
            remaining = self._circuit._get_remaining_open_time()
            raise CircuitBreakerError(self._circuit.name, remaining)

        try:
            # Use parent's connect for actual connection
            await super().connect()

            # Record success to close circuit if it was half-open
            if self._circuit:
                self._circuit.record_success_sync()

        except CircuitBreakerError:
            raise  # Don't wrap circuit breaker errors

        except Exception as e:
            # Record failure to potentially open circuit
            if self._circuit and is_connection_error(e):
                self._circuit.record_failure_sync(e)
                # Debounce the error log
                if self._debouncer:
                    self._debouncer.log_error_sync(
                        "redis_connect",
                        f"Redis connect failed: {e}",
                        level="warning",
                    )
            raise

    async def _with_circuit_breaker(
        self,
        operation_name: str,
        operation_func,
        *,
        suppress_open_error: bool = False,
    ):
        """Execute a Redis operation with circuit breaker protection.

        When the circuit is open, operations fail-fast instead of trying to
        connect to unavailable Redis. This prevents thundering herd when
        multiple background tasks all discover Redis is down simultaneously.

        IMPORTANT: This method handles connection AND operation failures.
        Pass a callable (lambda or function) that will be called AFTER
        the circuit check, not a coroutine.

        Args:
            operation_name: Name for logging (e.g., "check_results_batch")
            operation_func: Async callable that performs the operation
                           (called AFTER circuit check, so connect() is protected)
            suppress_open_error: If True, return None instead of raising when open

        Returns:
            Result of the operation, or None if circuit is open and suppress_open_error

        Raises:
            CircuitBreakerError: If circuit is open and not suppressed
            Exception: Any exception from the Redis operation
        """
        if not self._circuit:
            # Circuit breaker disabled - execute directly
            return await operation_func()

        # Check if circuit allows request BEFORE trying to connect
        if not self._circuit.allow_request_sync():
            if suppress_open_error:
                # Log with debouncing to reduce spam (sync version for thread safety)
                if self._debouncer:
                    self._debouncer.log_error_sync(
                        f"circuit_open_{operation_name}",
                        f"Circuit breaker open, skipping {operation_name}",
                        level="debug",
                    )
                return None
            remaining = self._circuit._get_remaining_open_time()
            raise CircuitBreakerError(self._circuit.name, remaining)

        try:
            # Now execute the operation (which may include connect())
            result = await operation_func()
            self._circuit.record_success_sync()
            return result
        except Exception as e:
            if is_connection_error(e):
                self._circuit.record_failure_sync(e)
                # Use debouncer for connection errors (sync version)
                if self._debouncer:
                    self._debouncer.log_error_sync(
                        f"redis_error_{operation_name}",
                        f"Redis {operation_name} failed: {e}",
                        level="warning",
                    )
            raise

    def _task_queue_key(self, role: str) -> str:
        """Get legacy task queue key for a role (List-based, kept for reference)."""
        return f"{self.TASK_QUEUE_PREFIX}:{role}"

    def _task_stream_key(self, role: str, urgent: bool = False) -> str:
        """Get task stream key for a role.

        Uses two streams per role for priority support:
        - urgent stream: priority <= 2 tasks and retries (processed first)
        - normal stream: priority > 2 tasks (FIFO)
        """
        suffix = ":urgent" if urgent else ":normal"
        return f"{self.TASK_STREAM_PREFIX}:{role}{suffix}"

    def _task_group_name(self, role: str) -> str:
        """Get consumer group name for a role."""
        return f"{self.TASK_GROUP_PREFIX}:{role}"

    async def _ensure_consumer_group(self, stream_key: str, group_name: str) -> None:
        """Create consumer group if it doesn't exist.

        Uses MKSTREAM to auto-create the stream if needed.
        Silently handles BUSYGROUP error (group already exists).
        """
        try:
            await self.redis.xgroup_create(stream_key, group_name, id="0", mkstream=True)
        except Exception as e:
            # BUSYGROUP means group already exists - that's fine
            if "BUSYGROUP" not in str(e):
                raise

    async def ack_task(self, role: str, stream_entry_id: str, urgent: bool = False) -> None:
        """Acknowledge a task after processing.

        This removes the message from the consumer's Pending Entries List (PEL).
        Unacknowledged messages can be reclaimed by other consumers via XAUTOCLAIM.

        Args:
            role: Worker role
            stream_entry_id: The stream entry ID returned by poll_task
            urgent: Whether the task was from the urgent stream
        """
        stream_key = self._task_stream_key(role, urgent=urgent)
        group_name = self._task_group_name(role)
        try:
            await self.redis.xack(stream_key, group_name, stream_entry_id)
        except Exception as e:
            # Log but don't raise - ack failure shouldn't crash the worker.
            # The message stays in PEL and can be reclaimed later.
            logger.warning(f"Failed to XACK {stream_entry_id} on {stream_key}: {e}")

    async def reclaim_pending_tasks(
        self,
        role: str,
        consumer_name: str,
        min_idle_ms: int = 60_000,
        count: int = 10,
    ) -> list[TaskMessage]:
        """Reclaim tasks from dead consumers using XAUTOCLAIM.

        Called on startup or periodically to pick up unacknowledged messages
        from consumers that crashed.

        Args:
            role: Worker role
            consumer_name: This consumer's name (claims will be reassigned here)
            min_idle_ms: Only reclaim messages idle longer than this (ms)
            count: Max messages to reclaim per call

        Returns:
            List of reclaimed TaskMessages
        """
        reclaimed: list[TaskMessage] = []
        for urgent in (True, False):
            stream_key = self._task_stream_key(role, urgent=urgent)
            group_name = self._task_group_name(role)
            try:
                await self._ensure_consumer_group(stream_key, group_name)
                # XAUTOCLAIM returns (new_start_id, claimed_entries, deleted_ids)
                _, entries, _ = await self.redis.xautoclaim(
                    stream_key,
                    group_name,
                    consumer_name,
                    min_idle_time=min_idle_ms,
                    start_id="0-0",
                    count=count,
                )
                for entry_id, fields in entries:
                    try:
                        task = TaskMessage.model_validate_json(fields["data"])
                        task.stream_entry_id = entry_id
                        task._stream_urgent = urgent
                        reclaimed.append(task)
                    except Exception as e:
                        logger.warning(f"Failed to parse reclaimed entry {entry_id}: {e}")
                        # ACK unparsable entries to prevent infinite reclaim loop
                        await self.redis.xack(stream_key, group_name, entry_id)
            except Exception as e:
                logger.warning(f"XAUTOCLAIM failed on {stream_key}: {e}")
        if reclaimed:
            logger.info(f"Reclaimed {len(reclaimed)} pending tasks for {role}/{consumer_name}")
        return reclaimed

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

        # Target service name for Tempo service graph
        target_service = f"ares-{target_role.replace('_', '-')}-agent"

        # Inject trace context into payload for cross-process trace propagation
        # This allows workers to link their spans back to the orchestrator's span
        payload_with_trace = dict(payload)  # Don't mutate original
        if _OTEL_PROPAGATE_AVAILABLE:
            trace_ctx: dict[str, str] = {}
            otel_inject(trace_ctx)
            if trace_ctx:
                payload_with_trace["_trace_context"] = trace_ctx

        task = TaskMessage(
            task_id=task_id,
            task_type=task_type,
            source_agent=source_agent,
            target_agent=target_role,
            payload=payload_with_trace,
            priority=priority,
            callback_queue=self._result_queue_key(task_id),
        )

        queue_key = self._task_queue_key(target_role)

        # Extract target info from payload for span metrics
        target_ip = None
        target_fqdn = None
        target_user = None

        # Check explicit IP fields first (NOT dc_ip - that's for auth, not target)
        # dc_ip is the domain controller used for authentication, not the attack target
        for field in ("target_ip", "ip"):
            val = payload.get(field)
            if val and IP_PATTERN.match(val):
                target_ip = val
                break

        # Check target_ips list (common in recon/credential_access payloads)
        target_hostname = None
        if not target_ip:
            target_ips = payload.get("target_ips", [])
            if target_ips and isinstance(target_ips, list) and target_ips[0]:
                first_target = target_ips[0]
                if IP_PATTERN.match(first_target):
                    target_ip = first_target
                elif is_likely_fqdn(first_target):
                    target_fqdn = first_target
                elif first_target:
                    # NetBIOS hostname - NOT an FQDN, use target_hostname
                    target_hostname = first_target

        # Check target/host fields - distinguish FQDN from username
        for field in ("target", "host", "hostname"):
            val = payload.get(field)
            if val:
                if IP_PATTERN.match(val):
                    if not target_ip:
                        target_ip = val
                elif "." in val and is_likely_fqdn(val):
                    if not target_fqdn:
                        target_fqdn = val
                elif "." in val:
                    # Has dot but not FQDN -> likely username (e.g., "jane.doe")
                    target_user = val
                # Plain hostname without dots - NOT an FQDN, use target_hostname
                elif val and not target_hostname:
                    target_hostname = val
                break

        if not target_user:
            target_user = (
                payload.get("target_user") or payload.get("username") or payload.get("user")
            )

        # Create PRODUCER span for Tempo service graph
        with producer_span(
            name="submit_task",
            target_service=target_service,
            role=source_agent.replace("ares-", "").replace("-agent", ""),
            team="red",
            target_ip=target_ip,
            target_fqdn=target_fqdn,
            target_hostname=target_hostname,
            target_user=target_user,
            additional_attrs={
                "task.id": task_id,
                "task.type": task_type,
                "task.target_role": target_role,
                "task.priority": priority,
            },
        ):
            try:
                # Priority-based insertion using two streams:
                # - priority <= 2 (urgent): written to the urgent stream (processed first)
                # - priority > 2 (normal): written to the normal stream (FIFO)
                # Workers check the urgent stream before the normal stream.
                task_json = task.model_dump_json()
                is_urgent = priority <= 2
                stream_key = self._task_stream_key(target_role, urgent=is_urgent)
                await self._ensure_consumer_group(stream_key, self._task_group_name(target_role))
                await timed_redis_write(
                    self.redis.xadd(
                        stream_key,
                        {"data": task_json},
                        maxlen=self.STREAM_MAXLEN,
                        approximate=True,
                    ),
                    operation_name=f"submit_task_{task_id}",
                )
                if is_urgent:
                    logger.info(
                        f"Task {task_id} URGENT (priority={priority}) submitted to {stream_key}"
                    )
                else:
                    logger.info(f"Task {task_id} submitted to {stream_key}")
                return task_id

            except asyncio.TimeoutError:
                logger.error(f"Timeout submitting task {task_id} to {queue_key}")
                raise

            except Exception as e:
                if is_connection_error(e):
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
            # Wrap BRPOP in asyncio.wait_for for proper timeout control.
            # The Redis BRPOP timeout only works if the request reaches the server.
            # On stale/dead TCP connections, BRPOP can hang forever without this wrapper.
            # We use timeout + 5s margin to allow BRPOP to return naturally if possible.
            result = await asyncio.wait_for(
                self.redis.brpop(result_key, timeout=int(timeout)),
                timeout=timeout + 5.0,
            )

            if result is None:
                logger.warning(f"Timeout waiting for task {task_id}")
                return None

            # result is (key, value) tuple
            _, data = result
            return TaskResult.model_validate_json(data)

        except asyncio.TimeoutError:
            # asyncio.wait_for timed out - this indicates a stale connection
            # since BRPOP should have returned None before asyncio timeout
            logger.warning(
                f"asyncio timeout waiting for task {task_id} - possible stale connection"
            )
            self._handle_connection_error(TimeoutError("asyncio.wait_for timeout"))
            return None

        except Exception as e:
            if is_connection_error(e):
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
        data = await self.redis.rpop(result_key)

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

        Circuit breaker protection: When Redis is unavailable, the circuit opens
        and subsequent calls fail-fast instead of waiting for timeout.

        Args:
            task_ids: List of task IDs to check

        Returns:
            Dict mapping task_id -> TaskResult (or None if not ready)
        """
        if not task_ids:
            return {}

        async def _execute_batch():
            # Connect inside the circuit breaker so failures are tracked
            if not self._connected:
                await self.connect()
            # Use pipeline for single round-trip
            pipe = self.redis.pipeline()
            for task_id in task_ids:
                result_key = self._result_queue_key(task_id)
                pipe.rpop(result_key)
            return await pipe.execute()

        results: dict[str, TaskResult | None] = {}
        try:
            # Wrap entire operation (including connect) with circuit breaker
            raw_results = await self._with_circuit_breaker(
                "check_results_batch",
                _execute_batch,  # Pass callable, not coroutine
                suppress_open_error=True,
            )

            if raw_results is None:
                # Circuit is open - return empty results
                return dict.fromkeys(task_ids)

            for task_id, data in zip(task_ids, raw_results, strict=False):
                if data is None:
                    results[task_id] = None
                else:
                    try:
                        results[task_id] = TaskResult.model_validate_json(data)
                    except Exception as e:
                        logger.warning(f"Failed to parse result for {task_id}: {e}")
                        results[task_id] = None

        except CircuitBreakerError:
            # Circuit is open - return empty results (already logged by circuit)
            return dict.fromkeys(task_ids)

        except Exception as e:
            # Handle connection errors to force reconnection on next call
            if is_connection_error(e):
                self._handle_connection_error(e)
                # Force fresh DNS resolution on reconnect (handles Sentinel pod restarts)
                invalidate_sentinel_client()
            # On pipeline failure, return empty results (caller will retry)
            # Note: Circuit breaker already logged this if it's a connection error
            if not self._circuit or not is_connection_error(e):
                logger.warning(f"Pipeline check_results_batch failed: {e}")
            return dict.fromkeys(task_ids)

        return results

    # === Worker Methods ===

    async def poll_task(
        self,
        role: str,
        timeout: float = 5.0,
        max_retries: int = 5,
        consumer_name: str = "default",
    ) -> TaskMessage | None:
        """
        Poll for next task using Redis Streams consumer groups.

        Checks the urgent stream first (non-blocking), then blocks on the
        normal stream. This ensures urgent/retry tasks are always processed
        before normal priority tasks.

        Includes automatic retry with exponential backoff on stale connection
        detection to avoid missed poll cycles when Sentinel pods restart.

        Args:
            role: Worker role to poll for
            timeout: How long to block waiting (seconds)
            max_retries: Max retries on stale connection (default: 5, giving 6 total attempts)
            consumer_name: Unique consumer name (typically agent_name or pod_name)

        Returns:
            TaskMessage or None if timeout

        Raises:
            Exception: Re-raises connection errors after marking connection as failed
        """
        urgent_stream = self._task_stream_key(role, urgent=True)
        normal_stream = self._task_stream_key(role, urgent=False)
        group_name = self._task_group_name(role)
        last_error: Exception | None = None
        base_delay = get_redis_retry_base_delay()
        max_delay = get_redis_retry_max_delay()

        for attempt in range(max_retries + 1):
            if not self._connected:
                await self.connect()

            try:
                # Ensure consumer groups exist for both streams
                await self._ensure_consumer_group(urgent_stream, group_name)
                await self._ensure_consumer_group(normal_stream, group_name)

                # 1. Check urgent stream first (non-blocking)
                urgent_result = await self.redis.xreadgroup(
                    group_name,
                    consumer_name,
                    {urgent_stream: ">"},
                    count=1,
                    block=None,  # Non-blocking
                )
                if urgent_result:
                    # urgent_result: [(stream_key, [(entry_id, fields)])]
                    entry_id, fields = urgent_result[0][1][0]
                    task = TaskMessage.model_validate_json(fields["data"])
                    task.stream_entry_id = entry_id
                    task._stream_urgent = True
                    return task

                # 2. Block on normal stream
                # Wrap in asyncio.wait_for to catch hung connections.
                # On a stale/dead TCP connection, the await hangs forever without this.
                timeout_ms = int(timeout * 1000)
                normal_result = await asyncio.wait_for(
                    self.redis.xreadgroup(
                        group_name,
                        consumer_name,
                        {normal_stream: ">"},
                        count=1,
                        block=timeout_ms,
                    ),
                    timeout=timeout + 2.0,  # Extra margin for network latency
                )

                if not normal_result:
                    return None

                entry_id, fields = normal_result[0][1][0]
                task = TaskMessage.model_validate_json(fields["data"])
                task.stream_entry_id = entry_id
                task._stream_urgent = False
                return task

            except asyncio.TimeoutError:
                # asyncio.wait_for timed out but XREADGROUP didn't return
                # This indicates a stale connection (e.g., Sentinel pod restarted)
                logger.warning(
                    f"XREADGROUP hung for {timeout + 2.0}s on {normal_stream} - "
                    f"stale connection detected (attempt {attempt + 1}/{max_retries + 1})"
                )
                invalidate_sentinel_client()
                self._handle_connection_error(
                    TimeoutError("XREADGROUP hung - possible stale Sentinel connection")
                )
                last_error = TimeoutError("XREADGROUP hung after retries")

            except Exception as e:
                if is_connection_error(e):
                    attempt_info = f"attempt {attempt + 1}/{max_retries + 1}"
                    logger.warning(f"Connection error during poll ({attempt_info}): {e}")
                    self._handle_connection_error(e)
                    last_error = e
                else:
                    raise

            # Exponential backoff before retry (except on last attempt)
            if attempt < max_retries:
                delay = get_retry_delay(attempt, base_delay, max_delay)
                logger.info(f"Retrying poll in {delay:.1f}s")
                await asyncio.sleep(delay)

        # All retries exhausted, return None to avoid blocking the worker loop
        if last_error:
            logger.error(f"poll_task failed after {max_retries + 1} attempts: {last_error}")
        return None

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
            # Push result and set TTL with timeout protection
            result_json = task_result.model_dump_json()
            await timed_redis_write(
                self.redis.lpush(result_key, result_json),
                operation_name=f"send_result_{task_id}",
            )
            await timed_redis_write(
                self.redis.expire(result_key, self.RESULT_TTL),
                operation_name=f"expire_result_{task_id}",
            )

            logger.info(f"Result sent for task {task_id}: success={success}")

        except asyncio.TimeoutError:
            logger.error(f"Timeout sending result for task {task_id}")
            raise

        except Exception as e:
            if is_connection_error(e):
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
            await self.redis.set(heartbeat_key, data, ex=self._heartbeat_ttl)
        except Exception as e:
            if is_connection_error(e):
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
            await self.redis.set(key, json.dumps(data, default=str), ex=self.TASK_STATUS_TTL)
        except Exception as e:
            if is_connection_error(e):
                self._handle_connection_error(e)
            raise

    async def get_heartbeat(self, agent_name: str) -> dict[str, Any] | None:
        """
        Get agent heartbeat data.

        Circuit breaker protection: When Redis is unavailable, returns None
        instead of blocking on timeout.

        Raises:
            Exception: Re-raises connection errors after marking connection as failed
        """
        heartbeat_key = self._heartbeat_key(agent_name)

        async def _get_heartbeat():
            if not self._connected:
                await self.connect()
            return await self.redis.get(heartbeat_key)

        try:
            data = await self._with_circuit_breaker(
                "get_heartbeat",
                _get_heartbeat,  # Pass callable, not coroutine
                suppress_open_error=True,
            )

            if data is None:
                return None

            return json.loads(data)

        except CircuitBreakerError:
            # Circuit is open - return None (agent status unknown)
            return None

        except Exception as e:
            if is_connection_error(e):
                self._handle_connection_error(e)
            raise

    async def get_all_heartbeats(self, pattern: str = "*") -> dict[str, dict]:
        """Get all agent heartbeats matching pattern."""
        if not self._connected:
            await self.connect()

        result = {}
        async for key in self.redis.scan_iter(f"{self.HEARTBEAT_PREFIX}:{pattern}"):
            agent_name = key.split(":")[-1]
            data = await self.redis.get(key)
            if data:
                result[agent_name] = json.loads(data)

        return result

    # === Queue Stats ===

    async def get_queue_length(self, role: str) -> int:
        """Get number of pending tasks for a role (sum of urgent + normal streams)."""
        if not self._connected:
            await self.connect()

        urgent_key = self._task_stream_key(role, urgent=True)
        normal_key = self._task_stream_key(role, urgent=False)
        urgent_len = await self.redis.xlen(urgent_key)
        normal_len = await self.redis.xlen(normal_key)
        return urgent_len + normal_len

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
            await self.redis.delete(key)
            await self.redis.set(key, "locked", ex=ttl_seconds)
            logger.info(f"Force-acquired operation lock for {operation_id}")
            return True

        # SETNX-style: only set if not exists
        result = await self.redis.set(key, "locked", nx=True, ex=ttl_seconds)

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
        await self.redis.delete(key)
        logger.info(f"Released operation lock for {operation_id}")

        # Clear the active operation pointer if it points to this operation
        try:
            active_op = await self.redis.get("ares:op:active")
            if active_op:
                active_op_str = (
                    active_op.decode() if isinstance(active_op, bytes) else str(active_op)
                )
                if active_op_str == operation_id:
                    await self.redis.delete("ares:op:active")
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
        result = await self.redis.expire(key, ttl_seconds)
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

        # Retries always go to the urgent stream for priority processing
        stream_key = self._task_stream_key(target_role, urgent=True)

        try:
            await self._ensure_consumer_group(stream_key, self._task_group_name(target_role))
            await self.redis.xadd(
                stream_key,
                {"data": task.model_dump_json()},
                maxlen=self.STREAM_MAXLEN,
                approximate=True,
            )

            logger.info(f"Task {task_id} requeued to {stream_key} (retry {retry_count})")
            return task_id

        except Exception as e:
            if is_connection_error(e):
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
            count = await self.redis.publish(channel, message)
            logger.debug(f"State update published to {channel} ({count} subscribers)")
            return count
        except Exception as e:
            if is_connection_error(e):
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
        pubsub = self.redis.pubsub()
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
            await self.redis.lpush(queue_key, message)
            await self.redis.expire(queue_key, self.DISCOVERY_TTL)
            logger.debug(f"Published {discovery_type} discovery to {queue_key}")
            return True
        except Exception as e:
            if is_connection_error(e):
                self._handle_connection_error(e)
            logger.warning(f"Failed to publish discovery: {e}")
            return False

    async def poll_discoveries(self, operation_id: str, max_items: int = 100) -> list[dict]:
        """
        Poll for pending discoveries (non-blocking).

        Circuit breaker protection: When Redis is unavailable, returns empty
        list instead of blocking on timeout.

        Args:
            operation_id: The operation ID
            max_items: Maximum discoveries to retrieve per poll

        Returns:
            List of discovery dicts
        """
        queue_key = self._discovery_queue_key(operation_id)
        discoveries = []

        async def _execute_poll():
            # Connect inside the circuit breaker so failures are tracked
            if not self._connected:
                await self.connect()
            # Use pipeline for efficiency
            pipe = self.redis.pipeline()
            for _ in range(max_items):
                pipe.rpop(queue_key)
            return await pipe.execute()

        try:
            results = await self._with_circuit_breaker(
                "poll_discoveries",
                _execute_poll,  # Pass callable, not coroutine
                suppress_open_error=True,
            )

            if results is None:
                # Circuit is open - return empty list
                return []

            for data in results:
                if data is None:
                    break
                try:
                    discoveries.append(json.loads(data))
                except json.JSONDecodeError:
                    logger.warning(f"Invalid discovery JSON: {data}")

        except CircuitBreakerError:
            # Circuit is open - return empty list
            return []

        except Exception as e:
            if is_connection_error(e):
                self._handle_connection_error(e)
            # Note: Circuit breaker already logged this if it's a connection error
            if not self._circuit or not is_connection_error(e):
                logger.warning(f"Failed to poll discoveries: {e}")

        return discoveries

    def get_circuit_breaker_status(self) -> dict[str, Any] | None:
        """Get circuit breaker status for monitoring.

        Returns:
            Dict with circuit breaker state, or None if disabled
        """
        if not self._circuit:
            return None
        return self._circuit.get_status()

    async def flush_error_debouncer(self) -> None:
        """Flush pending debounced errors (call on shutdown)."""
        if self._debouncer:
            await self._debouncer.flush()


__all__ = [
    "RedisTaskQueue",
    "TaskMessage",
    "TaskResult",
]
