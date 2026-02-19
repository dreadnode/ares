"""Central dispatcher for multi-agent red team operations.

This module provides the RedTeamDispatcher class which coordinates
communication and task routing between specialized red team agents
running in Kubernetes pods.

The dispatcher functionality is split across mixin classes for maintainability:
- ThrottlingMixin: Rate limiting and phase detection
- AgentMixin: Agent registration and management
- PublishingMixin: Discovery publishing (credentials, hosts, shares, vulnerabilities)
- RoutingMixin: Task routing to specialized agents
- ResultProcessingMixin: Task completion and data extraction
- VulnerabilityMixin: Vulnerability queue management
- MonitoringMixin: Heartbeat and result monitoring
- PersistenceMixin: State checkpointing and recovery
- StatusMixin: Status queries
- AnnouncementMixin: Domain admin and operation announcements
"""

from __future__ import annotations

import asyncio
import threading
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.config import (
    get_agent_heartbeat_timeout,
    get_offload_threshold,
    get_vulnerability_priorities,
)
from ares.core.context_manager import ContextOffloader

# Import all mixins
from ares.core.dispatcher.agents import AgentMixin
from ares.core.dispatcher.announcements import AnnouncementMixin
from ares.core.dispatcher.deferred_queue import DeferredQueueMixin
from ares.core.dispatcher.monitoring import MonitoringMixin
from ares.core.dispatcher.persistence import PersistenceMixin
from ares.core.dispatcher.publishing import PublishingMixin
from ares.core.dispatcher.result_processing import ResultProcessingMixin
from ares.core.dispatcher.routing import RoutingMixin
from ares.core.dispatcher.status import StatusMixin
from ares.core.dispatcher.throttling import ThrottlingMixin
from ares.core.dispatcher.vulnerability import VulnerabilityMixin
from ares.core.models import (
    AgentInfo,
    AgentRole,
    SharedRedTeamState,
)
from ares.core.redis_client import create_redis_client
from ares.core.task_queue import RedisTaskQueue
from ares.core.task_queue import TaskResult as QueueTaskResult

if TYPE_CHECKING:
    from collections.abc import Callable


class RedTeamDispatcher(
    ThrottlingMixin,
    DeferredQueueMixin,
    AgentMixin,
    PublishingMixin,
    RoutingMixin,
    ResultProcessingMixin,
    VulnerabilityMixin,
    MonitoringMixin,
    PersistenceMixin,
    StatusMixin,
    AnnouncementMixin,
):
    """
    Central coordinator for multi-agent red team operations.

    Responsibilities:
    - Agent registration and health monitoring
    - Task routing based on agent capabilities via Redis task queues
    - State aggregation across agents

    Usage:
        dispatcher = RedTeamDispatcher()
        await dispatcher.start(operation_id)

        # Register agents as they come online
        await dispatcher.register(agent_info)

        # Publish discoveries (updates shared state)
        await dispatcher.publish_credential(credential, "ares-recon")

        # Route tasks to specialized agents via Redis
        task_id = await dispatcher.request_crack(hash_data, "orchestrator")
    """

    def __init__(self, redis_url: str | None = None, *, is_orchestrator: bool = True):
        """
        Initialize the dispatcher.

        Args:
            redis_url: Optional Redis URL for state persistence and task queuing.
                       If not provided, uses in-memory state only.
            is_orchestrator: Whether this dispatcher is for the orchestrator (True) or
                            a worker (False). Workers don't run result consumer or
                            stale task cleanup since they only send results, not consume them.
        """
        self._is_orchestrator = is_orchestrator
        self._agents: dict[str, AgentInfo] = {}
        self._shared_state: SharedRedTeamState | None = None
        self._task_callbacks: dict[str, Callable] = {}
        self._running = False
        self._redis_url = redis_url
        self._redis_client = None
        self._heartbeat_task: asyncio.Task | None = None
        self._agent_heartbeat_timeout = get_agent_heartbeat_timeout()
        self._credential_access_event = asyncio.Event()

        # Redis task queue for cross-pod communication
        self._task_queue: RedisTaskQueue | None = None
        if redis_url:
            self._task_queue = RedisTaskQueue(redis_url)

        # Role-based routing
        self._role_queues: dict[AgentRole, str] = {}  # role -> agent_name

        # Vulnerability priorities from config (single source of truth)
        # Lower number = higher priority (exploited first)
        self._vulnerability_priorities: dict[str, int] = get_vulnerability_priorities()

        # Task completion futures for wait_for_task
        self._task_futures: dict[str, asyncio.Future[dict[str, Any]]] = {}

        # Threaded result consumer (initialized in MonitoringMixin methods)
        self._result_consumer_thread: threading.Thread | None = None
        self._result_consumer_stop_event: threading.Event | None = None
        # Asyncio task for maintenance (stale cleanup, reconciliation)
        self._maintenance_task: asyncio.Task | None = None

        # Rate limiting / throttling state
        self._last_dispatch_time: float = 0.0
        self._rate_limit_errors: int = 0
        self._global_backoff_until: float = 0.0
        # Lock created lazily to avoid event loop binding issues
        self._throttle_lock: asyncio.Lock | None = None

        # Phase tracking for transition logging
        self._last_phase: str = "initial_access"

        # Track vulnerabilities that have been dequeued (returned from get_next_vulnerability)
        # Separate from exploited_vulnerabilities to preserve accurate exploitation stats
        self._dequeued_vuln_ids: set[str] = set()

        # Deferred queue for throttled tasks (queue instead of drop)
        self._init_deferred_queue()

        # Signal for threaded consumer to request immediate checkpoint
        self._checkpoint_requested = threading.Event()

        # Thread-safe signal for credential access (asyncio.Event is not thread-safe)
        # Threaded consumer sets this, maintenance loop transfers to asyncio.Event
        self._credential_access_requested = threading.Event()

        # Pending deferred tasks from threaded consumer (processed by main loop)
        # This avoids event loop mismatch when enqueuing from non-main thread
        self._pending_deferred_tasks: list[tuple[str, str, dict, str, int]] = []
        self._deferred_task_requested = threading.Event()
        self._pending_deferred_lock = threading.Lock()

        # Pending task dispatches from threaded consumer (processed by main loop)
        # When _throttled_submit_task is called from non-main thread, it can't use
        # asyncio primitives (locks, event loop time) so we queue for main loop
        self._pending_dispatches: list[tuple[str, str, dict, str, int, float]] = []
        self._dispatch_requested = threading.Event()
        self._pending_dispatch_lock = threading.Lock()

        # Context offloader for large task outputs (initialized in start())
        self._context_offloader: ContextOffloader | None = None

    async def start(self, operation_id: str) -> None:
        """
        Start the dispatcher for an operation.

        Args:
            operation_id: Unique identifier for this operation.

        Raises:
            RuntimeError: If Redis URL is not configured or connection fails.
        """
        if not self._redis_url:
            raise RuntimeError("Redis URL required. Set ARES_REDIS_URL environment variable.")

        self._operation_id = operation_id
        self._shared_state = SharedRedTeamState(operation_id=operation_id)
        self._running = True

        # Connect to Redis (mandatory)
        try:
            self._redis_client = await create_redis_client(self._redis_url)
            await self._redis_client.ping()
            logger.info(f"Connected to Redis at {self._redis_url}")
        except Exception as e:
            raise RuntimeError(f"Redis connection failed: {e}") from e

        # Initialize Redis-native state backend (always enabled)
        from ares.core.state_backend import RedisStateBackend

        backend = RedisStateBackend(self._redis_client, operation_id)
        self._shared_state.set_backend(backend)
        logger.info("Redis-native state backend initialized")

        # Initialize context offloader for large task outputs
        self._context_offloader = ContextOffloader(
            redis=self._redis_client,
            operation_id=operation_id,
            offload_threshold=get_offload_threshold(),
        )
        logger.info(f"Context offloader initialized (threshold: {get_offload_threshold()} chars)")

        # Load processed sets from Redis into memory for sync access
        await self._shared_state.load_processed_sets_from_backend()

        # Load persistence tracking (golden tickets, backdoors, ACL chains, gMSA accounts)
        await self._shared_state.load_persistence_tracking_from_backend()

        # Load MSSQL enum dispatch tracking from Redis
        await self._load_mssql_enum_dispatched()

        # Enable evidence validation Redis persistence
        from ares.core.evidence_validation import load_from_redis, set_redis_client

        set_redis_client(self._redis_client, operation_id)
        await load_from_redis()

        # Load in-progress vulnerability IDs for crash recovery
        await self._load_in_progress_vulns()

        # Load pending tasks for throttle state recovery
        await self._load_pending_tasks()

        # Load completed tasks for task deduplication
        await self._load_completed_tasks()

        # Connect task queue for cross-pod communication
        if self._task_queue:
            try:
                await self._task_queue.connect()
                logger.info("Task queue connected for cross-pod messaging")
            except Exception as e:
                logger.warning(f"Failed to connect task queue: {e}")

        # Start background tasks
        self._heartbeat_task = asyncio.create_task(self._heartbeat_monitor())

        # Start result consumer for Redis-based task completion (orchestrator only)
        # Workers send results via task_queue.send_result(), they don't consume them.
        # Running result consumer on workers causes spurious warnings because workers
        # recover pending_tasks from Redis but never update them when tasks complete.
        #
        # IMPORTANT: The result consumer runs in a SEPARATE THREAD to prevent blocking
        # when the orchestrator's LLM API calls timeout. This mirrors the worker's
        # threaded heartbeat pattern. Without this, 14+ minute freezes can occur
        # when LiteLLM retries timeout (5 retries x 300s = 25 min blocking).
        if self._task_queue and self._is_orchestrator:
            self._start_threaded_result_consumer()
            logger.info("Threaded result consumer started for Redis task completion")

            # Start maintenance task for stale cleanup and reconciliation
            # This runs on the main event loop (okay if it gets blocked occasionally)
            self._maintenance_task = asyncio.create_task(self._maintenance_loop())
            logger.info("Maintenance task started for stale cleanup")

            # Start deferred queue processor (handles throttled tasks)
            await self._start_deferred_processor()

        logger.info(f"Dispatcher started for operation {operation_id}")

    async def stop(self) -> None:
        """Stop the dispatcher and cleanup resources."""
        self._running = False

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        # Stop threaded result consumer (runs in separate thread)
        self._stop_threaded_result_consumer()

        # Stop maintenance task
        if self._maintenance_task:
            self._maintenance_task.cancel()
            try:
                await self._maintenance_task
            except asyncio.CancelledError:
                pass

        # Stop deferred queue processor
        await self._stop_deferred_processor()

        # Cleanup background publish tasks in shared state
        if self._shared_state:
            await self._shared_state.cleanup_background_tasks()

        # Disconnect task queue
        if self._task_queue:
            try:
                await self._task_queue.disconnect()
            except Exception as e:
                logger.warning(f"Error disconnecting task queue: {e}")

        if self._redis_client:
            await self._redis_client.close()

        logger.info("Dispatcher stopped")

    @property
    def shared_state(self) -> SharedRedTeamState:
        """Get the shared state object."""
        if self._shared_state is None:
            raise RuntimeError("Dispatcher not started. Call start() first.")
        return self._shared_state

    @property
    def task_queue(self) -> RedisTaskQueue | None:
        """Get the Redis task queue for direct access if needed."""
        return self._task_queue

    @property
    def context_offloader(self) -> ContextOffloader | None:
        """Get the context offloader for large output management."""
        return self._context_offloader

    # Task Completion Waiting

    async def wait_for_task(
        self,
        task_id: str,
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        """
        Wait for a task to complete.

        Args:
            task_id: The task ID to wait for
            timeout: Maximum time to wait in seconds

        Returns:
            Task result dict with success, result, and error fields

        Raises:
            asyncio.TimeoutError: If task doesn't complete within timeout
        """
        # Check if already completed
        if task_id in self.shared_state.completed_tasks:
            result = self.shared_state.completed_tasks[task_id]
            return {
                "success": result.success,
                "result": result.result,
                "error": result.error,
            }

        # Create future if not exists
        if task_id not in self._task_futures:
            future: asyncio.Future[dict[str, Any]] = asyncio.get_event_loop().create_future()
            self._task_futures[task_id] = future

        try:
            return await asyncio.wait_for(self._task_futures[task_id], timeout=timeout)
        finally:
            # Cleanup future
            self._task_futures.pop(task_id, None)

    def _resolve_task_future(
        self,
        task_id: str,
        success: bool,
        result: Any = None,
        error: str | None = None,
    ) -> None:
        """Resolve a task future when task completes.

        NOTE: This method is skipped when called from non-main thread (e.g., threaded
        result consumer) because asyncio.Future.set_result() is not thread-safe.
        Futures will timeout naturally and be cleaned up by dispatch_and_wait.
        """
        # Skip when in non-main thread - futures are bound to main event loop
        if threading.current_thread() is not threading.main_thread():
            return

        if task_id in self._task_futures:
            future = self._task_futures[task_id]
            if not future.done():
                future.set_result(
                    {
                        "success": success,
                        "result": result,
                        "error": error,
                    }
                )

    # Redis Task Queue Methods

    async def dispatch_and_wait(
        self,
        task_type: str,
        target_role: str,
        payload: dict[str, Any],
        timeout: float = 300.0,
        source_agent: str = "orchestrator",
    ) -> QueueTaskResult | None:
        """
        Submit task and wait for result.

        Convenience method for synchronous-style task dispatch when using
        Redis task queues in Kubernetes multi-pod mode.

        Args:
            task_type: Type of task (crack, lateral, exploit, etc.)
            target_role: Role to handle the task (cracker, lateral, privesc, etc.)
            payload: Task-specific data
            timeout: Maximum wait time in seconds
            source_agent: Agent submitting the task

        Returns:
            QueueTaskResult or None if timeout/not available
        """
        if not self._task_queue:
            logger.error("Task queue not initialized - Redis URL required for dispatch_and_wait")
            return None

        task_id = await self._throttled_submit_task(
            task_type=task_type,
            target_role=target_role,
            payload=payload,
            source_agent=source_agent,
        )

        # Task was queued for main loop dispatch or deferred - can't wait for it
        if task_id in ("deferred", "queued"):
            logger.info(
                f"Task {task_type} {task_id} to background/main loop queue, cannot wait for result"
            )
            return None

        if not task_id:
            logger.warning(f"Task {task_type} dispatch failed")
            return None

        return await self._task_queue.wait_for_result(task_id, timeout=timeout)

    async def wait_for_redis_result(
        self,
        task_id: str,
        timeout: float = 300.0,
    ) -> QueueTaskResult | None:
        """
        Wait for a task result via Redis queue.

        Use this when you've submitted a task via Redis and want to wait
        for the worker to complete it.

        Args:
            task_id: Task ID to wait for
            timeout: Maximum wait time in seconds

        Returns:
            QueueTaskResult or None if timeout/not available
        """
        if not self._task_queue:
            logger.error("Task queue not initialized - cannot wait for Redis result")
            return None

        return await self._task_queue.wait_for_result(task_id, timeout=timeout)


__all__ = ["RedTeamDispatcher"]
