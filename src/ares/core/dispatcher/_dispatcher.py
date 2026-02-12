"""Central dispatcher for multi-agent red team operations.

This module provides the RedTeamDispatcher class which coordinates
communication and task routing between specialized red team agents
running in Kubernetes pods.

The dispatcher functionality is split across mixin classes for maintainability:
- ThrottlingMixin: Rate limiting and phase detection
- AgentMixin: Agent registration and management
- MessagingMixin: Message queue operations
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
from asyncio import Queue
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.config import get_agent_heartbeat_timeout

# Import all mixins
from ares.core.dispatcher.agents import AgentMixin
from ares.core.dispatcher.announcements import AnnouncementMixin
from ares.core.dispatcher.deferred_queue import DeferredQueueMixin
from ares.core.dispatcher.messaging import MessagingMixin
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

    from ares.core.messages import AgentMessage, MessageType


class RedTeamDispatcher(
    ThrottlingMixin,
    DeferredQueueMixin,
    AgentMixin,
    MessagingMixin,
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
    - Task routing based on agent capabilities
    - Credential/discovery broadcasting
    - State aggregation across agents

    Usage:
        dispatcher = RedTeamDispatcher()
        await dispatcher.start(operation_id)

        # Register agents as they come online
        await dispatcher.register(agent_info)

        # Publish discoveries to all agents
        await dispatcher.publish_credential(credential, "ares-recon")

        # Route tasks to specialized agents
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
        self._message_queues: dict[str, Queue[AgentMessage]] = {}
        self._shared_state: SharedRedTeamState | None = None
        self._subscribers: dict[MessageType, set[str]] = {}
        self._task_callbacks: dict[str, Callable] = {}
        self._running = False
        self._redis_url = redis_url
        self._redis_client = None
        self._heartbeat_task: asyncio.Task | None = None
        self._message_processor_task: asyncio.Task | None = None
        self._agent_heartbeat_timeout = get_agent_heartbeat_timeout()
        self._credential_access_event = asyncio.Event()

        # Redis task queue for cross-pod communication
        self._task_queue: RedisTaskQueue | None = None
        if redis_url:
            self._task_queue = RedisTaskQueue(redis_url)

        # Role-based routing
        self._role_queues: dict[AgentRole, str] = {}  # role -> agent_name

        # Vulnerability priorities (queue is now Redis-backed ZSET, see VulnerabilityMixin)
        self._vulnerability_priorities: dict[str, int] = {
            # Tier 1: Instant DA paths (priority 1-5)
            "krbtgt_hash": 1,  # krbtgt = golden ticket = instant DA
            "domain_admin_hash": 2,  # DA hash = instant DA
            "constrained_delegation": 3,  # S4U with DA impersonation = instant DA
            "unconstrained_delegation": 4,  # DC ticket = krbtgt = DA
            # Tier 2: ADCS attacks (priority 5-7)
            "ADCS_ESC1": 5,
            "ADCS_ESC4": 6,
            "ADCS_ESC8": 7,
            # Tier 3: Direct DA via ACL (priority 8-9)
            "genericall_domain_admins": 8,  # GenericAll on Domain Admins = instant DA
            "gpo_write": 9,  # GPO write on DC-linked GPO = SYSTEM on DC
            # Tier 4: Other ACL and delegation attacks (priority 10-13)
            "acl_abuse": 10,
            "rbcd": 11,
            # Tier 4: MSSQL attacks (priority 12-15)
            "mssql_impersonation": 12,
            "mssql_linked_xpcmdshell": 13,  # xp_cmdshell on linked server
            "mssql_linked": 14,
            "mssql_linked_server": 14,  # Alias for mssql_linked
            "mssql_xp_cmdshell": 15,
            # Tier 5: Other privilege escalation (priority 16-20)
            "gpo_abuse": 16,  # Generic GPO abuse (lower priority than gpo_write)
            "gmsa_readable": 17,  # gMSA password retrieval
            "laps_abuse": 18,
            "dcsync": 19,
            "shadow_credentials": 20,
            # Tier 6: Relay and persistence (priority 21+)
            "smb_relay_target": 21,
            "adminsd_holder_writable": 22,
            "adminsd_holder_acl": 22,  # Alias for detection from BloodHound
        }

        # Task completion futures for wait_for_task
        self._task_futures: dict[str, asyncio.Future[dict[str, Any]]] = {}

        # Track task IDs submitted via Redis for result consumption
        self._redis_task_ids: set[str] = set()
        self._result_consumer_task: asyncio.Task | None = None

        # Rate limiting / throttling state
        self._last_dispatch_time: float = 0.0
        self._rate_limit_errors: int = 0
        self._global_backoff_until: float = 0.0
        # Lock created lazily to avoid event loop binding issues
        self._throttle_lock: asyncio.Lock | None = None

        # Phase tracking for transition logging
        self._last_phase: str = "initial_access"

        # Deferred queue for throttled tasks (queue instead of drop)
        self._init_deferred_queue()

    async def start(self, operation_id: str) -> None:
        """
        Start the dispatcher for an operation.

        Args:
            operation_id: Unique identifier for this operation.
        """
        self._shared_state = SharedRedTeamState(operation_id=operation_id)
        self._running = True

        # Connect to Redis if URL provided
        if self._redis_url:
            try:
                self._redis_client = await create_redis_client(self._redis_url)
                await self._redis_client.ping()
                logger.info(f"Connected to Redis at {self._redis_url}")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}, using in-memory state")

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
        if self._task_queue and self._is_orchestrator:
            self._result_consumer_task = asyncio.create_task(self._result_consumer())
            logger.info("Result consumer started for Redis task completion")

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

        if self._result_consumer_task:
            self._result_consumer_task.cancel()
            try:
                await self._result_consumer_task
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
        """Resolve a task future when task completes."""
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
