"""Heartbeat and result monitoring for agent health and task completion.

This module provides background tasks for monitoring agent heartbeats
and consuming task results from Redis.

The result consumer runs in a separate thread with its own event loop to
prevent blocking when the main orchestrator's LLM API calls timeout. This
mirrors the pattern used by workers for threaded heartbeats.
"""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, ClassVar

from loguru import logger

from ares.core.config import (
    get_max_concurrent_tasks,
    get_max_redis_consecutive_failures,
    get_redis_retry_base_delay,
    get_redis_retry_max_delay,
    get_redis_url,
    get_stale_task_timeout,
)
from ares.core.models import TaskInfo, TaskStatus

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher
    from ares.core.task_queue import RedisTaskQueue


class MonitoringMixin:
    """Heartbeat and result monitoring for agent health and task completion.

    The result consumer runs in a separate thread to prevent the orchestrator's
    LLM API timeouts from blocking background tasks. This mirrors the worker's
    threaded heartbeat pattern.
    """

    # Rate-limit noisy warnings (class-level to persist across calls)
    _last_hard_cap_warning: float = 0.0
    _hard_cap_warning_interval: float = 30.0  # Only log every 30 seconds
    _last_pickup_warning: float = 0.0
    _pickup_warning_interval: float = 60.0  # Only log pickup warnings every 60 seconds
    # Track tasks we've already warned about - shared across all instances
    # Using a simple class variable here since MonitoringMixin is only used as a mixin
    # and tracking is ephemeral (reset on process restart which is fine)
    _warned_tasks: ClassVar[set[str]] = set()

    # Threaded result consumer state (initialized per-instance in dispatcher)
    _result_consumer_thread: threading.Thread | None = None
    _result_consumer_stop_event: threading.Event | None = None
    _last_result_consumer_iteration: float = 0.0  # For watchdog logging

    def _update_task_activity(
        self: RedTeamDispatcher,
        current_task: str | None,
        now: datetime,
    ) -> None:
        """Update task activity when a worker reports working on it.

        This keeps the task "alive" in stale detection and transitions
        PENDING tasks to IN_PROGRESS when a worker picks them up.
        """
        if not current_task or not self._shared_state:
            return
        task_info = self._shared_state.pending_tasks.get(current_task)
        if not task_info:
            return
        task_info.last_activity_at = now
        if task_info.status == TaskStatus.PENDING:
            task_info.status = TaskStatus.IN_PROGRESS
            task_info.started_at = now

    async def heartbeat(
        self: RedTeamDispatcher,
        agent_name: str,
        status: str,
        current_task: str | None = None,
    ) -> None:
        """
        Process heartbeat from an agent.

        Args:
            agent_name: Name of the agent.
            status: Current status (idle, busy, offline).
            current_task: Current task ID if busy.
        """
        now = datetime.now(timezone.utc)
        if agent_name in self._agents:
            self._agents[agent_name].status = status
            self._agents[agent_name].current_task = current_task
            self._agents[agent_name].last_heartbeat = now

        # Update task activity when worker reports working on it
        self._update_task_activity(current_task, now)

    async def _heartbeat_monitor(self: RedTeamDispatcher) -> None:
        """Background task to monitor agent heartbeats.

        Resilience: Continues running even if individual heartbeat checks fail.
        Connection errors are logged but don't stop the monitor.
        """
        consecutive_failures = 0

        while self._running:
            try:
                now = datetime.now(timezone.utc)

                # For cross-pod workers, read heartbeats from Redis
                if self._task_queue:
                    for agent_name in list(self._agents.keys()):
                        try:
                            heartbeat_data = await self._task_queue.get_heartbeat(agent_name)
                            if heartbeat_data:
                                # Update in-memory state from Redis heartbeat
                                timestamp_str = heartbeat_data.get("timestamp")
                                if timestamp_str:
                                    timestamp = datetime.fromisoformat(timestamp_str)
                                    self._agents[agent_name].last_heartbeat = timestamp
                                    self._agents[agent_name].status = heartbeat_data.get(
                                        "status", "idle"
                                    )
                                    current_task = heartbeat_data.get("current_task")
                                    self._agents[agent_name].current_task = current_task

                                    # Update task activity when worker reports working on it
                                    self._update_task_activity(current_task, now)
                        except Exception as e:
                            # Heartbeat failures could indicate auth issues - log at ERROR level
                            logger.error(
                                f"Failed to get heartbeat for {agent_name}: {e}. "
                                "This may indicate authentication failure or misconfiguration.",
                            )

                # Check for stale heartbeats
                for agent_name, agent_info in list(self._agents.items()):
                    elapsed = (now - agent_info.last_heartbeat).total_seconds()
                    stale_threshold = max(60, self._agent_heartbeat_timeout)
                    if elapsed > stale_threshold and agent_info.status != "offline":
                        logger.warning(
                            f"Agent {agent_name} heartbeat stale ({elapsed:.0f}s) - marking offline"
                        )
                        agent_info.status = "offline"

                # Reset failure counter on success
                consecutive_failures = 0
                await asyncio.sleep(15)

            except asyncio.CancelledError:
                logger.info("Heartbeat monitor cancelled")
                break

            except Exception as e:
                consecutive_failures += 1
                logger.warning(f"Heartbeat monitor error (attempt {consecutive_failures}): {e}")
                # Don't crash - heartbeat failures are less critical than result consumer
                # Just wait and retry
                await asyncio.sleep(min(15, consecutive_failures * 5))

    async def _result_consumer(self: RedTeamDispatcher) -> None:
        """
        Background task to consume results from Redis for completed tasks.

        This bridges the gap between Redis-based workers (which send results via
        task_queue.send_result()) and the dispatcher's in-memory pending_tasks
        tracking. Without this, tasks complete on workers but the orchestrator
        never knows about it.

        Resilience: If Redis becomes unavailable, this consumer will retry with
        exponential backoff. After MAX_REDIS_CONSECUTIVE_FAILURES, it raises
        an exception to crash the orchestrator so Kubernetes can restart it.
        """
        logger.info("Result consumer started")
        consecutive_failures = 0
        health_check_counter = 0  # Log health every N cycles

        while self._running:
            try:
                await self._consume_pending_results()
                # Success - reset failure counter and delay
                if consecutive_failures > 0:
                    logger.info(f"Result consumer recovered after {consecutive_failures} failures")
                consecutive_failures = 0

                # Log throttle health every 30 cycles (~30 seconds)
                health_check_counter += 1
                if health_check_counter >= 30:
                    health_check_counter = 0
                    await self._log_throttle_health()

                await asyncio.sleep(1)

            except asyncio.CancelledError:
                logger.info("Result consumer cancelled")
                break

            except Exception as e:
                consecutive_failures += 1
                # Check if this is a connection-related error
                error_str = str(e).lower()
                is_connection_error = any(
                    keyword in error_str
                    for keyword in [
                        "connection",
                        "connect",
                        "closed",
                        "timeout",
                        "broken pipe",
                        "reset",
                        "refused",
                        "sentinel",
                    ]
                )

                if is_connection_error:
                    # Exponential backoff with cap
                    max_failures = get_max_redis_consecutive_failures()
                    delay = min(
                        get_redis_retry_base_delay() * (2 ** min(consecutive_failures - 1, 4)),
                        get_redis_retry_max_delay(),
                    )
                    logger.warning(
                        f"Result consumer Redis error (attempt {consecutive_failures}/"
                        f"{max_failures}): {e}. Retrying in {delay:.1f}s"
                    )

                    # Fail fast after too many consecutive failures
                    if consecutive_failures >= max_failures:
                        logger.critical(
                            f"Result consumer failed {consecutive_failures} times consecutively. "
                            "Redis appears unavailable. Crashing orchestrator for restart."
                        )
                        raise RuntimeError(
                            f"Redis unavailable after {consecutive_failures} consecutive failures"
                        ) from e

                    await asyncio.sleep(delay)
                else:
                    # Non-connection error - log and continue with normal delay
                    logger.error(f"Result consumer error: {e}", exc_info=True)
                    await asyncio.sleep(1)

        logger.info("Result consumer stopped")

    async def _cleanup_stale_tasks(self: RedTeamDispatcher) -> None:
        """
        Clean up tasks that have been pending for too long.

        This prevents throttle deadlock when:
        - Workers crash without sending results
        - Tasks get lost in Redis
        - Network partitions cause result delivery failures

        Tasks older than stale_task_timeout (from config) are removed from
        pending_tasks (decreases LLM task count and stops result polling).

        Also detects deadlock conditions (at hard cap with no progress) and
        applies aggressive cleanup to break the deadlock.
        """
        if not self._shared_state:
            return

        stale_timeout = get_stale_task_timeout()
        now = datetime.now(timezone.utc)
        stale_task_ids: list[str] = []

        # Count active LLM tasks for deadlock detection
        # Snapshot to avoid "dict changed size during iteration"
        llm_count = sum(
            1
            for t in list(self._shared_state.pending_tasks.values())
            if t.task_type not in ("crack", "command")
            and t.status in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS)
        )
        max_tasks = get_max_concurrent_tasks()
        hard_cap = int(max_tasks * 1.5)

        # Deadlock detection: at hard cap with no recent activity
        # Use shorter timeout when at hard cap to break deadlock faster
        is_at_hard_cap = llm_count >= hard_cap
        effective_timeout = stale_timeout // 2 if is_at_hard_cap else stale_timeout

        if is_at_hard_cap:
            # Rate-limit this warning to avoid log spam (runs every 1s in the loop)
            current_time = time.monotonic()
            if (
                current_time - MonitoringMixin._last_hard_cap_warning
                >= MonitoringMixin._hard_cap_warning_interval
            ):
                MonitoringMixin._last_hard_cap_warning = current_time
                logger.warning(
                    f"Throttle at HARD CAP ({llm_count}/{hard_cap}) - "
                    f"using aggressive stale timeout ({effective_timeout}s)"
                )

        # Early warning for tasks not picked up within 60s
        # This helps identify worker availability issues before they become stale
        pickup_warning_threshold = 60  # seconds
        slow_pickup_tasks: list[tuple[str, str, str, float]] = []  # (task_id, type, agent, age)

        for task_id, task_info in list(self._shared_state.pending_tasks.items()):
            # Only clean up tasks still in PENDING or IN_PROGRESS
            if task_info.status not in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS):
                continue

            # Use last_activity_at for staleness check (more accurate than created_at)
            # Falls back to created_at if last_activity_at is not set
            activity_time = getattr(task_info, "last_activity_at", None) or task_info.created_at
            age_seconds = (now - activity_time).total_seconds()

            # Different timeouts for PENDING vs IN_PROGRESS:
            # - PENDING: task waiting in queue, no worker has picked it up yet.
            #   Use 3x the timeout since it's not "stale", just waiting for a worker.
            # - IN_PROGRESS: worker picked up but went silent. Use normal timeout.
            if task_info.status == TaskStatus.PENDING:
                task_timeout = effective_timeout * 3  # 270s at hard cap, 540s normal
            else:
                task_timeout = effective_timeout

            # MSSQL exploitation chains take longer (6+ tool calls, linked server ops)
            vuln_type = (task_info.params.get("vuln_type") or "") if task_info.params else ""
            if vuln_type == "mssql_cross_forest_pivot":
                task_timeout = max(task_timeout, 720)  # 12 min for cross-forest (multi-hop)
            elif vuln_type.startswith("mssql_"):
                task_timeout = max(task_timeout, 480)  # 8 min for standard MSSQL

            if age_seconds > task_timeout:
                stale_task_ids.append(task_id)
            elif self._should_warn_slow_pickup(
                task_id, task_info, age_seconds, pickup_warning_threshold
            ):
                slow_pickup_tasks.append(
                    (task_id, task_info.task_type, task_info.assigned_agent, age_seconds)
                )
                MonitoringMixin._warned_tasks.add(task_id)

        # Log early warning for slow task pickups
        self._log_slow_pickup_warning(slow_pickup_tasks)

        if stale_task_ids:
            for task_id in stale_task_ids:
                stale_task: TaskInfo | None = self._shared_state.pending_tasks.get(task_id)
                if stale_task is not None:
                    del self._shared_state.pending_tasks[task_id]
                    MonitoringMixin._warned_tasks.discard(task_id)  # Clean up warning tracking

                if stale_task is not None:
                    activity_time = (
                        getattr(stale_task, "last_activity_at", None) or stale_task.created_at
                    )
                    status_desc = (
                        "never picked up by worker"
                        if stale_task.status == TaskStatus.PENDING
                        else "worker went silent"
                    )
                    logger.warning(
                        f"Cleaned up stale task {task_id} ({stale_task.task_type} -> "
                        f"{stale_task.assigned_agent}) - {status_desc}, "
                        f"no activity for {(now - activity_time).total_seconds():.0f}s"
                    )

            logger.info(
                f"Stale task cleanup: removed {len(stale_task_ids)} tasks "
                f"(threshold: {effective_timeout}s, at_hard_cap: {is_at_hard_cap})"
            )

    def _threaded_stale_cleanup(self: RedTeamDispatcher) -> None:
        """Remove stale tasks from pending_tasks dict.

        This runs in the threaded consumer to ensure cleanup happens even when
        the main event loop is blocked by LLM API timeouts. Uses the configured
        stale_task_timeout (default 180s) since LLM API calls can take 60+ seconds.

        NOTE: This only updates in-memory state, not Redis. The main loop's
        _cleanup_stale_tasks handles Redis task ID cleanup when it's available.
        """
        if not self._shared_state:
            return

        now = datetime.now(timezone.utc)
        stale_timeout = get_stale_task_timeout()  # Use config value
        stale_task_ids: list[str] = []

        # Count LLM tasks to determine if we're at hard cap
        # Snapshot to avoid "dict changed size during iteration"
        llm_count = sum(
            1
            for t in list(self._shared_state.pending_tasks.values())
            if t.task_type not in ("crack", "command")
            and t.status in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS)
        )
        max_tasks = get_max_concurrent_tasks()
        hard_cap = int(max_tasks * 1.5)

        # Reduce timeout slightly when severely overloaded, but stay survivable
        if llm_count >= hard_cap * 2:
            stale_timeout = 120  # Still allows LLM calls to complete
        elif llm_count >= hard_cap:
            stale_timeout = 150

        for task_id, task_info in list(self._shared_state.pending_tasks.items()):
            if task_info.status not in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS):
                continue

            activity_time = getattr(task_info, "last_activity_at", None) or task_info.created_at
            age_seconds = (now - activity_time).total_seconds()

            # Different timeouts for PENDING vs IN_PROGRESS:
            # - PENDING: task waiting in queue, no worker picked it up. Use 3x timeout.
            # - IN_PROGRESS: worker picked up but went silent. Use normal timeout.
            if task_info.status == TaskStatus.PENDING:
                task_timeout = stale_timeout * 3
            else:
                task_timeout = stale_timeout

            # MSSQL exploitation chains take longer (6+ tool calls, linked server ops)
            vuln_type = (task_info.params.get("vuln_type") or "") if task_info.params else ""
            if vuln_type == "mssql_cross_forest_pivot":
                task_timeout = max(task_timeout, 720)
            elif vuln_type.startswith("mssql_"):
                task_timeout = max(task_timeout, 480)

            if age_seconds > task_timeout:
                stale_task_ids.append(task_id)

        if stale_task_ids:
            for task_id in stale_task_ids:
                stale_task: TaskInfo | None = self._shared_state.pending_tasks.pop(task_id, None)
                MonitoringMixin._warned_tasks.discard(task_id)

                if stale_task is not None:
                    activity_time = (
                        getattr(stale_task, "last_activity_at", None) or stale_task.created_at
                    )
                    status_desc = (
                        "never picked up by worker"
                        if stale_task.status == TaskStatus.PENDING
                        else "worker went silent"
                    )
                    logger.warning(
                        f"Threaded cleanup: removed stale task {task_id} ({stale_task.task_type} -> "
                        f"{stale_task.assigned_agent}) - {status_desc}, "
                        f"no activity for {(now - activity_time).total_seconds():.0f}s"
                    )

            logger.info(
                f"Threaded stale cleanup: removed {len(stale_task_ids)} tasks "
                f"(threshold: {stale_timeout}s, llm_count: {llm_count}, hard_cap: {hard_cap})"
            )

    def _should_warn_slow_pickup(
        self: RedTeamDispatcher,
        task_id: str,
        task_info: TaskInfo,
        age_seconds: float,
        threshold: float,
    ) -> bool:
        """Check if we should warn about a slow task pickup."""
        return (
            age_seconds > threshold
            and task_info.status == TaskStatus.PENDING
            and task_id not in MonitoringMixin._warned_tasks
        )

    def _log_slow_pickup_warning(
        self: RedTeamDispatcher,
        slow_pickup_tasks: list[tuple[str, str, str, float]],
    ) -> None:
        """Log warning for tasks not picked up by workers within expected time."""
        if not slow_pickup_tasks:
            return

        current_time = time.monotonic()
        if (
            current_time - MonitoringMixin._last_pickup_warning
            < MonitoringMixin._pickup_warning_interval
        ):
            return

        MonitoringMixin._last_pickup_warning = current_time
        task_summary = ", ".join(
            f"{t[0][:12]}({t[1]}->{t[2]}, {t[3]:.0f}s)" for t in slow_pickup_tasks[:5]
        )
        affected_agents = {t[2] for t in slow_pickup_tasks}
        logger.warning(
            f"⚠️ {len(slow_pickup_tasks)} task(s) pending >60s without worker pickup: "
            f"{task_summary}{'...' if len(slow_pickup_tasks) > 5 else ''} - "
            f"check worker availability for {affected_agents}"
        )

    async def _reconcile_tasks_with_workers(self: RedTeamDispatcher) -> None:
        """
        Reconcile pending_tasks with actual worker state.

        Checks if tasks claimed by workers still have active workers processing them.
        If a worker's heartbeat shows it's not working on a task we think it has,
        update the task's activity time to eventually trigger stale cleanup.
        """
        if not self._shared_state or not self._task_queue:
            return

        now = datetime.now(timezone.utc)

        # Build map of what each agent claims to be working on (from heartbeats)
        worker_current_tasks: dict[str, str | None] = {}
        for agent_name in list(self._agents.keys()):
            try:
                heartbeat_data = await self._task_queue.get_heartbeat(agent_name)
                if heartbeat_data:
                    worker_current_tasks[agent_name] = heartbeat_data.get("current_task")
            except Exception:
                pass

        # Check each pending task
        orphaned_count = 0
        for task_id, task_info in list(self._shared_state.pending_tasks.items()):
            if task_info.status != TaskStatus.IN_PROGRESS:
                continue

            agent = task_info.assigned_agent
            worker_task = worker_current_tasks.get(agent)

            # If worker's heartbeat shows it's working on THIS task, update activity
            if worker_task == task_id:
                task_info.last_activity_at = now
            # If worker exists but is working on a DIFFERENT task (or idle), this task may be orphaned
            elif agent in worker_current_tasks and worker_task != task_id:
                orphaned_count += 1
                # Don't immediately clean up - just log. Stale cleanup will handle it
                # based on last_activity_at not being updated.
                task_age = (now - task_info.last_activity_at).total_seconds()
                if task_age > 60:  # Only log if no activity for >60s
                    logger.debug(
                        f"Task {task_id} may be orphaned: assigned to {agent} but "
                        f"worker shows current_task={worker_task}, no activity for {task_age:.0f}s"
                    )

        if orphaned_count > 0:
            logger.info(
                f"Task reconciliation: {orphaned_count} potentially orphaned tasks detected"
            )

    async def _consume_pending_results(self: RedTeamDispatcher) -> None:
        """Check and consume results for all pending Redis tasks."""
        if not self._task_queue:
            logger.warning("Result consumer has no task queue; skipping result checks")
            return

        if not self._shared_state:
            return

        # Periodically clean up stale tasks to prevent throttle deadlock
        await self._cleanup_stale_tasks()

        # Reconcile tasks with workers every cycle to detect orphans
        await self._reconcile_tasks_with_workers()

        task_ids_to_check = list(self._shared_state.pending_tasks.keys())

        for task_id in task_ids_to_check:
            try:
                result = await self._task_queue.check_result(task_id)
                if result:
                    # Result found - process it
                    logger.info(
                        f"Result consumer received result for task {task_id}: "
                        f"success={result.success}"
                    )

                    # Track rate limit status for adaptive throttling
                    if result.success:
                        self.clear_rate_limit_backoff()
                    elif result.error:
                        error_str = str(result.error).lower()
                        rate_limit_indicators = [
                            "rate limit",
                            "rate_limit",
                            "ratelimit",
                            "too many requests",
                            "429",
                            "quota exceeded",
                            "tokens per min",
                            "requests per min",
                            "tpm limit",
                            "rpm limit",
                        ]
                        if any(ind in error_str for ind in rate_limit_indicators):
                            logger.warning(
                                f"Task {task_id} failed with rate limit error - triggering backoff"
                            )
                            self.record_rate_limit_error()

                    # Call complete_task to update dispatcher state
                    await self.complete_task(
                        task_id=task_id,
                        success=result.success,
                        result=result.result,
                        error=result.error,
                        source_agent=result.agent_name or result.worker_pod or "unknown",
                    )
            except Exception as e:
                logger.warning(f"Error checking result for task {task_id}: {e}")

        # Poll for real-time discoveries from workers
        await self._poll_discoveries()

    async def _poll_discoveries(self: RedTeamDispatcher) -> None:
        """
        Poll and process real-time discoveries from workers.

        Workers publish discoveries (delegation findings, credentials, etc.) immediately
        during task execution. This allows the orchestrator to dispatch follow-up tasks
        (e.g., exploit tasks) without waiting for the enumeration task to complete.
        """
        if not self._task_queue:
            return

        if not self._shared_state:
            return
        operation_id = self._shared_state.operation_id

        try:
            discoveries = await self._task_queue.poll_discoveries(operation_id, max_items=50)
            if not discoveries:
                return

            for discovery in discoveries:
                discovery_type = discovery.get("type", "")
                data = discovery.get("data", {})
                source_agent = discovery.get("source_agent", "unknown")
                discovery_task_id = discovery.get("task_id")

                if discovery_type == "delegation":
                    await self._process_realtime_delegation_discovery(data, source_agent)
                elif discovery_type == "credential":
                    await self._process_realtime_credential_discovery(
                        data, source_agent, task_queue=None
                    )
                elif discovery_type == "hash":
                    await self._process_realtime_hash_discovery(
                        data, source_agent, task_queue=None, task_id=discovery_task_id
                    )
                elif discovery_type == "vulnerability":
                    await self._process_realtime_vulnerability_discovery(data, source_agent)
                else:
                    logger.debug(f"Unknown discovery type: {discovery_type}")

        except Exception as e:
            logger.warning(f"Error polling discoveries: {e}")

    async def _process_realtime_delegation_discovery(
        self: RedTeamDispatcher, data: dict, source_agent: str, task_queue: Any = None
    ) -> None:
        """Process a real-time delegation discovery and dispatch exploit if applicable.

        Args:
            data: Delegation discovery data dict
            source_agent: Agent that discovered the delegation
            task_queue: Optional task queue for thread-safe Redis operations.
                        When called from threaded consumer, pass the thread's queue.
        """
        account = data.get("account", "")
        delegation_type = data.get("delegation_type", "").lower()
        target_spn = data.get("target_spn", "")

        if not account or not delegation_type:
            return

        vuln_type = (
            "constrained_delegation"
            if delegation_type == "constrained"
            else "unconstrained_delegation"
        )

        logger.info(
            f"📡 Processing real-time {vuln_type} discovery: {account} -> {target_spn or 'any'}"
        )

        # Queue vulnerability and dispatch exploit using existing logic
        # This reuses _auto_queue_delegation_vulnerabilities which handles deduplication
        queued = await self._auto_queue_delegation_vulnerabilities(
            [data], source_agent, task_queue=task_queue
        )
        if queued > 0:
            logger.warning(
                f"🚀 Real-time delegation exploit dispatched for {account} "
                f"(queued {queued} vuln(s))"
            )

    async def _process_realtime_credential_discovery(
        self: RedTeamDispatcher, data: dict, source_agent: str, task_queue: Any = None
    ) -> None:
        """Process a real-time credential discovery."""
        from ares.core.models import Credential

        username = data.get("username", "")
        password = data.get("password", "")
        domain = data.get("domain", "")

        if not username or not password:
            return

        cred = Credential(
            username=username,
            password=password,
            domain=domain,
            source=f"realtime:{source_agent}",
            is_admin=data.get("is_admin", False),
        )

        # publish_credential handles deduplication and triggers auto-exploit
        await self.publish_credential(cred, source_agent, task_queue=task_queue)
        logger.info(f"📡 Real-time credential: {domain}\\{username}")

    async def _process_realtime_hash_discovery(
        self: RedTeamDispatcher,
        data: dict,
        source_agent: str,
        task_queue: Any = None,
        task_id: str | None = None,
    ) -> None:
        """Process a real-time hash discovery."""
        from ares.core.models import Hash

        username = data.get("username", "")
        hash_value = data.get("hash_value", "")
        hash_type = data.get("hash_type", "NTLM")
        domain = data.get("domain", "")

        if not username or not hash_value:
            return

        # Look up parent credential and target from task params for attack chain tracking
        parent_credential_id: str | None = None
        parent_attack_step: int = 0
        target_ip: str | None = None

        # First try to get target from the data payload itself (worker may include it)
        target_ip = data.get("target") or data.get("target_ip") or data.get("target_host")
        logger.info(
            f"_process_realtime_hash_discovery: domain={domain}, target_from_data={target_ip}, task_id={task_id}"
        )

        # Fallback to task params if not in data
        if not target_ip and task_id and self._shared_state:
            task_info = self._shared_state.pending_tasks.get(task_id)
            if task_info and task_info.params:
                parent_credential_id = task_info.params.get("parent_credential_id")
                parent_attack_step = int(task_info.params.get("parent_attack_step", 0) or 0)
                # Get target IP for domain resolution
                target_ip = task_info.params.get("target") or task_info.params.get("target_host")
                if not target_ip:
                    target_ips = task_info.params.get("target_ips", [])
                    if target_ips and isinstance(target_ips, list):
                        target_ip = target_ips[0]
            logger.info(f"_process_realtime_hash_discovery: target_from_task_params={target_ip}")

        # Resolve NetBIOS domain names (e.g., "CHILD") to FQDN (e.g., "child.contoso.local")
        # This handles domain-prefixed secretsdump output like "CHILD\krbtgt:..."
        if domain and "." not in domain and self._shared_state:
            resolved = self._shared_state._resolve_netbios_to_fqdn(domain)
            if resolved != domain:
                logger.debug(f"Resolved NetBIOS domain: {domain} -> {resolved}")
                domain = resolved

        # Fallback to domain resolved from target host if still empty or unresolved NetBIOS
        # (non-domain-prefixed secretsdump output: "user:rid:lmhash:nthash:::")
        # This correctly handles child domain DCs (e.g., dc02 serves child.contoso.local)
        if not domain or (domain and "." not in domain):
            target_domain = self._resolve_domain_from_target_host(target_ip)
            if target_domain and "." in target_domain:
                domain = target_domain

        aes_key = data.get("aes_key") or ""

        hash_obj = Hash(
            username=username,
            hash_value=hash_value,
            hash_type=hash_type,
            domain=domain,
            source=f"realtime:{source_agent}",
            parent_id=parent_credential_id,
            attack_step=parent_attack_step + 1 if parent_credential_id else 0,
            aes_key=aes_key,
        )

        # publish_hash handles deduplication, DA detection, and immediate crack dispatch
        await self.publish_hash(hash_obj, source_agent, task_queue=task_queue)
        logger.info(
            f"📡 Real-time hash: {domain}\\{username} ({hash_type}) "
            f"[source: {source_agent}, target: {target_ip or 'unknown'}]"
        )

    async def _process_realtime_vulnerability_discovery(
        self: RedTeamDispatcher, data: dict, source_agent: str, task_queue: Any = None
    ) -> None:
        """Process a real-time vulnerability discovery and queue for exploitation."""
        from ares.core.models import VulnerabilityInfo

        vuln_type = data.get("vuln_type", "")
        target = data.get("target", "")
        vuln_id = data.get("vuln_id", "")

        if not vuln_type or not target:
            return

        # Generate vuln_id if not provided (must match queue_vulnerability format)
        normalized_type = vuln_type.lower()
        if not vuln_id:
            vuln_id = f"{normalized_type}_{target}_{uuid.uuid4().hex[:8]}"

        # Check for duplicates by type+target (same logic as queue_vulnerability)
        # Snapshot to avoid "dict changed size during iteration" from threaded consumer
        for existing in list(self.shared_state.discovered_vulnerabilities.values()):
            if existing.vuln_type.lower() == normalized_type and existing.target == target:
                logger.debug(
                    f"Skipping duplicate vulnerability: {existing.vuln_id} "
                    f"(type={normalized_type}, target={target})"
                )
                return

        # Create and store vulnerability
        # Defensive: ensure details is always a dict (may be string from improper serialization)
        raw_details = data.get("details", {})
        details = raw_details if isinstance(raw_details, dict) else {}
        priority = data.get("priority", 5)

        vuln = VulnerabilityInfo(
            vuln_id=vuln_id,
            vuln_type=vuln_type,
            target=target,
            discovered_by=f"realtime:{source_agent}",
            details=details,
            priority=priority,
        )

        self.shared_state.discovered_vulnerabilities[vuln_id] = vuln
        logger.warning(f"📡 Real-time vulnerability: {vuln_type} on {target}")

        # Auto-dispatch exploit task for high-value vulnerabilities
        high_value_vulns = {
            "constrained_delegation",
            "unconstrained_delegation",
            "esc1",
            "esc4",
            "esc8",
            "adcs_esc1",
            "adcs_esc4",
            "adcs_esc8",
            "mssql_impersonation",
            "mssql_cross_forest_pivot",
        }

        # Auto-dispatch exploit for high-value vulnerabilities
        if vuln_type.lower() in high_value_vulns:
            await self.request_exploit(
                vuln_type, vuln_id, target, source_agent, details, task_queue=task_queue
            )
            logger.warning(f"🚀 Auto-dispatched exploit for {vuln_type} on {target}")

    async def _ping_or_reconnect_dispatcher_redis(
        self: RedTeamDispatcher, timeout: float = 5.0
    ) -> bool:
        """Ping dispatcher's Redis client and reconnect if stale.

        The dispatcher has its own _redis_client separate from _task_queue.
        Both need health checking to detect stale Sentinel connections after
        pod restarts.

        Args:
            timeout: Max seconds to wait for ping response

        Returns:
            True if ping succeeded, False if reconnection was needed
        """
        if not self._redis_client:
            return True  # No client to check

        try:
            await asyncio.wait_for(self._redis_client.ping(), timeout=timeout)
            return True
        except Exception as e:
            logger.warning(
                f"Dispatcher Redis ping failed ({type(e).__name__}: {e}), forcing reconnection"
            )
            # Invalidate Sentinel client to force fresh DNS resolution
            from ares.core.redis_client import create_redis_client, invalidate_sentinel_client

            invalidate_sentinel_client()

            # Close stale client
            try:
                await self._redis_client.aclose()
            except Exception:
                pass
            self._redis_client = None

            # Reconnect with fresh Sentinel IPs
            try:
                self._redis_client = await create_redis_client(self._redis_url)
                await self._redis_client.ping()

                # Update state backend with new client
                if self._shared_state and hasattr(self._shared_state, "_backend"):
                    from ares.core.state_backend import RedisStateBackend

                    backend = RedisStateBackend(self._redis_client, self._shared_state.operation_id)
                    self._shared_state.set_backend(backend)

                # Update context offloader with new client
                if self._context_offloader:
                    self._context_offloader._redis = self._redis_client

                logger.info("Dispatcher Redis client reconnected successfully")
                return False
            except Exception as reconnect_error:
                logger.error(f"Dispatcher Redis reconnection failed: {reconnect_error}")
                raise

    async def _maintenance_loop(self: RedTeamDispatcher) -> None:
        """
        Background task for stale cleanup, task reconciliation, and periodic checkpointing.

        This runs on the main event loop, separate from the threaded result consumer.
        It's okay if this gets blocked occasionally by LLM timeouts since it handles
        less critical maintenance operations. The critical result consumption path
        runs in the threaded consumer.

        Checkpointing is done here (not in the threaded consumer) because the Redis
        client is bound to the main event loop.
        """
        logger.info("Maintenance loop started")
        consecutive_failures = 0
        checkpoint_interval = 10  # seconds
        health_log_interval = 30  # seconds
        connection_check_interval = 15  # seconds - check Redis health frequently
        last_checkpoint = 0.0
        last_health_log = 0.0
        last_connection_check = 0.0

        while self._running:
            try:
                # Clean up stale tasks to prevent throttle deadlock
                await self._cleanup_stale_tasks()

                # Reconcile tasks with workers to detect orphans
                await self._reconcile_tasks_with_workers()

                now = time.monotonic()

                # Check Redis connection health to detect stale Sentinel connections
                # This catches issues when Sentinel pods restart with new IPs
                # Both _task_queue and _redis_client need health checks - they are separate clients
                if now - last_connection_check >= connection_check_interval:
                    # Check task queue Redis client
                    if self._task_queue:
                        try:
                            ping_ok = await self._task_queue.ping_or_reconnect(timeout=5.0)
                            if not ping_ok:
                                logger.warning("Task queue Redis was stale, reconnected")
                        except Exception as e:
                            logger.error(f"Task queue Redis health check failed: {e}")

                    # Check dispatcher's Redis client (used for state persistence, vulns, etc.)
                    if self._redis_client:
                        try:
                            ping_ok = await self._ping_or_reconnect_dispatcher_redis(timeout=5.0)
                            if not ping_ok:
                                logger.warning("Dispatcher Redis was stale, reconnected")
                        except Exception as e:
                            logger.error(f"Dispatcher Redis health check failed: {e}")

                    last_connection_check = now

                # Log throttle health periodically (uses Redis, must run on main loop)
                if now - last_health_log >= health_log_interval:
                    await self._log_throttle_health()
                    last_health_log = now

                # Checkpoint if requested by threaded consumer or on periodic interval
                checkpoint_requested = self._checkpoint_requested.is_set()
                if checkpoint_requested or now - last_checkpoint >= checkpoint_interval:
                    if checkpoint_requested:
                        self._checkpoint_requested.clear()
                        logger.info(
                            f"⚡ Immediate checkpoint triggered by threaded consumer (creds={len(self.shared_state.all_credentials)})"
                        )
                    await self._checkpoint()
                    last_checkpoint = now

                # Transfer thread-safe credential access signal to asyncio.Event
                # This wakes up _auto_credential_access immediately instead of waiting 60s
                if self._credential_access_requested.is_set():
                    self._credential_access_requested.clear()
                    self.signal_credential_access()
                    logger.debug("Credential access signal transferred from threaded consumer")

                # Process pending deferred tasks from threaded consumer
                # These were queued because the threaded consumer can't access Redis directly
                await self._process_pending_deferred_tasks()

                # Process pending task dispatches from threaded consumer
                # These were queued because _throttled_submit_task can't use asyncio primitives
                # from a non-main thread (locks, event loop time, etc.)
                await self._process_pending_dispatches()

                # Reset failure counter on success
                consecutive_failures = 0

                # Run maintenance every 2 seconds to respond quickly to checkpoint requests
                await asyncio.sleep(2)

            except asyncio.CancelledError:
                logger.info("Maintenance loop cancelled")
                break

            except Exception as e:
                consecutive_failures += 1
                logger.warning(f"Maintenance loop error (attempt {consecutive_failures}): {e}")
                # Don't crash - maintenance failures are less critical
                await asyncio.sleep(min(15, consecutive_failures * 5))

        logger.info("Maintenance loop stopped")

    async def _process_pending_deferred_tasks(self: RedTeamDispatcher) -> None:
        """Process deferred tasks queued by the threaded consumer.

        The threaded result consumer can't call _enqueue_deferred_task directly
        because it uses the main thread's Redis client. Instead, it queues tasks
        in _pending_deferred_tasks and sets _deferred_task_requested. This method
        processes those pending tasks on the main event loop.
        """
        if not self._deferred_task_requested.is_set():
            return

        self._deferred_task_requested.clear()

        # Atomically get and clear pending tasks
        with self._pending_deferred_lock:
            tasks_to_process = self._pending_deferred_tasks.copy()
            self._pending_deferred_tasks.clear()

        if not tasks_to_process:
            return

        logger.info(
            f"Processing {len(tasks_to_process)} pending deferred tasks from threaded consumer"
        )

        for task_type, target_role, payload, source_agent, priority in tasks_to_process:
            try:
                # Now we're on the main thread, so Redis operations will work
                queued = await self._enqueue_deferred_task(
                    task_type=task_type,
                    target_role=target_role,
                    payload=payload,
                    source_agent=source_agent,
                    priority=priority,
                )
                if not queued:
                    logger.warning(
                        f"Failed to enqueue deferred task from threaded consumer: "
                        f"{task_type} -> {target_role}"
                    )
            except Exception as e:
                logger.error(f"Error processing pending deferred task: {e}")

    async def _process_pending_dispatches(self: RedTeamDispatcher) -> None:
        """Process task dispatches queued by the threaded consumer.

        The threaded result consumer can't call _throttled_submit_task directly
        because it uses asyncio primitives bound to the main event loop (locks,
        event loop time). Instead, it queues dispatch requests in _pending_dispatches
        and sets _dispatch_requested. This method processes those requests on the
        main event loop where the asyncio primitives work correctly.
        """
        if not self._dispatch_requested.is_set():
            return

        self._dispatch_requested.clear()

        # Atomically get and clear pending dispatches
        with self._pending_dispatch_lock:
            dispatches_to_process = self._pending_dispatches.copy()
            self._pending_dispatches.clear()

        if not dispatches_to_process:
            return

        logger.info(
            f"Processing {len(dispatches_to_process)} pending task dispatches from threaded consumer"
        )

        for (
            task_type,
            target_role,
            payload,
            source_agent,
            priority,
            max_wait,
        ) in dispatches_to_process:
            try:
                # Now we're on the main thread, so asyncio operations will work
                task_id = await self._throttled_submit_task(
                    task_type=task_type,
                    target_role=target_role,
                    payload=payload,
                    source_agent=source_agent,
                    priority=priority,
                    max_wait=max_wait,
                )
                if not task_id:
                    logger.debug(
                        f"Task dispatch from threaded consumer returned no ID: "
                        f"{task_type} -> {target_role}"
                    )
                elif task_id in ("deferred", "queued"):
                    # Task was deferred again (rare) - skip TaskInfo creation
                    logger.debug(
                        f"Task dispatch from threaded consumer {task_id}: "
                        f"{task_type} -> {target_role}"
                    )
                else:
                    # Task was successfully submitted - create TaskInfo for tracking
                    # This is critical: without this, results for tasks dispatched from
                    # the threaded consumer would never be processed (no entry in pending_tasks)
                    from ares.core.models import TaskInfo

                    task_info = TaskInfo(
                        task_id=task_id,
                        task_type=task_type,
                        assigned_agent=target_role,
                        params=payload,
                    )
                    if self._shared_state:
                        # Write to Redis FIRST (source of truth), then cache in memory
                        await self._persist_task_info_to_redis(task_id, task_info)
                        self._shared_state.pending_tasks[task_id] = task_info
                        logger.info(
                            f"Task {task_id} ({task_type}) submitted from pending dispatch, "
                            f"added to pending_tasks for result tracking"
                        )
            except Exception as e:
                logger.error(f"Error processing pending task dispatch: {e}")

    async def _log_throttle_health(self: RedTeamDispatcher) -> None:
        """
        Log throttle health status for observability.

        Call periodically to track throttle state and detect potential deadlocks.
        """
        if not self._shared_state:
            return

        # Count tasks by status
        pending_count = 0
        in_progress_count = 0
        llm_count = 0
        oldest_task_age = 0.0
        now = datetime.now(timezone.utc)

        # Snapshot to avoid "dict changed size during iteration"
        for task_info in list(self._shared_state.pending_tasks.values()):
            if task_info.status == TaskStatus.PENDING:
                pending_count += 1
            elif task_info.status == TaskStatus.IN_PROGRESS:
                in_progress_count += 1

            if task_info.task_type not in ("crack", "command") and task_info.status in (
                TaskStatus.PENDING,
                TaskStatus.IN_PROGRESS,
            ):
                llm_count += 1

            # Track oldest task
            activity_time = getattr(task_info, "last_activity_at", None) or task_info.created_at
            age = (now - activity_time).total_seconds()
            oldest_task_age = max(oldest_task_age, age)

        max_tasks = get_max_concurrent_tasks()
        hard_cap = int(max_tasks * 1.5)

        # Get deferred queue status (async - Redis-backed)
        deferred_status: dict[str, Any] = {}
        if hasattr(self, "get_deferred_queue_status"):
            deferred_status = await self.get_deferred_queue_status()
        deferred_total = deferred_status.get("total_queued", 0)

        # Log warning if at hard cap or tasks are very old
        if llm_count >= hard_cap or oldest_task_age > 120:
            logger.warning(
                f"Throttle health: llm_tasks={llm_count}/{max_tasks} (hard_cap={hard_cap}), "
                f"pending={pending_count}, in_progress={in_progress_count}, "
                f"deferred={deferred_total}, oldest_task_age={oldest_task_age:.0f}s"
            )
        else:
            logger.debug(
                f"Throttle health: llm_tasks={llm_count}/{max_tasks}, "
                f"pending={pending_count}, in_progress={in_progress_count}, "
                f"deferred={deferred_total}"
            )

    def _start_threaded_result_consumer(self: RedTeamDispatcher) -> None:
        """Start the result consumer in a separate thread.

        This prevents LLM API timeouts in the main event loop from blocking
        background tasks like result consumption and discovery polling.
        """
        if self._result_consumer_thread is not None:
            logger.warning("Threaded result consumer already running")
            return

        self._result_consumer_stop_event = threading.Event()
        self._result_consumer_thread = threading.Thread(
            target=self._threaded_result_consumer_loop,
            name="orchestrator-result-consumer",
            daemon=True,
        )
        self._result_consumer_thread.start()
        logger.info("Threaded result consumer started (isolated from main event loop)")

    def _stop_threaded_result_consumer(self: RedTeamDispatcher) -> None:
        """Stop the threaded result consumer gracefully."""
        if self._result_consumer_stop_event:
            self._result_consumer_stop_event.set()

        if self._result_consumer_thread and self._result_consumer_thread.is_alive():
            self._result_consumer_thread.join(timeout=5.0)
            if self._result_consumer_thread.is_alive():
                logger.warning("Threaded result consumer did not stop gracefully")
            else:
                logger.info("Threaded result consumer stopped")

        self._result_consumer_thread = None
        self._result_consumer_stop_event = None

    def _threaded_result_consumer_loop(self: RedTeamDispatcher) -> None:
        """Run result consumer in a dedicated thread with its own event loop.

        This mirrors the worker's threaded heartbeat pattern. By running in a
        separate thread, the result consumer continues even when the main
        orchestrator event loop is blocked by LLM API timeouts.

        The thread creates its own Redis connection to avoid sharing connections
        across threads (which is not safe for async Redis).
        """
        # Get operation_id for log context (shared_state is set before thread starts)
        operation_id = self._shared_state.operation_id if self._shared_state else "-"

        # Use contextualize so all logs from this thread include the operation_id
        with logger.contextualize(operation_id=operation_id):
            self._threaded_result_consumer_loop_inner()

    def _threaded_result_consumer_loop_inner(self: RedTeamDispatcher) -> None:
        """Inner implementation of the threaded result consumer loop."""
        from ares.core.task_queue import RedisTaskQueue

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # Create a dedicated task queue for this thread
        redis_url = get_redis_url()
        task_queue: RedisTaskQueue | None = None

        try:
            # Connect to Redis with retries (Sentinel may not be ready immediately)
            if redis_url:
                max_connect_retries = 10
                for attempt in range(max_connect_retries):
                    try:
                        task_queue = RedisTaskQueue(redis_url)
                        loop.run_until_complete(task_queue.connect())
                        logger.info("Threaded result consumer connected to Redis")
                        break
                    except Exception as e:
                        if attempt < max_connect_retries - 1:
                            wait_time = min(2**attempt, 30)  # Exponential backoff, max 30s
                            logger.warning(
                                f"Threaded consumer Redis connect failed (attempt {attempt + 1}/"
                                f"{max_connect_retries}): {e}. Retrying in {wait_time}s..."
                            )
                            time.sleep(wait_time)
                        else:
                            logger.error(
                                f"Threaded consumer failed to connect to Redis after "
                                f"{max_connect_retries} attempts. Result processing disabled."
                            )
                            return  # Exit thread - can't function without Redis

            consecutive_failures = 0
            health_check_counter = 0
            watchdog_interval = 5.0  # Log warning if loop takes longer than this
            stop_event = self._result_consumer_stop_event  # Capture for thread safety

            while stop_event is not None and not stop_event.is_set():
                iteration_start = time.monotonic()

                try:
                    # Use the thread's task queue for result checking
                    loop.run_until_complete(self._threaded_consume_results(task_queue, loop))

                    if consecutive_failures > 0:
                        logger.info(
                            f"Threaded result consumer recovered after "
                            f"{consecutive_failures} failures"
                        )
                    consecutive_failures = 0

                    # Run stale cleanup every 10 cycles (~10 seconds)
                    # This ensures cleanup happens even when main loop is blocked
                    health_check_counter += 1
                    if health_check_counter >= 10:
                        self._threaded_stale_cleanup()
                        health_check_counter = 0

                    # NOTE: _log_throttle_health() is NOT called here because it uses
                    # the main loop's Redis client (self._task_queue.redis). Health
                    # logging is handled by the maintenance loop on the main event loop.

                    # Watchdog: log if iteration took too long (indicates blocking)
                    iteration_duration = time.monotonic() - iteration_start
                    if iteration_duration > watchdog_interval:
                        logger.warning(
                            f"⚠️ Result consumer iteration took {iteration_duration:.1f}s "
                            f"(expected <{watchdog_interval}s) - possible blocking detected"
                        )

                except Exception as e:
                    consecutive_failures += 1
                    should_stop = self._handle_consumer_error(e, consecutive_failures)
                    if should_stop:
                        break

                # Sleep between iterations (use threading.Event for interruptibility)
                # Reduced from 1.0s to 0.5s since batch checking is now O(1) round-trips
                stop_event.wait(timeout=0.5)

        finally:
            if task_queue:
                try:
                    loop.run_until_complete(task_queue.disconnect())
                except Exception:
                    pass
            loop.close()
            logger.debug("Threaded result consumer loop stopped")

    def _handle_consumer_error(self: RedTeamDispatcher, e: Exception, failures: int) -> bool:
        """Handle errors in the threaded result consumer. Returns True if should stop."""
        from ares.core.redis_client import invalidate_sentinel_client

        error_str = str(e).lower()
        connection_keywords = [
            "connection",
            "closed",
            "timeout",
            "broken pipe",
            "reset",
            "refused",
            "sentinel",
            # DNS resolution failures
            "name or service not known",
            "getaddrinfo",
            "temporary failure in name resolution",
        ]
        is_connection_error = any(kw in error_str for kw in connection_keywords)

        if is_connection_error:
            # Invalidate Sentinel client to force fresh DNS resolution on reconnect
            invalidate_sentinel_client()
            max_failures = get_max_redis_consecutive_failures()
            delay = min(
                get_redis_retry_base_delay() * (2 ** min(failures - 1, 4)),
                get_redis_retry_max_delay(),
            )
            logger.warning(
                f"Threaded result consumer Redis error "
                f"(attempt {failures}/{max_failures}): {e}. "
                f"Retrying in {delay:.1f}s"
            )

            if failures >= max_failures:
                logger.critical(
                    f"Threaded result consumer failed {failures} times. "
                    "Redis unavailable - stopping thread."
                )
                return True

            time.sleep(delay)
        else:
            logger.error(f"Threaded result consumer error: {e}", exc_info=True)
            time.sleep(1)

        return False

    async def _threaded_consume_results(
        self: RedTeamDispatcher,
        task_queue: RedisTaskQueue | None,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Consume results using the thread's task queue.

        This is called from the threaded result consumer loop. It uses the
        thread-local task queue for Redis operations but updates the shared
        dispatcher state (which is thread-safe for the operations we perform).

        Uses batched pipeline checking for efficiency - with N tasks and 30s
        socket timeout, sequential checking can block for N * 30s during
        connectivity issues. Pipeline batching reduces this to a single
        timeout window regardless of N.

        NOTE: Stale cleanup and task reconciliation are NOT done here because
        they use self._task_queue which is bound to the main event loop.
        Those operations continue to run on the main loop when it's not blocked.
        This thread focuses on the critical path: result consumption and
        discovery polling.
        """
        if not task_queue:
            return

        if not self._shared_state:
            return

        # Check results for all pending Redis tasks using batch pipeline
        # This is O(1) round-trips instead of O(N), critical for preventing
        # 787s blocking when checking 25+ tasks with 30s socket timeout
        task_ids_to_check = list(self._shared_state.pending_tasks.keys())

        if not task_ids_to_check:
            # No tasks to check - still poll discoveries
            await self._poll_discoveries_threaded(task_queue)
            return

        try:
            batch_results = await task_queue.check_results_batch(task_ids_to_check)
        except Exception as e:
            logger.warning(f"Batch result check failed: {e}")
            batch_results = {}

        # Process results
        for task_id, result in batch_results.items():
            if result is None:
                continue

            try:
                logger.info(
                    f"Threaded result consumer received result for task {task_id}: "
                    f"success={result.success}"
                )

                # Track rate limit status
                if result.success:
                    self.clear_rate_limit_backoff()
                elif result.error:
                    error_str = str(result.error).lower()
                    rate_limit_indicators = [
                        "rate limit",
                        "rate_limit",
                        "ratelimit",
                        "too many requests",
                        "429",
                        "quota exceeded",
                        "tokens per min",
                        "requests per min",
                        "tpm limit",
                        "rpm limit",
                    ]
                    if any(ind in error_str for ind in rate_limit_indicators):
                        logger.warning(
                            f"Task {task_id} failed with rate limit error - triggering backoff"
                        )
                        self.record_rate_limit_error()

                # Complete the task (updates shared state)
                # Skip checkpoint because we're in a different event loop (threaded consumer)
                # Checkpointing is handled by the maintenance loop on the main loop
                # Pass task_queue so dispatches happen directly (don't wait for blocked main loop)
                await self.complete_task(
                    task_id=task_id,
                    success=result.success,
                    result=result.result,
                    error=result.error,
                    source_agent=result.agent_name or result.worker_pod or "unknown",
                    skip_checkpoint=True,
                    task_queue=task_queue,
                )
            except Exception as e:
                logger.warning(f"Error processing result for task {task_id}: {e}")

        # Poll for real-time discoveries
        await self._poll_discoveries_threaded(task_queue)

    async def _poll_discoveries_threaded(
        self: RedTeamDispatcher,
        task_queue: RedisTaskQueue,
    ) -> None:
        """Poll discoveries using the thread's task queue."""
        if not self._shared_state:
            return
        operation_id = self._shared_state.operation_id

        try:
            discoveries = await task_queue.poll_discoveries(operation_id, max_items=50)
            if not discoveries:
                return

            for discovery in discoveries:
                discovery_type = discovery.get("type", "")
                data = discovery.get("data", {})
                source_agent = discovery.get("source_agent", "unknown")
                discovery_task_id = discovery.get("task_id")

                if discovery_type == "delegation":
                    await self._process_realtime_delegation_discovery(
                        data, source_agent, task_queue=task_queue
                    )
                elif discovery_type == "credential":
                    await self._process_realtime_credential_discovery(
                        data, source_agent, task_queue=task_queue
                    )
                elif discovery_type == "hash":
                    await self._process_realtime_hash_discovery(
                        data, source_agent, task_queue=task_queue, task_id=discovery_task_id
                    )
                elif discovery_type == "vulnerability":
                    await self._process_realtime_vulnerability_discovery(
                        data, source_agent, task_queue=task_queue
                    )
                else:
                    logger.debug(f"Unknown discovery type: {discovery_type}")

        except Exception as e:
            logger.warning(f"Error polling discoveries (threaded): {e}")


__all__ = ["MonitoringMixin"]
