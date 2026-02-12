"""Heartbeat and result monitoring for agent health and task completion.

This module provides background tasks for monitoring agent heartbeats
and consuming task results from Redis.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from loguru import logger

from ares.core.config import (
    get_max_redis_consecutive_failures,
    get_redis_retry_base_delay,
    get_redis_retry_max_delay,
    get_stale_task_timeout,
)
from ares.core.models import TaskInfo, TaskStatus

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher


class MonitoringMixin:
    """Heartbeat and result monitoring for agent health and task completion."""

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
        if agent_name in self._agents:
            self._agents[agent_name].status = status
            self._agents[agent_name].current_task = current_task
            self._agents[agent_name].last_heartbeat = datetime.now(timezone.utc)

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
                                    self._agents[agent_name].current_task = heartbeat_data.get(
                                        "current_task"
                                    )
                        except Exception as e:  # noqa: PERF203
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

            except asyncio.CancelledError:  # noqa: PERF203
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

        while self._running:
            try:
                await self._consume_pending_results()
                # Success - reset failure counter and delay
                if consecutive_failures > 0:
                    logger.info(f"Result consumer recovered after {consecutive_failures} failures")
                consecutive_failures = 0
                await asyncio.sleep(1)

            except asyncio.CancelledError:  # noqa: PERF203
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

        Tasks older than stale_task_timeout (from config) are removed from:
        - pending_tasks (decreases LLM task count)
        - _redis_task_ids (stops result polling)
        """
        if not self._shared_state:
            return

        stale_timeout = get_stale_task_timeout()
        now = datetime.now(timezone.utc)
        stale_task_ids: list[str] = []

        for task_id, task_info in list(self._shared_state.pending_tasks.items()):
            # Only clean up tasks still in PENDING or IN_PROGRESS
            if task_info.status not in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS):
                continue

            age_seconds = (now - task_info.created_at).total_seconds()
            if age_seconds > stale_timeout:
                stale_task_ids.append(task_id)

        if stale_task_ids:
            for task_id in stale_task_ids:
                stale_task: TaskInfo | None = self._shared_state.pending_tasks.get(task_id)
                if stale_task is not None:
                    del self._shared_state.pending_tasks[task_id]
                self._redis_task_ids.discard(task_id)

                if stale_task is not None:
                    logger.warning(
                        f"Cleaned up stale task {task_id} ({stale_task.task_type} -> "
                        f"{stale_task.assigned_agent}) - pending for "
                        f"{(now - stale_task.created_at).total_seconds():.0f}s"
                    )

            logger.info(
                f"Stale task cleanup: removed {len(stale_task_ids)} tasks "
                f"(threshold: {stale_timeout}s)"
            )

    async def _consume_pending_results(self: RedTeamDispatcher) -> None:
        """Check and consume results for all pending Redis tasks."""
        if not self._task_queue:
            logger.warning("Result consumer has no task queue; skipping result checks")
            return

        # Periodically clean up stale tasks to prevent throttle deadlock
        await self._cleanup_stale_tasks()

        task_ids_to_check = list(self._redis_task_ids)

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

                    # Remove from tracking set
                    self._redis_task_ids.discard(task_id)

                    # Call complete_task to update dispatcher state
                    await self.complete_task(
                        task_id=task_id,
                        success=result.success,
                        result=result.result,
                        error=result.error,
                        source_agent=result.agent_name or result.worker_pod or "unknown",
                    )
            except Exception as e:  # noqa: PERF203
                logger.warning(f"Error checking result for task {task_id}: {e}")


__all__ = ["MonitoringMixin"]
