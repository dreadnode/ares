"""Heartbeat and result monitoring for agent health and task completion.

This module provides background tasks for monitoring agent heartbeats
and consuming task results from Redis.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from loguru import logger

from ares.core.models import TaskInfo, TaskStatus

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher

# Stale task timeout in seconds - tasks pending longer than this are cleaned up
# This prevents throttle deadlock when tasks get lost in Redis or workers crash
STALE_TASK_TIMEOUT_SECONDS = 600  # 10 minutes


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
        """Background task to monitor agent heartbeats."""
        while self._running:
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
                            exc_info=True,
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

            await asyncio.sleep(15)

    async def _result_consumer(self: RedTeamDispatcher) -> None:
        """
        Background task to consume results from Redis for completed tasks.

        This bridges the gap between Redis-based workers (which send results via
        task_queue.send_result()) and the dispatcher's in-memory pending_tasks
        tracking. Without this, tasks complete on workers but the orchestrator
        never knows about it.
        """
        logger.info("Result consumer started")

        try:
            while self._running:
                await self._consume_pending_results()
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            logger.info("Result consumer cancelled")
        except Exception as e:
            logger.error(f"Result consumer fatal error: {e}", exc_info=True)

        logger.info("Result consumer stopped")

    async def _cleanup_stale_tasks(self: RedTeamDispatcher) -> None:
        """
        Clean up tasks that have been pending for too long.

        This prevents throttle deadlock when:
        - Workers crash without sending results
        - Tasks get lost in Redis
        - Network partitions cause result delivery failures

        Tasks older than STALE_TASK_TIMEOUT_SECONDS are removed from:
        - pending_tasks (decreases LLM task count)
        - _redis_task_ids (stops result polling)
        """
        if not self._shared_state:
            return

        now = datetime.now(timezone.utc)
        stale_task_ids: list[str] = []

        for task_id, task_info in list(self._shared_state.pending_tasks.items()):
            # Only clean up tasks still in PENDING or IN_PROGRESS
            if task_info.status not in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS):
                continue

            age_seconds = (now - task_info.created_at).total_seconds()
            if age_seconds > STALE_TASK_TIMEOUT_SECONDS:
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
                f"(threshold: {STALE_TASK_TIMEOUT_SECONDS}s)"
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
