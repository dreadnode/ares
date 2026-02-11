"""Deferred task queue for throttled tasks.

Instead of dropping tasks when at capacity, this module queues them
for later dispatch when slots open up. Includes priority-based
processing and automatic eviction of stale tasks.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.config import get_max_concurrent_tasks
from ares.core.models import TaskInfo

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher

# Configuration constants
MAX_DEFERRED_PER_TYPE = 5  # Max queued tasks per task_type
DEFERRED_TASK_MAX_AGE_SECONDS = 300  # 5 minutes - evict older tasks
DEFERRED_QUEUE_CHECK_INTERVAL = 10.0  # Check every 10 seconds


@dataclass(order=True)
class DeferredTask:
    """A task waiting to be dispatched when capacity allows.

    Ordered by (priority, enqueue_time) so lower priority numbers
    and earlier times are processed first.
    """

    priority: int
    enqueue_time: float
    task_type: str = field(compare=False)
    target_role: str = field(compare=False)
    payload: dict[str, Any] = field(compare=False)
    source_agent: str = field(compare=False)


class DeferredQueueMixin:
    """Manages a deferred queue for tasks that can't be immediately dispatched.

    When the system hits max_concurrent_tasks, instead of dropping tasks,
    they're queued here and processed when slots open up.

    Features:
    - Priority-based processing (lower priority number = higher priority)
    - Per-task-type queue limits to prevent unbounded growth
    - Automatic eviction of stale tasks (>5 min old)
    - Background processor that runs when slots are available
    """

    def _init_deferred_queue(self: RedTeamDispatcher) -> None:
        """Initialize deferred queue state. Call from __init__."""
        # Queue organized by task_type for per-type limits
        self._deferred_queues: dict[str, list[DeferredTask]] = {}
        # Lock is created lazily in async context to avoid event loop binding issues
        self._deferred_queue_lock: asyncio.Lock | None = None
        self._deferred_processor_task: asyncio.Task | None = None
        self._deferred_queue_stats = {
            "queued": 0,
            "processed": 0,
            "evicted_age": 0,
            "evicted_capacity": 0,
        }

    def _get_deferred_lock(self: RedTeamDispatcher) -> asyncio.Lock:
        """Get or create the deferred queue lock (lazy init for event loop safety)."""
        if self._deferred_queue_lock is None:
            self._deferred_queue_lock = asyncio.Lock()
        return self._deferred_queue_lock

    async def _start_deferred_processor(self: RedTeamDispatcher) -> None:
        """Start the background task that processes deferred queue."""
        # Ensure lock is created in the correct event loop
        self._get_deferred_lock()

        if self._deferred_processor_task is None:
            self._deferred_processor_task = asyncio.create_task(self._deferred_queue_processor())
            logger.info("Deferred queue processor started")

    async def _stop_deferred_processor(self: RedTeamDispatcher) -> None:
        """Stop the deferred queue processor."""
        if self._deferred_processor_task:
            self._deferred_processor_task.cancel()
            try:
                await self._deferred_processor_task
            except asyncio.CancelledError:
                pass
            self._deferred_processor_task = None

    async def _enqueue_deferred_task(
        self: RedTeamDispatcher,
        task_type: str,
        target_role: str,
        payload: dict[str, Any],
        source_agent: str,
        priority: int,
    ) -> bool:
        """
        Add a task to the deferred queue.

        Returns True if queued, False if rejected (queue full with higher priority tasks).
        """
        async with self._get_deferred_lock():
            # Get or create queue for this task type
            if task_type not in self._deferred_queues:
                self._deferred_queues[task_type] = []

            queue = self._deferred_queues[task_type]
            now = time.time()

            # First, evict stale tasks (>5 min old)
            original_len = len(queue)
            queue[:] = [t for t in queue if now - t.enqueue_time < DEFERRED_TASK_MAX_AGE_SECONDS]
            evicted = original_len - len(queue)
            if evicted > 0:
                self._deferred_queue_stats["evicted_age"] += evicted
                logger.debug(f"Evicted {evicted} stale {task_type} tasks from deferred queue")

            # Check if queue is at capacity
            if len(queue) >= MAX_DEFERRED_PER_TYPE:
                # Find lowest priority task (highest priority number)
                worst_idx = max(range(len(queue)), key=lambda i: queue[i].priority)
                worst_task = queue[worst_idx]

                # Only evict if new task has higher priority (lower number)
                if priority < worst_task.priority:
                    queue.pop(worst_idx)
                    self._deferred_queue_stats["evicted_capacity"] += 1
                    logger.info(
                        f"Evicted lower-priority {task_type} task (priority {worst_task.priority}) "
                        f"to make room for priority {priority} task"
                    )
                else:
                    # Queue full with equal or higher priority tasks - reject
                    logger.warning(
                        f"Deferred queue full for {task_type} ({len(queue)} tasks), "
                        f"DROPPING priority {priority} task (queue has equal/higher priority tasks)"
                    )
                    return False

            # Add to queue
            task = DeferredTask(
                priority=priority,
                enqueue_time=now,
                task_type=task_type,
                target_role=target_role,
                payload=payload,
                source_agent=source_agent,
            )
            queue.append(task)
            queue.sort()  # Maintain priority order

            self._deferred_queue_stats["queued"] += 1
            logger.info(
                f"QUEUED {task_type} task for {target_role} (priority {priority}, "
                f"queue size: {len(queue)}/{MAX_DEFERRED_PER_TYPE})"
            )
            return True

    async def _deferred_queue_processor(self: RedTeamDispatcher) -> None:
        """Background task that processes deferred queue when slots open."""
        logger.info("Deferred queue processor running")

        while self._running:
            try:
                await asyncio.sleep(DEFERRED_QUEUE_CHECK_INTERVAL)

                # HALT: If DA achieved, drain deferred queues and stop processing
                if self._shared_state and self._shared_state.has_domain_admin:
                    # Drain all queues - these tasks are no longer needed
                    total_drained = 0
                    async with self._get_deferred_lock():
                        for queue in self._deferred_queues.values():
                            if queue:
                                total_drained += len(queue)
                                queue.clear()
                    if total_drained > 0:
                        logger.info(
                            f"DA achieved - drained {total_drained} tasks from deferred queues"
                        )
                    continue  # Keep loop alive but skip processing

                # Check if we have capacity
                llm_count = await self._get_llm_task_count()
                max_tasks = get_max_concurrent_tasks()

                if llm_count >= max_tasks:
                    # Still at capacity, skip this cycle
                    continue

                # Calculate available slots
                available_slots = max_tasks - llm_count

                # Process tasks from deferred queue
                tasks_to_submit = await self._get_highest_priority_deferred(available_slots)

                for task in tasks_to_submit:
                    # Submit directly to task queue (bypassing throttle check)
                    if self._task_queue:
                        try:
                            task_id = await self._task_queue.submit_task(
                                task_type=task.task_type,
                                target_role=task.target_role,
                                payload=task.payload,
                                source_agent=task.source_agent,
                                priority=task.priority,
                            )

                            # CRITICAL: Track task for result consumption
                            # Without this, results from deferred tasks are never consumed
                            if task_id and self._shared_state:
                                task_info = TaskInfo(
                                    task_id=task_id,
                                    task_type=task.task_type,
                                    assigned_agent=task.target_role,
                                    params=task.payload,
                                )
                                self._shared_state.pending_tasks[task_id] = task_info
                                self._redis_task_ids.add(task_id)

                            self._deferred_queue_stats["processed"] += 1
                            age = time.time() - task.enqueue_time
                            logger.info(
                                f"Processed deferred {task.task_type} task -> {task.target_role} "
                                f"(task_id={task_id}, waited {age:.1f}s)"
                            )
                        except Exception as e:
                            logger.error(f"Failed to submit deferred task: {e}")
                            # Re-queue the task if submission failed
                            await self._enqueue_deferred_task(
                                task.task_type,
                                task.target_role,
                                task.payload,
                                task.source_agent,
                                task.priority,
                            )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Deferred queue processor error: {e}")
                await asyncio.sleep(5.0)  # Back off on error

        logger.info("Deferred queue processor stopped")

    async def _get_highest_priority_deferred(
        self: RedTeamDispatcher, max_count: int
    ) -> list[DeferredTask]:
        """Get up to max_count highest priority tasks from all queues."""
        async with self._get_deferred_lock():
            # Collect all tasks from all queues
            all_tasks: list[DeferredTask] = []
            for queue in self._deferred_queues.values():
                all_tasks.extend(queue)

            if not all_tasks:
                return []

            # Sort by priority (dataclass ordering) and take top N
            all_tasks.sort()
            tasks_to_return = all_tasks[:max_count]

            # Remove selected tasks from their queues
            for task in tasks_to_return:
                queue = self._deferred_queues.get(task.task_type, [])
                if task in queue:
                    queue.remove(task)

            return tasks_to_return

    def get_deferred_queue_status(self: RedTeamDispatcher) -> dict[str, Any]:
        """Get status of deferred queues for monitoring."""
        queue_sizes = {
            task_type: len(queue) for task_type, queue in self._deferred_queues.items() if queue
        }
        return {
            "queue_sizes": queue_sizes,
            "total_queued": sum(queue_sizes.values()),
            "stats": self._deferred_queue_stats.copy(),
        }


__all__ = ["DeferredQueueMixin", "DeferredTask"]
