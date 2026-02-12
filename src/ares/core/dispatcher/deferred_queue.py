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

from ares.core.config import (
    get_critical_priority_threshold,
    get_deferred_queue_check_interval,
    get_deferred_task_max_age,
    get_max_concurrent_tasks,
    get_max_deferred_per_type,
    get_max_deferred_total,
)
from ares.core.models import TaskInfo

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher


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

            # First, evict stale tasks across ALL queues
            max_age = get_deferred_task_max_age()
            total_evicted = 0
            for q in self._deferred_queues.values():
                original_len = len(q)
                q[:] = [t for t in q if now - t.enqueue_time < max_age]
                total_evicted += original_len - len(q)
            if total_evicted > 0:
                self._deferred_queue_stats["evicted_age"] += total_evicted
                logger.debug(f"Evicted {total_evicted} stale tasks from deferred queues")

            # Calculate total queue size across all types
            total_queued = sum(len(q) for q in self._deferred_queues.values())
            max_total = get_max_deferred_total()

            # Check TOTAL queue capacity first (hard limit across all types)
            if total_queued >= max_total:
                # Find lowest priority task across ALL queues
                all_tasks = [(t, tt) for tt, q in self._deferred_queues.items() for t in q]
                if all_tasks:
                    worst_task, worst_type = max(all_tasks, key=lambda x: x[0].priority)
                    if priority < worst_task.priority:
                        self._deferred_queues[worst_type].remove(worst_task)
                        self._deferred_queue_stats["evicted_capacity"] += 1
                        logger.info(
                            f"Evicted lower-priority {worst_type} task (priority {worst_task.priority}) "
                            f"to make room for {task_type} priority {priority} task"
                        )
                    else:
                        logger.warning(
                            f"Deferred queue TOTAL full ({total_queued}/{max_total}), "
                            f"DROPPING {task_type} priority {priority} task"
                        )
                        return False

            # Check per-type capacity (secondary limit)
            max_per_type = get_max_deferred_per_type()
            if len(queue) >= max_per_type:
                # Find lowest priority task in THIS type's queue
                worst_idx = max(range(len(queue)), key=lambda i: queue[i].priority)
                worst_task = queue[worst_idx]

                if priority < worst_task.priority:
                    queue.pop(worst_idx)
                    self._deferred_queue_stats["evicted_capacity"] += 1
                    logger.info(
                        f"Evicted lower-priority {task_type} task (priority {worst_task.priority}) "
                        f"to make room for priority {priority} task"
                    )
                else:
                    logger.warning(
                        f"Deferred queue full for {task_type} ({len(queue)}/{max_per_type}), "
                        f"DROPPING priority {priority} task"
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
                f"queue size: {len(queue)}/{max_per_type})"
            )
            return True

    async def _submit_deferred_task(
        self: RedTeamDispatcher, task: DeferredTask, *, is_critical: bool = False
    ) -> bool:
        """Submit a single deferred task to the queue. Returns True on success."""
        if not self._task_queue:
            return False

        try:
            task_id = await self._task_queue.submit_task(
                task_type=task.task_type,
                target_role=task.target_role,
                payload=task.payload,
                source_agent=task.source_agent,
                priority=task.priority,
            )

            # Track task for result consumption
            if task_id and self._shared_state:
                from datetime import datetime, timezone

                now = datetime.now(timezone.utc)
                task_info = TaskInfo(
                    task_id=task_id,
                    task_type=task.task_type,
                    assigned_agent=task.target_role,
                    params=task.payload,
                    last_activity_at=now,  # Fresh activity time for stale detection
                )
                self._shared_state.pending_tasks[task_id] = task_info
                self._redis_task_ids.add(task_id)

            self._deferred_queue_stats["processed"] += 1
            age = time.time() - task.enqueue_time
            prefix = "Force-drained critical" if is_critical else "Processed deferred"
            logger.info(
                f"{prefix} {task.task_type} task -> {task.target_role} "
                f"(task_id={task_id}, priority={task.priority}, waited {age:.1f}s)"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to submit deferred task: {e}")
            return False

    async def _drain_queues_on_da(self: RedTeamDispatcher) -> None:
        """Drain all deferred queues when DA is achieved."""
        total_drained = 0
        async with self._get_deferred_lock():
            for queue in self._deferred_queues.values():
                total_drained += len(queue)
                queue.clear()
        if total_drained > 0:
            logger.info(f"DA achieved - drained {total_drained} tasks from deferred queues")

    async def _deferred_queue_processor(self: RedTeamDispatcher) -> None:
        """Background task that processes deferred queue when slots open."""
        logger.info("Deferred queue processor running")

        while self._running:
            try:
                await asyncio.sleep(get_deferred_queue_check_interval())

                # HALT: If DA achieved, drain deferred queues and stop processing
                if self._shared_state and self._shared_state.has_domain_admin:
                    await self._drain_queues_on_da()
                    continue

                llm_count = await self._get_llm_task_count()
                max_tasks = get_max_concurrent_tasks()
                available_slots = max(0, max_tasks - llm_count)

                # Force-drain critical priority tasks (1-3) even at capacity
                critical_tasks = await self._get_critical_priority_deferred()
                if critical_tasks:
                    logger.info(
                        f"Force-draining {len(critical_tasks)} critical priority tasks "
                        f"(at {llm_count}/{max_tasks} capacity)"
                    )
                    for task in critical_tasks:
                        await self._submit_deferred_task(task, is_critical=True)

                if llm_count >= max_tasks:
                    continue

                # Process remaining tasks from deferred queue
                for task in await self._get_highest_priority_deferred(available_slots):
                    success = await self._submit_deferred_task(task)
                    if not success:
                        # Re-queue on failure
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
                await asyncio.sleep(5.0)

        logger.info("Deferred queue processor stopped")

    async def _get_critical_priority_deferred(self: RedTeamDispatcher) -> list[DeferredTask]:
        """Get all critical priority tasks (priority <= threshold) for force-drain."""
        async with self._get_deferred_lock():
            critical_tasks: list[DeferredTask] = []
            threshold = get_critical_priority_threshold()

            for queue in self._deferred_queues.values():
                # Find tasks with priority <= threshold (lower = higher priority)
                for task in list(queue):  # Copy to allow modification
                    if task.priority <= threshold:
                        critical_tasks.append(task)
                        queue.remove(task)

            # Sort by priority (lowest first = highest priority)
            critical_tasks.sort()
            return critical_tasks

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
        total = sum(queue_sizes.values())
        max_total = get_max_deferred_total()
        return {
            "queue_sizes": queue_sizes,
            "total_queued": total,
            "max_total": max_total,
            "capacity_pct": round(100 * total / max_total, 1) if max_total else 0,
            "stats": self._deferred_queue_stats.copy(),
        }


__all__ = ["DeferredQueueMixin", "DeferredTask"]
