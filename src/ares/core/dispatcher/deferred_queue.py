"""Redis-backed deferred task queue for throttled tasks.

Instead of dropping tasks when at capacity, this module queues them
in Redis ZSETs for later dispatch when slots open up. Tasks survive
orchestrator restarts.

Features:
- Priority-based processing (lower priority number = higher priority)
- Per-task-type queue limits to prevent unbounded growth
- Automatic eviction of stale tasks (>5 min old)
- Background processor that runs when slots are available
- Crash resilience via Redis persistence
"""

from __future__ import annotations

import asyncio
import json
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

# Redis key prefix for deferred queues
DEFERRED_QUEUE_PREFIX = "ares:deferred"


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

    def to_json(self) -> str:
        """Serialize to JSON for Redis storage."""
        return json.dumps(
            {
                "priority": self.priority,
                "enqueue_time": self.enqueue_time,
                "task_type": self.task_type,
                "target_role": self.target_role,
                "payload": self.payload,
                "source_agent": self.source_agent,
            }
        )

    @classmethod
    def from_json(cls, data: str) -> DeferredTask:
        """Deserialize from JSON."""
        d = json.loads(data)
        return cls(**d)


class DeferredQueueMixin:
    """Manages a Redis-backed deferred queue for tasks that can't be immediately dispatched.

    When the system hits max_concurrent_tasks, instead of dropping tasks,
    they're queued in Redis ZSETs and processed when slots open up.

    Redis Structure:
    - Key: ares:deferred:{operation_id}:{task_type}
    - Type: ZSET
    - Member: JSON-serialized DeferredTask
    - Score: (priority * 1e9) + (enqueue_time * 1000)
      Lower score = higher priority (processed first)

    Features:
    - Priority-based processing (lower priority number = higher priority)
    - Per-task-type queue limits to prevent unbounded growth
    - Automatic eviction of stale tasks (>5 min old)
    - Background processor that runs when slots are available
    - Crash resilience - tasks survive orchestrator restarts
    """

    def _init_deferred_queue(self: RedTeamDispatcher) -> None:
        """Initialize deferred queue state. Call from __init__."""
        self._deferred_processor_task: asyncio.Task | None = None
        self._deferred_queue_stats = {
            "queued": 0,
            "processed": 0,
            "evicted_age": 0,
            "evicted_capacity": 0,
            "recovered": 0,
        }

    def _deferred_queue_key(self: RedTeamDispatcher, task_type: str) -> str:
        """Get Redis key for a deferred queue."""
        return f"{DEFERRED_QUEUE_PREFIX}:{self._operation_id}:{task_type}"

    def _deferred_queue_pattern(self: RedTeamDispatcher) -> str:
        """Get glob pattern for all deferred queues in this operation."""
        return f"{DEFERRED_QUEUE_PREFIX}:{self._operation_id}:*"

    @staticmethod
    def _compute_score(priority: int, enqueue_time: float) -> float:
        """Compute ZSET score from priority and time.

        Score structure: priority * 1e15 + enqueue_time_ms
        Lower score = higher priority (processed first).
        Within same priority, earlier enqueue time wins.

        Using 1e15 multiplier to accommodate Unix timestamps in milliseconds
        (current timestamps are ~1.7e12).
        """
        return (priority * 1_000_000_000_000_000) + int(enqueue_time * 1000)

    @staticmethod
    def _parse_score(score: float) -> tuple[int, float]:
        """Extract priority and enqueue_time from score."""
        priority = int(score // 1_000_000_000_000_000)
        enqueue_time = (score % 1_000_000_000_000_000) / 1000
        return priority, enqueue_time

    async def _get_all_deferred_task_types(self: RedTeamDispatcher) -> list[str]:
        """Get all task types with deferred queues in Redis."""
        if not self._task_queue or not self._task_queue.redis:
            return []

        redis = self._task_queue.redis
        pattern = self._deferred_queue_pattern()
        task_types = []

        try:
            async for key in redis.scan_iter(match=pattern):
                # Extract task_type from key: ares:deferred:{op_id}:{task_type}
                parts = key.split(":")
                if len(parts) >= 4:
                    task_types.append(parts[-1])
        except Exception as e:
            logger.error(f"Failed to scan deferred queue keys: {e}")

        return task_types

    async def _get_total_deferred_count(self: RedTeamDispatcher) -> int:
        """Get total count across all deferred queues."""
        if not self._task_queue or not self._task_queue.redis:
            return 0

        redis = self._task_queue.redis
        total = 0

        try:
            for task_type in await self._get_all_deferred_task_types():
                key = self._deferred_queue_key(task_type)
                total += await redis.zcard(key)
        except Exception as e:
            logger.error(f"Failed to count deferred tasks: {e}")

        return total

    async def _find_lowest_priority_task(
        self: RedTeamDispatcher,
    ) -> dict[str, Any] | None:
        """Find the lowest priority task across all queues (highest score)."""
        if not self._task_queue or not self._task_queue.redis:
            return None

        redis = self._task_queue.redis
        worst: dict[str, Any] | None = None
        worst_score = -1.0

        try:
            for task_type in await self._get_all_deferred_task_types():
                key = self._deferred_queue_key(task_type)
                # Get highest score (lowest priority) in this queue
                items = await redis.zrange(key, -1, -1, withscores=True)
                if items:
                    member, score = items[0]
                    if score > worst_score:
                        worst_score = score
                        priority, _ = self._parse_score(score)
                        worst = {
                            "task_type": task_type,
                            "member": member,
                            "score": score,
                            "priority": priority,
                        }
        except Exception as e:
            logger.error(f"Failed to find lowest priority task: {e}")

        return worst

    async def _evict_stale_deferred_tasks(self: RedTeamDispatcher) -> int:
        """Evict tasks older than max_age from all queues. Returns count evicted."""
        if not self._task_queue or not self._task_queue.redis:
            return 0

        redis = self._task_queue.redis
        max_age = get_deferred_task_max_age()
        now = time.time()
        cutoff_time = now - max_age
        total_evicted = 0

        try:
            for task_type in await self._get_all_deferred_task_types():
                key = self._deferred_queue_key(task_type)

                # Score encodes both priority and time, so check each task
                items = await redis.zrange(key, 0, -1, withscores=True)
                stale_members = []

                for member, score in items:
                    _, enqueue_time = self._parse_score(score)
                    if enqueue_time < cutoff_time:
                        stale_members.append(member)

                if stale_members:
                    removed = await redis.zrem(key, *stale_members)
                    total_evicted += removed

        except Exception as e:
            logger.error(f"Failed to evict stale deferred tasks: {e}")

        return total_evicted

    async def _start_deferred_processor(self: RedTeamDispatcher) -> None:
        """Start the background task that processes deferred queue."""
        # Log recovered tasks on startup
        try:
            total = await self._get_total_deferred_count()
            if total > 0:
                logger.info(f"Recovered {total} deferred tasks from Redis")
                self._deferred_queue_stats["recovered"] = total
        except Exception as e:
            logger.warning(f"Failed to count recovered deferred tasks: {e}")

        if self._deferred_processor_task is None:
            self._deferred_processor_task = asyncio.create_task(self._deferred_queue_processor())
            logger.info("Deferred queue processor started (Redis-backed)")

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
        """Add a task to the deferred queue in Redis.

        Returns True if queued, False if rejected (queue full with higher priority tasks).

        When called from the threaded result consumer (non-main thread), queues
        the task for processing by the main event loop instead of accessing
        Redis directly (avoids event loop mismatch).
        """
        import threading

        # When called from non-main thread (threaded consumer), queue for main loop
        # This avoids "Future attached to a different loop" errors
        if threading.current_thread() is not threading.main_thread():
            with self._pending_deferred_lock:
                self._pending_deferred_tasks.append(
                    (task_type, target_role, payload.copy(), source_agent, priority)
                )
            self._deferred_task_requested.set()
            logger.debug(
                f"Queued deferred task for main loop: {task_type} -> {target_role} (priority {priority})"
            )
            return True  # Task accepted for deferred processing

        if not self._task_queue or not self._task_queue.redis:
            logger.error("Cannot enqueue deferred task: Redis not available")
            return False

        redis = self._task_queue.redis
        key = self._deferred_queue_key(task_type)
        now = time.time()

        try:
            # 1. Evict stale tasks across ALL queues
            evicted = await self._evict_stale_deferred_tasks()
            if evicted > 0:
                self._deferred_queue_stats["evicted_age"] += evicted
                logger.debug(f"Evicted {evicted} stale tasks from deferred queues")

            # 2. Check TOTAL queue capacity
            total_queued = await self._get_total_deferred_count()
            max_total = get_max_deferred_total()

            if total_queued >= max_total:
                # Find lowest priority task across ALL queues
                worst = await self._find_lowest_priority_task()
                if worst and priority < worst["priority"]:
                    await redis.zrem(self._deferred_queue_key(worst["task_type"]), worst["member"])
                    self._deferred_queue_stats["evicted_capacity"] += 1
                    logger.info(
                        f"Evicted lower-priority {worst['task_type']} task "
                        f"(priority {worst['priority']}) to make room for "
                        f"{task_type} priority {priority} task"
                    )
                else:
                    logger.warning(
                        f"Deferred queue TOTAL full ({total_queued}/{max_total}), "
                        f"DROPPING {task_type} priority {priority} task"
                    )
                    return False

            # 3. Check per-type capacity
            type_count = await redis.zcard(key)
            max_per_type = get_max_deferred_per_type()

            if type_count >= max_per_type:
                # Evict lowest priority in THIS type (highest score = last in ZSET)
                worst_items = await redis.zrange(key, -1, -1, withscores=True)
                if worst_items:
                    worst_member, worst_score = worst_items[0]
                    worst_priority, _ = self._parse_score(worst_score)

                    if priority < worst_priority:
                        await redis.zrem(key, worst_member)
                        self._deferred_queue_stats["evicted_capacity"] += 1
                        logger.info(
                            f"Evicted lower-priority {task_type} task "
                            f"(priority {worst_priority}) to make room for "
                            f"priority {priority} task"
                        )
                    else:
                        logger.warning(
                            f"Deferred queue full for {task_type} "
                            f"({type_count}/{max_per_type}), "
                            f"DROPPING priority {priority} task"
                        )
                        return False

            # 4. Add task to Redis ZSET
            task = DeferredTask(
                priority=priority,
                enqueue_time=now,
                task_type=task_type,
                target_role=target_role,
                payload=payload,
                source_agent=source_agent,
            )
            score = self._compute_score(priority, now)
            await redis.zadd(key, {task.to_json(): score})

            self._deferred_queue_stats["queued"] += 1
            new_count = await redis.zcard(key)
            logger.info(
                f"QUEUED {task_type} task for {target_role} (priority {priority}, "
                f"queue size: {new_count}/{max_per_type})"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to enqueue deferred task: {e}")
            return False

    async def _submit_deferred_task(
        self: RedTeamDispatcher, task: DeferredTask, *, is_critical: bool = False
    ) -> bool:
        """Submit a single deferred task to the task queue. Returns True on success."""
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
                    last_activity_at=now,
                )
                # Write to Redis FIRST (source of truth), then cache in memory
                await self._persist_task_info_to_redis(task_id, task_info)
                self._shared_state.pending_tasks[task_id] = task_info

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
        if not self._task_queue or not self._task_queue.redis:
            return

        redis = self._task_queue.redis
        total_drained = 0

        try:
            for task_type in await self._get_all_deferred_task_types():
                key = self._deferred_queue_key(task_type)
                count = await redis.zcard(key)
                if count > 0:
                    await redis.delete(key)
                    total_drained += count

            if total_drained > 0:
                logger.info(f"DA achieved - drained {total_drained} tasks from deferred queues")
        except Exception as e:
            logger.error(f"Failed to drain deferred queues on DA: {e}")

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

                # At soft cap but below hard cap: still process deferred tasks for starved roles
                # This mirrors the minimum-slots logic in throttling - roles with 0 pending
                # tasks shouldn't be starved just because recon/exploit are filling slots
                hard_cap = int(max_tasks * 1.5)
                if llm_count >= hard_cap:
                    # At hard cap - only critical tasks (already processed above)
                    continue

                # Process remaining tasks from deferred queue
                if available_slots > 0:
                    # Below soft cap - process normally with available slots
                    tasks_to_process = await self._get_highest_priority_deferred(available_slots)
                else:
                    # At soft cap - only process tasks for starved roles (0 pending)
                    tasks_to_process = await self._get_deferred_for_starved_roles()

                for task in tasks_to_process:
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

    async def _get_critical_priority_deferred(
        self: RedTeamDispatcher,
    ) -> list[DeferredTask]:
        """Get all critical priority tasks (priority <= threshold) for force-drain."""
        if not self._task_queue or not self._task_queue.redis:
            return []

        redis = self._task_queue.redis
        threshold = get_critical_priority_threshold()
        # Max score for critical tasks: (threshold+1) * 1e15 - 1
        # This captures all tasks with priority <= threshold
        max_score = ((threshold + 1) * 1_000_000_000_000_000) - 1
        critical_tasks: list[DeferredTask] = []

        try:
            for task_type in await self._get_all_deferred_task_types():
                key = self._deferred_queue_key(task_type)

                # Get all critical priority tasks
                items = await redis.zrangebyscore(key, "-inf", max_score, withscores=True)

                for member, _score in items:
                    # Remove from queue immediately
                    await redis.zrem(key, member)
                    task = DeferredTask.from_json(member)
                    critical_tasks.append(task)

        except Exception as e:
            logger.error(f"Failed to get critical priority deferred tasks: {e}")

        # Sort by dataclass ordering (priority, enqueue_time)
        critical_tasks.sort()
        return critical_tasks

    async def _get_highest_priority_deferred(
        self: RedTeamDispatcher, max_count: int
    ) -> list[DeferredTask]:
        """Get up to max_count highest priority tasks from all queues."""
        if not self._task_queue or not self._task_queue.redis or max_count <= 0:
            return []

        redis = self._task_queue.redis
        all_items: list[tuple[str, str, float]] = []  # (key, member, score)

        try:
            # Collect all tasks from all queues
            for task_type in await self._get_all_deferred_task_types():
                key = self._deferred_queue_key(task_type)
                items = await redis.zrange(key, 0, -1, withscores=True)
                for member, score in items:
                    all_items.append((key, member, score))

            if not all_items:
                return []

            # Sort by score (lowest first = highest priority)
            all_items.sort(key=lambda x: x[2])

            # Take top N and remove from Redis
            result: list[DeferredTask] = []
            for key, member, _score in all_items[:max_count]:
                await redis.zrem(key, member)
                task = DeferredTask.from_json(member)
                result.append(task)

            return result

        except Exception as e:
            logger.error(f"Failed to get highest priority deferred tasks: {e}")
            return []

    async def _get_deferred_for_starved_roles(
        self: RedTeamDispatcher,
    ) -> list[DeferredTask]:
        """Get highest priority deferred task for each role that has 0 pending tasks.

        This prevents role starvation when at soft cap - roles with no pending
        tasks get priority over adding more tasks to already-busy roles.

        Returns:
            List of tasks, one per starved role (highest priority for that role)
        """
        if not self._task_queue or not self._task_queue.redis:
            return []

        redis = self._task_queue.redis
        result: list[DeferredTask] = []

        try:
            # Group deferred tasks by target_role
            # Store (key, member, score, task) to avoid double deserialization
            role_tasks: dict[str, list[tuple[str, str, float, DeferredTask]]] = {}

            for task_type in await self._get_all_deferred_task_types():
                key = self._deferred_queue_key(task_type)
                items = await redis.zrange(key, 0, -1, withscores=True)

                for member, score in items:
                    task = DeferredTask.from_json(member)
                    role = task.target_role
                    if role not in role_tasks:
                        role_tasks[role] = []
                    role_tasks[role].append((key, member, score, task))

            if not role_tasks:
                return []

            # For each role, check if it's starved and pick highest priority task
            for role, tasks in role_tasks.items():
                pending_count = await self._get_pending_count_by_role(role)
                if pending_count > 0:
                    # Role already has tasks - not starved
                    continue

                # Role is starved - pick highest priority task (lowest score)
                tasks.sort(key=lambda x: x[2])
                key, member, _score, task = tasks[0]

                # Remove from Redis and add to result
                await redis.zrem(key, member)
                result.append(task)
                logger.info(
                    f"Processing deferred {task.task_type} task for starved role {role} "
                    f"(priority {task.priority})"
                )

        except Exception as e:
            logger.error(f"Failed to get deferred tasks for starved roles: {e}")

        return result

    async def get_deferred_queue_status(
        self: RedTeamDispatcher,
    ) -> dict[str, Any]:
        """Get status of deferred queues for monitoring."""
        queue_sizes: dict[str, int] = {}

        if self._task_queue and self._task_queue.redis:
            redis = self._task_queue.redis
            try:
                for task_type in await self._get_all_deferred_task_types():
                    key = self._deferred_queue_key(task_type)
                    count = await redis.zcard(key)
                    if count > 0:
                        queue_sizes[task_type] = count
            except Exception as e:
                logger.error(f"Failed to get deferred queue status: {e}")

        total = sum(queue_sizes.values())
        max_total = get_max_deferred_total()

        return {
            "queue_sizes": queue_sizes,
            "total_queued": total,
            "max_total": max_total,
            "capacity_pct": round(100 * total / max_total, 1) if max_total else 0,
            "stats": self._deferred_queue_stats.copy(),
            "redis_backed": True,
        }


__all__ = ["DeferredQueueMixin", "DeferredTask"]
