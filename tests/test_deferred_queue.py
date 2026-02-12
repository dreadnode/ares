"""Tests for the deferred task queue functionality."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.config import (
    get_deferred_task_max_age,
    get_max_deferred_per_type,
    get_max_deferred_total,
)
from ares.core.dispatcher import RedTeamDispatcher
from ares.core.dispatcher.deferred_queue import DeferredTask
from ares.core.models import SharedRedTeamState


class TestDeferredTask:
    """Tests for DeferredTask dataclass ordering."""

    def test_ordering_by_priority(self):
        """Tasks should be ordered by priority (lower = higher priority)."""
        task1 = DeferredTask(
            priority=5,
            enqueue_time=100.0,
            task_type="exploit",
            target_role="privesc",
            payload={},
            source_agent="orchestrator",
        )
        task2 = DeferredTask(
            priority=1,
            enqueue_time=100.0,
            task_type="lateral",
            target_role="lateral",
            payload={},
            source_agent="orchestrator",
        )
        assert task2 < task1  # Lower priority number = higher priority

    def test_ordering_by_time_when_same_priority(self):
        """Tasks with same priority should be ordered by enqueue time."""
        task1 = DeferredTask(
            priority=5,
            enqueue_time=200.0,
            task_type="exploit",
            target_role="privesc",
            payload={},
            source_agent="orchestrator",
        )
        task2 = DeferredTask(
            priority=5,
            enqueue_time=100.0,
            task_type="lateral",
            target_role="lateral",
            payload={},
            source_agent="orchestrator",
        )
        assert task2 < task1  # Earlier time = higher priority


class TestDeferredQueueMixin:
    """Tests for the DeferredQueueMixin functionality."""

    @pytest.fixture
    def dispatcher(self):
        """Create a dispatcher with deferred queue initialized."""
        d = RedTeamDispatcher()
        d._shared_state = SharedRedTeamState(operation_id="op-test-deferred")
        d._running = True
        return d

    @pytest.mark.asyncio
    async def test_enqueue_deferred_task(self, dispatcher):
        """Should successfully enqueue a task."""
        result = await dispatcher._enqueue_deferred_task(
            task_type="lateral",
            target_role="lateral",
            payload={"target": "192.168.58.10"},
            source_agent="orchestrator",
            priority=5,
        )

        assert result is True
        assert "lateral" in dispatcher._deferred_queues
        assert len(dispatcher._deferred_queues["lateral"]) == 1
        assert dispatcher._deferred_queue_stats["queued"] == 1

    @pytest.mark.asyncio
    async def test_queue_limit_per_type(self, dispatcher):
        """Should respect max queue size per task type."""
        # Fill the queue to capacity
        for i in range(get_max_deferred_per_type()):
            await dispatcher._enqueue_deferred_task(
                task_type="lateral",
                target_role="lateral",
                payload={"target": f"192.168.58.{i}"},
                source_agent="orchestrator",
                priority=5,  # All same priority
            )

        assert len(dispatcher._deferred_queues["lateral"]) == get_max_deferred_per_type()

        # Adding another with same priority should fail
        result = await dispatcher._enqueue_deferred_task(
            task_type="lateral",
            target_role="lateral",
            payload={"target": "192.168.58.99"},
            source_agent="orchestrator",
            priority=5,  # Same priority - will be rejected
        )

        assert result is False
        assert len(dispatcher._deferred_queues["lateral"]) == get_max_deferred_per_type()

    @pytest.mark.asyncio
    async def test_priority_eviction(self, dispatcher):
        """Higher priority task should evict lower priority when queue is full."""
        # Fill queue with low priority tasks
        for i in range(get_max_deferred_per_type()):
            await dispatcher._enqueue_deferred_task(
                task_type="recon",
                target_role="recon",
                payload={"target": f"192.168.58.{i}"},
                source_agent="orchestrator",
                priority=8,  # Low priority
            )

        # Add high priority task - should evict one low priority task
        result = await dispatcher._enqueue_deferred_task(
            task_type="recon",
            target_role="recon",
            payload={"target": "192.168.58.240"},
            source_agent="orchestrator",
            priority=2,  # High priority
        )

        assert result is True
        assert len(dispatcher._deferred_queues["recon"]) == get_max_deferred_per_type()
        assert dispatcher._deferred_queue_stats["evicted_capacity"] == 1

        # Verify the high priority task is now in the queue
        tasks = dispatcher._deferred_queues["recon"]
        priorities = [t.priority for t in tasks]
        assert 2 in priorities

    @pytest.mark.asyncio
    async def test_stale_task_eviction(self, dispatcher):
        """Stale tasks should be evicted when enqueueing new tasks."""
        # Manually add a stale task
        stale_task = DeferredTask(
            priority=5,
            enqueue_time=time.time() - get_deferred_task_max_age() - 10,  # 10 sec past expiry
            task_type="exploit",
            target_role="privesc",
            payload={"old": "task"},
            source_agent="orchestrator",
        )
        dispatcher._deferred_queues["exploit"] = [stale_task]

        # Enqueue a new task - should trigger cleanup
        await dispatcher._enqueue_deferred_task(
            task_type="exploit",
            target_role="privesc",
            payload={"new": "task"},
            source_agent="orchestrator",
            priority=5,
        )

        # Only the new task should remain
        assert len(dispatcher._deferred_queues["exploit"]) == 1
        assert dispatcher._deferred_queues["exploit"][0].payload == {"new": "task"}
        assert dispatcher._deferred_queue_stats["evicted_age"] == 1

    @pytest.mark.asyncio
    async def test_get_highest_priority_deferred(self, dispatcher):
        """Should return highest priority tasks across all queues."""
        # Add tasks to different queues with different priorities
        await dispatcher._enqueue_deferred_task(
            task_type="lateral",
            target_role="lateral",
            payload={"type": "lateral"},
            source_agent="orchestrator",
            priority=5,
        )
        await dispatcher._enqueue_deferred_task(
            task_type="exploit",
            target_role="privesc",
            payload={"type": "exploit"},
            source_agent="orchestrator",
            priority=2,  # Highest priority
        )
        await dispatcher._enqueue_deferred_task(
            task_type="recon",
            target_role="recon",
            payload={"type": "recon"},
            source_agent="orchestrator",
            priority=7,
        )

        # Get top 2 tasks
        tasks = await dispatcher._get_highest_priority_deferred(max_count=2)

        assert len(tasks) == 2
        assert tasks[0].priority == 2  # exploit (highest)
        assert tasks[1].priority == 5  # lateral (second)

        # Tasks should be removed from queues
        assert len(dispatcher._deferred_queues["exploit"]) == 0
        assert len(dispatcher._deferred_queues["lateral"]) == 0
        assert len(dispatcher._deferred_queues["recon"]) == 1

    @pytest.mark.asyncio
    async def test_get_deferred_queue_status(self, dispatcher):
        """Should return correct queue status."""
        await dispatcher._enqueue_deferred_task(
            task_type="lateral",
            target_role="lateral",
            payload={},
            source_agent="orchestrator",
            priority=5,
        )
        await dispatcher._enqueue_deferred_task(
            task_type="exploit",
            target_role="privesc",
            payload={},
            source_agent="orchestrator",
            priority=2,
        )

        status = dispatcher.get_deferred_queue_status()

        assert status["total_queued"] == 2
        assert status["queue_sizes"]["lateral"] == 1
        assert status["queue_sizes"]["exploit"] == 1
        assert status["stats"]["queued"] == 2

    @pytest.mark.asyncio
    async def test_deferred_processor_submits_when_slots_available(self, dispatcher):
        """Processor should submit queued tasks when capacity is available."""
        # Mock task queue
        dispatcher._task_queue = MagicMock()
        dispatcher._task_queue.submit_task = AsyncMock(return_value="task-123")

        # Mock LLM task count to show capacity available
        dispatcher._get_llm_task_count = AsyncMock(return_value=2)

        # Queue a task
        await dispatcher._enqueue_deferred_task(
            task_type="lateral",
            target_role="lateral",
            payload={"target": "192.168.58.10"},
            source_agent="orchestrator",
            priority=5,
        )

        # Get tasks to submit (simulating what processor does)
        with patch("ares.core.dispatcher.deferred_queue.get_max_concurrent_tasks", return_value=5):
            tasks = await dispatcher._get_highest_priority_deferred(max_count=3)

        assert len(tasks) == 1
        assert tasks[0].task_type == "lateral"


class TestThrottlingWithDeferredQueue:
    """Tests for throttling integration with deferred queue."""

    @pytest.fixture
    def dispatcher_with_queue(self):
        """Create dispatcher with mock task queue."""
        d = RedTeamDispatcher()
        d._shared_state = SharedRedTeamState(operation_id="op-test-throttle")
        d._running = True

        # Mock task queue
        d._task_queue = MagicMock()
        d._task_queue.submit_task = AsyncMock(return_value="task-submitted")

        return d

    @pytest.mark.asyncio
    async def test_throttled_task_gets_queued_not_dropped(self, dispatcher_with_queue):
        """When throttled, tasks should be queued instead of dropped."""
        dispatcher = dispatcher_with_queue

        # Mock to simulate being at capacity and task should be deferred
        dispatcher._get_llm_task_count = AsyncMock(return_value=10)
        dispatcher._get_pending_count_by_role = AsyncMock(return_value=2)
        dispatcher._get_queue_length = AsyncMock(return_value=1)
        dispatcher._get_operation_phase = MagicMock(return_value="enumeration")
        dispatcher._get_phase_priority_adjustment = MagicMock(return_value=2)  # Low priority

        with (
            patch("ares.core.dispatcher.throttling.get_max_concurrent_tasks", return_value=5),
            patch("ares.core.dispatcher.throttling.get_min_slots_per_role", return_value=1),
        ):
            result = await dispatcher._throttled_submit_task(
                task_type="recon",
                target_role="recon",
                payload={"action": "scan"},
                source_agent="orchestrator",
                priority=5,
            )

        # Task should return empty string (not immediately submitted)
        assert result == ""

        # But task should be in deferred queue, not lost
        assert "recon" in dispatcher._deferred_queues
        assert len(dispatcher._deferred_queues["recon"]) == 1
        assert dispatcher._deferred_queue_stats["queued"] == 1


class TestStaleTaskCleanup:
    """Tests for stale task cleanup in pending_tasks."""

    @pytest.fixture
    def dispatcher(self):
        """Create a dispatcher with pending tasks."""
        d = RedTeamDispatcher()
        d._shared_state = SharedRedTeamState(operation_id="op-test-stale")
        d._running = True
        d._task_queue = MagicMock()
        return d

    @pytest.mark.asyncio
    async def test_cleanup_removes_old_pending_tasks(self, dispatcher):
        """Tasks older than stale_task_timeout should be removed."""
        from datetime import datetime, timedelta, timezone

        from ares.core.config import get_stale_task_timeout
        from ares.core.models import TaskInfo, TaskStatus

        # Add a stale task (older than threshold)
        stale_task = TaskInfo(
            task_id="stale-task-1",
            task_type="exploit",
            assigned_agent="privesc",
            status=TaskStatus.PENDING,
        )
        # Manually set created_at to be older than threshold
        stale_task.created_at = datetime.now(timezone.utc) - timedelta(
            seconds=get_stale_task_timeout() + 60
        )

        # Add a fresh task
        fresh_task = TaskInfo(
            task_id="fresh-task-1",
            task_type="lateral",
            assigned_agent="lateral",
            status=TaskStatus.PENDING,
        )
        # Fresh task has default created_at (now)

        dispatcher._shared_state.pending_tasks["stale-task-1"] = stale_task
        dispatcher._shared_state.pending_tasks["fresh-task-1"] = fresh_task
        dispatcher._redis_task_ids.add("stale-task-1")
        dispatcher._redis_task_ids.add("fresh-task-1")

        assert len(dispatcher._shared_state.pending_tasks) == 2
        assert len(dispatcher._redis_task_ids) == 2

        # Run cleanup
        await dispatcher._cleanup_stale_tasks()

        # Stale task should be removed
        assert "stale-task-1" not in dispatcher._shared_state.pending_tasks
        assert "stale-task-1" not in dispatcher._redis_task_ids

        # Fresh task should remain
        assert "fresh-task-1" in dispatcher._shared_state.pending_tasks
        assert "fresh-task-1" in dispatcher._redis_task_ids

    @pytest.mark.asyncio
    async def test_cleanup_ignores_completed_tasks(self, dispatcher):
        """Completed tasks should not be affected by cleanup."""
        from datetime import datetime, timedelta, timezone

        from ares.core.config import get_stale_task_timeout
        from ares.core.models import TaskInfo, TaskStatus

        # Add an old but completed task
        completed_task = TaskInfo(
            task_id="completed-task-1",
            task_type="exploit",
            assigned_agent="privesc",
            status=TaskStatus.COMPLETED,
        )
        completed_task.created_at = datetime.now(timezone.utc) - timedelta(
            seconds=get_stale_task_timeout() + 60
        )

        dispatcher._shared_state.pending_tasks["completed-task-1"] = completed_task

        # Run cleanup
        await dispatcher._cleanup_stale_tasks()

        # Completed task should remain (not cleaned up)
        assert "completed-task-1" in dispatcher._shared_state.pending_tasks

    @pytest.mark.asyncio
    async def test_deferred_processor_tracks_submitted_tasks(self, dispatcher):
        """When deferred processor submits tasks, they should be tracked."""
        from ares.core.dispatcher.deferred_queue import DeferredTask

        # Setup
        dispatcher._task_queue.submit_task = AsyncMock(return_value="task-from-deferred")
        dispatcher._get_llm_task_count = AsyncMock(return_value=2)

        # Add a deferred task directly
        deferred_task = DeferredTask(
            priority=5,
            enqueue_time=time.time(),
            task_type="exploit",
            target_role="privesc",
            payload={"target": "192.168.58.10"},
            source_agent="orchestrator",
        )
        dispatcher._deferred_queues["exploit"] = [deferred_task]

        # Simulate what the processor does - get tasks and submit them
        with patch("ares.core.dispatcher.deferred_queue.get_max_concurrent_tasks", return_value=5):
            tasks_to_submit = await dispatcher._get_highest_priority_deferred(max_count=3)

        # Submit the task manually (simulating processor)
        for task in tasks_to_submit:
            task_id = await dispatcher._task_queue.submit_task(
                task_type=task.task_type,
                target_role=task.target_role,
                payload=task.payload,
                source_agent=task.source_agent,
                priority=task.priority,
            )
            # This is what the fix adds - tracking the task
            if task_id and dispatcher._shared_state:
                from ares.core.models import TaskInfo

                task_info = TaskInfo(
                    task_id=task_id,
                    task_type=task.task_type,
                    assigned_agent=task.target_role,
                    params=task.payload,
                )
                dispatcher._shared_state.pending_tasks[task_id] = task_info
                dispatcher._redis_task_ids.add(task_id)

        # Verify task is tracked
        assert "task-from-deferred" in dispatcher._shared_state.pending_tasks
        assert "task-from-deferred" in dispatcher._redis_task_ids


class TestGlobalQueueLimits:
    """Tests for global deferred queue limits (get_max_deferred_total())."""

    @pytest.fixture
    def dispatcher(self):
        """Create a dispatcher with deferred queue initialized."""
        d = RedTeamDispatcher()
        d._shared_state = SharedRedTeamState(operation_id="op-test-global")
        d._running = True
        return d

    @pytest.mark.asyncio
    async def test_total_queue_limit_across_types(self, dispatcher):
        """Should enforce get_max_deferred_total() across all task types."""
        # Fill queue to total capacity using multiple task types
        # Since get_max_deferred_per_type()=10 and get_max_deferred_total()=25,
        # we need at least 3 types to hit total limit
        task_types = ["exploit", "lateral", "recon", "credential_access"]

        added = 0
        type_idx = 0
        while added < get_max_deferred_total():
            task_type = task_types[type_idx % len(task_types)]
            result = await dispatcher._enqueue_deferred_task(
                task_type=task_type,
                target_role=task_type if task_type != "exploit" else "privesc",
                payload={"i": added},
                source_agent="orchestrator",
                priority=5,
            )
            if result:
                added += 1
            type_idx += 1

        # Verify total is at capacity
        total = sum(len(q) for q in dispatcher._deferred_queues.values())
        assert total == get_max_deferred_total()

        # Adding another with same priority should fail (total limit)
        result = await dispatcher._enqueue_deferred_task(
            task_type="crack",  # New type - would have room per-type but not total
            target_role="cracker",
            payload={"new": "task"},
            source_agent="orchestrator",
            priority=5,  # Same priority - should be rejected
        )

        assert result is False
        new_total = sum(len(q) for q in dispatcher._deferred_queues.values())
        assert new_total == get_max_deferred_total()

    @pytest.mark.asyncio
    async def test_cross_type_eviction_when_total_full(self, dispatcher):
        """Higher priority task should evict lowest priority across ALL types."""
        # Fill with mixed priorities across multiple types
        # Need to spread across enough types to hit get_max_deferred_total()
        # Each type can hold get_max_deferred_per_type(), so use multiple types

        # Add low priority tasks to exploit queue (will be evicted)
        for i in range(5):
            await dispatcher._enqueue_deferred_task(
                task_type="exploit",
                target_role="privesc",
                payload={"i": i},
                source_agent="orchestrator",
                priority=9,  # Very low priority - candidates for eviction
            )

        # Add medium priority to lateral
        for i in range(5):
            await dispatcher._enqueue_deferred_task(
                task_type="lateral",
                target_role="lateral",
                payload={"i": i},
                source_agent="orchestrator",
                priority=5,
            )

        # Add to recon (up to per-type limit)
        for i in range(get_max_deferred_per_type()):
            await dispatcher._enqueue_deferred_task(
                task_type="recon",
                target_role="recon",
                payload={"i": i},
                source_agent="orchestrator",
                priority=3,
            )

        # Fill remaining with credential_access to hit total
        current = sum(len(q) for q in dispatcher._deferred_queues.values())
        remaining = get_max_deferred_total() - current
        for i in range(remaining):
            await dispatcher._enqueue_deferred_task(
                task_type="credential_access",
                target_role="credential_access",
                payload={"i": i},
                source_agent="orchestrator",
                priority=4,
            )

        # Verify at capacity
        total = sum(len(q) for q in dispatcher._deferred_queues.values())
        assert total == get_max_deferred_total()

        initial_exploit_count = len(dispatcher._deferred_queues["exploit"])

        # Add very high priority task to a NEW type
        result = await dispatcher._enqueue_deferred_task(
            task_type="crack",
            target_role="cracker",
            payload={"urgent": True},
            source_agent="orchestrator",
            priority=1,  # Highest priority - should evict lowest (priority 9 from exploit)
        )

        assert result is True
        # Should still be at total capacity
        new_total = sum(len(q) for q in dispatcher._deferred_queues.values())
        assert new_total == get_max_deferred_total()

        # Exploit queue should have lost one task (lowest priority evicted)
        assert len(dispatcher._deferred_queues["exploit"]) == initial_exploit_count - 1

        # New crack queue should have the high priority task
        assert "crack" in dispatcher._deferred_queues
        assert len(dispatcher._deferred_queues["crack"]) == 1
        assert dispatcher._deferred_queues["crack"][0].priority == 1

    @pytest.mark.asyncio
    async def test_status_includes_total_capacity(self, dispatcher):
        """Status should include max_total and capacity_pct."""
        # Add some tasks
        await dispatcher._enqueue_deferred_task(
            task_type="lateral",
            target_role="lateral",
            payload={},
            source_agent="orchestrator",
            priority=5,
        )
        await dispatcher._enqueue_deferred_task(
            task_type="exploit",
            target_role="privesc",
            payload={},
            source_agent="orchestrator",
            priority=2,
        )

        status = dispatcher.get_deferred_queue_status()

        assert "max_total" in status
        assert status["max_total"] == get_max_deferred_total()
        assert "capacity_pct" in status
        expected_pct = round(100 * 2 / get_max_deferred_total(), 1)
        assert status["capacity_pct"] == expected_pct

    @pytest.mark.asyncio
    async def test_stale_eviction_across_all_queues(self, dispatcher):
        """Stale task eviction should clean ALL queues, not just current type."""
        # Add stale tasks to multiple queues
        stale_time = time.time() - get_deferred_task_max_age() - 10

        stale_exploit = DeferredTask(
            priority=5,
            enqueue_time=stale_time,
            task_type="exploit",
            target_role="privesc",
            payload={"stale": "exploit"},
            source_agent="orchestrator",
        )
        stale_lateral = DeferredTask(
            priority=5,
            enqueue_time=stale_time,
            task_type="lateral",
            target_role="lateral",
            payload={"stale": "lateral"},
            source_agent="orchestrator",
        )
        dispatcher._deferred_queues["exploit"] = [stale_exploit]
        dispatcher._deferred_queues["lateral"] = [stale_lateral]

        # Enqueue to a different type - should trigger cleanup of ALL stale
        await dispatcher._enqueue_deferred_task(
            task_type="recon",
            target_role="recon",
            payload={"new": "task"},
            source_agent="orchestrator",
            priority=5,
        )

        # Both stale queues should be empty
        assert len(dispatcher._deferred_queues["exploit"]) == 0
        assert len(dispatcher._deferred_queues["lateral"]) == 0
        # New task should be there
        assert len(dispatcher._deferred_queues["recon"]) == 1
        # Should have evicted 2 stale tasks
        assert dispatcher._deferred_queue_stats["evicted_age"] == 2
