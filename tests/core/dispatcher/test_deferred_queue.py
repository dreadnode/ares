"""Tests for the Redis-backed deferred task queue functionality."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from ares.core.config import (
    get_deferred_task_max_age,
    get_max_deferred_per_type,
    get_max_deferred_total,
)
from ares.core.dispatcher import RedTeamDispatcher
from ares.core.dispatcher.deferred_queue import (
    DEFERRED_QUEUE_PREFIX,
    DeferredQueueMixin,
    DeferredTask,
)
from ares.core.models import SharedRedTeamState


class FakeRedis:
    """Fake Redis client for testing ZSET operations."""

    def __init__(self):
        self._data: dict[str, dict[str, float]] = {}  # key -> {member: score}

    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        if key not in self._data:
            self._data[key] = {}
        added = 0
        for member, score in mapping.items():
            if member not in self._data[key]:
                added += 1
            self._data[key][member] = score
        return added

    async def zrem(self, key: str, *members: str) -> int:
        if key not in self._data:
            return 0
        removed = 0
        for member in members:
            if member in self._data[key]:
                del self._data[key][member]
                removed += 1
        return removed

    async def zcard(self, key: str) -> int:
        return len(self._data.get(key, {}))

    async def zrange(self, key: str, start: int, end: int, withscores: bool = False) -> list:
        if key not in self._data:
            return []
        items = sorted(self._data[key].items(), key=lambda x: x[1])
        # Handle negative indices
        end = len(items) if end == -1 else end + 1
        if start < 0:
            start = len(items) + start
        selected = items[start:end]
        if withscores:
            return selected
        return [member for member, _ in selected]

    async def zrangebyscore(
        self,
        key: str,
        min_score: str | float,
        max_score: float,
        withscores: bool = False,
    ) -> list:
        if key not in self._data:
            return []
        min_val = float("-inf") if min_score == "-inf" else float(min_score)
        items = [(m, s) for m, s in self._data[key].items() if min_val <= s <= max_score]
        items.sort(key=lambda x: x[1])
        if withscores:
            return items
        return [member for member, _ in items]

    async def delete(self, key: str) -> int:
        if key in self._data:
            del self._data[key]
            return 1
        return 0

    async def scan_iter(self, match: str):
        """Yield keys matching the pattern."""
        import fnmatch

        for key in list(self._data.keys()):
            if fnmatch.fnmatch(key, match):
                yield key

    def get_zset(self, key: str) -> dict[str, float]:
        """Helper for tests to inspect ZSET contents."""
        return self._data.get(key, {})

    def clear(self):
        """Clear all data."""
        self._data.clear()


class TestDeferredTask:
    """Tests for DeferredTask dataclass ordering and serialization."""

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

    def test_json_serialization(self):
        """Tasks should serialize to/from JSON correctly."""
        task = DeferredTask(
            priority=3,
            enqueue_time=1234567890.123,
            task_type="exploit",
            target_role="privesc",
            payload={"target": "192.168.58.10", "cred_id": "abc123"},
            source_agent="orchestrator",
        )

        json_str = task.to_json()
        restored = DeferredTask.from_json(json_str)

        assert restored.priority == task.priority
        assert restored.enqueue_time == task.enqueue_time
        assert restored.task_type == task.task_type
        assert restored.target_role == task.target_role
        assert restored.payload == task.payload
        assert restored.source_agent == task.source_agent


class TestScoreComputation:
    """Tests for ZSET score computation."""

    def test_compute_score_priority_ordering(self):
        """Higher priority (lower number) should have lower score."""
        score_high = DeferredQueueMixin._compute_score(1, 1000.0)  # High priority
        score_low = DeferredQueueMixin._compute_score(9, 1000.0)  # Low priority
        assert score_high < score_low

    def test_compute_score_time_ordering_within_priority(self):
        """Earlier time should have lower score within same priority."""
        score_early = DeferredQueueMixin._compute_score(5, 1000.0)
        score_late = DeferredQueueMixin._compute_score(5, 2000.0)
        assert score_early < score_late

    def test_parse_score_roundtrip(self):
        """Score should roundtrip through compute/parse."""
        priority = 3
        enqueue_time = 1707955200.123

        score = DeferredQueueMixin._compute_score(priority, enqueue_time)
        parsed_priority, parsed_time = DeferredQueueMixin._parse_score(score)

        assert parsed_priority == priority
        # Time loses sub-millisecond precision
        assert abs(parsed_time - enqueue_time) < 0.001


class TestDeferredQueueMixin:
    """Tests for the DeferredQueueMixin functionality with Redis."""

    @pytest.fixture
    def fake_redis(self):
        """Create a fake Redis client."""
        return FakeRedis()

    @pytest.fixture
    def dispatcher(self, fake_redis):
        """Create a dispatcher with fake Redis."""
        d = RedTeamDispatcher()
        d._shared_state = SharedRedTeamState(operation_id="op-test-deferred")
        d._operation_id = "op-test-deferred"
        d._running = True

        # Mock task queue with fake Redis
        d._task_queue = MagicMock()
        d._task_queue.redis = fake_redis
        d._task_queue.submit_task = AsyncMock(return_value="task-123")

        return d

    def _queue_key(self, dispatcher, task_type: str) -> str:
        """Helper to get queue key."""
        return f"{DEFERRED_QUEUE_PREFIX}:{dispatcher._operation_id}:{task_type}"

    @pytest.mark.asyncio
    async def test_enqueue_deferred_task(self, dispatcher, fake_redis):
        """Should successfully enqueue a task to Redis."""
        result = await dispatcher._enqueue_deferred_task(
            task_type="lateral",
            target_role="lateral",
            payload={"target": "192.168.58.10"},
            source_agent="orchestrator",
            priority=5,
        )

        assert result is True
        key = self._queue_key(dispatcher, "lateral")
        assert await fake_redis.zcard(key) == 1
        assert dispatcher._deferred_queue_stats["queued"] == 1

    @pytest.mark.asyncio
    async def test_queue_limit_per_type(self, dispatcher, fake_redis):
        """Should respect max queue size per task type."""
        key = self._queue_key(dispatcher, "lateral")

        # Fill the queue to capacity
        for i in range(get_max_deferred_per_type()):
            await dispatcher._enqueue_deferred_task(
                task_type="lateral",
                target_role="lateral",
                payload={"target": f"192.168.58.{i}"},
                source_agent="orchestrator",
                priority=5,  # All same priority
            )

        assert await fake_redis.zcard(key) == get_max_deferred_per_type()

        # Adding another with same priority should fail
        result = await dispatcher._enqueue_deferred_task(
            task_type="lateral",
            target_role="lateral",
            payload={"target": "192.168.58.99"},
            source_agent="orchestrator",
            priority=5,  # Same priority - will be rejected
        )

        assert result is False
        assert await fake_redis.zcard(key) == get_max_deferred_per_type()

    @pytest.mark.asyncio
    async def test_priority_eviction(self, dispatcher, fake_redis):
        """Higher priority task should evict lower priority when queue is full."""
        key = self._queue_key(dispatcher, "recon")

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
        assert await fake_redis.zcard(key) == get_max_deferred_per_type()
        assert dispatcher._deferred_queue_stats["evicted_capacity"] >= 1

        # Verify the high priority task is now in the queue
        items = await fake_redis.zrange(key, 0, -1, withscores=True)
        priorities = [DeferredQueueMixin._parse_score(s)[0] for _, s in items]
        assert 2 in priorities

    @pytest.mark.asyncio
    async def test_stale_task_eviction(self, dispatcher, fake_redis):
        """Stale tasks should be evicted when enqueueing new tasks."""
        key = self._queue_key(dispatcher, "exploit")

        # Manually add a stale task to Redis
        stale_time = time.time() - get_deferred_task_max_age() - 10
        stale_task = DeferredTask(
            priority=5,
            enqueue_time=stale_time,
            task_type="exploit",
            target_role="privesc",
            payload={"old": "task"},
            source_agent="orchestrator",
        )
        score = DeferredQueueMixin._compute_score(5, stale_time)
        await fake_redis.zadd(key, {stale_task.to_json(): score})

        # Enqueue a new task - should trigger cleanup
        await dispatcher._enqueue_deferred_task(
            task_type="exploit",
            target_role="privesc",
            payload={"new": "task"},
            source_agent="orchestrator",
            priority=5,
        )

        # Only the new task should remain
        assert await fake_redis.zcard(key) == 1
        items = await fake_redis.zrange(key, 0, -1)
        task = DeferredTask.from_json(items[0])
        assert task.payload == {"new": "task"}
        assert dispatcher._deferred_queue_stats["evicted_age"] == 1

    @pytest.mark.asyncio
    async def test_get_highest_priority_deferred(self, dispatcher, fake_redis):
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
        assert await fake_redis.zcard(self._queue_key(dispatcher, "exploit")) == 0
        assert await fake_redis.zcard(self._queue_key(dispatcher, "lateral")) == 0
        assert await fake_redis.zcard(self._queue_key(dispatcher, "recon")) == 1

    @pytest.mark.asyncio
    async def test_get_deferred_queue_status(self, dispatcher, fake_redis):
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

        status = await dispatcher.get_deferred_queue_status()

        assert status["total_queued"] == 2
        assert status["queue_sizes"]["lateral"] == 1
        assert status["queue_sizes"]["exploit"] == 1
        assert status["stats"]["queued"] == 2
        assert status["redis_backed"] is True

    @pytest.mark.asyncio
    async def test_get_critical_priority_deferred(self, dispatcher, fake_redis):
        """Should return only critical priority tasks."""
        # Add tasks with various priorities
        await dispatcher._enqueue_deferred_task(
            task_type="exploit",
            target_role="privesc",
            payload={"critical": True},
            source_agent="orchestrator",
            priority=1,  # Critical
        )
        await dispatcher._enqueue_deferred_task(
            task_type="lateral",
            target_role="lateral",
            payload={"critical": True},
            source_agent="orchestrator",
            priority=3,  # Critical (threshold is 3)
        )
        await dispatcher._enqueue_deferred_task(
            task_type="recon",
            target_role="recon",
            payload={"normal": True},
            source_agent="orchestrator",
            priority=5,  # Not critical
        )

        critical_tasks = await dispatcher._get_critical_priority_deferred()

        assert len(critical_tasks) == 2
        assert all(t.priority <= 3 for t in critical_tasks)
        # Non-critical task should remain
        assert await fake_redis.zcard(self._queue_key(dispatcher, "recon")) == 1

    @pytest.mark.asyncio
    async def test_drain_queues_on_da(self, dispatcher, fake_redis):
        """Should drain all queues when DA is achieved."""
        # Add tasks to multiple queues
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

        # Verify tasks exist
        assert await fake_redis.zcard(self._queue_key(dispatcher, "lateral")) == 1
        assert await fake_redis.zcard(self._queue_key(dispatcher, "exploit")) == 1

        # Drain on DA
        await dispatcher._drain_queues_on_da()

        # All queues should be empty
        assert await fake_redis.zcard(self._queue_key(dispatcher, "lateral")) == 0
        assert await fake_redis.zcard(self._queue_key(dispatcher, "exploit")) == 0

    @pytest.mark.asyncio
    async def test_get_deferred_for_starved_roles(self, dispatcher, fake_redis):
        """Should return one task per starved role (roles with 0 pending tasks)."""
        from ares.core.models import TaskInfo, TaskStatus

        # Add tasks for multiple roles
        await dispatcher._enqueue_deferred_task(
            task_type="credential_access",
            target_role="credential",
            payload={"target": "dc01.contoso.local"},
            source_agent="orchestrator",
            priority=4,
        )
        await dispatcher._enqueue_deferred_task(
            task_type="lateral",
            target_role="lateral",
            payload={"target": "192.168.58.10"},
            source_agent="orchestrator",
            priority=5,
        )
        await dispatcher._enqueue_deferred_task(
            task_type="recon",
            target_role="recon",
            payload={"target": "192.168.58.0/24"},
            source_agent="orchestrator",
            priority=6,
        )

        # Simulate lateral role having 1 pending task (not starved)
        dispatcher._shared_state.pending_tasks["task-1"] = TaskInfo(
            task_id="task-1",
            task_type="lateral",
            assigned_agent="lateral",
            params={},
            status=TaskStatus.IN_PROGRESS,
        )

        # Get deferred tasks for starved roles (credential, recon are starved)
        tasks = await dispatcher._get_deferred_for_starved_roles()

        # Should get 2 tasks (credential and recon), not lateral
        assert len(tasks) == 2
        target_roles = {t.target_role for t in tasks}
        assert target_roles == {"credential", "recon"}

        # Lateral task should remain in queue
        assert await fake_redis.zcard(self._queue_key(dispatcher, "lateral")) == 1


class TestGlobalQueueLimits:
    """Tests for global deferred queue limits (get_max_deferred_total())."""

    @pytest.fixture
    def fake_redis(self):
        return FakeRedis()

    @pytest.fixture
    def dispatcher(self, fake_redis):
        d = RedTeamDispatcher()
        d._shared_state = SharedRedTeamState(operation_id="op-test-global")
        d._operation_id = "op-test-global"
        d._running = True
        d._task_queue = MagicMock()
        d._task_queue.redis = fake_redis
        d._task_queue.submit_task = AsyncMock(return_value="task-123")
        return d

    @pytest.mark.asyncio
    async def test_total_queue_limit_across_types(self, dispatcher, fake_redis):
        """Should enforce get_max_deferred_total() across all task types."""
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
        total = await dispatcher._get_total_deferred_count()
        assert total == get_max_deferred_total()

        # Adding another with same priority should fail
        result = await dispatcher._enqueue_deferred_task(
            task_type="crack",
            target_role="cracker",
            payload={"new": "task"},
            source_agent="orchestrator",
            priority=5,
        )

        assert result is False
        new_total = await dispatcher._get_total_deferred_count()
        assert new_total == get_max_deferred_total()

    @pytest.mark.asyncio
    async def test_cross_type_eviction_when_total_full(self, dispatcher, fake_redis):
        """Higher priority task should evict lowest priority across ALL types."""
        # Add low priority tasks to exploit queue
        for i in range(5):
            await dispatcher._enqueue_deferred_task(
                task_type="exploit",
                target_role="privesc",
                payload={"i": i},
                source_agent="orchestrator",
                priority=9,  # Very low priority
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

        # Add to recon
        for i in range(get_max_deferred_per_type()):
            await dispatcher._enqueue_deferred_task(
                task_type="recon",
                target_role="recon",
                payload={"i": i},
                source_agent="orchestrator",
                priority=3,
            )

        # Fill remaining with credential_access
        current = await dispatcher._get_total_deferred_count()
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
        total = await dispatcher._get_total_deferred_count()
        assert total == get_max_deferred_total()

        exploit_key = f"{DEFERRED_QUEUE_PREFIX}:{dispatcher._operation_id}:exploit"
        initial_exploit_count = await fake_redis.zcard(exploit_key)

        # Add very high priority task to a NEW type
        result = await dispatcher._enqueue_deferred_task(
            task_type="crack",
            target_role="cracker",
            payload={"urgent": True},
            source_agent="orchestrator",
            priority=1,  # Highest priority
        )

        assert result is True
        new_total = await dispatcher._get_total_deferred_count()
        assert new_total == get_max_deferred_total()

        # Exploit queue should have lost one task
        assert await fake_redis.zcard(exploit_key) == initial_exploit_count - 1

        # New crack queue should have the high priority task
        crack_key = f"{DEFERRED_QUEUE_PREFIX}:{dispatcher._operation_id}:crack"
        assert await fake_redis.zcard(crack_key) == 1

    @pytest.mark.asyncio
    async def test_status_includes_total_capacity(self, dispatcher, fake_redis):
        """Status should include max_total and capacity_pct."""
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

        status = await dispatcher.get_deferred_queue_status()

        assert "max_total" in status
        assert status["max_total"] == get_max_deferred_total()
        assert "capacity_pct" in status
        expected_pct = round(100 * 2 / get_max_deferred_total(), 1)
        assert status["capacity_pct"] == expected_pct


class TestRecoveryOnStartup:
    """Tests for recovering deferred tasks after restart."""

    @pytest.fixture
    def fake_redis(self):
        return FakeRedis()

    @pytest.fixture
    def dispatcher(self, fake_redis):
        d = RedTeamDispatcher()
        d._shared_state = SharedRedTeamState(operation_id="op-test-recovery")
        d._operation_id = "op-test-recovery"
        d._running = True
        d._task_queue = MagicMock()
        d._task_queue.redis = fake_redis
        d._task_queue.submit_task = AsyncMock(return_value="task-123")
        return d

    @pytest.mark.asyncio
    async def test_startup_counts_recovered_tasks(self, dispatcher, fake_redis):
        """On startup, should count existing tasks in Redis."""
        # Pre-populate Redis with tasks (simulating crash recovery)
        key = f"{DEFERRED_QUEUE_PREFIX}:{dispatcher._operation_id}:exploit"
        for i in range(3):
            task = DeferredTask(
                priority=5,
                enqueue_time=time.time(),
                task_type="exploit",
                target_role="privesc",
                payload={"i": i},
                source_agent="orchestrator",
            )
            score = DeferredQueueMixin._compute_score(5, task.enqueue_time)
            await fake_redis.zadd(key, {task.to_json(): score})

        # Start processor (this counts recovered tasks)
        await dispatcher._start_deferred_processor()

        assert dispatcher._deferred_queue_stats["recovered"] == 3

        # Clean up
        await dispatcher._stop_deferred_processor()


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

        # Add a stale task
        stale_task = TaskInfo(
            task_id="stale-task-1",
            task_type="exploit",
            assigned_agent="privesc",
            status=TaskStatus.PENDING,
        )
        # PENDING tasks use 3x the stale timeout, so we need to exceed that threshold
        old_time = datetime.now(timezone.utc) - timedelta(seconds=get_stale_task_timeout() * 3 + 60)
        stale_task.created_at = old_time
        stale_task.last_activity_at = old_time

        # Add a fresh task
        fresh_task = TaskInfo(
            task_id="fresh-task-1",
            task_type="lateral",
            assigned_agent="lateral",
            status=TaskStatus.PENDING,
        )

        dispatcher._shared_state.pending_tasks["stale-task-1"] = stale_task
        dispatcher._shared_state.pending_tasks["fresh-task-1"] = fresh_task

        # Run cleanup
        await dispatcher._cleanup_stale_tasks()

        # Stale task should be removed
        assert "stale-task-1" not in dispatcher._shared_state.pending_tasks

        # Fresh task should remain
        assert "fresh-task-1" in dispatcher._shared_state.pending_tasks
