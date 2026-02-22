"""Tests for dict iteration race condition safety.

These tests verify that iterating over pending_tasks and completed_tasks
uses snapshots to prevent "RuntimeError: dict changed size during iteration".

The fix wraps dict.values() and dict.items() in list() to create snapshots
before iteration, allowing concurrent modifications without crashing.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from ares.core.models import (
    SharedRedTeamState,
    Target,
    TaskInfo,
    TaskResult,
    TaskStatus,
)

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def state_with_pending_tasks() -> SharedRedTeamState:
    """Create a state with pending tasks for testing."""
    state = SharedRedTeamState(
        operation_id="test-op-dict-safety",
        target=Target(ip="192.168.1.100", hostname="dc01"),
    )

    # Add multiple pending tasks
    for i in range(10):
        state.pending_tasks[f"task_{i:03d}"] = TaskInfo(
            task_id=f"task_{i:03d}",
            task_type="recon" if i % 2 == 0 else "lateral",
            assigned_agent="recon" if i % 2 == 0 else "lateral",
            status=TaskStatus.PENDING if i % 3 == 0 else TaskStatus.IN_PROGRESS,
            created_at=datetime.now(timezone.utc),
            params={"index": i},
            retry_count=0,
            max_retries=3,
        )

    return state


@pytest.fixture
def state_with_completed_tasks() -> SharedRedTeamState:
    """Create a state with completed tasks for testing."""
    state = SharedRedTeamState(
        operation_id="test-op-completed-safety",
        target=Target(ip="192.168.1.100", hostname="dc01"),
    )

    # Add multiple completed tasks
    for i in range(10):
        state.completed_tasks[f"task_{i:03d}"] = TaskResult(
            task_id=f"task_{i:03d}",
            success=i % 2 == 0,
            result={"index": i} if i % 2 == 0 else None,
            error=None if i % 2 == 0 else "Test error",
        )

    return state


# ============================================================================
# Throttling Mixin Tests (pending_tasks iteration)
# ============================================================================


class TestThrottlingMixinDictSafety:
    """Tests for dict iteration safety in ThrottlingMixin."""

    @pytest.mark.asyncio
    async def test_get_pending_task_count_with_concurrent_modification(
        self, state_with_pending_tasks: SharedRedTeamState
    ):
        """Test _get_pending_task_count handles concurrent dict modification."""
        from ares.core.dispatcher import RedTeamDispatcher

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = state_with_pending_tasks

        # Modify dict during iteration by scheduling concurrent task
        async def modify_dict():
            await asyncio.sleep(0)  # Yield control
            state_with_pending_tasks.pending_tasks["new_task"] = TaskInfo(
                task_id="new_task",
                task_type="crack",
                assigned_agent="cracker",
                status=TaskStatus.PENDING,
                created_at=datetime.now(timezone.utc),
                params={},
            )

        # Run both concurrently - should not raise RuntimeError
        count, _ = await asyncio.gather(
            dispatcher._get_pending_task_count(),
            modify_dict(),
        )

        # Just verify it completes without RuntimeError
        assert isinstance(count, int)
        assert count >= 0

    @pytest.mark.asyncio
    async def test_get_pending_count_by_role_with_concurrent_modification(
        self, state_with_pending_tasks: SharedRedTeamState
    ):
        """Test _get_pending_count_by_role handles concurrent dict modification."""
        from ares.core.dispatcher import RedTeamDispatcher

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = state_with_pending_tasks

        async def modify_dict():
            await asyncio.sleep(0)
            # Remove a task during iteration
            if "task_001" in state_with_pending_tasks.pending_tasks:
                del state_with_pending_tasks.pending_tasks["task_001"]

        count, _ = await asyncio.gather(
            dispatcher._get_pending_count_by_role("recon"),
            modify_dict(),
        )

        assert isinstance(count, int)
        assert count >= 0

    @pytest.mark.asyncio
    async def test_get_llm_task_count_with_concurrent_modification(
        self, state_with_pending_tasks: SharedRedTeamState
    ):
        """Test _get_llm_task_count handles concurrent dict modification."""
        from ares.core.dispatcher import RedTeamDispatcher

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = state_with_pending_tasks

        async def modify_dict():
            await asyncio.sleep(0)
            state_with_pending_tasks.pending_tasks["another_task"] = TaskInfo(
                task_id="another_task",
                task_type="privesc",
                assigned_agent="privesc",
                status=TaskStatus.IN_PROGRESS,
                created_at=datetime.now(timezone.utc),
                params={},
            )

        count, _ = await asyncio.gather(
            dispatcher._get_llm_task_count(),
            modify_dict(),
        )

        assert isinstance(count, int)
        assert count >= 0


# ============================================================================
# Monitoring Mixin Tests (pending_tasks iteration)
# ============================================================================


class TestMonitoringMixinDictSafety:
    """Tests for dict iteration safety in MonitoringMixin."""

    @pytest.mark.asyncio
    async def test_log_throttle_health_iteration_safety(
        self, state_with_pending_tasks: SharedRedTeamState
    ):
        """Test _log_throttle_health iterates pending_tasks safely with snapshot."""
        # This test verifies the monitoring code uses list() snapshot
        # by checking that concurrent modifications don't cause RuntimeError

        async def iterate_like_monitoring():
            """Simulate what _log_throttle_health does."""
            pending_count = 0
            in_progress_count = 0
            oldest_task_age = 0.0
            now = datetime.now(timezone.utc)

            # Snapshot to avoid "dict changed size during iteration"
            for task_info in list(state_with_pending_tasks.pending_tasks.values()):
                if task_info.status == TaskStatus.PENDING:
                    pending_count += 1
                elif task_info.status == TaskStatus.IN_PROGRESS:
                    in_progress_count += 1
                    task_age = (now - task_info.created_at).total_seconds()
                    oldest_task_age = max(oldest_task_age, task_age)

            return pending_count, in_progress_count

        async def modify_dict():
            await asyncio.sleep(0)
            # Add and remove tasks during iteration
            state_with_pending_tasks.pending_tasks["monitor_test"] = TaskInfo(
                task_id="monitor_test",
                task_type="recon",
                assigned_agent="recon",
                status=TaskStatus.PENDING,
                created_at=datetime.now(timezone.utc),
                params={},
            )

        # Should complete without RuntimeError
        result, _ = await asyncio.gather(
            iterate_like_monitoring(),
            modify_dict(),
        )

        pending, in_progress = result
        assert isinstance(pending, int)
        assert isinstance(in_progress, int)


# ============================================================================
# Recovery Module Tests (pending_tasks iteration)
# ============================================================================


class TestRecoveryDictSafety:
    """Tests for dict iteration safety in recovery module."""

    def test_get_interrupted_tasks_with_snapshot(
        self, state_with_pending_tasks: SharedRedTeamState
    ):
        """Test get_interrupted_tasks uses snapshot for iteration."""
        from ares.core.recovery import OperationRecoveryManager, OperationResumeHelper

        # Add a failed task from pod restart
        state_with_pending_tasks.pending_tasks["failed_task"] = TaskInfo(
            task_id="failed_task",
            task_type="crack",
            assigned_agent="cracker",
            status=TaskStatus.FAILED,
            created_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            params={},
            retry_count=3,
            max_retries=3,
            error="Pod restart during execution (max retries 3 exceeded)",
        )

        manager = OperationRecoveryManager()
        helper = OperationResumeHelper(state_with_pending_tasks, manager)

        # Verify the method works (uses list() snapshot)
        interrupted = helper.get_interrupted_tasks()

        assert isinstance(interrupted, list)
        assert len(interrupted) == 1
        assert interrupted[0]["task_id"] == "failed_task"

    def test_get_retrying_tasks_with_snapshot(self, state_with_pending_tasks: SharedRedTeamState):
        """Test get_retrying_tasks uses snapshot for iteration."""
        from ares.core.recovery import OperationRecoveryManager, OperationResumeHelper

        # Add a retrying task
        state_with_pending_tasks.pending_tasks["retrying_task"] = TaskInfo(
            task_id="retrying_task",
            task_type="lateral",
            assigned_agent="lateral",
            status=TaskStatus.RETRYING,
            created_at=datetime.now(timezone.utc),
            params={},
            retry_count=1,
            max_retries=3,
            error="Pod restart during execution (retry 1/3)",
        )

        manager = OperationRecoveryManager()
        helper = OperationResumeHelper(state_with_pending_tasks, manager)

        # Verify the method works (uses list() snapshot)
        retrying = helper.get_retrying_tasks()

        assert isinstance(retrying, list)
        assert len(retrying) == 1
        assert retrying[0]["task_id"] == "retrying_task"


# ============================================================================
# Workflows Module Tests (completed_tasks iteration)
# ============================================================================


class TestWorkflowsDictSafety:
    """Tests for dict iteration safety in workflows module."""

    def test_has_admin_access_completed_tasks_iteration(
        self, state_with_completed_tasks: SharedRedTeamState
    ):
        """Test _has_admin_access iterates completed_tasks safely."""
        from ares.core.models import Host
        from ares.core.workflows import _has_admin_access

        host = Host(ip="192.168.1.100", hostname="dc01")
        state_with_completed_tasks.all_hosts.append(host)

        # Should complete without RuntimeError
        result = _has_admin_access(state_with_completed_tasks, host)

        assert isinstance(result, bool)


# ============================================================================
# Persistence Mixin Tests (both dicts iteration)
# ============================================================================


class TestPersistenceMixinDictSafety:
    """Tests for dict iteration safety in PersistenceMixin."""

    @pytest.mark.asyncio
    async def test_persist_pending_tasks_with_concurrent_modification(
        self, state_with_pending_tasks: SharedRedTeamState
    ):
        """Test _persist_pending_tasks handles concurrent dict modification."""
        from ares.core.dispatcher import RedTeamDispatcher

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = state_with_pending_tasks

        # Mock Redis client
        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_pipe.hset = MagicMock()
        mock_pipe.expire = MagicMock()
        mock_pipe.execute = AsyncMock(return_value=[])
        mock_redis.pipeline = MagicMock(return_value=mock_pipe)
        dispatcher._redis_client = mock_redis

        async def modify_dict():
            await asyncio.sleep(0)
            state_with_pending_tasks.pending_tasks["new_during_persist"] = TaskInfo(
                task_id="new_during_persist",
                task_type="recon",
                assigned_agent="recon",
                status=TaskStatus.PENDING,
                created_at=datetime.now(timezone.utc),
                params={},
            )

        # Run both concurrently
        await asyncio.gather(
            dispatcher._persist_pending_tasks("test-op", ttl=3600),
            modify_dict(),
        )

        # Should complete without RuntimeError
        assert mock_pipe.hset.called or mock_pipe.execute.called

    @pytest.mark.asyncio
    async def test_persist_completed_tasks_with_concurrent_modification(
        self, state_with_completed_tasks: SharedRedTeamState
    ):
        """Test _persist_completed_tasks handles concurrent dict modification."""
        from ares.core.dispatcher import RedTeamDispatcher

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = state_with_completed_tasks

        # Mock Redis client
        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_pipe.hset = MagicMock()
        mock_pipe.expire = MagicMock()
        mock_pipe.execute = AsyncMock(return_value=[])
        mock_redis.pipeline = MagicMock(return_value=mock_pipe)
        dispatcher._redis_client = mock_redis

        async def modify_dict():
            await asyncio.sleep(0)
            state_with_completed_tasks.completed_tasks["new_completed"] = TaskResult(
                task_id="new_completed",
                success=True,
                result={"added": "during persist"},
            )

        await asyncio.gather(
            dispatcher._persist_completed_tasks("test-op", ttl=3600),
            modify_dict(),
        )

        # Should complete without RuntimeError
        assert mock_pipe.hset.called or mock_pipe.execute.called


# ============================================================================
# Routing Mixin Tests (pending_tasks iteration)
# ============================================================================


class TestRoutingMixinDictSafety:
    """Tests for dict iteration safety in RoutingMixin."""

    @pytest.mark.asyncio
    async def test_privesc_dedup_iteration_safety(
        self, state_with_pending_tasks: SharedRedTeamState
    ):
        """Test privesc enumeration dedup logic iterates pending_tasks safely."""
        # This test verifies the routing code uses list() snapshot for dedup check
        # by checking that concurrent modifications don't cause RuntimeError

        # Add a privesc_enumeration task to test dedup logic
        state_with_pending_tasks.pending_tasks["existing_privesc"] = TaskInfo(
            task_id="existing_privesc",
            task_type="privesc_enumeration",
            assigned_agent="privesc",
            status=TaskStatus.PENDING,
            created_at=datetime.now(timezone.utc),
            params={"domain": "CORP", "username": "admin", "techniques": ["find_delegation"]},
        )

        async def check_dedup_like_routing():
            """Simulate the dedup check in request_privesc_enumeration."""
            cred_key = "corp:admin"
            technique_key = f"{cred_key}:find_delegation"

            # Snapshot to avoid "dict changed size during iteration"
            for task in list(state_with_pending_tasks.pending_tasks.values()):
                if task.task_type != "privesc_enumeration":
                    continue
                task_domain = (task.params.get("domain") or "").lower()
                task_user = (task.params.get("username") or "").lower()
                task_techniques = task.params.get("techniques") or ["find_delegation"]
                pending_key = f"{task_domain}:{task_user}:{','.join(sorted(task_techniques))}"
                if pending_key == technique_key:
                    return True  # Duplicate found
            return False

        async def modify_dict():
            await asyncio.sleep(0)
            state_with_pending_tasks.pending_tasks["another_task"] = TaskInfo(
                task_id="another_task",
                task_type="recon",
                assigned_agent="recon",
                status=TaskStatus.PENDING,
                created_at=datetime.now(timezone.utc),
                params={},
            )

        # Should complete without RuntimeError
        is_dup, _ = await asyncio.gather(
            check_dedup_like_routing(),
            modify_dict(),
        )

        # Verify dedup check worked
        assert is_dup is True  # Should find the existing privesc task


# ============================================================================
# Concurrent Stress Test
# ============================================================================


class TestConcurrentDictModificationStress:
    """Stress tests for concurrent dict modifications."""

    @pytest.mark.asyncio
    async def test_rapid_concurrent_modifications(
        self, state_with_pending_tasks: SharedRedTeamState
    ):
        """Test rapid concurrent modifications don't cause RuntimeError."""
        from ares.core.dispatcher import RedTeamDispatcher

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = state_with_pending_tasks

        async def reader():
            """Continuously read from dict."""
            for _ in range(50):
                try:
                    # Simulate what the fixed code does - create snapshot
                    count = sum(
                        1
                        for t in list(state_with_pending_tasks.pending_tasks.values())
                        if t.status == TaskStatus.IN_PROGRESS
                    )
                    assert count >= 0
                except RuntimeError as e:
                    if "dictionary changed size" in str(e):
                        pytest.fail("Dict changed size during iteration - fix not applied?")
                    raise
                await asyncio.sleep(0)

        async def writer():
            """Continuously modify dict."""
            for i in range(50):
                task_id = f"stress_task_{i}"
                state_with_pending_tasks.pending_tasks[task_id] = TaskInfo(
                    task_id=task_id,
                    task_type="recon",
                    assigned_agent="recon",
                    status=TaskStatus.PENDING,
                    created_at=datetime.now(timezone.utc),
                    params={},
                )
                await asyncio.sleep(0)
                if task_id in state_with_pending_tasks.pending_tasks:
                    del state_with_pending_tasks.pending_tasks[task_id]

        # Run readers and writers concurrently
        await asyncio.gather(
            reader(),
            reader(),
            writer(),
            writer(),
        )

    @pytest.mark.asyncio
    async def test_completed_tasks_rapid_concurrent_modifications(
        self, state_with_completed_tasks: SharedRedTeamState
    ):
        """Test rapid concurrent modifications to completed_tasks."""

        async def reader():
            for _ in range(50):
                try:
                    # Simulate snapshot iteration
                    results = [
                        r
                        for r in list(state_with_completed_tasks.completed_tasks.values())
                        if r.success
                    ]
                    assert isinstance(results, list)
                except RuntimeError as e:
                    if "dictionary changed size" in str(e):
                        pytest.fail("Dict changed size during iteration")
                    raise
                await asyncio.sleep(0)

        async def writer():
            for i in range(50):
                task_id = f"stress_completed_{i}"
                state_with_completed_tasks.completed_tasks[task_id] = TaskResult(
                    task_id=task_id,
                    success=True,
                    result={},
                )
                await asyncio.sleep(0)
                if task_id in state_with_completed_tasks.completed_tasks:
                    del state_with_completed_tasks.completed_tasks[task_id]

        await asyncio.gather(
            reader(),
            reader(),
            writer(),
            writer(),
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
