"""Tests for operation recovery manager.

Tests the OperationRecoveryManager and OperationResumeHelper classes
used for handling pod restarts and operation recovery.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from ares.core.models import (
    Hash,
    SharedRedTeamState,
    Target,
    TaskInfo,
    TaskStatus,
    VulnerabilityInfo,
)
from ares.core.recovery import (
    OperationRecoveryManager,
    OperationResumeHelper,
    RecoveryError,
)

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_redis_client():
    """Create a mock Redis async client."""
    client = AsyncMock()
    client.ping = AsyncMock(return_value=True)
    client.set = AsyncMock(return_value=True)
    client.get = AsyncMock(return_value=None)
    client.exists = AsyncMock(return_value=0)
    client.delete = AsyncMock(return_value=1)
    client.expire = AsyncMock(return_value=True)
    client.close = AsyncMock()
    client.scan_iter = AsyncMock(return_value=iter([]))
    return client


@pytest.fixture
def sample_state():
    """Create a sample SharedRedTeamState for testing."""
    return SharedRedTeamState(
        operation_id="test-op-001",
        target=Target(ip="192.168.1.100", hostname="dc01"),
    )


@pytest.fixture
def state_with_in_progress_tasks():
    """Create a state with in-progress tasks for recovery testing."""
    state = SharedRedTeamState(
        operation_id="test-op-002",
        target=Target(ip="192.168.1.100", hostname="dc01"),
    )

    # Add some in-progress tasks
    state.pending_tasks["task_001"] = TaskInfo(
        task_id="task_001",
        task_type="crack",
        assigned_agent="cracker",
        status=TaskStatus.IN_PROGRESS,
        created_at=datetime.now(timezone.utc),
        params={"hash_value": "abc123"},
        retry_count=0,
        max_retries=3,
    )
    state.pending_tasks["task_002"] = TaskInfo(
        task_id="task_002",
        task_type="lateral",
        assigned_agent="lateral",
        status=TaskStatus.IN_PROGRESS,
        created_at=datetime.now(timezone.utc),
        params={"target_host": "192.168.1.50"},
        retry_count=2,  # Already retried twice
        max_retries=3,
    )
    state.pending_tasks["task_003"] = TaskInfo(
        task_id="task_003",
        task_type="enum",
        assigned_agent="enum",
        status=TaskStatus.PENDING,  # Not in progress - should not be touched
        created_at=datetime.now(timezone.utc),
        params={},
    )

    return state


@pytest.fixture
def state_with_max_retries_exceeded():
    """Create a state with tasks that have exceeded max retries."""
    state = SharedRedTeamState(
        operation_id="test-op-003",
        target=Target(ip="192.168.1.100", hostname="dc01"),
    )

    # Add a task that has already hit max retries
    state.pending_tasks["task_maxed"] = TaskInfo(
        task_id="task_maxed",
        task_type="crack",
        assigned_agent="cracker",
        status=TaskStatus.IN_PROGRESS,
        created_at=datetime.now(timezone.utc),
        params={"hash_value": "xyz789"},
        retry_count=3,  # Already at max
        max_retries=3,
    )

    return state


@pytest.fixture
def state_with_retrying_tasks():
    """Create a state with tasks in RETRYING status."""
    state = SharedRedTeamState(
        operation_id="test-op-004",
        target=Target(ip="192.168.1.100", hostname="dc01"),
    )

    state.pending_tasks["task_retry_1"] = TaskInfo(
        task_id="task_retry_1",
        task_type="crack",
        assigned_agent="cracker",
        status=TaskStatus.RETRYING,
        created_at=datetime.now(timezone.utc),
        params={"hash_value": "abc"},
        retry_count=1,
        max_retries=3,
        error="Pod restart during execution (retry 1/3)",
    )
    state.pending_tasks["task_retry_2"] = TaskInfo(
        task_id="task_retry_2",
        task_type="lateral",
        assigned_agent="lateral",
        status=TaskStatus.RETRYING,
        created_at=datetime.now(timezone.utc),
        params={"target": "host1"},
        retry_count=2,
        max_retries=3,
        error="Pod restart during execution (retry 2/3)",
    )

    return state


@pytest.fixture
def state_with_failed_tasks():
    """Create a state with permanently failed tasks."""
    state = SharedRedTeamState(
        operation_id="test-op-005",
        target=Target(ip="192.168.1.100", hostname="dc01"),
    )

    state.pending_tasks["task_failed_1"] = TaskInfo(
        task_id="task_failed_1",
        task_type="crack",
        assigned_agent="cracker",
        status=TaskStatus.FAILED,
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        params={"hash_value": "xyz"},
        retry_count=3,
        max_retries=3,
        error="Pod restart during execution (max retries 3 exceeded)",
    )
    state.pending_tasks["task_normal_fail"] = TaskInfo(
        task_id="task_normal_fail",
        task_type="enum",
        assigned_agent="enum",
        status=TaskStatus.FAILED,
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        params={},
        error="Regular task failure - not from pod restart",
    )

    return state


@pytest.fixture
def state_for_resume_prompt():
    """Create a comprehensive state for resume prompt testing."""
    state = SharedRedTeamState(
        operation_id="test-op-resume",
        target=Target(ip="192.168.1.100", hostname="dc01"),
    )

    # Add some credentials and hosts
    from ares.core.models import Credential, Host

    state.all_credentials = [
        Credential(username="admin", password="pass", domain="CORP"),  # pragma: allowlist secret
    ]
    state.all_hosts = [
        Host(ip="192.168.1.100", hostname="dc01"),
        Host(ip="192.168.1.101", hostname="web01"),
    ]

    # Add retrying task
    state.pending_tasks["retry_task"] = TaskInfo(
        task_id="retry_task",
        task_type="crack",
        assigned_agent="cracker",
        status=TaskStatus.RETRYING,
        created_at=datetime.now(timezone.utc),
        params={},
        retry_count=1,
        max_retries=3,
    )

    # Add failed task (from pod restart)
    state.pending_tasks["failed_task"] = TaskInfo(
        task_id="failed_task",
        task_type="lateral",
        assigned_agent="lateral",
        status=TaskStatus.FAILED,
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        params={},
        retry_count=3,
        error="Pod restart during execution (max retries 3 exceeded)",
    )

    # Add discovered vulnerability
    state.discovered_vulnerabilities["vuln_001"] = VulnerabilityInfo(
        vuln_id="vuln_001",
        vuln_type="ADCS_ESC1",
        target="dc01",
        discovered_by="acl",
        priority=1,
        recommended_agent="privesc",
    )

    # Add uncracked hash (empty cracked_password means not cracked)
    state.all_hashes = [
        Hash(
            username="svc_account",
            hash_value="aad3b435:31d6cfe0",
            hash_type="NTLM",
            domain="CORP",
        ),
    ]

    return state


# ============================================================================
# OperationRecoveryManager Tests
# ============================================================================


class TestOperationRecoveryManagerInit:
    """Tests for OperationRecoveryManager initialization."""

    def test_init_defaults(self):
        """Test initialization with defaults."""
        manager = OperationRecoveryManager()

        assert manager._k8s is None
        assert manager._redis_url is None
        assert manager._checkpoint_interval == 60

    def test_init_with_params(self):
        """Test initialization with custom parameters."""
        manager = OperationRecoveryManager(
            redis_url="redis://localhost:6379",
            checkpoint_interval=30,
        )

        assert manager._redis_url == "redis://localhost:6379"
        assert manager._checkpoint_interval == 30


class TestOperationRecoveryManagerRecovery:
    """Tests for recover_operation method."""

    @pytest.mark.asyncio
    async def test_recover_operation_no_redis(self):
        """Test recovery fails without Redis."""
        manager = OperationRecoveryManager()

        with pytest.raises(RecoveryError, match="Redis not available"):
            await manager.recover_operation("test-op")

    @pytest.mark.asyncio
    async def test_recover_operation_no_checkpoint(self, mock_redis_client):
        """Test recovery fails when no checkpoint exists."""
        manager = OperationRecoveryManager(redis_url="redis://localhost:6379")
        manager._redis_client = mock_redis_client
        mock_redis_client.get.return_value = None

        with pytest.raises(RecoveryError, match="No checkpoint found"):
            await manager.recover_operation("nonexistent-op")

    @pytest.mark.asyncio
    async def test_recover_operation_requeues_tasks(
        self, mock_redis_client, state_with_in_progress_tasks
    ):
        """Test recovery requeues in-progress tasks."""
        manager = OperationRecoveryManager(redis_url="redis://localhost:6379")
        manager._redis_client = mock_redis_client

        # Mock get to return state for first call, and checkpoint time for second
        mock_redis_client.get.side_effect = [
            state_with_in_progress_tasks.to_bytes(),
            b"2024-01-15T10:00:00+00:00",  # checkpoint time
        ]

        # Mock the task queue
        with patch("ares.core.recovery.RedisTaskQueue") as mock_task_queue_class:
            mock_queue = AsyncMock()
            mock_task_queue_class.return_value = mock_queue
            mock_queue.connect = AsyncMock()
            mock_queue.disconnect = AsyncMock()
            mock_queue.requeue_task = AsyncMock(return_value="task_001")

            recovered = await manager.recover_operation(state_with_in_progress_tasks.operation_id)

            # Verify tasks were requeued
            assert mock_queue.requeue_task.call_count == 2  # task_001 and task_002

            # Verify task statuses were updated
            task_001 = recovered.pending_tasks["task_001"]
            assert task_001.status == TaskStatus.RETRYING
            assert task_001.retry_count == 1

            task_002 = recovered.pending_tasks["task_002"]
            assert task_002.status == TaskStatus.RETRYING
            assert task_002.retry_count == 3

            # Pending task should not be touched
            task_003 = recovered.pending_tasks["task_003"]
            assert task_003.status == TaskStatus.PENDING

    @pytest.mark.asyncio
    async def test_recover_operation_marks_max_retries_failed(
        self, mock_redis_client, state_with_max_retries_exceeded
    ):
        """Test recovery marks tasks with max retries as failed."""
        manager = OperationRecoveryManager(redis_url="redis://localhost:6379")
        manager._redis_client = mock_redis_client

        # Mock get to return state for first call, and checkpoint time for second
        mock_redis_client.get.side_effect = [
            state_with_max_retries_exceeded.to_bytes(),
            b"2024-01-15T10:00:00+00:00",  # checkpoint time
        ]

        with patch("ares.core.recovery.RedisTaskQueue") as mock_task_queue_class:
            mock_queue = AsyncMock()
            mock_task_queue_class.return_value = mock_queue
            mock_queue.connect = AsyncMock()
            mock_queue.disconnect = AsyncMock()
            mock_queue.requeue_task = AsyncMock()

            recovered = await manager.recover_operation(
                state_with_max_retries_exceeded.operation_id
            )

            # Task should be marked as failed (max retries exceeded)
            task = recovered.pending_tasks["task_maxed"]
            assert task.status == TaskStatus.FAILED
            assert task.retry_count == 4  # Incremented to 4
            assert "max retries" in task.error
            assert task.completed_at is not None

            # Should NOT have been requeued
            mock_queue.requeue_task.assert_not_called()

    @pytest.mark.asyncio
    async def test_recover_operation_auto_requeue_disabled(
        self, mock_redis_client, state_with_in_progress_tasks
    ):
        """Test recovery with auto_requeue disabled marks all as failed."""
        manager = OperationRecoveryManager(redis_url="redis://localhost:6379")
        manager._redis_client = mock_redis_client

        # Mock get to return state for first call, and checkpoint time for second
        mock_redis_client.get.side_effect = [
            state_with_in_progress_tasks.to_bytes(),
            b"2024-01-15T10:00:00+00:00",  # checkpoint time
        ]

        recovered = await manager.recover_operation(
            state_with_in_progress_tasks.operation_id,
            auto_requeue=False,
        )

        # All in-progress tasks should be marked as failed
        task_001 = recovered.pending_tasks["task_001"]
        assert task_001.status == TaskStatus.FAILED
        assert task_001.completed_at is not None

        task_002 = recovered.pending_tasks["task_002"]
        assert task_002.status == TaskStatus.FAILED


# ============================================================================
# OperationResumeHelper Tests
# ============================================================================


class TestOperationResumeHelperGetInterruptedTasks:
    """Tests for get_interrupted_tasks method."""

    def test_get_interrupted_tasks_finds_failed_from_pod_restart(self, state_with_failed_tasks):
        """Test finding tasks that failed from pod restart."""
        manager = OperationRecoveryManager()
        helper = OperationResumeHelper(state_with_failed_tasks, manager)

        interrupted = helper.get_interrupted_tasks()

        # Should only find the task that failed from pod restart
        assert len(interrupted) == 1
        assert interrupted[0]["task_id"] == "task_failed_1"
        assert interrupted[0]["task_type"] == "crack"
        assert interrupted[0]["retry_count"] == 3
        assert "Pod restart" in interrupted[0]["error"]

    def test_get_interrupted_tasks_empty_when_no_pod_restart_failures(self, sample_state):
        """Test returns empty when no pod restart failures."""
        manager = OperationRecoveryManager()
        helper = OperationResumeHelper(sample_state, manager)

        interrupted = helper.get_interrupted_tasks()

        assert interrupted == []


class TestOperationResumeHelperGetRetryingTasks:
    """Tests for get_retrying_tasks method."""

    def test_get_retrying_tasks_finds_all_retrying(self, state_with_retrying_tasks):
        """Test finding all tasks with RETRYING status."""
        manager = OperationRecoveryManager()
        helper = OperationResumeHelper(state_with_retrying_tasks, manager)

        retrying = helper.get_retrying_tasks()

        assert len(retrying) == 2

        # Verify task details
        task_ids = {t["task_id"] for t in retrying}
        assert task_ids == {"task_retry_1", "task_retry_2"}

        # Verify retry info is included
        for task in retrying:
            assert "retry_count" in task
            assert "max_retries" in task
            assert task["max_retries"] == 3

    def test_get_retrying_tasks_empty_when_none_retrying(self, sample_state):
        """Test returns empty when no retrying tasks."""
        manager = OperationRecoveryManager()
        helper = OperationResumeHelper(sample_state, manager)

        retrying = helper.get_retrying_tasks()

        assert retrying == []


class TestOperationResumeHelperGetResumePrompt:
    """Tests for get_resume_prompt method."""

    def test_get_resume_prompt_includes_operation_info(self, state_for_resume_prompt):
        """Test resume prompt includes operation info."""
        manager = OperationRecoveryManager()
        helper = OperationResumeHelper(state_for_resume_prompt, manager)

        prompt = helper.get_resume_prompt()

        assert "OPERATION RESUMED AFTER RECOVERY" in prompt
        assert "test-op-resume" in prompt
        assert "Credentials found: 1" in prompt
        assert "Hosts discovered: 2" in prompt
        assert "Domain admin: NO" in prompt

    def test_get_resume_prompt_shows_retrying_tasks(self, state_for_resume_prompt):
        """Test resume prompt shows retrying tasks."""
        manager = OperationRecoveryManager()
        helper = OperationResumeHelper(state_for_resume_prompt, manager)

        prompt = helper.get_resume_prompt()

        assert "[RETRYING]" in prompt
        assert "crack -> cracker" in prompt
        assert "retry 1/3" in prompt

    def test_get_resume_prompt_shows_failed_tasks(self, state_for_resume_prompt):
        """Test resume prompt shows permanently failed tasks."""
        manager = OperationRecoveryManager()
        helper = OperationResumeHelper(state_for_resume_prompt, manager)

        prompt = helper.get_resume_prompt()

        assert "[FAILED]" in prompt
        assert "lateral -> lateral" in prompt
        assert "retried 3x" in prompt

    def test_get_resume_prompt_shows_vulnerabilities(self, state_for_resume_prompt):
        """Test resume prompt shows unexploited vulnerabilities."""
        manager = OperationRecoveryManager()
        helper = OperationResumeHelper(state_for_resume_prompt, manager)

        prompt = helper.get_resume_prompt()

        assert "[PENDING]" in prompt
        assert "unexploited vulnerabilities" in prompt
        assert "ADCS_ESC1" in prompt

    def test_get_resume_prompt_shows_uncracked_hashes(self, state_for_resume_prompt):
        """Test resume prompt shows uncracked hashes."""
        manager = OperationRecoveryManager()
        helper = OperationResumeHelper(state_for_resume_prompt, manager)

        prompt = helper.get_resume_prompt()

        assert "uncracked hashes" in prompt

    def test_get_resume_prompt_clean_recovery(self, sample_state):
        """Test resume prompt shows clean recovery when nothing interrupted."""
        manager = OperationRecoveryManager()
        helper = OperationResumeHelper(sample_state, manager)

        prompt = helper.get_resume_prompt()

        assert "[OK] No interrupted tasks - clean recovery" in prompt


class TestOperationResumeHelperGetUnexploitedVulnerabilities:
    """Tests for get_unexploited_vulnerabilities method."""

    def test_get_unexploited_vulnerabilities(self, state_for_resume_prompt):
        """Test getting unexploited vulnerabilities."""
        manager = OperationRecoveryManager()
        helper = OperationResumeHelper(state_for_resume_prompt, manager)

        vulns = helper.get_unexploited_vulnerabilities()

        assert len(vulns) == 1
        assert vulns[0]["vuln_id"] == "vuln_001"
        assert vulns[0]["vuln_type"] == "ADCS_ESC1"
        assert vulns[0]["priority"] == 1


class TestOperationResumeHelperGetUncrackedHashes:
    """Tests for get_uncracked_hashes method."""

    def test_get_uncracked_hashes(self, state_for_resume_prompt):
        """Test getting uncracked hashes."""
        manager = OperationRecoveryManager()
        helper = OperationResumeHelper(state_for_resume_prompt, manager)

        hashes = helper.get_uncracked_hashes()

        assert len(hashes) == 1
        assert hashes[0]["username"] == "svc_account"
        assert hashes[0]["hash_type"] == "NTLM"


# ============================================================================
# RecoveryError Tests
# ============================================================================


class TestRecoveryError:
    """Tests for RecoveryError exception."""

    def test_recovery_error_message(self):
        """Test RecoveryError has correct message."""
        error = RecoveryError("Test error message")

        assert str(error) == "Test error message"

    def test_recovery_error_is_exception(self):
        """Test RecoveryError is an Exception."""
        assert issubclass(RecoveryError, Exception)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
