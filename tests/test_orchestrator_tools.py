"""Tests for orchestrator tools module."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from ares.core.models import Credential, SharedRedTeamState, Target, TaskInfo, TaskStatus
from ares.tools.red.orchestrator import OrchestratorTools


@pytest.fixture
def mock_dispatcher():
    """Create a mock dispatcher."""
    dispatcher = MagicMock()
    dispatcher.get_agent_status = MagicMock(return_value={})
    dispatcher.publish_credential = AsyncMock(return_value=True)
    return dispatcher


@pytest.fixture
def shared_state():
    """Create a shared state for testing."""
    return SharedRedTeamState(
        operation_id="test-op",
        target=Target(ip="192.168.56.100", hostname="dc01"),
    )


@pytest.fixture
def orchestrator_tools(mock_dispatcher, shared_state):
    """Create an OrchestratorTools instance for testing."""
    tools = OrchestratorTools()
    tools.set_dispatcher(mock_dispatcher)
    tools.set_shared_state(shared_state)
    return tools


class TestCleanupOrphanedTasks:
    """Tests for cleanup_orphaned_tasks method."""

    @pytest.mark.asyncio
    async def test_cleanup_no_pending_tasks(self, orchestrator_tools):
        """Test cleanup when there are no pending tasks."""
        result = await orchestrator_tools.cleanup_orphaned_tasks()
        assert "No pending tasks to clean up" in result

    @pytest.mark.asyncio
    async def test_cleanup_specific_task_ids(self, orchestrator_tools, shared_state):
        """Test cleanup of specific task IDs."""
        # Add some pending tasks
        now = datetime.now(timezone.utc)
        shared_state.pending_tasks["task_001"] = TaskInfo(
            task_id="task_001",
            task_type="crack",
            assigned_agent="cracker",
            status=TaskStatus.PENDING,
            created_at=now - timedelta(minutes=10),
            params={},
        )
        shared_state.pending_tasks["task_002"] = TaskInfo(
            task_id="task_002",
            task_type="lateral",
            assigned_agent="lateral",
            status=TaskStatus.PENDING,
            created_at=now - timedelta(minutes=8),
            params={},
        )
        shared_state.pending_tasks["task_003"] = TaskInfo(
            task_id="task_003",
            task_type="recon",
            assigned_agent="recon",
            status=TaskStatus.PENDING,
            created_at=now - timedelta(minutes=5),
            params={},
        )

        # Cleanup specific tasks
        result = await orchestrator_tools.cleanup_orphaned_tasks(task_ids=["task_001", "task_003"])

        # Verify only specified tasks were cleaned
        assert "task_001" in result
        assert "task_003" in result
        assert "task_002" not in result

        # Verify tasks removed from shared state
        assert "task_001" not in shared_state.pending_tasks
        assert "task_002" in shared_state.pending_tasks  # Should still exist
        assert "task_003" not in shared_state.pending_tasks

    @pytest.mark.asyncio
    async def test_cleanup_nonexistent_task_id(self, orchestrator_tools, shared_state):
        """Test cleanup with non-existent task ID."""
        # Add one task
        now = datetime.now(timezone.utc)
        shared_state.pending_tasks["task_001"] = TaskInfo(
            task_id="task_001",
            task_type="crack",
            assigned_agent="cracker",
            status=TaskStatus.PENDING,
            created_at=now - timedelta(minutes=10),
            params={},
        )

        # Try to cleanup non-existent task
        result = await orchestrator_tools.cleanup_orphaned_tasks(task_ids=["nonexistent_task"])

        # Should report no tasks cleaned
        assert "No orphaned tasks found to clean up" in result
        assert "task_001" in shared_state.pending_tasks  # Original task still exists

    @pytest.mark.asyncio
    async def test_cleanup_all_stale_tasks(self, orchestrator_tools, shared_state):
        """Test automatic cleanup of all stale pending/retrying/in-progress tasks (>5 minutes old)."""
        now = datetime.now(timezone.utc)

        # Add tasks with different ages
        shared_state.pending_tasks["task_old_1"] = TaskInfo(
            task_id="task_old_1",
            task_type="crack",
            assigned_agent="cracker",
            status=TaskStatus.PENDING,
            created_at=now - timedelta(minutes=10),
            params={},
        )

        shared_state.pending_tasks["task_old_2"] = TaskInfo(
            task_id="task_old_2",
            task_type="lateral",
            assigned_agent="lateral",
            status=TaskStatus.PENDING,
            created_at=now - timedelta(minutes=6),
            params={},
        )
        shared_state.pending_tasks["task_recent"] = TaskInfo(
            task_id="task_recent",
            task_type="recon",
            assigned_agent="recon",
            status=TaskStatus.PENDING,
            created_at=now - timedelta(minutes=2),
            params={},
        )
        shared_state.pending_tasks["task_retrying"] = TaskInfo(
            task_id="task_retrying",
            task_type="lateral",
            assigned_agent="lateral",
            status=TaskStatus.RETRYING,
            created_at=now - timedelta(minutes=9),
            params={},
        )
        shared_state.pending_tasks["task_in_progress"] = TaskInfo(
            task_id="task_in_progress",
            task_type="acl",
            assigned_agent="acl",
            status=TaskStatus.IN_PROGRESS,
            created_at=now - timedelta(minutes=10),
            params={},
        )

        # Cleanup all stale tasks (no task_ids specified)
        result = await orchestrator_tools.cleanup_orphaned_tasks()

        # Verify stale pending/retrying/in-progress tasks were cleaned
        assert "task_old_1" in result
        assert "task_old_2" in result
        assert "task_retrying" in result
        assert "task_in_progress" in result
        assert "600s" in result or "360s" in result  # Age should be mentioned

        # Verify recent task was NOT cleaned
        assert "task_recent" not in result
        assert "task_recent" in shared_state.pending_tasks

        # Verify old tasks removed from shared state
        assert "task_old_1" not in shared_state.pending_tasks
        assert "task_old_2" not in shared_state.pending_tasks
        assert "task_retrying" not in shared_state.pending_tasks
        assert "task_in_progress" not in shared_state.pending_tasks

    @pytest.mark.asyncio
    async def test_cleanup_respects_status_filter(self, orchestrator_tools, shared_state):
        """Test that pending/retrying/in-progress are auto-cleaned, not other statuses."""
        now = datetime.now(timezone.utc)

        # Add tasks with different statuses but all old
        shared_state.pending_tasks["task_pending"] = TaskInfo(
            task_id="task_pending",
            task_type="crack",
            assigned_agent="cracker",
            status=TaskStatus.PENDING,
            created_at=now - timedelta(minutes=10),
            params={},
        )
        shared_state.pending_tasks["task_retrying"] = TaskInfo(
            task_id="task_retrying",
            task_type="lateral",
            assigned_agent="lateral",
            status=TaskStatus.RETRYING,
            created_at=now - timedelta(minutes=10),
            params={},
        )
        shared_state.pending_tasks["task_in_progress"] = TaskInfo(
            task_id="task_in_progress",
            task_type="acl",
            assigned_agent="acl",
            status=TaskStatus.IN_PROGRESS,
            created_at=now - timedelta(minutes=10),
            params={},
        )
        shared_state.pending_tasks["task_completed"] = TaskInfo(
            task_id="task_completed",
            task_type="recon",
            assigned_agent="recon",
            status=TaskStatus.COMPLETED,
            created_at=now - timedelta(minutes=10),
            params={},
        )
        shared_state.pending_tasks["task_failed"] = TaskInfo(
            task_id="task_failed",
            task_type="acl",
            assigned_agent="acl",
            status=TaskStatus.FAILED,
            created_at=now - timedelta(minutes=10),
            params={},
        )

        # Cleanup all stale tasks
        result = await orchestrator_tools.cleanup_orphaned_tasks()

        # Only pending/retrying/in-progress tasks should be cleaned
        assert "task_pending" in result
        assert "task_retrying" in result
        assert "task_in_progress" in result
        assert "task_completed" not in result
        assert "task_failed" not in result

        # Verify only pending/retrying/in-progress tasks were removed
        assert "task_pending" not in shared_state.pending_tasks
        assert "task_retrying" not in shared_state.pending_tasks
        assert "task_in_progress" not in shared_state.pending_tasks
        assert "task_completed" in shared_state.pending_tasks
        assert "task_failed" in shared_state.pending_tasks

    @pytest.mark.asyncio
    async def test_cleanup_with_none_auto_cleans_stale(self, orchestrator_tools, shared_state):
        """Test cleanup with None (no task_ids) auto-cleans stale pending tasks."""
        now = datetime.now(timezone.utc)
        shared_state.pending_tasks["task_old"] = TaskInfo(
            task_id="task_old",
            task_type="crack",
            assigned_agent="cracker",
            status=TaskStatus.PENDING,
            created_at=now - timedelta(minutes=10),
            params={},
        )

        # None should auto-clean all stale tasks (>5 min old)
        result = await orchestrator_tools.cleanup_orphaned_tasks(task_ids=None)

        # Should have cleaned the stale task
        assert "task_old" in result
        assert "task_old" not in shared_state.pending_tasks

    @pytest.mark.asyncio
    async def test_cleanup_displays_task_types(self, orchestrator_tools, shared_state):
        """Test that cleanup result includes task types."""
        now = datetime.now(timezone.utc)
        shared_state.pending_tasks["task_001"] = TaskInfo(
            task_id="task_001",
            task_type="crack",
            assigned_agent="cracker",
            status=TaskStatus.PENDING,
            created_at=now - timedelta(minutes=10),
            params={},
        )

        result = await orchestrator_tools.cleanup_orphaned_tasks(task_ids=["task_001"])

        # Should include task type in output
        assert "crack" in result
        assert "task_001" in result


class TestScanForMssqlHosts:
    """Tests for scan_for_mssql_hosts method."""

    @pytest.mark.asyncio
    async def test_scan_no_hosts_returns_no_new_found(self, orchestrator_tools, shared_state):
        """Test scan when no hosts exist."""
        orchestrator_tools.dispatcher.scan_hosts_for_mssql = AsyncMock(return_value=0)

        result = await orchestrator_tools.scan_for_mssql_hosts()

        assert "no new MSSQL hosts found" in result

    @pytest.mark.asyncio
    async def test_scan_queues_new_mssql_vulnerabilities(self, orchestrator_tools, shared_state):
        """Test scan queues vulnerabilities when MSSQL hosts found."""
        orchestrator_tools.dispatcher.scan_hosts_for_mssql = AsyncMock(return_value=2)

        result = await orchestrator_tools.scan_for_mssql_hosts()

        assert "queued 2 new MSSQL vulnerability" in result
        assert "get_vulnerability_queue_status()" in result

    @pytest.mark.asyncio
    async def test_scan_single_mssql_host(self, orchestrator_tools, shared_state):
        """Test scan with single MSSQL host."""
        orchestrator_tools.dispatcher.scan_hosts_for_mssql = AsyncMock(return_value=1)

        result = await orchestrator_tools.scan_for_mssql_hosts()

        assert "queued 1 new MSSQL vulnerability" in result


class TestCredentialHandling:
    """Tests for credential guardrails and reporting."""

    def test_get_all_credentials_filters_placeholder_users(self, orchestrator_tools, shared_state):
        """Ensure placeholder usernames are skipped in output."""
        shared_state.all_credentials.extend(
            [
                Credential(
                    username="(none)",
                    password="hash123",  # pragma: allowlist secret
                    domain="contoso.local",
                    source="orchestrator:note",
                ),
                Credential(
                    username="user1",
                    password="password1",  # pragma: allowlist secret
                    domain="contoso.local",
                    source="username_as_password",
                ),
            ]
        )

        output = orchestrator_tools.get_all_credentials()
        assert "contoso.local\\user1" in output
        assert "contoso.local\\(none)" not in output

    def test_get_all_credentials_only_invalid_returns_empty(self, orchestrator_tools, shared_state):
        """If only invalid creds exist, return the empty message."""
        shared_state.all_credentials.append(
            Credential(
                username="none",
                password="hash123",  # pragma: allowlist secret
                domain="contoso.local",
                source="orchestrator:note",
            )
        )

        output = orchestrator_tools.get_all_credentials()
        assert output == "No credentials discovered yet"

    @pytest.mark.asyncio
    async def test_broadcast_credential_rejects_placeholder_username(self, orchestrator_tools):
        """Reject placeholder usernames and avoid publishing."""
        result = await orchestrator_tools.broadcast_credential(
            username="(none)",
            password="hash123",  # pragma: allowlist secret
            domain="contoso.local",
        )

        assert "Invalid username" in result
        orchestrator_tools.dispatcher.publish_credential.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_broadcast_credential_rejects_missing_secret(self, orchestrator_tools):
        """Reject broadcast with no password/hash."""
        result = await orchestrator_tools.broadcast_credential(
            username="user1",
            domain="contoso.local",
        )

        assert "Missing password/hash" in result
        orchestrator_tools.dispatcher.publish_credential.assert_not_awaited()

    def test_get_all_credentials_hides_no_creds_source_when_valid_exists(
        self, orchestrator_tools, shared_state
    ):
        """Ensure 'no valid creds yet' source never surfaces once real creds exist."""
        shared_state.all_credentials.extend(
            [
                Credential(
                    username="(none)",
                    password="hash123",  # pragma: allowlist secret
                    domain="contoso.local",
                    source="orchestrator:No valid creds yet; only unauthenticated enumeration performed.",
                ),
                Credential(
                    username="user1",
                    password="password1",  # pragma: allowlist secret
                    domain="contoso.local",
                    source="username_as_password",
                ),
            ]
        )

        output = orchestrator_tools.get_all_credentials()
        assert "No valid creds yet" not in output
