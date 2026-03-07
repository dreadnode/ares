"""Tests for BlueOrchestratorTools and BlueTeamOrchestrator."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from ares.agents.blue.multi_agent_orchestrator import BlueOrchestratorTools
from ares.core.blue_task_queue import BlueTaskResult
from ares.core.models import BlueRole, BlueTaskInfo, BlueTaskType


class TestBlueOrchestratorToolsInit:
    """Tests for BlueOrchestratorTools initialization."""

    def test_initializes_with_empty_workers(self):
        tools = BlueOrchestratorTools()
        assert tools._workers == {}
        assert tools._dispatcher is None
        assert tools._use_distributed_workers is False
        assert tools._blue_task_queue is None

    def test_set_dispatcher(self):
        tools = BlueOrchestratorTools()
        mock_dispatcher = MagicMock()
        mock_dispatcher.investigation_id = "inv-123"

        tools.set_dispatcher(mock_dispatcher)

        assert tools._dispatcher is mock_dispatcher
        assert tools._investigation_id == "inv-123"

    def test_set_workers(self):
        tools = BlueOrchestratorTools()
        mock_workers = {BlueRole.TRIAGE: MagicMock(), BlueRole.THREAT_HUNTER: MagicMock()}

        tools.set_workers(mock_workers)

        assert tools._workers == mock_workers

    def test_set_distributed_mode(self):
        tools = BlueOrchestratorTools()
        mock_queue = MagicMock()

        tools.set_distributed_mode(
            blue_task_queue=mock_queue,
            investigation_id="inv-456",
        )

        assert tools._use_distributed_workers is True
        assert tools._blue_task_queue is mock_queue
        assert tools._investigation_id == "inv-456"


class TestBlueOrchestratorToolsDispatchTriage:
    """Tests for dispatch_triage tool method."""

    @pytest.fixture
    def tools_with_dispatcher(self):
        tools = BlueOrchestratorTools()
        mock_dispatcher = MagicMock()
        mock_dispatcher.investigation_id = "inv-123"
        mock_dispatcher.shared_state = MagicMock()
        mock_dispatcher.shared_state.alert = {"labels": {"alertname": "HighCPU"}}
        mock_dispatcher.shared_state.correlation_context = {}
        mock_dispatcher.dispatch_triage = AsyncMock(
            return_value=BlueTaskInfo(
                task_id="triage-001",
                task_type=BlueTaskType.TRIAGE_ALERT,
                investigation_id="inv-123",
                assigned_role=BlueRole.TRIAGE,
                params={"alert": {"labels": {"alertname": "HighCPU"}}},
            )
        )
        mock_dispatcher.wait_for_result = AsyncMock(
            return_value={"success": True, "findings": ["suspicious"]}
        )
        tools.set_dispatcher(mock_dispatcher)
        return tools

    @pytest.mark.asyncio
    async def test_returns_error_without_dispatcher(self):
        tools = BlueOrchestratorTools()

        result = await tools.dispatch_triage()

        assert "ERROR" in result
        assert "No dispatcher" in result

    @pytest.mark.asyncio
    async def test_dispatch_to_local_worker_async(self, tools_with_dispatcher):
        mock_worker = MagicMock()
        mock_worker.start_task = MagicMock()
        tools_with_dispatcher.set_workers({BlueRole.TRIAGE: mock_worker})

        result = await tools_with_dispatcher.dispatch_triage(wait_for_result=False)

        assert "dispatched" in result.lower()
        assert "triage-001" in result
        mock_worker.start_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_to_local_worker_sync(self, tools_with_dispatcher):
        mock_worker = MagicMock()
        mock_worker.start_task = MagicMock()
        tools_with_dispatcher.set_workers({BlueRole.TRIAGE: mock_worker})

        result = await tools_with_dispatcher.dispatch_triage(wait_for_result=True)

        assert "triage-001" in result.lower() or "Triage" in result
        mock_worker.start_task.assert_called_once()
        tools_with_dispatcher._dispatcher.wait_for_result.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_dispatch_without_worker_returns_error(self, tools_with_dispatcher):
        # No workers set
        result = await tools_with_dispatcher.dispatch_triage()

        assert "ERROR" in result
        assert "No triage worker" in result

    @pytest.mark.asyncio
    async def test_dispatch_to_redis_queue_async(self, tools_with_dispatcher):
        mock_queue = AsyncMock()
        mock_queue.submit_task = AsyncMock(return_value="triage-001")

        tools_with_dispatcher.set_distributed_mode(mock_queue, "inv-123")

        result = await tools_with_dispatcher.dispatch_triage(wait_for_result=False)

        assert "remote worker" in result.lower()
        assert "triage-001" in result
        mock_queue.submit_task.assert_awaited_once()
        call_kwargs = mock_queue.submit_task.call_args.kwargs
        assert call_kwargs["investigation_id"] == "inv-123"
        assert call_kwargs["task_type"] == "triage_alert"
        assert call_kwargs["target_role"] == "triage"

    @pytest.mark.asyncio
    async def test_dispatch_to_redis_queue_sync(self, tools_with_dispatcher):
        mock_queue = AsyncMock()
        mock_queue.submit_task = AsyncMock(return_value="triage-001")
        mock_queue.wait_for_result = AsyncMock(
            return_value=BlueTaskResult(
                task_id="triage-001",
                success=True,
                result={"findings": ["suspicious_login"]},
            )
        )

        tools_with_dispatcher.set_distributed_mode(mock_queue, "inv-123")

        result = await tools_with_dispatcher.dispatch_triage(wait_for_result=True)

        assert "Triage" in result or "triage-001" in result
        mock_queue.wait_for_result.assert_awaited_once_with("triage-001", timeout=60)

    @pytest.mark.asyncio
    async def test_dispatch_to_redis_queue_timeout(self, tools_with_dispatcher):
        mock_queue = AsyncMock()
        mock_queue.submit_task = AsyncMock(return_value="triage-001")
        mock_queue.wait_for_result = AsyncMock(return_value=None)  # Timeout

        tools_with_dispatcher.set_distributed_mode(mock_queue, "inv-123")

        result = await tools_with_dispatcher.dispatch_triage(wait_for_result=True)

        assert "ERROR" in result
        assert "timed out" in result.lower()


class TestBlueOrchestratorToolsDispatchThreatHunt:
    """Tests for dispatch_threat_hunt tool method."""

    @pytest.fixture
    def tools_with_dispatcher(self):
        tools = BlueOrchestratorTools()
        mock_dispatcher = MagicMock()
        mock_dispatcher.investigation_id = "inv-123"
        mock_dispatcher.dispatch_threat_hunt = AsyncMock(
            return_value=BlueTaskInfo(
                task_id="hunt-001",
                task_type=BlueTaskType.THREAT_HUNT,
                investigation_id="inv-123",
                assigned_role=BlueRole.THREAT_HUNTER,
                params={"technique_id": "T1558.003"},
            )
        )
        mock_dispatcher.wait_for_result = AsyncMock(
            return_value={"success": True, "detections": ["kerberoasting"]}
        )
        tools.set_dispatcher(mock_dispatcher)
        return tools

    @pytest.mark.asyncio
    async def test_returns_error_without_dispatcher(self):
        tools = BlueOrchestratorTools()

        result = await tools.dispatch_threat_hunt(technique_id="T1558")

        assert "ERROR" in result

    @pytest.mark.asyncio
    async def test_dispatch_with_technique_id(self, tools_with_dispatcher):
        mock_worker = MagicMock()
        tools_with_dispatcher.set_workers({BlueRole.THREAT_HUNTER: mock_worker})

        await tools_with_dispatcher.dispatch_threat_hunt(
            technique_id="T1558.003",
            hostname="dc01.contoso.local",
        )

        tools_with_dispatcher._dispatcher.dispatch_threat_hunt.assert_awaited_once_with(
            technique_id="T1558.003",
            detection_method="",
            hostname="dc01.contoso.local",
            username="",
            context="",
        )

    @pytest.mark.asyncio
    async def test_dispatch_to_redis_queue(self, tools_with_dispatcher):
        mock_queue = AsyncMock()
        mock_queue.submit_task = AsyncMock(return_value="hunt-001")

        tools_with_dispatcher.set_distributed_mode(mock_queue, "inv-123")

        result = await tools_with_dispatcher.dispatch_threat_hunt(
            technique_id="T1558.003",
            wait_for_result=False,
        )

        assert "remote worker" in result.lower()
        call_kwargs = mock_queue.submit_task.call_args.kwargs
        assert call_kwargs["task_type"] == "threat_hunt"
        assert call_kwargs["target_role"] == "threat_hunter"


class TestBlueOrchestratorToolsDispatchLateralAnalysis:
    """Tests for dispatch_lateral_analysis tool method."""

    @pytest.fixture
    def tools_with_dispatcher(self):
        tools = BlueOrchestratorTools()
        mock_dispatcher = MagicMock()
        mock_dispatcher.investigation_id = "inv-123"
        mock_dispatcher.dispatch_lateral_analysis = AsyncMock(
            return_value=BlueTaskInfo(
                task_id="lateral-001",
                task_type=BlueTaskType.LATERAL_ANALYSIS,
                investigation_id="inv-123",
                assigned_role=BlueRole.LATERAL_ANALYST,
                params={"focus_host": "ws01.contoso.local"},
            )
        )
        mock_dispatcher.wait_for_result = AsyncMock(
            return_value={"success": True, "lateral_paths": []}
        )
        tools.set_dispatcher(mock_dispatcher)
        return tools

    @pytest.mark.asyncio
    async def test_returns_error_without_dispatcher(self):
        tools = BlueOrchestratorTools()

        result = await tools.dispatch_lateral_analysis(focus_host="ws01")

        assert "ERROR" in result

    @pytest.mark.asyncio
    async def test_dispatch_with_focus_host(self, tools_with_dispatcher):
        mock_worker = MagicMock()
        tools_with_dispatcher.set_workers({BlueRole.LATERAL_ANALYST: mock_worker})

        await tools_with_dispatcher.dispatch_lateral_analysis(
            focus_host="ws01.contoso.local",
            focus_user="testuser",
            context="Investigating lateral movement after initial compromise",
        )

        tools_with_dispatcher._dispatcher.dispatch_lateral_analysis.assert_awaited_once_with(
            focus_host="ws01.contoso.local",
            focus_user="testuser",
            context="Investigating lateral movement after initial compromise",
        )

    @pytest.mark.asyncio
    async def test_dispatch_to_redis_queue(self, tools_with_dispatcher):
        mock_queue = AsyncMock()
        mock_queue.submit_task = AsyncMock(return_value="lateral-001")
        mock_queue.wait_for_result = AsyncMock(
            return_value=BlueTaskResult(
                task_id="lateral-001",
                success=True,
                result={"lateral_paths": ["ws01 -> dc01"]},
            )
        )

        tools_with_dispatcher.set_distributed_mode(mock_queue, "inv-123")

        await tools_with_dispatcher.dispatch_lateral_analysis(
            focus_host="ws01.contoso.local",
            wait_for_result=True,
        )

        call_kwargs = mock_queue.submit_task.call_args.kwargs
        assert call_kwargs["task_type"] == "lateral_analysis"
        assert call_kwargs["target_role"] == "lateral_analyst"


class TestBlueOrchestratorToolsGetInvestigationStatus:
    """Tests for get_investigation_status tool method."""

    @pytest.fixture
    def tools_with_dispatcher(self):
        tools = BlueOrchestratorTools()
        mock_dispatcher = MagicMock()
        mock_dispatcher.investigation_id = "inv-123"
        mock_dispatcher.get_investigation_summary = AsyncMock(
            return_value={
                "stage": "threat_hunt",
                "evidence_count": 5,
                "technique_count": 2,
                "techniques_identified": ["T1078", "T1558"],
                "highest_pyramid_level": 4,
                "hosts_investigated": ["dc01.contoso.local", "ws01.contoso.local"],
                "users_investigated": ["testuser"],
                "pending_tasks": 2,
                "completed_tasks": 3,
            }
        )
        mock_dispatcher.get_evidence_summary = AsyncMock(
            return_value={
                "by_type": {"log_evidence": 3, "alert_evidence": 2},
                "by_pyramid_level": {4: 2, 3: 3},
            }
        )
        tools.set_dispatcher(mock_dispatcher)
        return tools

    @pytest.mark.asyncio
    async def test_returns_error_without_dispatcher(self):
        tools = BlueOrchestratorTools()

        result = await tools.get_investigation_status()

        assert "ERROR" in result

    @pytest.mark.asyncio
    async def test_returns_formatted_status(self, tools_with_dispatcher):
        result = await tools_with_dispatcher.get_investigation_status()

        # Should contain key status info
        assert "Investigation Status" in result or "Stage" in result
        assert "threat_hunt" in result or "T1078" in result


class TestBlueOrchestratorToolsGetTaskResult:
    """Tests for get_task_result tool method."""

    @pytest.fixture
    def tools_with_dispatcher(self):
        tools = BlueOrchestratorTools()
        mock_dispatcher = MagicMock()
        mock_dispatcher.investigation_id = "inv-123"
        mock_dispatcher.wait_for_result = AsyncMock(
            return_value={"success": True, "findings": ["suspicious_activity"]}
        )
        tools.set_dispatcher(mock_dispatcher)
        return tools

    @pytest.mark.asyncio
    async def test_returns_error_without_dispatcher(self):
        tools = BlueOrchestratorTools()

        result = await tools.get_task_result("task-123")

        assert "ERROR" in result

    @pytest.mark.asyncio
    async def test_returns_task_result(self, tools_with_dispatcher):
        result = await tools_with_dispatcher.get_task_result("task-123")

        tools_with_dispatcher._dispatcher.wait_for_result.assert_awaited_once_with(
            "task-123", timeout=10
        )
        # Result should be formatted
        assert "task-123" in result.lower() or "Task" in result

    @pytest.mark.asyncio
    async def test_returns_running_when_timeout(self, tools_with_dispatcher):
        tools_with_dispatcher._dispatcher.wait_for_result = AsyncMock(
            return_value={"error": "timed out waiting for result"}
        )

        result = await tools_with_dispatcher.get_task_result("task-456")

        assert "running" in result.lower() or "still" in result.lower()


class TestBlueOrchestratorToolsDistributedModeIntegration:
    """Integration tests for distributed mode with BlueTaskQueue."""

    @pytest.fixture
    def fully_configured_tools(self):
        tools = BlueOrchestratorTools()

        # Mock dispatcher with full shared state
        mock_dispatcher = MagicMock()
        mock_dispatcher.investigation_id = "inv-integration"
        mock_dispatcher.shared_state = MagicMock()
        mock_dispatcher.shared_state.alert = {
            "labels": {"alertname": "CriticalAlert", "severity": "critical"}
        }
        mock_dispatcher.shared_state.correlation_context = {"related_alerts": []}

        # Mock task creation
        mock_dispatcher.dispatch_triage = AsyncMock(
            return_value=BlueTaskInfo(
                task_id="triage-int-001",
                task_type=BlueTaskType.TRIAGE_ALERT,
                investigation_id="inv-integration",
                assigned_role=BlueRole.TRIAGE,
                params={"alert": {"labels": {"alertname": "CriticalAlert"}}},
            )
        )
        mock_dispatcher.dispatch_threat_hunt = AsyncMock(
            return_value=BlueTaskInfo(
                task_id="hunt-int-001",
                task_type=BlueTaskType.THREAT_HUNT,
                investigation_id="inv-integration",
                assigned_role=BlueRole.THREAT_HUNTER,
                params={"technique_id": "T1003"},
            )
        )

        tools.set_dispatcher(mock_dispatcher)

        # Mock task queue
        mock_queue = AsyncMock()
        mock_queue.submit_task = AsyncMock(side_effect=lambda **kwargs: kwargs["task_id"])
        mock_queue.wait_for_result = AsyncMock(
            return_value=BlueTaskResult(
                task_id="triage-int-001",
                success=True,
                result={"findings": ["credential_dumping_detected"]},
                worker_pod="blue-worker-1",
            )
        )

        tools.set_distributed_mode(mock_queue, "inv-integration")

        return tools

    @pytest.mark.asyncio
    async def test_parallel_dispatch_pattern(self, fully_configured_tools):
        """Test typical pattern: dispatch triage, then parallel threat hunts."""
        # Dispatch triage first (async)
        triage_result = await fully_configured_tools.dispatch_triage(wait_for_result=False)
        assert "remote worker" in triage_result.lower()
        assert "triage-int-001" in triage_result

        # Dispatch threat hunt (would normally run in parallel)
        hunt_result = await fully_configured_tools.dispatch_threat_hunt(
            technique_id="T1003",
            wait_for_result=False,
        )
        assert "remote worker" in hunt_result.lower()
        assert "hunt-int-001" in hunt_result

    @pytest.mark.asyncio
    async def test_waits_for_result_from_remote_worker(self, fully_configured_tools):
        """Test waiting for result from distributed worker."""
        result = await fully_configured_tools.dispatch_triage(wait_for_result=True)

        # Result should contain findings from the mock
        assert "credential_dumping" in result.lower() or "success" in result.lower()

    @pytest.mark.asyncio
    async def test_handles_failed_remote_task(self, fully_configured_tools):
        """Test handling of failed remote task."""
        fully_configured_tools._blue_task_queue.wait_for_result = AsyncMock(
            return_value=BlueTaskResult(
                task_id="triage-int-001",
                success=False,
                error="Worker crashed",
            )
        )

        result = await fully_configured_tools.dispatch_triage(wait_for_result=True)

        # Should indicate failure
        assert "error" in result.lower() or "crashed" in result.lower()


class TestBlueOrchestratorToolsWaitForAllTasks:
    """Tests for wait_for_all_tasks with heartbeat-aware timeout."""

    @pytest.fixture
    def tools_with_dispatcher(self):
        tools = BlueOrchestratorTools()
        mock_dispatcher = MagicMock()
        mock_dispatcher.investigation_id = "inv-123"
        mock_dispatcher.backend = MagicMock()
        mock_dispatcher.wait_for_result = AsyncMock(return_value={"success": True, "result": {}})
        tools.set_dispatcher(mock_dispatcher)
        return tools

    @pytest.mark.asyncio
    async def test_returns_error_without_dispatcher(self):
        tools = BlueOrchestratorTools()
        result = await tools.wait_for_all_tasks()
        assert "ERROR" in result

    @pytest.mark.asyncio
    async def test_returns_immediately_when_no_pending_tasks(self, tools_with_dispatcher):
        tools_with_dispatcher._dispatcher.backend.get_pending_tasks = AsyncMock(return_value={})

        result = await tools_with_dispatcher.wait_for_all_tasks()

        assert "[+]" in result
        assert "complete" in result.lower()

    @pytest.mark.asyncio
    async def test_waits_for_tasks_to_complete(self, tools_with_dispatcher):
        # First call returns pending, second call returns empty
        tools_with_dispatcher._dispatcher.backend.get_pending_tasks = AsyncMock(
            side_effect=[
                {"task-1": {"task_type": "triage", "assigned_role": "triage"}},
                {},  # Tasks completed
            ]
        )

        result = await tools_with_dispatcher.wait_for_all_tasks(timeout=60)

        assert "[+]" in result
        assert "complete" in result.lower()

    @pytest.mark.asyncio
    async def test_hard_timeout_exceeded(self, tools_with_dispatcher):
        # Always return pending tasks
        tools_with_dispatcher._dispatcher.backend.get_pending_tasks = AsyncMock(
            return_value={"task-1": {"task_type": "triage", "assigned_role": "triage"}}
        )
        # Result always times out
        tools_with_dispatcher._dispatcher.wait_for_result = AsyncMock(
            return_value={"error": "timed out"}
        )

        # Use very short timeouts for fast test
        result = await tools_with_dispatcher.wait_for_all_tasks(timeout=1, hard_timeout=2)

        assert "[!]" in result
        assert "timeout" in result.lower()

    @pytest.mark.asyncio
    async def test_extends_deadline_when_workers_heartbeating_in_process_mode(
        self, tools_with_dispatcher
    ):
        """In-process mode always considers workers alive."""
        call_count = 0

        async def mock_get_pending():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return {"task-1": {"task_type": "threat_hunt", "assigned_role": "threat_hunter"}}
            return {}  # Complete on 3rd call

        tools_with_dispatcher._dispatcher.backend.get_pending_tasks = AsyncMock(
            side_effect=mock_get_pending
        )

        result = await tools_with_dispatcher.wait_for_all_tasks(timeout=60)

        assert "[+]" in result
        assert call_count >= 3

    @pytest.mark.asyncio
    async def test_distributed_mode_checks_heartbeats(self, tools_with_dispatcher):
        """In distributed mode, checks heartbeats to determine liveness."""
        mock_queue = AsyncMock()
        mock_queue.get_all_heartbeats = AsyncMock(
            return_value={
                "blue-threat_hunter-pod1": {
                    "current_task": "task-1",
                    "timestamp": "2026-03-05T12:00:00+00:00",
                    "status": "busy",
                }
            }
        )
        tools_with_dispatcher.set_distributed_mode(mock_queue, "inv-123")

        call_count = 0

        async def mock_get_pending():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return {"task-1": {"task_type": "threat_hunt", "assigned_role": "threat_hunter"}}
            return {}

        tools_with_dispatcher._dispatcher.backend.get_pending_tasks = AsyncMock(
            side_effect=mock_get_pending
        )

        result = await tools_with_dispatcher.wait_for_all_tasks(timeout=60)

        assert "[+]" in result

    @pytest.mark.asyncio
    async def test_times_out_when_no_heartbeats(self, tools_with_dispatcher):
        """Times out when workers stop heartbeating."""
        mock_queue = AsyncMock()
        # No heartbeats returned
        mock_queue.get_all_heartbeats = AsyncMock(return_value={})
        tools_with_dispatcher.set_distributed_mode(mock_queue, "inv-123")

        tools_with_dispatcher._dispatcher.backend.get_pending_tasks = AsyncMock(
            return_value={"task-1": {"task_type": "triage", "assigned_role": "triage"}}
        )
        tools_with_dispatcher._dispatcher.wait_for_result = AsyncMock(
            return_value={"error": "timed out"}
        )

        result = await tools_with_dispatcher.wait_for_all_tasks(timeout=1, hard_timeout=5)

        assert "[!]" in result
        assert "no worker heartbeats" in result.lower()


class TestCheckWorkersAliveForTasks:
    """Tests for _check_workers_alive_for_tasks helper method."""

    @pytest.fixture
    def tools_with_queue(self):
        tools = BlueOrchestratorTools()
        mock_queue = AsyncMock()
        tools.set_distributed_mode(mock_queue, "inv-123")
        return tools

    @pytest.mark.asyncio
    async def test_returns_true_for_inprocess_mode(self):
        """In-process workers are always considered alive."""
        tools = BlueOrchestratorTools()
        # No task queue = in-process mode

        any_alive, count = await tools._check_workers_alive_for_tasks({"task-1", "task-2"})

        assert any_alive is True
        assert count == 2

    @pytest.mark.asyncio
    async def test_returns_true_when_heartbeat_matches_pending_task(self, tools_with_queue):
        from datetime import datetime, timezone

        # Use a fresh timestamp (now)
        fresh_timestamp = datetime.now(timezone.utc).isoformat()
        tools_with_queue._blue_task_queue.get_all_heartbeats = AsyncMock(
            return_value={
                "blue-triage-pod1": {
                    "current_task": "task-1",
                    "timestamp": fresh_timestamp,
                }
            }
        )

        any_alive, count = await tools_with_queue._check_workers_alive_for_tasks(
            {"task-1", "task-2"}
        )

        assert any_alive is True
        assert count == 1

    @pytest.mark.asyncio
    async def test_returns_false_when_no_matching_heartbeats(self, tools_with_queue):
        tools_with_queue._blue_task_queue.get_all_heartbeats = AsyncMock(
            return_value={
                "blue-triage-pod1": {
                    "current_task": "other-task",  # Different task
                    "timestamp": "2026-03-05T13:00:00+00:00",
                }
            }
        )

        any_alive, count = await tools_with_queue._check_workers_alive_for_tasks(
            {"task-1", "task-2"}
        )

        assert any_alive is False
        assert count == 0

    @pytest.mark.asyncio
    async def test_returns_false_when_heartbeat_stale(self, tools_with_queue):
        tools_with_queue._blue_task_queue.get_all_heartbeats = AsyncMock(
            return_value={
                "blue-triage-pod1": {
                    "current_task": "task-1",
                    # Stale timestamp (more than 60s ago)
                    "timestamp": "2020-01-01T00:00:00+00:00",
                }
            }
        )

        any_alive, count = await tools_with_queue._check_workers_alive_for_tasks({"task-1"})

        assert any_alive is False
        assert count == 0

    @pytest.mark.asyncio
    async def test_handles_heartbeat_error_gracefully(self, tools_with_queue):
        tools_with_queue._blue_task_queue.get_all_heartbeats = AsyncMock(
            side_effect=Exception("Redis connection error")
        )

        # Should not raise, assumes alive on error
        any_alive, count = await tools_with_queue._check_workers_alive_for_tasks({"task-1"})

        assert any_alive is True  # Assumes alive on error
        assert count == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
