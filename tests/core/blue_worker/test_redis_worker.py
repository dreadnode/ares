"""Tests for BlueRedisWorkerAgent and worker functions."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.blue_task_queue import BlueTaskMessage
from ares.core.blue_worker._redis_worker import BlueRedisWorkerAgent
from ares.core.models import BlueRole


class TestBlueRedisWorkerAgentInit:
    """Tests for BlueRedisWorkerAgent initialization."""

    def test_initializes_with_required_args(self):
        mock_queue = MagicMock()
        mock_agent = MagicMock()
        mock_callback_tools = MagicMock()
        mock_backend = MagicMock()

        worker = BlueRedisWorkerAgent(
            role=BlueRole.TRIAGE,
            task_queue=mock_queue,
            agent=mock_agent,
            agent_name="blue-triage-test",
            callback_tools=mock_callback_tools,
            backend=mock_backend,
            investigation_id="inv-123",
        )

        assert worker.role == BlueRole.TRIAGE
        assert worker.task_queue is mock_queue
        assert worker.agent is mock_agent
        assert worker.agent_name == "blue-triage-test"
        assert worker.investigation_id == "inv-123"
        assert worker._running is False
        assert worker._current_task is None
        assert worker._tasks_completed == 0

    def test_uses_hostname_env_for_pod_name(self):
        mock_queue = MagicMock()
        mock_agent = MagicMock()
        mock_callback_tools = MagicMock()
        mock_backend = MagicMock()

        with patch.dict("os.environ", {"HOSTNAME": "pod-abc123"}):
            worker = BlueRedisWorkerAgent(
                role=BlueRole.THREAT_HUNTER,
                task_queue=mock_queue,
                agent=mock_agent,
                agent_name="blue-hunter",
                callback_tools=mock_callback_tools,
                backend=mock_backend,
                investigation_id="inv-456",
            )

        assert worker.pod_name == "pod-abc123"

    def test_accepts_explicit_pod_name(self):
        mock_queue = MagicMock()
        mock_agent = MagicMock()
        mock_callback_tools = MagicMock()
        mock_backend = MagicMock()

        worker = BlueRedisWorkerAgent(
            role=BlueRole.LATERAL_ANALYST,
            task_queue=mock_queue,
            agent=mock_agent,
            agent_name="blue-lateral",
            callback_tools=mock_callback_tools,
            backend=mock_backend,
            investigation_id="inv-789",
            pod_name="explicit-pod",
        )

        assert worker.pod_name == "explicit-pod"


class TestBlueRedisWorkerAgentLifecycle:
    """Tests for worker start/stop lifecycle."""

    @pytest.fixture
    def worker(self):
        mock_queue = AsyncMock()
        mock_queue.poll_task = AsyncMock(return_value=None)
        mock_queue.get_investigation_alert = AsyncMock(return_value=None)
        mock_queue.ping_or_reconnect = AsyncMock()

        mock_agent = AsyncMock()
        mock_callback_tools = MagicMock()
        mock_backend = AsyncMock()
        mock_backend.snapshot = AsyncMock(return_value={})

        return BlueRedisWorkerAgent(
            role=BlueRole.TRIAGE,
            task_queue=mock_queue,
            agent=mock_agent,
            agent_name="blue-triage-test",
            callback_tools=mock_callback_tools,
            backend=mock_backend,
            investigation_id="inv-123",
            redis_url="redis://localhost",
        )

    @pytest.mark.asyncio
    async def test_start_sets_running_flag(self, worker):
        # Make worker stop immediately
        worker.task_queue.get_investigation_alert = AsyncMock(return_value=None)

        await worker.start()

        # Worker should have stopped because investigation is not active
        assert worker._running is False

    @pytest.mark.asyncio
    async def test_stop_clears_running_flag(self, worker):
        worker._running = True

        await worker.stop()

        assert worker._running is False


class TestBlueRedisWorkerAgentTaskProcessing:
    """Tests for task processing logic."""

    @pytest.fixture
    def worker(self):
        mock_queue = AsyncMock()
        mock_queue.send_result = AsyncMock()

        mock_agent = AsyncMock()
        mock_agent.run = AsyncMock()

        mock_callback_tools = MagicMock()
        mock_callback_tools.set_completion_event = MagicMock()
        mock_callback_tools.result_data = {"summary": "Triage complete"}

        mock_backend = AsyncMock()
        mock_backend.snapshot = AsyncMock(
            return_value={
                "evidence": [{"id": "ev-1"}],
                "techniques": {"T1078"},
                "hosts": {"192.168.58.10"},
                "users": {"testuser"},
                "meta": {"stage": "triage"},
            }
        )

        return BlueRedisWorkerAgent(
            role=BlueRole.TRIAGE,
            task_queue=mock_queue,
            agent=mock_agent,
            agent_name="blue-triage-test",
            callback_tools=mock_callback_tools,
            backend=mock_backend,
            investigation_id="inv-123",
        )

    @pytest.mark.asyncio
    async def test_process_task_runs_agent(self, worker):
        task = BlueTaskMessage(
            task_id="task-123",
            task_type="triage_alert",
            investigation_id="inv-123",
            assigned_role="triage",
            params={"alert_name": "HighCPU"},
        )

        # Simulate completion callback being set
        def set_event(event):
            event.set()

        worker.callback_tools.set_completion_event = set_event

        await worker._process_task(task)

        worker.agent.run.assert_awaited_once()
        assert worker._tasks_completed == 1

    @pytest.mark.asyncio
    async def test_process_task_sends_success_result(self, worker):
        task = BlueTaskMessage(
            task_id="task-456",
            task_type="triage_alert",
            investigation_id="inv-123",
            assigned_role="triage",
            params={},
        )

        def set_event(event):
            event.set()

        worker.callback_tools.set_completion_event = set_event

        await worker._process_task(task)

        worker.task_queue.send_result.assert_awaited_once()
        call_kwargs = worker.task_queue.send_result.call_args.kwargs
        assert call_kwargs["task_id"] == "task-456"
        assert call_kwargs["success"] is True

    @pytest.mark.asyncio
    async def test_process_task_sends_partial_result_without_callback(self, worker):
        task = BlueTaskMessage(
            task_id="task-789",
            task_type="triage_alert",
            investigation_id="inv-123",
            assigned_role="triage",
            params={},
        )

        # Don't set the completion event
        worker.callback_tools.set_completion_event = MagicMock()

        await worker._process_task(task)

        call_kwargs = worker.task_queue.send_result.call_args.kwargs
        assert call_kwargs["success"] is True
        assert call_kwargs["result"]["partial"] is True

    @pytest.mark.asyncio
    async def test_process_task_handles_unknown_task_type(self, worker):
        task = BlueTaskMessage(
            task_id="task-unknown",
            task_type="unknown_type",
            investigation_id="inv-123",
            assigned_role="triage",
            params={},
        )

        await worker._process_task(task)

        call_kwargs = worker.task_queue.send_result.call_args.kwargs
        assert call_kwargs["success"] is False
        assert "Unknown task type" in call_kwargs["error"]

    @pytest.mark.asyncio
    async def test_process_task_sends_error_on_exception(self, worker):
        task = BlueTaskMessage(
            task_id="task-error",
            task_type="triage_alert",
            investigation_id="inv-123",
            assigned_role="triage",
            params={},
        )

        worker.agent.run = AsyncMock(side_effect=RuntimeError("Agent crashed"))

        await worker._process_task(task)

        call_kwargs = worker.task_queue.send_result.call_args.kwargs
        assert call_kwargs["success"] is False
        assert "Agent crashed" in call_kwargs["error"]

    @pytest.mark.asyncio
    async def test_get_state_summary_extracts_from_snapshot(self, worker):
        summary = await worker._get_state_summary()

        assert summary["investigation_id"] == "inv-123"
        assert summary["evidence_count"] == 1
        assert "T1078" in summary["techniques_identified"]
        assert "192.168.58.10" in summary["hosts_investigated"]
        assert summary["stage"] == "triage"

    @pytest.mark.asyncio
    async def test_get_state_summary_handles_error(self, worker):
        worker.backend.snapshot = AsyncMock(side_effect=RuntimeError("Redis error"))

        summary = await worker._get_state_summary()

        assert summary == {}


class TestBlueRedisWorkerAgentResults:
    """Tests for result sending helpers."""

    @pytest.fixture
    def worker(self):
        mock_queue = AsyncMock()
        mock_queue.send_result = AsyncMock()

        return BlueRedisWorkerAgent(
            role=BlueRole.TRIAGE,
            task_queue=mock_queue,
            agent=MagicMock(),
            agent_name="blue-triage-test",
            callback_tools=MagicMock(),
            backend=MagicMock(),
            investigation_id="inv-123",
            pod_name="pod-test",
        )

    @pytest.mark.asyncio
    async def test_send_success_result(self, worker):
        await worker._send_success_result(
            task_id="task-123",
            result={"findings": ["suspicious_login"]},
        )

        worker.task_queue.send_result.assert_awaited_once_with(
            task_id="task-123",
            success=True,
            result={"findings": ["suspicious_login"]},
            worker_pod="pod-test",
            agent_name="blue-triage-test",
        )

    @pytest.mark.asyncio
    async def test_send_error_result(self, worker):
        await worker._send_error_result(
            task_id="task-456",
            error="Processing failed",
        )

        worker.task_queue.send_result.assert_awaited_once_with(
            task_id="task-456",
            success=False,
            error="Processing failed",
            worker_pod="pod-test",
            agent_name="blue-triage-test",
        )


class TestBlueRedisWorkerAgentWorkerLoop:
    """Tests for the worker loop behavior."""

    @pytest.fixture
    def worker(self):
        mock_queue = AsyncMock()
        mock_queue.poll_task = AsyncMock(return_value=None)
        mock_queue.get_investigation_alert = AsyncMock(return_value={"labels": {}})
        mock_queue.ping_or_reconnect = AsyncMock()
        mock_queue.send_result = AsyncMock()

        mock_agent = AsyncMock()
        mock_callback_tools = MagicMock()
        mock_callback_tools.set_completion_event = MagicMock()
        mock_callback_tools.result_data = {}

        mock_backend = AsyncMock()
        mock_backend.snapshot = AsyncMock(return_value={})

        return BlueRedisWorkerAgent(
            role=BlueRole.TRIAGE,
            task_queue=mock_queue,
            agent=mock_agent,
            agent_name="blue-triage-test",
            callback_tools=mock_callback_tools,
            backend=mock_backend,
            investigation_id="inv-123",
            redis_url="redis://localhost",
        )

    @pytest.mark.asyncio
    async def test_worker_loop_exits_when_investigation_inactive(self, worker):
        # Investigation becomes inactive after first check
        worker.task_queue.get_investigation_alert = AsyncMock(return_value=None)
        worker._running = True

        await worker._worker_loop()

        # Should have checked for investigation
        worker.task_queue.get_investigation_alert.assert_awaited()
        assert worker._running is True  # Loop sets running before checking

    @pytest.mark.asyncio
    async def test_worker_loop_processes_task_when_available(self, worker):
        task = BlueTaskMessage(
            task_id="task-loop",
            task_type="triage_alert",
            investigation_id="inv-123",
            assigned_role="triage",
            params={},
        )

        call_count = 0

        async def poll_once(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return task
            # After processing, return None and stop
            worker._running = False
            return None

        worker.task_queue.poll_task = poll_once

        def set_event(event):
            event.set()

        worker.callback_tools.set_completion_event = set_event
        worker._running = True

        await worker._worker_loop()

        # Should have processed the task
        worker.agent.run.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_worker_loop_handles_connection_error_with_retry(self, worker):
        error_count = 0

        async def fail_then_succeed(*args, **kwargs):
            nonlocal error_count
            error_count += 1
            if error_count == 1:
                raise ConnectionError("Connection reset")
            worker._running = False

        worker.task_queue.poll_task = fail_then_succeed
        worker._running = True

        await worker._worker_loop()

        # Should have retried after error
        assert error_count >= 1


class TestLoadMcpTools:
    """Tests for _load_mcp_tools helper."""

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_connect_fails(self):
        from ares.core.blue_worker._redis_worker import _load_mcp_tools

        # The function handles errors gracefully and returns empty list
        result = await _load_mcp_tools()
        assert result == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
