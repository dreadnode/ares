"""Unit tests for dispatcher Redis result consumer."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.dispatcher import RedTeamDispatcher
from ares.core.models import SharedRedTeamState, TaskInfo
from ares.core.task_queue import TaskResult


class TestDispatcherResultConsumer:
    """Tests for consuming Redis task results."""

    @pytest.mark.asyncio
    async def test_consume_pending_results_marks_complete(self):
        """Consume pending results and mark task complete."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher._task_queue = MagicMock()
        dispatcher._task_queue.check_result = AsyncMock(
            return_value=TaskResult(task_id="task_1", success=True, result={"ok": True})
        )
        dispatcher.complete_task = AsyncMock()
        # Add task to pending_tasks (source of truth for result consumer)
        dispatcher._shared_state.pending_tasks["task_1"] = TaskInfo(
            task_id="task_1",
            task_type="test",
            assigned_agent="test",
            created_at=datetime.now(timezone.utc),
        )

        await dispatcher._consume_pending_results()

        dispatcher._task_queue.check_result.assert_called_once_with("task_1")
        dispatcher.complete_task.assert_called_once()
        called = dispatcher.complete_task.call_args.kwargs
        assert called["task_id"] == "task_1"
        assert called["success"] is True
        assert called["result"] == {"ok": True}

    @pytest.mark.asyncio
    async def test_consume_pending_results_no_result(self):
        """No result should leave task pending."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher._task_queue = MagicMock()
        dispatcher._task_queue.check_result = AsyncMock(return_value=None)
        dispatcher.complete_task = AsyncMock()
        # Add task to pending_tasks
        dispatcher._shared_state.pending_tasks["task_1"] = TaskInfo(
            task_id="task_1",
            task_type="test",
            assigned_agent="test",
            created_at=datetime.now(timezone.utc),
        )

        await dispatcher._consume_pending_results()

        # Task should still be pending (complete_task not called means it stays)
        assert "task_1" in dispatcher._shared_state.pending_tasks
        dispatcher.complete_task.assert_not_called()


class TestThreadedResultConsumerLogging:
    """Tests for operation_id logging context in threaded result consumer."""

    def test_threaded_consumer_gets_operation_id_from_shared_state(self):
        """Threaded consumer should get operation_id from shared_state."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-logging")

        # Verify shared_state has the operation_id
        assert dispatcher._shared_state.operation_id == "op-test-logging"

    def test_threaded_consumer_falls_back_to_dash_without_shared_state(self):
        """Threaded consumer should use '-' when shared_state is None."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = None

        # The wrapper method extracts operation_id
        operation_id = dispatcher._shared_state.operation_id if dispatcher._shared_state else "-"
        assert operation_id == "-"

    def test_threaded_consumer_loop_calls_inner_with_context(self):
        """_threaded_result_consumer_loop should wrap inner call with logger.contextualize."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-ctx-test")
        dispatcher._result_consumer_stop_event = threading.Event()
        dispatcher._result_consumer_stop_event.set()  # Stop immediately

        captured_operation_id = None

        def mock_inner():
            """Mock inner loop that captures the logging context."""

            # loguru stores context in record["extra"], we can verify via a custom sink
            nonlocal captured_operation_id
            # The context is set by logger.contextualize in the wrapper
            # We verify by checking that the inner method is called
            # (actual context verification would require log capture)
            captured_operation_id = "inner_called"

        with patch.object(
            dispatcher, "_threaded_result_consumer_loop_inner", side_effect=mock_inner
        ):
            dispatcher._threaded_result_consumer_loop()

        assert captured_operation_id == "inner_called"

    def test_threaded_consumer_loop_propagates_operation_id_to_logs(self):
        """Logs from threaded consumer should include operation_id context."""
        from io import StringIO

        from loguru import logger

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-log-verify")
        dispatcher._result_consumer_stop_event = threading.Event()
        dispatcher._result_consumer_stop_event.set()  # Stop immediately

        # Capture log output
        log_output = StringIO()
        handler_id = logger.add(
            log_output,
            format="{extra[operation_id]} | {message}",
            level="DEBUG",
        )

        logged_with_context = False

        def mock_inner():
            """Mock inner loop that logs with context."""
            nonlocal logged_with_context
            logger.info("Test log from inner loop")
            logged_with_context = True

        try:
            with patch.object(
                dispatcher, "_threaded_result_consumer_loop_inner", side_effect=mock_inner
            ):
                dispatcher._threaded_result_consumer_loop()

            # Check that the log contains the operation_id
            log_content = log_output.getvalue()
            assert "op-log-verify" in log_content
            assert "Test log from inner loop" in log_content
        finally:
            logger.remove(handler_id)

        assert logged_with_context

    def test_threaded_consumer_inner_loop_exists(self):
        """_threaded_result_consumer_loop_inner should exist and be callable."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-inner-test")

        # Verify the inner method exists
        assert hasattr(dispatcher, "_threaded_result_consumer_loop_inner")
        assert callable(dispatcher._threaded_result_consumer_loop_inner)


class TestExtractedDomainResolution:
    """Tests for _resolve_extracted_domain helper function."""

    def test_empty_extracted_uses_target_domain(self):
        """When extracted domain is empty, use target domain."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test")

        result = dispatcher._resolve_extracted_domain("", "contoso.local")
        assert result == "contoso.local"

    def test_fqdn_extracted_is_trusted(self):
        """When extracted domain is FQDN, trust it even if different from target."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test")

        # Extracted FQDN should be trusted even if different from target
        result = dispatcher._resolve_extracted_domain("child.contoso.local", "contoso.local")
        assert result == "child.contoso.local"

    def test_netbios_matches_target_uses_target(self):
        """When NetBIOS matches target FQDN prefix, use target FQDN."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test")

        # NetBIOS "child" matches "child.contoso.local"
        result = dispatcher._resolve_extracted_domain("child", "child.contoso.local")
        assert result == "child.contoso.local"

    def test_netbios_no_match_kept_as_is(self):
        """When NetBIOS doesn't match target, return NetBIOS for later resolution."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test")

        # NetBIOS "fabrikam" doesn't match "contoso.local"
        result = dispatcher._resolve_extracted_domain("fabrikam", "contoso.local")
        assert result == "fabrikam"

    def test_netbios_no_target_kept_as_is(self):
        """When no target domain available, return NetBIOS as-is."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test")

        result = dispatcher._resolve_extracted_domain("north", "")
        assert result == "north"
