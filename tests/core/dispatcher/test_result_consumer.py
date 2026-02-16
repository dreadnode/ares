"""Unit tests for dispatcher Redis result consumer."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

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
