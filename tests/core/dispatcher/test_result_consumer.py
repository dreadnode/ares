"""Unit tests for dispatcher Redis result consumer."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from ares.core.dispatcher import RedTeamDispatcher
from ares.core.task_queue import TaskResult


class TestDispatcherResultConsumer:
    """Tests for consuming Redis task results."""

    @pytest.mark.asyncio
    async def test_consume_pending_results_marks_complete(self):
        """Consume pending results and mark task complete."""
        dispatcher = RedTeamDispatcher()
        dispatcher._task_queue = MagicMock()
        dispatcher._task_queue.check_result = AsyncMock(
            return_value=TaskResult(task_id="task_1", success=True, result={"ok": True})
        )
        dispatcher.complete_task = AsyncMock()
        dispatcher._redis_task_ids.add("task_1")

        await dispatcher._consume_pending_results()

        assert "task_1" not in dispatcher._redis_task_ids
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
        dispatcher._task_queue = MagicMock()
        dispatcher._task_queue.check_result = AsyncMock(return_value=None)
        dispatcher.complete_task = AsyncMock()
        dispatcher._redis_task_ids.add("task_1")

        await dispatcher._consume_pending_results()

        assert "task_1" in dispatcher._redis_task_ids
        dispatcher.complete_task.assert_not_called()
