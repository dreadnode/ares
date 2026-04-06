"""Tests for dispatch-level dedup of secretsdump and share spider tasks.

Prevents duplicate dispatch of expensive credential access operations:
- secretsdump: per target IP (no point re-dumping an already-dumped host)
- smbclient_spider: by sorted target IP set (identical spider batches)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from ares.core.dispatcher import RedTeamDispatcher
from ares.core.models import SharedRedTeamState, Target, TaskInfo


def _make_dispatcher(op_id: str = "op-dedup-1") -> RedTeamDispatcher:
    """Create a minimal dispatcher with required stubs for dispatch dedup tests."""
    d = RedTeamDispatcher()
    d._shared_state = SharedRedTeamState(operation_id=op_id)
    d._shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")
    # Stub methods called before dedup check in request_credential_access
    d._normalize_domain = lambda domain: domain.lower() if domain else ""
    d._find_domain_controller_ip = lambda _domain: "192.168.58.10"
    d._find_credential_id = lambda *_a, **_kw: (None, 0)
    d._ensure_credential_in_state = lambda **_kw: None
    d._should_skip_for_da = lambda: False
    d._should_skip_dominated_domain_task = lambda *_a, **_kw: False
    # Mock task queue so dispatch proceeds to the throttled submit
    d._task_queue = MagicMock()
    d._throttled_submit_task = AsyncMock(return_value="task-001")
    d._persist_task_info_to_redis = AsyncMock()
    return d


class TestSecretsdumpDedup:
    """Secretsdump should not be dispatched twice for the same target IP."""

    @pytest.mark.asyncio
    async def test_first_secretsdump_dispatches(self):
        d = _make_dispatcher()
        task_id = await d.request_credential_access(
            source_agent="test",
            domain="contoso.local",
            target_ips=["192.168.58.10"],
            techniques=["secretsdump"],
        )
        assert task_id == "task-001"
        d._throttled_submit_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_second_secretsdump_same_target_is_skipped(self):
        d = _make_dispatcher()
        # First dispatch succeeds
        await d.request_credential_access(
            source_agent="test",
            domain="contoso.local",
            target_ips=["192.168.58.10"],
            techniques=["secretsdump"],
        )
        d._throttled_submit_task.reset_mock()

        # Second dispatch to same target should be skipped
        task_id = await d.request_credential_access(
            source_agent="test",
            domain="contoso.local",
            target_ips=["192.168.58.10"],
            techniques=["secretsdump"],
        )
        assert task_id == ""
        d._throttled_submit_task.assert_not_called()

    @pytest.mark.asyncio
    async def test_secretsdump_different_targets_dispatch(self):
        d = _make_dispatcher()
        await d.request_credential_access(
            source_agent="test",
            domain="contoso.local",
            target_ips=["192.168.58.10"],
            techniques=["secretsdump"],
        )
        d._throttled_submit_task.reset_mock()

        # Different target IP should still dispatch
        task_id = await d.request_credential_access(
            source_agent="test",
            domain="contoso.local",
            target_ips=["192.168.58.20"],
            techniques=["secretsdump"],
        )
        assert task_id == "task-001"
        d._throttled_submit_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_secretsdump_partial_overlap_still_dispatches(self):
        """If at least one target is new, dispatch proceeds."""
        d = _make_dispatcher()
        await d.request_credential_access(
            source_agent="test",
            domain="contoso.local",
            target_ips=["192.168.58.10"],
            techniques=["secretsdump"],
        )
        d._throttled_submit_task.reset_mock()

        # Mixed: one already dispatched, one new
        task_id = await d.request_credential_access(
            source_agent="test",
            domain="contoso.local",
            target_ips=["192.168.58.10", "192.168.58.20"],
            techniques=["secretsdump"],
        )
        assert task_id == "task-001"
        d._throttled_submit_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_secretsdump_all_overlap_skipped(self):
        """If all targets are already dispatched, skip."""
        d = _make_dispatcher()
        await d.request_credential_access(
            source_agent="test",
            domain="contoso.local",
            target_ips=["192.168.58.10", "192.168.58.20"],
            techniques=["secretsdump"],
        )
        d._throttled_submit_task.reset_mock()

        task_id = await d.request_credential_access(
            source_agent="test",
            domain="contoso.local",
            target_ips=["192.168.58.20", "192.168.58.10"],
            techniques=["secretsdump"],
        )
        assert task_id == ""
        d._throttled_submit_task.assert_not_called()

    @pytest.mark.asyncio
    async def test_secretsdump_failure_clears_dedup(self):
        """Failed secretsdump should allow retry on same target."""
        d = _make_dispatcher()
        await d.request_credential_access(
            source_agent="test",
            domain="contoso.local",
            target_ips=["192.168.58.10"],
            techniques=["secretsdump"],
        )
        d._throttled_submit_task.reset_mock()

        # Simulate failure -- clears dedup
        d.mark_secretsdump_failed("192.168.58.10")

        # Should dispatch again after failure
        task_id = await d.request_credential_access(
            source_agent="test",
            domain="contoso.local",
            target_ips=["192.168.58.10"],
            techniques=["secretsdump"],
        )
        assert task_id == "task-001"
        d._throttled_submit_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_non_secretsdump_not_affected_by_dedup(self):
        """Kerberoast and other techniques should not be deduped by this logic."""
        d = _make_dispatcher()
        await d.request_credential_access(
            source_agent="test",
            domain="contoso.local",
            target_ips=["192.168.58.10"],
            techniques=["kerberoast"],
        )
        d._throttled_submit_task.reset_mock()

        # Same target, different technique -- should not be blocked
        task_id = await d.request_credential_access(
            source_agent="test",
            domain="contoso.local",
            target_ips=["192.168.58.10"],
            techniques=["kerberoast"],
        )
        assert task_id == "task-001"
        d._throttled_submit_task.assert_called_once()


class TestShareSpiderDedup:
    """Share spider should not be dispatched twice for identical target IP sets."""

    @pytest.mark.asyncio
    async def test_first_spider_dispatches(self):
        d = _make_dispatcher()
        task_id = await d.request_credential_access(
            source_agent="orchestrator",
            domain="contoso.local",
            target_ips=["192.168.58.10"],
            techniques=["smbclient_spider"],
            reason="auto_share_spider_public",
        )
        assert task_id == "task-001"
        d._throttled_submit_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_same_spider_targets_skipped(self):
        d = _make_dispatcher()
        await d.request_credential_access(
            source_agent="orchestrator",
            domain="contoso.local",
            target_ips=["192.168.58.10", "192.168.58.20"],
            techniques=["smbclient_spider"],
            reason="auto_share_spider_all",
        )
        d._throttled_submit_task.reset_mock()

        # Identical target set (different order) should be skipped
        task_id = await d.request_credential_access(
            source_agent="orchestrator",
            domain="contoso.local",
            target_ips=["192.168.58.20", "192.168.58.10"],
            techniques=["smbclient_spider"],
            reason="auto_share_spider_all",
        )
        assert task_id == ""
        d._throttled_submit_task.assert_not_called()

    @pytest.mark.asyncio
    async def test_different_spider_targets_dispatch(self):
        d = _make_dispatcher()
        await d.request_credential_access(
            source_agent="orchestrator",
            domain="contoso.local",
            target_ips=["192.168.58.10"],
            techniques=["smbclient_spider"],
            reason="auto_share_spider_public",
        )
        d._throttled_submit_task.reset_mock()

        # Different target set should dispatch
        task_id = await d.request_credential_access(
            source_agent="orchestrator",
            domain="contoso.local",
            target_ips=["192.168.58.20"],
            techniques=["smbclient_spider"],
            reason="auto_share_spider_data",
        )
        assert task_id == "task-001"
        d._throttled_submit_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_spider_five_targets_dedup(self):
        """Reproduces the bug: two agents get identical 5-target spider tasks."""
        d = _make_dispatcher()
        targets = [
            "192.168.58.10",
            "192.168.58.20",
            "192.168.58.30",
            "192.168.58.40",
            "192.168.58.50",
        ]

        await d.request_credential_access(
            source_agent="agent-1",
            domain="contoso.local",
            target_ips=targets,
            techniques=["smbclient_spider"],
            reason="auto_share_spider_data",
        )
        d._throttled_submit_task.reset_mock()

        # Second agent tries same 5 targets -- should be blocked
        task_id = await d.request_credential_access(
            source_agent="agent-2",
            domain="contoso.local",
            target_ips=list(reversed(targets)),
            techniques=["smbclient_spider"],
            reason="auto_share_spider_data",
        )
        assert task_id == ""
        d._throttled_submit_task.assert_not_called()


class TestCompleteTaskClearsSecretsdumpDedup:
    """Verify that failed secretsdump tasks clear the dispatch dedup in complete_task."""

    @pytest.mark.asyncio
    async def test_complete_task_clears_secretsdump_dedup_on_failure(self):
        d = _make_dispatcher()
        d._redis_client = None
        d._context_offloader = None
        d._resolve_task_future = lambda *_a, **_kw: None
        d._checkpoint = AsyncMock()

        # Pre-populate dedup
        d._dispatched_secretsdump_targets = {"192.168.58.10"}

        task_info = TaskInfo(
            task_id="task-sd-1",
            task_type="credential_access",
            assigned_agent="credential_access",
            params={
                "domain": "contoso.local",
                "target_ips": ["192.168.58.10"],
                "techniques": ["secretsdump"],
            },
        )
        d._shared_state.pending_tasks["task-sd-1"] = task_info

        await d.complete_task(
            task_id="task-sd-1",
            success=False,
            error="Connection refused",
            source_agent="credential_access",
        )

        # Dedup should be cleared for failed target
        assert "192.168.58.10" not in d._dispatched_secretsdump_targets

    @pytest.mark.asyncio
    async def test_complete_task_keeps_secretsdump_dedup_on_success(self):
        d = _make_dispatcher()
        d._redis_client = None
        d._context_offloader = None
        d._resolve_task_future = lambda *_a, **_kw: None
        d._checkpoint = AsyncMock()

        d._dispatched_secretsdump_targets = {"192.168.58.10"}

        task_info = TaskInfo(
            task_id="task-sd-2",
            task_type="credential_access",
            assigned_agent="credential_access",
            params={
                "domain": "contoso.local",
                "target_ips": ["192.168.58.10"],
                "techniques": ["secretsdump"],
            },
        )
        d._shared_state.pending_tasks["task-sd-2"] = task_info

        await d.complete_task(
            task_id="task-sd-2",
            success=True,
            result={"output": "dumped hashes"},
            source_agent="credential_access",
        )

        # Dedup should remain for successfully completed target
        assert "192.168.58.10" in d._dispatched_secretsdump_targets
