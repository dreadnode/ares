"""Tests for orchestrator module."""

from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ares.core.models import SharedRedTeamState, Target, VulnerabilityInfo
from ares.core.orchestrator import run_multi_agent_operation


@pytest.mark.asyncio
async def test_run_multi_agent_operation_requires_model(monkeypatch):
    monkeypatch.delenv("ARES_ORCHESTRATOR_MODEL", raising=False)
    monkeypatch.delenv("ARES_MODEL", raising=False)

    with pytest.raises(ValueError, match="No model specified"):
        await run_multi_agent_operation(
            operation_id="op-1",
            target_domain="contoso.local",
            target_ips=["192.168.56.1"],
        )


@pytest.mark.asyncio
async def test_run_multi_agent_operation_skips_wait_when_completed(monkeypatch):
    from ares.core import orchestrator as orch

    shared_state = SimpleNamespace(
        completed=False,
        has_domain_admin=False,
        domain_admin_path=None,
        has_golden_ticket=False,
        all_credentials=[],
        all_hashes=[],
        all_hosts=[],
        discovered_vulnerabilities=[],
        exploited_vulnerabilities=[],
        completed_tasks=[],
    )

    dispatcher = SimpleNamespace(shared_state=shared_state)
    dispatcher.start = AsyncMock()
    dispatcher.recover_state = AsyncMock(return_value=None)
    dispatcher.register = AsyncMock()
    dispatcher.stop = AsyncMock()
    dispatcher.get_exploitation_status = AsyncMock(
        return_value={"pending": [], "total_discovered": 0, "total_succeeded": 0}
    )

    task_queue = SimpleNamespace()
    task_queue.connect = AsyncMock()
    task_queue.acquire_operation_lock = AsyncMock(return_value=True)
    task_queue.release_operation_lock = AsyncMock()
    task_queue.disconnect = AsyncMock()

    recovery = SimpleNamespace()
    recovery.start = AsyncMock()
    recovery.start_periodic_checkpoint = AsyncMock()

    class DummyAgent:
        async def run(self, _prompt):
            dispatcher.shared_state.completed = True
            return SimpleNamespace(stop_reason="completed")

    monkeypatch.setattr(orch, "RedTeamDispatcher", lambda **_kwargs: dispatcher)
    monkeypatch.setattr(orch, "RedisTaskQueue", lambda *_args, **_kwargs: task_queue)
    monkeypatch.setattr(orch, "OperationRecoveryManager", lambda **_kwargs: recovery)
    monkeypatch.setattr(orch, "get_redis_url", lambda: "redis://")
    monkeypatch.setattr(orch, "get_namespace", lambda: "default")
    monkeypatch.setattr(orch, "_load_or_initialize_state", AsyncMock())
    monkeypatch.setattr(orch, "_create_agent_ensemble", AsyncMock(return_value=[]))
    monkeypatch.setattr(orch, "_register_agents", AsyncMock())
    monkeypatch.setattr(orch, "_ensure_required_workers", AsyncMock())
    monkeypatch.setattr(orch, "_prime_operation", AsyncMock())
    monkeypatch.setattr(orch, "_create_orchestrator_agent", AsyncMock(return_value=DummyAgent()))
    monkeypatch.setattr(orch, "_build_orchestrator_prompt", lambda **_kwargs: "prompt")
    monkeypatch.setattr(orch, "_log_orchestrator_result", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        orch, "_generate_multi_agent_report", lambda *_args, **_kwargs: (None, None)
    )
    monkeypatch.setattr(orch, "_run_mandatory_user_enum", lambda *_args, **_kwargs: None)

    async def _noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(orch, "exploitation_workflow", _noop)
    monkeypatch.setattr(orch, "_monitor_agent_health", _noop)
    monkeypatch.setattr(orch, "_extend_operation_lock", _noop)

    wait_mock = AsyncMock()
    monkeypatch.setattr(orch, "_wait_for_completion", wait_mock)

    monkeypatch.setattr(orch.dn, "run", lambda **_kwargs: nullcontext())
    monkeypatch.setattr(orch.dn, "log_params", MagicMock())

    await run_multi_agent_operation(
        operation_id="op-2",
        target_domain="contoso.local",
        target_ips=["192.168.56.2"],
        model="test-model",
    )

    wait_mock.assert_not_awaited()


def test_build_redteam_report_state_uses_exploitation_status_counts():
    """Report state should honor exploitation_status counts when provided."""
    from ares.core.orchestrator import _build_redteam_report_state

    state = SharedRedTeamState(
        operation_id="op-3",
        target=Target(ip="192.168.56.3", domain="contoso.local"),
    )
    vuln = VulnerabilityInfo(
        vuln_id="ADCS_ESC1_dc01",
        vuln_type="ADCS_ESC1",
        target="dc01",
        discovered_by="recon",
    )
    state.discovered_vulnerabilities[vuln.vuln_id] = vuln
    state.exploited_vulnerabilities.add(vuln.vuln_id)

    report_state = _build_redteam_report_state(
        state,
        {"total_discovered": 4, "total_succeeded": 2},
    )

    assert report_state.vulnerability_count == 4
    assert report_state.exploited_count == 2
