"""Tests for orchestrator module."""

import pytest

from ares.core.orchestrator import run_multi_agent_operation


@pytest.mark.asyncio
async def test_run_multi_agent_operation_requires_model(monkeypatch):
    monkeypatch.delenv("ARES_ORCHESTRATOR_MODEL", raising=False)
    monkeypatch.delenv("ARES_MODEL", raising=False)

    with pytest.raises(ValueError, match="No model specified"):
        await run_multi_agent_operation(
            operation_id="op-1",
            target_domain="example.com",
            target_ips=["10.0.0.1"],
        )
