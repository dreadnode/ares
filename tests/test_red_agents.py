"""Tests for red_agents factory helpers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.factories.red_agents import create_multi_agent_ensemble
from ares.core.models import AgentRole


@pytest.mark.asyncio
async def test_create_multi_agent_ensemble_requires_model(monkeypatch):
    monkeypatch.delenv("ARES_MODEL", raising=False)
    monkeypatch.delenv("ARES_ORCHESTRATOR_MODEL", raising=False)
    monkeypatch.delenv("ARES_WORKER_MODEL", raising=False)

    dispatcher = MagicMock(shared_state=SimpleNamespace())

    with pytest.raises(ValueError, match="No model specified"):
        await create_multi_agent_ensemble(
            operation_id="op-1",
            target_ip="192.168.56.1",
            dispatcher=dispatcher,
            roles=[AgentRole.ENUM],
        )


@pytest.mark.asyncio
async def test_create_multi_agent_ensemble_uses_env_models(monkeypatch):
    monkeypatch.setenv("ARES_ORCHESTRATOR_MODEL", "orch-model")
    monkeypatch.setenv("ARES_WORKER_MODEL", "worker-model")

    dispatcher = MagicMock(shared_state=SimpleNamespace())
    dispatcher.register = AsyncMock()

    with patch("ares.core.factories.red_agents.create_specialized_agent") as mock_create:
        mock_create.return_value = MagicMock()

        await create_multi_agent_ensemble(
            operation_id="op-2",
            target_ip="192.168.56.2",
            dispatcher=dispatcher,
            roles=[AgentRole.ENUM, AgentRole.CRACKER],
        )

    assert mock_create.call_count == 2
    assert mock_create.call_args_list[0].kwargs["model"] == "orch-model"
    assert mock_create.call_args_list[1].kwargs["model"] == "worker-model"


def test_create_specialized_agent_uses_set_state_when_shared_state_missing(monkeypatch):
    created: dict[str, MagicMock] = {}

    class DummyToolset:
        def __init__(self) -> None:
            self.set_state = MagicMock()
            created["instance"] = self

    monkeypatch.setattr(
        "ares.core.factories.red_agents.ROLE_TOOLSETS",
        {AgentRole.ENUM: [DummyToolset]},
    )
    monkeypatch.setattr(
        "ares.core.factories.red_agents.load_agent_instructions",
        lambda _role: "instructions",
    )
    monkeypatch.setattr(
        "ares.core.factories.red_agents.create_role_hooks",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr("ares.core.factories.red_agents.dn.Agent", MagicMock())

    from ares.core.factories.red_agents import create_specialized_agent

    shared_state = MagicMock()
    dispatcher = MagicMock()

    create_specialized_agent(
        role=AgentRole.ENUM,
        model="test-model",
        shared_state=shared_state,
        dispatcher=dispatcher,
    )

    created["instance"].set_state.assert_called_once_with(shared_state)
