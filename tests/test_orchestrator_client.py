"""Tests for orchestrator client operations."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from ares.core.orchestrator_client import submit_operation


class FakeRedisQueue:
    """Minimal RedisTaskQueue stand-in for submit_operation tests."""

    def __init__(self, _redis_url: str):
        self._client = AsyncMock()
        self._client.rpush = AsyncMock()

    async def connect(self) -> None:
        return None

    async def disconnect(self) -> None:
        return None


@pytest.mark.asyncio
async def test_submit_operation_uses_env_model_and_env_vars(monkeypatch):
    monkeypatch.setenv("ARES_ORCHESTRATOR_MODEL", "orch-model")
    fake_queue = FakeRedisQueue("redis://")

    with patch("ares.core.orchestrator_client.RedisTaskQueue", return_value=fake_queue):
        result = await submit_operation(
            operation_id="op-1",
            target_domain="contoso.local",
            target_ips=["192.168.56.1"],
            model=None,
            env_vars={"OPENAI_API_KEY": "test-key"},  # pragma: allowlist secret
        )

    assert result["status"] == "submitted"
    fake_queue._client.rpush.assert_awaited_once()
    queue_call = fake_queue._client.rpush.call_args
    payload = json.loads(queue_call.args[1])
    assert payload["model"] == "orch-model"
    assert payload["env_vars"] == {"OPENAI_API_KEY": "test-key"}  # pragma: allowlist secret


@pytest.mark.asyncio
async def test_submit_operation_raises_when_model_missing(monkeypatch):
    monkeypatch.delenv("ARES_ORCHESTRATOR_MODEL", raising=False)
    monkeypatch.delenv("ARES_MODEL", raising=False)

    with pytest.raises(ValueError, match="No model specified"):
        await submit_operation(
            operation_id="op-2",
            target_domain="contoso.local",
            target_ips=["192.168.56.2"],
            model=None,
        )
