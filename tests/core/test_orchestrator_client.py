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
        self._client.set = AsyncMock()
        self._client.expire = AsyncMock()

    async def connect(self) -> None:
        return None

    async def disconnect(self) -> None:
        return None


@pytest.mark.asyncio
async def test_submit_operation_uses_env_model_and_env_vars(monkeypatch):
    """Test that env_vars are stored separately from the main request payload."""
    monkeypatch.setenv("ARES_ORCHESTRATOR_MODEL", "orch-model")
    fake_queue = FakeRedisQueue("redis://")

    with patch("ares.core.orchestrator_client.RedisTaskQueue", return_value=fake_queue):
        result = await submit_operation(
            operation_id="op-1",
            target_domain="contoso.local",
            target_ips=["192.168.58.1"],
            model=None,
            env_vars={"OPENAI_API_KEY": "test-key"},  # pragma: allowlist secret
        )

    assert result["status"] == "submitted"
    fake_queue._client.rpush.assert_awaited_once()
    queue_call = fake_queue._client.rpush.call_args
    payload = json.loads(queue_call.args[1])
    assert payload["model"] == "orch-model"
    # env_vars should NOT be in the main payload (stored separately for security)
    assert "env_vars" not in payload

    # env_vars should be stored in a separate Redis key
    fake_queue._client.set.assert_awaited_once()
    set_call = fake_queue._client.set.call_args
    assert set_call.args[0] == "ares:operation:op-1:env_vars"
    env_vars_payload = json.loads(set_call.args[1])
    assert env_vars_payload == {"OPENAI_API_KEY": "test-key"}  # pragma: allowlist secret

    # Should set TTL on the env_vars key
    fake_queue._client.expire.assert_awaited_once_with("ares:operation:op-1:env_vars", 3600)


@pytest.mark.asyncio
async def test_submit_operation_no_env_vars_key_when_empty(monkeypatch):
    """Test that no separate key is created when env_vars is empty."""
    monkeypatch.setenv("ARES_ORCHESTRATOR_MODEL", "orch-model")
    fake_queue = FakeRedisQueue("redis://")

    with patch("ares.core.orchestrator_client.RedisTaskQueue", return_value=fake_queue):
        result = await submit_operation(
            operation_id="op-1",
            target_domain="contoso.local",
            target_ips=["192.168.58.1"],
            model=None,
            env_vars=None,
        )

    assert result["status"] == "submitted"
    # Should not store env_vars separately when None
    fake_queue._client.set.assert_not_awaited()
    fake_queue._client.expire.assert_not_awaited()


@pytest.mark.asyncio
async def test_submit_operation_raises_when_model_missing(monkeypatch):
    monkeypatch.delenv("ARES_ORCHESTRATOR_MODEL", raising=False)
    monkeypatch.delenv("ARES_MODEL", raising=False)

    with pytest.raises(ValueError, match="No model specified"):
        await submit_operation(
            operation_id="op-2",
            target_domain="contoso.local",
            target_ips=["192.168.58.2"],
            model=None,
        )
