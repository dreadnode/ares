"""Tests for blue_orchestrator_client."""

from __future__ import annotations

import json
import os
from unittest.mock import AsyncMock, patch

import pytest

from ares.core.blue_orchestrator_client import (
    get_investigation_status,
    submit_investigation,
    wait_for_investigation_completion,
)


@pytest.mark.asyncio
async def test_submit_investigation_basic():
    """Test basic investigation submission."""
    mock_queue = AsyncMock()
    mock_queue.connect = AsyncMock()
    mock_queue.disconnect = AsyncMock()
    mock_queue._client = AsyncMock()
    mock_queue._client.rpush = AsyncMock()
    mock_queue._client.set = AsyncMock()
    mock_queue._client.expire = AsyncMock()

    alert = {"labels": {"alertname": "TestAlert", "severity": "low"}}

    with (
        patch("ares.core.blue_orchestrator_client.RedisTaskQueue", return_value=mock_queue),
        patch("ares.core.blue_orchestrator_client.get_redis_url", return_value="redis://"),
        patch.dict(os.environ, {"ARES_MODEL": "test-model"}),
    ):
        result = await submit_investigation(
            alert=alert,
            investigation_id="inv-test",
        )

    assert result["investigation_id"] == "inv-test"
    assert result["status"] == "submitted"
    mock_queue._client.rpush.assert_awaited_once()

    # Verify the request data
    call_args = mock_queue._client.rpush.call_args
    assert call_args[0][0] == "ares:blue:investigations"
    request_data = json.loads(call_args[0][1])
    assert request_data["investigation_id"] == "inv-test"
    assert request_data["alert"] == alert
    assert request_data["model"] == "test-model"


@pytest.mark.asyncio
async def test_submit_investigation_with_env_vars():
    """Test that env_vars are stored separately."""
    mock_queue = AsyncMock()
    mock_queue.connect = AsyncMock()
    mock_queue.disconnect = AsyncMock()
    mock_queue._client = AsyncMock()
    mock_queue._client.rpush = AsyncMock()
    mock_queue._client.set = AsyncMock()
    mock_queue._client.expire = AsyncMock()

    alert = {"labels": {"alertname": "TestAlert"}}
    env_vars = {"OPENAI_API_KEY": "secret-key"}  # pragma: allowlist secret

    with (
        patch("ares.core.blue_orchestrator_client.RedisTaskQueue", return_value=mock_queue),
        patch("ares.core.blue_orchestrator_client.get_redis_url", return_value="redis://"),
        patch.dict(os.environ, {"ARES_MODEL": "test-model"}),
    ):
        await submit_investigation(
            alert=alert,
            investigation_id="inv-env",
            env_vars=env_vars,
        )

    # Verify env_vars stored separately
    mock_queue._client.set.assert_awaited_once()
    set_call = mock_queue._client.set.call_args
    assert set_call[0][0] == "ares:blue:inv:inv-env:env_vars"
    assert json.loads(set_call[0][1]) == env_vars

    # Verify TTL set
    mock_queue._client.expire.assert_awaited_once_with("ares:blue:inv:inv-env:env_vars", 3600)

    # Verify env_vars NOT in the queue request
    rpush_call = mock_queue._client.rpush.call_args
    request_data = json.loads(rpush_call[0][1])
    assert "env_vars" not in request_data


@pytest.mark.asyncio
async def test_submit_investigation_missing_model():
    """Test that missing model raises ValueError."""
    alert = {"labels": {"alertname": "TestAlert"}}

    with (
        patch("ares.core.blue_orchestrator_client.get_redis_url", return_value="redis://"),
        patch.dict(os.environ, {}, clear=True),
        pytest.raises(ValueError, match="No model specified"),
    ):
        await submit_investigation(alert=alert, investigation_id="inv-no-model")


@pytest.mark.asyncio
async def test_submit_investigation_auto_generates_id():
    """Test that investigation_id is auto-generated if not provided."""
    mock_queue = AsyncMock()
    mock_queue.connect = AsyncMock()
    mock_queue.disconnect = AsyncMock()
    mock_queue._client = AsyncMock()
    mock_queue._client.rpush = AsyncMock()

    alert = {"labels": {"alertname": "TestAlert"}}

    with (
        patch("ares.core.blue_orchestrator_client.RedisTaskQueue", return_value=mock_queue),
        patch("ares.core.blue_orchestrator_client.get_redis_url", return_value="redis://"),
        patch.dict(os.environ, {"ARES_MODEL": "test-model"}),
    ):
        result = await submit_investigation(alert=alert)

    assert result["investigation_id"].startswith("inv-")
    assert len(result["investigation_id"]) == 12  # "inv-" + 8 hex chars


@pytest.mark.asyncio
async def test_submit_investigation_with_all_options():
    """Test submission with all options specified."""
    mock_queue = AsyncMock()
    mock_queue.connect = AsyncMock()
    mock_queue.disconnect = AsyncMock()
    mock_queue._client = AsyncMock()
    mock_queue._client.rpush = AsyncMock()

    alert = {"labels": {"alertname": "TestAlert", "severity": "critical"}}

    with (
        patch("ares.core.blue_orchestrator_client.RedisTaskQueue", return_value=mock_queue),
        patch("ares.core.blue_orchestrator_client.get_redis_url", return_value="redis://"),
    ):
        result = await submit_investigation(
            alert=alert,
            investigation_id="inv-full",
            correlation_context={"related_alerts": ["alert-1"]},
            model="gpt-4.1",
            max_steps=100,
            multi_agent=True,
            auto_route=False,
            report_dir="/reports",
            grafana_url="http://grafana:3000",
            grafana_api_key="grafana-key",  # pragma: allowlist secret
        )

    assert result["investigation_id"] == "inv-full"

    rpush_call = mock_queue._client.rpush.call_args
    request_data = json.loads(rpush_call[0][1])
    assert request_data["model"] == "gpt-4.1"
    assert request_data["max_steps"] == 100
    assert request_data["multi_agent"] is True
    assert request_data["auto_route"] is False
    assert request_data["correlation_context"] == {"related_alerts": ["alert-1"]}


@pytest.mark.asyncio
async def test_wait_for_investigation_completion():
    """Test waiting for investigation completion."""
    mock_queue = AsyncMock()
    mock_queue.connect = AsyncMock()
    mock_queue.disconnect = AsyncMock()
    mock_queue.redis = AsyncMock()
    mock_queue.redis.get = AsyncMock(
        return_value=json.dumps(
            {
                "status": "completed",
                "completed_at": "2026-02-23T12:00:00Z",
            }
        ).encode()
    )

    with patch("ares.core.blue_orchestrator_client.RedisTaskQueue", return_value=mock_queue):
        result = await wait_for_investigation_completion(
            investigation_id="inv-wait",
            redis_url="redis://",
            poll_interval=0.01,
        )

    assert result["status"] == "completed"
    mock_queue.redis.get.assert_awaited_with("ares:blue:inv:inv-wait:status")


@pytest.mark.asyncio
async def test_wait_for_investigation_completion_polls_until_done():
    """Test that waiting polls until investigation completes."""
    mock_queue = AsyncMock()
    mock_queue.connect = AsyncMock()
    mock_queue.disconnect = AsyncMock()
    mock_queue.redis = AsyncMock()

    # Return running twice, then completed
    mock_queue.redis.get = AsyncMock(
        side_effect=[
            json.dumps({"status": "running"}).encode(),
            json.dumps({"status": "running"}).encode(),
            json.dumps({"status": "completed", "completed_at": "2026-02-23T12:00:00Z"}).encode(),
        ]
    )

    with patch("ares.core.blue_orchestrator_client.RedisTaskQueue", return_value=mock_queue):
        result = await wait_for_investigation_completion(
            investigation_id="inv-poll",
            redis_url="redis://",
            poll_interval=0.01,
        )

    assert result["status"] == "completed"
    assert mock_queue.redis.get.await_count == 3


@pytest.mark.asyncio
async def test_wait_for_investigation_completion_timeout():
    """Test that waiting times out."""
    mock_queue = AsyncMock()
    mock_queue.connect = AsyncMock()
    mock_queue.disconnect = AsyncMock()
    mock_queue.redis = AsyncMock()
    mock_queue.redis.get = AsyncMock(return_value=json.dumps({"status": "running"}).encode())

    with (
        patch("ares.core.blue_orchestrator_client.RedisTaskQueue", return_value=mock_queue),
        pytest.raises(TimeoutError, match="did not complete"),
    ):
        await wait_for_investigation_completion(
            investigation_id="inv-timeout",
            redis_url="redis://",
            poll_interval=0.01,
            timeout=0.05,
        )


@pytest.mark.asyncio
async def test_get_investigation_status_found():
    """Test getting investigation status when found."""
    mock_queue = AsyncMock()
    mock_queue.connect = AsyncMock()
    mock_queue.disconnect = AsyncMock()
    mock_queue._client = AsyncMock()
    mock_queue.redis = AsyncMock()
    mock_queue.redis.get = AsyncMock(
        return_value=json.dumps(
            {
                "status": "completed",
                "evidence_count": 5,
            }
        ).encode()
    )

    with (
        patch("ares.core.blue_orchestrator_client.RedisTaskQueue", return_value=mock_queue),
        patch("ares.core.blue_orchestrator_client.get_redis_url", return_value="redis://"),
    ):
        result = await get_investigation_status("inv-found")

    assert result is not None
    assert result["status"] == "completed"
    assert result["evidence_count"] == 5


@pytest.mark.asyncio
async def test_get_investigation_status_not_found():
    """Test getting investigation status when not found."""
    mock_queue = AsyncMock()
    mock_queue.connect = AsyncMock()
    mock_queue.disconnect = AsyncMock()
    mock_queue._client = AsyncMock()
    mock_queue.redis = AsyncMock()
    mock_queue.redis.get = AsyncMock(return_value=None)

    with (
        patch("ares.core.blue_orchestrator_client.RedisTaskQueue", return_value=mock_queue),
        patch("ares.core.blue_orchestrator_client.get_redis_url", return_value="redis://"),
    ):
        result = await get_investigation_status("inv-not-found")

    assert result is None
