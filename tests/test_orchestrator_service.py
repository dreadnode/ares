"""Tests for OrchestratorService recovery handling."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from ares.core.models import Credential, Host, SharedRedTeamState, Target
from ares.core.orchestrator_service import OrchestratorService


@pytest.mark.asyncio
async def test_discover_orphaned_operations_filters_and_sorts():
    service = OrchestratorService(redis_url="redis://", namespace="test")
    client = AsyncMock()
    service.task_queue = SimpleNamespace(_client=client)
    service._max_operation_age = 300

    now = datetime.now(timezone.utc)

    async def scan_iter(_pattern):
        keys = [
            b"ares:operation:op_recent:state",
            b"ares:operation:op_less_recent:state",
            b"ares:operation:op_stale:state",
            b"ares:operation:op_locked:state",
            b"ares:operation:op_completed:state",
            b"ares:operation:op_no_checkpoint:state",
        ]
        for key in keys:
            yield key

    client.scan_iter = scan_iter

    def get_side_effect(key):
        key = key.decode() if isinstance(key, bytes) else key
        if key.endswith(":checkpoint_time"):
            op_id = key.split(":")[2]
            if op_id == "op_recent":
                return (now - timedelta(seconds=10)).isoformat().encode()
            if op_id == "op_less_recent":
                return (now - timedelta(seconds=20)).isoformat().encode()
            if op_id == "op_stale":
                return (now - timedelta(seconds=600)).isoformat().encode()
            if op_id == "op_locked":
                return (now - timedelta(seconds=30)).isoformat().encode()
            if op_id == "op_completed":
                return (now - timedelta(seconds=40)).isoformat().encode()
            if op_id == "op_no_checkpoint":
                return None
        if key.endswith(":status"):
            op_id = key.split(":")[2]
            if op_id == "op_completed":
                return json.dumps({"status": "completed"}).encode()
        return None

    client.get = AsyncMock(side_effect=get_side_effect)

    def exists_side_effect(key):
        key = key.decode() if isinstance(key, bytes) else key
        return 1 if key == "ares:lock:op_locked" else 0

    client.exists = AsyncMock(side_effect=exists_side_effect)

    result = await service._discover_orphaned_operations()

    assert result == ["op_recent", "op_less_recent"]


@pytest.mark.asyncio
async def test_recover_orphaned_operation_runs_and_publishes_status():
    service = OrchestratorService(redis_url="redis://", namespace="test")
    service._publish_operation_status = AsyncMock()

    state = SharedRedTeamState(
        operation_id="op-123",
        target=Target(ip="192.168.58.1", domain="contoso.local"),
    )
    state.all_hosts.append(Host(ip="192.168.58.1", hostname="dc01"))
    state.all_credentials.append(
        Credential(
            username="danj",
            password="hunter2",  # pragma: allowlist secret
            domain="contoso.local",
        )
    )

    recovery_manager = AsyncMock()
    recovery_manager.start = AsyncMock()
    recovery_manager.stop = AsyncMock()
    recovery_manager.recover_operation = AsyncMock(return_value=state)

    with (
        patch(
            "ares.core.orchestrator_service.OperationRecoveryManager",
            return_value=recovery_manager,
        ),
        patch(
            "ares.core.orchestrator_service.run_multi_agent_operation",
            new=AsyncMock(return_value={"ok": True}),
        ) as mock_run,
    ):
        await service._recover_orphaned_operation("op-123")

    mock_run.assert_awaited_once()
    _, kwargs = mock_run.call_args
    assert kwargs["target_domain"] == "contoso.local"
    assert kwargs["target_ips"] == ["192.168.58.1"]
    assert kwargs["resume_from_checkpoint"] is True
    assert kwargs["initial_credential"].username == "danj"

    calls = service._publish_operation_status.await_args_list
    assert len(calls) == 2
    assert calls[0].args[0] == "op-123"
    assert calls[0].args[1] == "running"
    assert calls[0].args[2]["recovered"] is True
    assert calls[1].args[0] == "op-123"
    assert calls[1].args[1] == "completed"
    assert calls[1].args[2]["recovered"] is True


@pytest.mark.asyncio
async def test_recover_orphaned_operation_publishes_failed_on_error():
    service = OrchestratorService(redis_url="redis://", namespace="test")
    service._publish_operation_status = AsyncMock()

    recovery_manager = AsyncMock()
    recovery_manager.start = AsyncMock()
    recovery_manager.stop = AsyncMock()
    recovery_manager.recover_operation = AsyncMock(side_effect=RuntimeError("boom"))

    with (
        patch(
            "ares.core.orchestrator_service.OperationRecoveryManager",
            return_value=recovery_manager,
        ),
        patch(
            "ares.core.orchestrator_service.run_multi_agent_operation",
            new=AsyncMock(),
        ),
    ):
        await service._recover_orphaned_operation("op-err")

    calls = service._publish_operation_status.await_args_list
    assert calls[0].args[0] == "op-err"
    assert calls[0].args[1] == "failed"
    assert calls[0].args[2]["recovered"] is True


@pytest.mark.asyncio
async def test_process_operation_request_sets_env_vars():
    service = OrchestratorService(redis_url="redis://", namespace="test")
    service._publish_operation_status = AsyncMock()

    request_data = {
        "operation_id": "op-env",
        "target_domain": "contoso.local",
        "target_ips": ["192.168.58.1"],
        "model": "test-model",
        "env_vars": {"OPENAI_API_KEY": "test-key", "EMPTY": ""},  # pragma: allowlist secret
    }

    with (
        patch.dict(os.environ, {}, clear=True),
        patch(
            "ares.core.orchestrator_service.run_multi_agent_operation",
            new=AsyncMock(return_value={"ok": True}),
        ) as mock_run,
    ):
        await service._process_operation_request(request_data)
        assert os.environ["OPENAI_API_KEY"] == "test-key"  # pragma: allowlist secret
        assert "EMPTY" not in os.environ
        mock_run.assert_awaited_once()
        _, kwargs = mock_run.call_args
        assert kwargs["model"] == "test-model"


@pytest.mark.asyncio
async def test_process_operation_request_missing_model_publishes_failed():
    service = OrchestratorService(redis_url="redis://", namespace="test")
    service._publish_operation_status = AsyncMock()

    request_data = {
        "operation_id": "op-missing-model",
        "target_domain": "contoso.local",
        "target_ips": ["192.168.58.2"],
    }

    with (
        patch.dict(os.environ, {}, clear=True),
        patch(
            "ares.core.orchestrator_service.run_multi_agent_operation",
            new=AsyncMock(),
        ) as mock_run,
    ):
        await service._process_operation_request(request_data)

    mock_run.assert_not_awaited()
    calls = service._publish_operation_status.await_args_list
    assert calls[-1].args[1] == "failed"
    assert "No model specified" in calls[-1].args[2]["error"]


@pytest.mark.asyncio
async def test_process_operation_request_fetches_env_vars_from_separate_key():
    """Test that env_vars are fetched from separate Redis key when not in request."""
    service = OrchestratorService(redis_url="redis://", namespace="test")
    service._publish_operation_status = AsyncMock()

    # Create a mock task queue with client
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(
        return_value=json.dumps({"OPENAI_API_KEY": "test-key"}).encode()  # pragma: allowlist secret
    )
    mock_client.delete = AsyncMock()
    service.task_queue = SimpleNamespace(_client=mock_client)

    request_data = {
        "operation_id": "op-env-separate",
        "target_domain": "contoso.local",
        "target_ips": ["192.168.58.1"],
        "model": "test-model",
        # Note: no env_vars in request - should be fetched from Redis
    }

    with (
        patch.dict(os.environ, {}, clear=True),
        patch(
            "ares.core.orchestrator_service.run_multi_agent_operation",
            new=AsyncMock(return_value={"ok": True}),
        ),
    ):
        await service._process_operation_request(request_data)
        # Verify env var was set from the separate key
        assert os.environ.get("OPENAI_API_KEY") == "test-key"  # pragma: allowlist secret

    # Verify the separate key was fetched
    mock_client.get.assert_awaited_with("ares:operation:op-env-separate:env_vars")
    # Verify the key was deleted after reading (security)
    mock_client.delete.assert_awaited_with("ares:operation:op-env-separate:env_vars")


@pytest.mark.asyncio
async def test_process_operation_request_uses_inline_env_vars_when_present():
    """Test that inline env_vars in request take precedence (backward compatibility)."""
    service = OrchestratorService(redis_url="redis://", namespace="test")
    service._publish_operation_status = AsyncMock()

    # Create a mock task queue (should not be called for env_vars)
    mock_client = AsyncMock()
    mock_client.get = AsyncMock()
    service.task_queue = SimpleNamespace(_client=mock_client)

    request_data = {
        "operation_id": "op-env-inline",
        "target_domain": "contoso.local",
        "target_ips": ["192.168.58.1"],
        "model": "test-model",
        "env_vars": {"INLINE_KEY": "inline-value"},  # inline takes precedence
    }

    with (
        patch.dict(os.environ, {}, clear=True),
        patch(
            "ares.core.orchestrator_service.run_multi_agent_operation",
            new=AsyncMock(return_value={"ok": True}),
        ),
    ):
        await service._process_operation_request(request_data)
        # Verify inline env var was used
        assert os.environ.get("INLINE_KEY") == "inline-value"

    # Should NOT fetch from separate key when env_vars present in request
    # The get call should not have been made for env_vars key
    for call in mock_client.get.await_args_list:
        assert "env_vars" not in str(call)
