"""Tests for OrchestratorService recovery handling."""

from __future__ import annotations

import asyncio
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

    # Use redis-native format: ares:op:*:meta
    async def scan_iter(_pattern):
        keys = [
            b"ares:op:op_recent:meta",
            b"ares:op:op_less_recent:meta",
            b"ares:op:op_stale:meta",
            b"ares:op:op_locked:meta",
            b"ares:op:op_completed:meta",
            b"ares:op:op_no_checkpoint:meta",
        ]
        for key in keys:
            yield key

    client.scan_iter = scan_iter

    # Mock hget for started_at from meta hash
    def hget_side_effect(key, field):
        key = key.decode() if isinstance(key, bytes) else key
        if field == "started_at" and key.startswith("ares:op:"):
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
        return None

    client.hget = AsyncMock(side_effect=hget_side_effect)

    def get_side_effect(key):
        key = key.decode() if isinstance(key, bytes) else key
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
    recovery_manager.recover_operation = AsyncMock(return_value=(state, []))

    with (
        patch(
            "ares.core.orchestrator_service.OperationRecoveryManager",
            return_value=recovery_manager,
        ),
        patch(
            "ares.core.orchestrator_service.run_multi_agent_operation",
            new=AsyncMock(return_value={"ok": True}),
        ) as mock_run,
        patch.dict(os.environ, {"ARES_MODEL": "test-model"}),
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
    mock_client.get.assert_awaited_with("ares:op:op-env-separate:env_vars")
    # Verify the key was deleted after reading (security)
    mock_client.delete.assert_awaited_with("ares:op:op-env-separate:env_vars")


@pytest.mark.asyncio
async def test_process_operation_request_uses_inline_env_vars_when_present():
    """Test that inline env_vars in request take precedence."""
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


@pytest.mark.asyncio
async def test_process_operation_request_persists_worker_credentials():
    """Test that worker credentials are persisted during operation processing."""
    service = OrchestratorService(redis_url="redis://", namespace="test")
    service._publish_operation_status = AsyncMock()
    service._persist_worker_credentials = AsyncMock()

    # Create a mock task queue with client
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=None)
    mock_client.set = AsyncMock()
    service.task_queue = SimpleNamespace(_client=mock_client)

    request_data = {
        "operation_id": "op-cred-persist",
        "target_domain": "contoso.local",
        "target_ips": ["192.168.58.1"],
        "model": "test-model",
        "env_vars": {
            "OPENAI_API_KEY": "sk-test",  # pragma: allowlist secret
            "DREADNODE_API_KEY": "dn-test",  # pragma: allowlist secret
        },
    }

    with (
        patch.dict(os.environ, {}, clear=True),
        patch(
            "ares.core.orchestrator_service.run_multi_agent_operation",
            new=AsyncMock(return_value={"ok": True}),
        ),
    ):
        await service._process_operation_request(request_data)

    # Verify worker credentials were persisted
    service._persist_worker_credentials.assert_awaited_once()
    call_args = service._persist_worker_credentials.call_args
    assert call_args[0][0] == "op-cred-persist"
    assert call_args[0][1]["OPENAI_API_KEY"] == "sk-test"  # pragma: allowlist secret


@pytest.mark.asyncio
async def test_process_operation_request_wraps_with_logging_context():
    """Test that operation processing is wrapped with logging context."""
    service = OrchestratorService(redis_url="redis://", namespace="test")
    service._publish_operation_status = AsyncMock()

    request_data = {
        "operation_id": "op-logging-test",
        "target_domain": "contoso.local",
        "target_ips": ["192.168.58.1"],
        "model": "test-model",
    }

    # Track if _process_operation_request_inner is called
    inner_called = False
    original_inner = service._process_operation_request_inner

    async def track_inner(request_data):
        nonlocal inner_called
        inner_called = True
        await original_inner(request_data)

    service._process_operation_request_inner = track_inner

    with (
        patch.dict(os.environ, {}, clear=True),
        patch(
            "ares.core.orchestrator_service.run_multi_agent_operation",
            new=AsyncMock(return_value={"ok": True}),
        ),
    ):
        await service._process_operation_request(request_data)

    # Inner method should have been called (via contextualize wrapper)
    assert inner_called


@pytest.mark.asyncio
async def test_process_operation_request_timeout_publishes_failed():
    """Test that operation timeout publishes failed status and continues."""
    service = OrchestratorService(redis_url="redis://", namespace="test")
    service._publish_operation_status = AsyncMock()

    request_data = {
        "operation_id": "op-timeout-test",
        "target_domain": "contoso.local",
        "target_ips": ["192.168.58.1"],
        "model": "test-model",
        "env_vars": {"OPENAI_API_KEY": "test-key"},  # pragma: allowlist secret
    }

    async def hang_forever(*args, **kwargs):
        """Simulate a hanging operation."""
        await asyncio.sleep(3600)  # 1 hour - will be cancelled by timeout

    with (
        patch.dict(os.environ, {}, clear=True),
        patch(
            "ares.core.orchestrator_service.run_multi_agent_operation",
            new=hang_forever,
        ),
        patch(
            "ares.core.orchestrator_service.get_operation_timeout",
            return_value=1,  # 1 second timeout for test
        ),
    ):
        # Should complete without hanging (timeout triggers)
        await service._process_operation_request(request_data)

    # Verify failed status was published with timeout error
    calls = service._publish_operation_status.await_args_list
    # First call is "running", second should be "failed" due to timeout
    assert len(calls) == 2
    assert calls[0].args[1] == "running"
    assert calls[1].args[1] == "failed"
    assert "timeout" in calls[1].args[2]["error"].lower()


@pytest.mark.asyncio
async def test_recover_orphaned_operation_timeout_publishes_failed():
    """Test that recovered operation timeout publishes failed status."""
    service = OrchestratorService(redis_url="redis://", namespace="test")
    service._publish_operation_status = AsyncMock()

    state = SharedRedTeamState(
        operation_id="op-recover-timeout",
        target=Target(ip="192.168.58.1", domain="contoso.local"),
    )
    state.all_hosts.append(Host(ip="192.168.58.1", hostname="dc01"))
    state.all_credentials.append(
        Credential(
            username="testuser",
            password="P@ssw0rd!",  # pragma: allowlist secret
            domain="contoso.local",
        )
    )

    recovery_manager = AsyncMock()
    recovery_manager.start = AsyncMock()
    recovery_manager.stop = AsyncMock()
    recovery_manager.recover_operation = AsyncMock(return_value=(state, []))

    async def hang_forever(*args, **kwargs):
        """Simulate a hanging operation."""
        await asyncio.sleep(3600)

    with (
        patch(
            "ares.core.orchestrator_service.OperationRecoveryManager",
            return_value=recovery_manager,
        ),
        patch(
            "ares.core.orchestrator_service.run_multi_agent_operation",
            new=hang_forever,
        ),
        patch(
            "ares.core.orchestrator_service.get_operation_timeout",
            return_value=1,  # 1 second timeout for test
        ),
        patch.dict(os.environ, {"ARES_MODEL": "test-model"}),
    ):
        await service._recover_orphaned_operation("op-recover-timeout")

    # Verify failed status was published with timeout error and recovered flag
    calls = service._publish_operation_status.await_args_list
    assert len(calls) == 2
    assert calls[0].args[1] == "running"
    assert calls[1].args[1] == "failed"
    assert "timeout" in calls[1].args[2]["error"].lower()
    assert calls[1].args[2]["recovered"] is True
