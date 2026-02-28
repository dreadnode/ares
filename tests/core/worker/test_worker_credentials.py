"""Tests for worker credential persistence and retrieval.

Tests the flow of credentials from orchestrator to workers via Redis.
"""

from __future__ import annotations

import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestGetWorkerCredentials:
    """Tests for get_worker_credentials function."""

    @pytest.fixture
    def mock_redis_setup(self):
        """Create mock Redis setup."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=None)
        mock_client.aclose = AsyncMock()

        mock_redis_async = MagicMock()
        mock_redis_async.from_url = MagicMock(return_value=mock_client)

        mock_redis = MagicMock()
        mock_redis.asyncio = mock_redis_async

        return mock_client, patch.dict(
            sys.modules, {"redis": mock_redis, "redis.asyncio": mock_redis_async}
        )

    @pytest.mark.asyncio
    async def test_returns_credentials_when_present(self, mock_redis_setup):
        """Test that credentials are returned when they exist in Redis."""
        from ares.core.worker.operations import get_worker_credentials

        mock_client, redis_patch = mock_redis_setup
        credentials = {
            "OPENAI_API_KEY": "sk-test-key",  # pragma: allowlist secret
            "DREADNODE_API_KEY": "dn-test-key",  # pragma: allowlist secret
        }
        mock_client.get = AsyncMock(return_value=json.dumps(credentials))

        with redis_patch:
            result = await get_worker_credentials("redis://localhost:6379", "op-123")

        assert result == credentials
        mock_client.get.assert_awaited_with("ares:op:op-123:worker_credentials")

    @pytest.mark.asyncio
    async def test_returns_none_when_no_credentials(self, mock_redis_setup):
        """Test that None is returned when no credentials exist."""
        from ares.core.worker.operations import get_worker_credentials

        mock_client, redis_patch = mock_redis_setup
        mock_client.get = AsyncMock(return_value=None)

        with redis_patch:
            result = await get_worker_credentials("redis://localhost:6379", "op-456")

        assert result is None

    @pytest.mark.asyncio
    async def test_filters_empty_values(self, mock_redis_setup):
        """Test that empty credential values are filtered out."""
        from ares.core.worker.operations import get_worker_credentials

        mock_client, redis_patch = mock_redis_setup
        credentials = {
            "OPENAI_API_KEY": "sk-valid-key",  # pragma: allowlist secret
            "EMPTY_KEY": "",
            "NULL_KEY": None,
        }
        mock_client.get = AsyncMock(return_value=json.dumps(credentials))

        with redis_patch:
            result = await get_worker_credentials("redis://localhost:6379", "op-789")

        assert result == {"OPENAI_API_KEY": "sk-valid-key"}  # pragma: allowlist secret

    @pytest.mark.asyncio
    async def test_handles_invalid_json(self, mock_redis_setup):
        """Test graceful handling of invalid JSON."""
        from ares.core.worker.operations import get_worker_credentials

        mock_client, redis_patch = mock_redis_setup
        mock_client.get = AsyncMock(return_value="not valid json")

        with redis_patch:
            result = await get_worker_credentials("redis://localhost:6379", "op-bad")

        assert result is None

    @pytest.mark.asyncio
    async def test_handles_redis_error(self, mock_redis_setup):
        """Test graceful handling of Redis errors."""
        from ares.core.worker.operations import get_worker_credentials

        mock_client, redis_patch = mock_redis_setup
        mock_client.get = AsyncMock(side_effect=ConnectionError("Redis down"))

        with redis_patch:
            result = await get_worker_credentials("redis://localhost:6379", "op-err")

        assert result is None

    @pytest.mark.asyncio
    async def test_handles_non_dict_payload(self, mock_redis_setup):
        """Test handling of unexpected payload type."""
        from ares.core.worker.operations import get_worker_credentials

        mock_client, redis_patch = mock_redis_setup
        mock_client.get = AsyncMock(return_value=json.dumps(["list", "instead"]))

        with redis_patch:
            result = await get_worker_credentials("redis://localhost:6379", "op-list")

        assert result is None

    @pytest.mark.asyncio
    async def test_closes_client_on_success(self, mock_redis_setup):
        """Test that Redis client is closed after successful read."""
        from ares.core.worker.operations import get_worker_credentials

        mock_client, redis_patch = mock_redis_setup
        mock_client.get = AsyncMock(return_value=json.dumps({"KEY": "value"}))

        with redis_patch:
            await get_worker_credentials("redis://localhost:6379", "op-close")

        mock_client.aclose.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_closes_client_on_error(self, mock_redis_setup):
        """Test that Redis client is closed even on error."""
        from ares.core.worker.operations import get_worker_credentials

        mock_client, redis_patch = mock_redis_setup
        mock_client.get = AsyncMock(side_effect=ConnectionError("Redis down"))

        with redis_patch:
            await get_worker_credentials("redis://localhost:6379", "op-err")

        mock_client.aclose.assert_awaited_once()


class TestPersistWorkerCredentials:
    """Tests for _persist_worker_credentials in OrchestratorService."""

    @pytest.mark.asyncio
    async def test_persists_api_credentials(self):
        """Test that API credentials are persisted to Redis."""
        from ares.core.orchestrator_service import OrchestratorService

        service = OrchestratorService(redis_url="redis://", namespace="test")
        mock_client = AsyncMock()
        mock_client.set = AsyncMock()
        service.task_queue = SimpleNamespace(_client=mock_client)

        env_vars = {
            "OPENAI_API_KEY": "sk-test",  # pragma: allowlist secret
            "DREADNODE_API_KEY": "dn-test",  # pragma: allowlist secret
            "ANTHROPIC_API_KEY": "ant-test",  # pragma: allowlist secret
            "OTHER_VAR": "should-be-ignored",
        }

        await service._persist_worker_credentials("op-123", env_vars)

        mock_client.set.assert_awaited_once()
        call_args = mock_client.set.call_args
        assert call_args[0][0] == "ares:op:op-123:worker_credentials"

        persisted = json.loads(call_args[0][1])
        assert persisted == {
            "OPENAI_API_KEY": "sk-test",  # pragma: allowlist secret
            "DREADNODE_API_KEY": "dn-test",  # pragma: allowlist secret
            "ANTHROPIC_API_KEY": "ant-test",  # pragma: allowlist secret
        }

    @pytest.mark.asyncio
    async def test_skips_empty_env_vars(self):
        """Test that empty env_vars dict is skipped."""
        from ares.core.orchestrator_service import OrchestratorService

        service = OrchestratorService(redis_url="redis://", namespace="test")
        mock_client = AsyncMock()
        mock_client.set = AsyncMock()
        service.task_queue = SimpleNamespace(_client=mock_client)

        await service._persist_worker_credentials("op-123", {})

        mock_client.set.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skips_none_env_vars(self):
        """Test that None env_vars is skipped."""
        from ares.core.orchestrator_service import OrchestratorService

        service = OrchestratorService(redis_url="redis://", namespace="test")
        mock_client = AsyncMock()
        mock_client.set = AsyncMock()
        service.task_queue = SimpleNamespace(_client=mock_client)

        await service._persist_worker_credentials("op-123", None)

        mock_client.set.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skips_when_no_task_queue(self):
        """Test that persist is skipped when task_queue is unavailable."""
        from ares.core.orchestrator_service import OrchestratorService

        service = OrchestratorService(redis_url="redis://", namespace="test")
        service.task_queue = None

        # Should not raise
        await service._persist_worker_credentials(
            "op-123",
            {"OPENAI_API_KEY": "test"},  # pragma: allowlist secret
        )

    @pytest.mark.asyncio
    async def test_skips_when_no_client(self):
        """Test that persist is skipped when client is unavailable."""
        from ares.core.orchestrator_service import OrchestratorService

        service = OrchestratorService(redis_url="redis://", namespace="test")
        service.task_queue = SimpleNamespace(_client=None)

        # Should not raise
        await service._persist_worker_credentials(
            "op-123",
            {"OPENAI_API_KEY": "test"},  # pragma: allowlist secret
        )

    @pytest.mark.asyncio
    async def test_skips_when_no_matching_credentials(self):
        """Test that persist is skipped when no API keys are present."""
        from ares.core.orchestrator_service import OrchestratorService

        service = OrchestratorService(redis_url="redis://", namespace="test")
        mock_client = AsyncMock()
        mock_client.set = AsyncMock()
        service.task_queue = SimpleNamespace(_client=mock_client)

        env_vars = {
            "SOME_OTHER_VAR": "value",
            "ANOTHER_VAR": "another",
        }

        await service._persist_worker_credentials("op-123", env_vars)

        mock_client.set.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_handles_redis_error_gracefully(self):
        """Test that Redis errors are logged but don't crash."""
        from ares.core.orchestrator_service import OrchestratorService

        service = OrchestratorService(redis_url="redis://", namespace="test")
        mock_client = AsyncMock()
        mock_client.set = AsyncMock(side_effect=ConnectionError("Redis down"))
        service.task_queue = SimpleNamespace(_client=mock_client)

        # Should not raise
        await service._persist_worker_credentials(
            "op-123",
            {"OPENAI_API_KEY": "test"},  # pragma: allowlist secret
        )


class TestRunWorkerCredentialLoading:
    """Tests for credential loading in run_worker."""

    @pytest.mark.asyncio
    async def test_loads_credentials_from_redis(self, monkeypatch):
        """Test that run_worker loads credentials from Redis."""
        from ares.core.models import AgentRole
        from ares.core.worker import _worker as worker_module
        from ares.core.worker import run_worker

        # Clear existing env vars
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("ARES_MODEL", "test-model")

        credentials = {
            "OPENAI_API_KEY": "sk-from-redis",  # pragma: allowlist secret
        }

        # Mock all the dependencies
        monkeypatch.setattr(
            worker_module,
            "get_worker_credentials",
            AsyncMock(return_value=credentials),
        )
        monkeypatch.setattr(
            worker_module,
            "get_operation_model_overrides",
            AsyncMock(return_value=None),
        )
        monkeypatch.setattr(
            worker_module,
            "get_operation_model",
            AsyncMock(return_value=None),
        )

        shared_state = MagicMock()
        dispatcher = MagicMock(shared_state=shared_state)
        dispatcher.start = AsyncMock()
        dispatcher.recover_state = AsyncMock(return_value=None)
        dispatcher.register = AsyncMock()
        dispatcher.stop = AsyncMock()

        agent_info = MagicMock()
        agent_info.name = "test-agent"

        monkeypatch.setattr(worker_module, "RedTeamDispatcher", lambda **_kwargs: dispatcher)
        monkeypatch.setattr(
            worker_module, "create_agent_info", lambda *_args, **_kwargs: agent_info
        )
        monkeypatch.setattr(worker_module, "create_specialized_agent", MagicMock())

        worker_instance = MagicMock()
        worker_instance.start = AsyncMock()
        monkeypatch.setattr(worker_module, "WorkerAgent", MagicMock(return_value=worker_instance))

        await run_worker(
            role=AgentRole.RECON,
            operation_id="op-cred-test",
            discover_operation=False,
            use_redis_queue=False,
        )

        # Verify credential was set in environment
        assert os.environ.get("OPENAI_API_KEY") == "sk-from-redis"  # pragma: allowlist secret

        # Clean up
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    @pytest.mark.asyncio
    async def test_does_not_override_existing_env_var(self, monkeypatch):
        """Test that existing env vars are not overridden."""
        from ares.core.models import AgentRole
        from ares.core.worker import _worker as worker_module
        from ares.core.worker import run_worker

        # Set existing env var (e.g., from mounted secret)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-existing")  # pragma: allowlist secret
        monkeypatch.setenv("ARES_MODEL", "test-model")

        credentials = {
            "OPENAI_API_KEY": "sk-from-redis",  # pragma: allowlist secret
        }

        monkeypatch.setattr(
            worker_module,
            "get_worker_credentials",
            AsyncMock(return_value=credentials),
        )
        monkeypatch.setattr(
            worker_module,
            "get_operation_model_overrides",
            AsyncMock(return_value=None),
        )
        monkeypatch.setattr(
            worker_module,
            "get_operation_model",
            AsyncMock(return_value=None),
        )

        shared_state = MagicMock()
        dispatcher = MagicMock(shared_state=shared_state)
        dispatcher.start = AsyncMock()
        dispatcher.recover_state = AsyncMock(return_value=None)
        dispatcher.register = AsyncMock()
        dispatcher.stop = AsyncMock()

        agent_info = MagicMock()
        agent_info.name = "test-agent"

        monkeypatch.setattr(worker_module, "RedTeamDispatcher", lambda **_kwargs: dispatcher)
        monkeypatch.setattr(
            worker_module, "create_agent_info", lambda *_args, **_kwargs: agent_info
        )
        monkeypatch.setattr(worker_module, "create_specialized_agent", MagicMock())

        worker_instance = MagicMock()
        worker_instance.start = AsyncMock()
        monkeypatch.setattr(worker_module, "WorkerAgent", MagicMock(return_value=worker_instance))

        await run_worker(
            role=AgentRole.RECON,
            operation_id="op-no-override",
            discover_operation=False,
            use_redis_queue=False,
        )

        # Existing value should be preserved
        assert os.environ.get("OPENAI_API_KEY") == "sk-existing"  # pragma: allowlist secret


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
