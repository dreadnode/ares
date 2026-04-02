"""Tests for BlueOrchestratorService."""

from __future__ import annotations

import json
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.blue_orchestrator_service import (
    BlueOrchestratorService,
    InvestigationRequest,
)


class TestInvestigationRequest:
    """Tests for InvestigationRequest dataclass."""

    def test_from_dict_basic(self):
        data = {
            "investigation_id": "inv-12345678",
            "alert": {"labels": {"alertname": "HighCPU", "severity": "warning"}},
        }
        with patch.dict(os.environ, {"ARES_MODEL": "test-model"}):
            request = InvestigationRequest.from_dict(data)

        assert request.investigation_id == "inv-12345678"
        assert request.alert["labels"]["alertname"] == "HighCPU"
        assert request.model == "test-model"
        assert request.max_steps == 25
        assert request.multi_agent is False
        assert request.auto_route is True

    def test_from_dict_with_all_fields(self):
        data = {
            "investigation_id": "inv-full",
            "alert": {"labels": {"alertname": "Test"}},
            "correlation_context": {"related_alerts": []},
            "model": "gpt-4.1",
            "max_steps": 100,
            "multi_agent": True,
            "auto_route": False,
            "report_dir": "/reports",
            "grafana_url": "http://grafana:3000",
            "grafana_api_key": "test-key",  # pragma: allowlist secret
            "env_vars": {"CUSTOM_VAR": "value"},
        }
        request = InvestigationRequest.from_dict(data)

        assert request.investigation_id == "inv-full"
        assert request.model == "gpt-4.1"
        assert request.max_steps == 100
        assert request.multi_agent is True
        assert request.auto_route is False
        assert request.report_dir == "/reports"
        assert request.grafana_url == "http://grafana:3000"
        assert request.grafana_api_key == "test-key"  # pragma: allowlist secret

    def test_from_dict_model_from_env_vars(self):
        data = {
            "investigation_id": "inv-env",
            "alert": {"labels": {}},
            "env_vars": {"ARES_ORCHESTRATOR_MODEL": "env-model"},
        }
        with patch.dict(os.environ, {}, clear=True):
            request = InvestigationRequest.from_dict(data)

        assert request.model == "env-model"

    def test_from_dict_grafana_from_env_vars(self):
        data = {
            "investigation_id": "inv-grafana",
            "alert": {"labels": {}},
            "env_vars": {
                "GRAFANA_URL": "http://env-grafana:3000",
                "GRAFANA_SERVICE_ACCOUNT_TOKEN": "env-token",  # pragma: allowlist secret
            },
        }
        request = InvestigationRequest.from_dict(data)

        assert request.grafana_url == "http://env-grafana:3000"
        assert request.grafana_api_key == "env-token"  # pragma: allowlist secret


class TestBlueOrchestratorService:
    """Tests for BlueOrchestratorService."""

    @pytest.mark.asyncio
    async def test_should_use_multi_agent_forced(self):
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")
        request = InvestigationRequest(
            investigation_id="inv-forced",
            alert={"labels": {"severity": "low"}},
            multi_agent=True,
            auto_route=True,
        )
        assert service._should_use_multi_agent(request) is True

    @pytest.mark.asyncio
    async def test_should_use_multi_agent_critical_severity(self):
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")
        request = InvestigationRequest(
            investigation_id="inv-critical",
            alert={"labels": {"severity": "critical"}},
            multi_agent=False,
            auto_route=True,
        )
        assert service._should_use_multi_agent(request) is True

    @pytest.mark.asyncio
    async def test_should_use_multi_agent_high_severity(self):
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")
        request = InvestigationRequest(
            investigation_id="inv-high",
            alert={"labels": {"severity": "high"}},
            multi_agent=False,
            auto_route=True,
        )
        assert service._should_use_multi_agent(request) is True

    @pytest.mark.asyncio
    async def test_should_use_multi_agent_low_severity(self):
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")
        request = InvestigationRequest(
            investigation_id="inv-low",
            alert={"labels": {"severity": "low"}},
            multi_agent=False,
            auto_route=True,
        )
        assert service._should_use_multi_agent(request) is False

    @pytest.mark.asyncio
    async def test_should_use_multi_agent_auto_route_disabled(self):
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")
        request = InvestigationRequest(
            investigation_id="inv-no-route",
            alert={"labels": {"severity": "critical"}},
            multi_agent=False,
            auto_route=False,
        )
        assert service._should_use_multi_agent(request) is False

    @pytest.mark.asyncio
    async def test_process_investigation_request_sets_env_vars(self):
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")
        service._publish_investigation_status = AsyncMock()
        service._grafana_url = "http://grafana:3000"
        service._grafana_api_key = "test-key"  # pragma: allowlist secret

        request_data = {
            "investigation_id": "inv-env",
            "alert": {"labels": {"alertname": "Test", "severity": "low"}},
            "model": "test-model",
            "env_vars": {"OPENAI_API_KEY": "test-key", "EMPTY": ""},  # pragma: allowlist secret
        }

        mock_orchestrator = MagicMock()
        mock_orchestrator.investigate = AsyncMock(
            return_value={
                "investigation_id": "inv-env",
                "status": "completed",
                "evidence_count": 5,
                "techniques_identified": ["T1003"],
                "highest_pyramid_level": 4,
            }
        )

        with (
            patch.dict(os.environ, {}, clear=True),
            patch(
                "ares.agents.blue.InvestigationOrchestrator",
                return_value=mock_orchestrator,
            ),
            patch("ares.integrations.mitre.MITREAttackClient"),
            patch("ares.core.litellm_env.configure_litellm_env"),
        ):
            await service._process_investigation_request(request_data)
            assert os.environ["OPENAI_API_KEY"] == "test-key"  # pragma: allowlist secret
            assert "EMPTY" not in os.environ
            mock_orchestrator.investigate.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_process_investigation_request_missing_model_publishes_failed(self):
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")
        service._publish_investigation_status = AsyncMock()
        service._grafana_url = "http://grafana:3000"

        request_data = {
            "investigation_id": "inv-missing-model",
            "alert": {"labels": {"alertname": "Test"}},
        }

        with patch.dict(os.environ, {}, clear=True):
            await service._process_investigation_request(request_data)

        calls = service._publish_investigation_status.await_args_list
        assert calls[-1].args[1] == "failed"
        assert "No model specified" in calls[-1].args[2]["error"]

    @pytest.mark.asyncio
    async def test_process_investigation_request_missing_grafana_url_publishes_failed(self):
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")
        service._publish_investigation_status = AsyncMock()
        service._grafana_url = ""  # Empty Grafana URL

        request_data = {
            "investigation_id": "inv-missing-grafana",
            "alert": {"labels": {"alertname": "Test"}},
            "model": "test-model",
        }

        with patch.dict(os.environ, {}, clear=True):
            await service._process_investigation_request(request_data)

        calls = service._publish_investigation_status.await_args_list
        assert calls[-1].args[1] == "failed"
        assert "GRAFANA_URL" in calls[-1].args[2]["error"]

    @pytest.mark.asyncio
    async def test_process_investigation_request_uses_multi_agent_for_critical(self):
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")
        service._publish_investigation_status = AsyncMock()
        service._grafana_url = "http://grafana:3000"
        service._grafana_api_key = "test-key"  # pragma: allowlist secret

        request_data = {
            "investigation_id": "inv-critical",
            "alert": {"labels": {"alertname": "CriticalAlert", "severity": "critical"}},
            "model": "test-model",
            "auto_route": True,
        }

        mock_multi_orchestrator = MagicMock()
        mock_multi_orchestrator.investigate = AsyncMock(
            return_value={
                "investigation_id": "inv-critical",
                "status": "completed",
                "evidence_count": 10,
                "techniques_identified": ["T1003", "T1558"],
                "highest_pyramid_level": 5,
            }
        )

        with (
            patch.dict(os.environ, {}, clear=True),
            patch(
                "ares.agents.blue.BlueTeamOrchestrator",
                return_value=mock_multi_orchestrator,
            ) as mock_blue_team,
            patch("ares.agents.blue.InvestigationOrchestrator") as mock_single,
            patch("ares.integrations.mitre.MITREAttackClient"),
            patch("ares.core.litellm_env.configure_litellm_env"),
        ):
            await service._process_investigation_request(request_data)
            mock_blue_team.assert_called_once()
            mock_single.assert_not_called()
            mock_multi_orchestrator.investigate.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_process_investigation_request_uses_single_agent_for_low(self):
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")
        service._publish_investigation_status = AsyncMock()
        service._grafana_url = "http://grafana:3000"
        service._grafana_api_key = "test-key"  # pragma: allowlist secret

        request_data = {
            "investigation_id": "inv-low",
            "alert": {"labels": {"alertname": "LowAlert", "severity": "low"}},
            "model": "test-model",
            "auto_route": True,
        }

        mock_single_orchestrator = MagicMock()
        mock_single_orchestrator.investigate = AsyncMock(
            return_value={
                "investigation_id": "inv-low",
                "status": "completed",
                "evidence_count": 2,
                "techniques_identified": [],
                "highest_pyramid_level": 2,
            }
        )

        with (
            patch.dict(os.environ, {}, clear=True),
            patch("ares.agents.blue.BlueTeamOrchestrator") as mock_multi,
            patch(
                "ares.agents.blue.InvestigationOrchestrator",
                return_value=mock_single_orchestrator,
            ) as mock_single,
            patch("ares.integrations.mitre.MITREAttackClient"),
            patch("ares.core.litellm_env.configure_litellm_env"),
        ):
            await service._process_investigation_request(request_data)
            mock_single.assert_called_once()
            mock_multi.assert_not_called()
            mock_single_orchestrator.investigate.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_process_investigation_request_fetches_env_vars_from_separate_key(self):
        """Test that env_vars are fetched from separate Redis key when not in request."""
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")
        service._publish_investigation_status = AsyncMock()
        service._grafana_url = "http://grafana:3000"
        service._grafana_api_key = "test-key"  # pragma: allowlist secret

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(
            return_value=json.dumps(
                {"OPENAI_API_KEY": "redis-key"}  # pragma: allowlist secret
            ).encode()
        )
        mock_client.delete = AsyncMock()
        service.task_queue = SimpleNamespace(_client=mock_client)

        request_data = {
            "investigation_id": "inv-env-separate",
            "alert": {"labels": {"alertname": "Test", "severity": "low"}},
            "model": "test-model",
        }

        mock_orchestrator = MagicMock()
        mock_orchestrator.investigate = AsyncMock(
            return_value={
                "investigation_id": "inv-env-separate",
                "status": "completed",
                "evidence_count": 1,
                "techniques_identified": [],
                "highest_pyramid_level": 1,
            }
        )

        with (
            patch.dict(os.environ, {}, clear=True),
            patch(
                "ares.agents.blue.InvestigationOrchestrator",
                return_value=mock_orchestrator,
            ),
            patch("ares.integrations.mitre.MITREAttackClient"),
            patch("ares.core.litellm_env.configure_litellm_env"),
        ):
            await service._process_investigation_request(request_data)
            assert os.environ.get("OPENAI_API_KEY") == "redis-key"  # pragma: allowlist secret

        mock_client.get.assert_awaited_with("ares:blue:inv:inv-env-separate:env_vars")
        mock_client.delete.assert_awaited_with("ares:blue:inv:inv-env-separate:env_vars")

    @pytest.mark.asyncio
    async def test_publish_investigation_status(self):
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")

        mock_client = AsyncMock()
        mock_client.setex = AsyncMock()
        service.task_queue = SimpleNamespace(_client=mock_client)

        await service._publish_investigation_status(
            "inv-status",
            "running",
            {"started_at": "2026-02-23T12:00:00Z"},
        )

        mock_client.setex.assert_awaited_once()
        call_args = mock_client.setex.call_args
        assert call_args[0][0] == "ares:blue:inv:inv-status:status"
        assert call_args[0][1] == 86400

        status_data = json.loads(call_args[0][2])
        assert status_data["status"] == "running"
        assert status_data["started_at"] == "2026-02-23T12:00:00Z"

    @pytest.mark.asyncio
    async def test_pop_investigation_request(self):
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")

        mock_client = AsyncMock()
        mock_client.blpop = AsyncMock(
            return_value=(
                b"ares:blue:investigations",
                json.dumps({"investigation_id": "inv-pop", "alert": {}}).encode(),
            )
        )
        service.task_queue = SimpleNamespace(_client=mock_client)

        result = await service._pop_investigation_request()

        assert result is not None
        assert result["investigation_id"] == "inv-pop"
        mock_client.blpop.assert_awaited_with("ares:blue:investigations", timeout=5)

    @pytest.mark.asyncio
    async def test_pop_investigation_request_empty_queue(self):
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")

        mock_client = AsyncMock()
        mock_client.blpop = AsyncMock(return_value=None)
        service.task_queue = SimpleNamespace(_client=mock_client)

        result = await service._pop_investigation_request()

        assert result is None

    @pytest.mark.asyncio
    async def test_pop_investigation_request_retries_on_timeout(self):
        """Test that _pop_investigation_request retries on asyncio.TimeoutError."""
        import asyncio

        service = BlueOrchestratorService(redis_url="redis://", namespace="test")
        service._force_reconnect = AsyncMock()

        mock_client = AsyncMock()
        # First call times out, second succeeds
        mock_client.blpop = AsyncMock(
            side_effect=[
                asyncio.TimeoutError("Stale connection"),
                (
                    b"ares:blue:investigations",
                    json.dumps({"investigation_id": "inv-retry", "alert": {}}).encode(),
                ),
            ]
        )
        service.task_queue = SimpleNamespace(_client=mock_client)

        result = await service._pop_investigation_request()

        assert result is not None
        assert result["investigation_id"] == "inv-retry"
        service._force_reconnect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_pop_investigation_request_retries_on_connection_error(self):
        """Test that _pop_investigation_request retries on connection errors."""
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")
        service._force_reconnect = AsyncMock()

        mock_client = AsyncMock()
        # First call has connection error, second succeeds
        mock_client.blpop = AsyncMock(
            side_effect=[
                ConnectionError("Connection closed"),
                (
                    b"ares:blue:investigations",
                    json.dumps({"investigation_id": "inv-conn", "alert": {}}).encode(),
                ),
            ]
        )
        service.task_queue = SimpleNamespace(_client=mock_client)

        result = await service._pop_investigation_request()

        assert result is not None
        assert result["investigation_id"] == "inv-conn"
        service._force_reconnect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_pop_investigation_request_returns_none_after_max_retries(self):
        """Test that _pop_investigation_request returns None after exhausting retries."""
        import asyncio

        service = BlueOrchestratorService(redis_url="redis://", namespace="test")
        service._force_reconnect = AsyncMock()

        mock_client = AsyncMock()
        # All calls timeout
        mock_client.blpop = AsyncMock(side_effect=asyncio.TimeoutError("Stale connection"))
        service.task_queue = SimpleNamespace(_client=mock_client)

        result = await service._pop_investigation_request(max_retries=2)

        assert result is None
        # Should have called force_reconnect for each retry
        assert service._force_reconnect.await_count == 3  # initial + 2 retries

    @pytest.mark.asyncio
    async def test_is_connection_alive_returns_true_on_pong(self):
        """Test _is_connection_alive returns True when ping succeeds."""
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")

        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(return_value=True)
        service.task_queue = SimpleNamespace(_client=mock_client)

        result = await service._is_connection_alive()

        assert result is True

    @pytest.mark.asyncio
    async def test_is_connection_alive_returns_false_on_exception(self):
        """Test _is_connection_alive returns False when ping fails."""
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")

        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(side_effect=Exception("Connection lost"))
        service.task_queue = SimpleNamespace(_client=mock_client)

        result = await service._is_connection_alive()

        assert result is False

    @pytest.mark.asyncio
    async def test_publish_status_handles_timeout(self):
        """Test _publish_investigation_status handles timeout gracefully."""
        import asyncio

        service = BlueOrchestratorService(redis_url="redis://", namespace="test")

        mock_client = AsyncMock()
        mock_client.setex = AsyncMock(side_effect=asyncio.TimeoutError("Timeout"))
        service.task_queue = SimpleNamespace(_client=mock_client)

        # Should not raise - just log warning
        await service._publish_investigation_status(
            "inv-timeout",
            "running",
            {"started_at": "2026-02-23T12:00:00Z"},
        )

    @pytest.mark.asyncio
    async def test_force_reconnect_reconnects_both_queues(self):
        """Test _force_reconnect reconnects both task_queue and blue_task_queue."""
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")

        mock_task_queue = MagicMock()
        mock_task_queue.disconnect = AsyncMock()
        mock_task_queue.connect = AsyncMock()
        service.task_queue = mock_task_queue

        mock_blue_queue = MagicMock()
        mock_blue_queue.disconnect = AsyncMock()
        mock_blue_queue.connect = AsyncMock()
        service.blue_task_queue = mock_blue_queue

        await service._force_reconnect()

        mock_task_queue.disconnect.assert_awaited_once()
        mock_task_queue.connect.assert_awaited_once()
        mock_blue_queue.disconnect.assert_awaited_once()
        mock_blue_queue.connect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_process_investigation_request_retries_on_connection_error(self):
        """Test that _process_investigation_request retries on Redis connection errors."""
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")
        service._publish_investigation_status = AsyncMock()
        service._grafana_url = "http://grafana:3000"
        service._grafana_api_key = "test-key"  # pragma: allowlist secret

        request_data = {
            "investigation_id": "inv-conn-retry",
            "alert": {"labels": {"alertname": "TestAlert", "severity": "low"}},
            "model": "test-model",
            "auto_route": True,
        }

        call_count = 0

        async def mock_investigate(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First call fails with connection error
                raise Exception("Connection refused")  # noqa: TRY002
            # Second call succeeds
            return {
                "investigation_id": "inv-conn-retry",
                "status": "completed",
                "evidence_count": 1,
                "techniques_identified": [],
            }

        mock_orchestrator = MagicMock()
        mock_orchestrator.investigate = AsyncMock(side_effect=mock_investigate)

        with (
            patch.dict(os.environ, {}, clear=True),
            patch(
                "ares.agents.blue.InvestigationOrchestrator",
                return_value=mock_orchestrator,
            ),
            patch("ares.integrations.mitre.MITREAttackClient"),
            patch("ares.core.litellm_env.configure_litellm_env"),
        ):
            await service._process_investigation_request(request_data)

            # Should have retried and succeeded on second attempt
            assert call_count == 2

            # Should have published running status, not failed
            status_calls = service._publish_investigation_status.call_args_list
            # Check the last call was not a "failed" status
            assert not any(call[0][1] == "failed" for call in status_calls), (
                "Investigation should not have failed"
            )

    @pytest.mark.asyncio
    async def test_process_investigation_request_fails_after_max_retries_on_connection_error(
        self,
    ):
        """Test that investigation fails after exhausting retries on connection errors."""
        service = BlueOrchestratorService(redis_url="redis://", namespace="test")
        service._publish_investigation_status = AsyncMock()
        service._grafana_url = "http://grafana:3000"
        service._grafana_api_key = "test-key"  # pragma: allowlist secret

        request_data = {
            "investigation_id": "inv-conn-exhaust",
            "alert": {"labels": {"alertname": "TestAlert", "severity": "low"}},
            "model": "test-model",
            "auto_route": True,
        }

        mock_orchestrator = MagicMock()
        # All calls fail with connection error
        mock_orchestrator.investigate = AsyncMock(side_effect=Exception("Connection refused"))

        with (
            patch.dict(os.environ, {}, clear=True),
            patch(
                "ares.agents.blue.InvestigationOrchestrator",
                return_value=mock_orchestrator,
            ),
            patch("ares.integrations.mitre.MITREAttackClient"),
            patch("ares.core.litellm_env.configure_litellm_env"),
        ):
            await service._process_investigation_request(request_data)

            # Should have tried 3 times (max_retries)
            assert mock_orchestrator.investigate.await_count == 3

            # Should have published "failed" status
            failed_call = None
            for call in service._publish_investigation_status.call_args_list:
                if call[0][1] == "failed":
                    failed_call = call
                    break
            assert failed_call is not None, "Should have published failed status"
            assert "Connection refused" in failed_call[0][2]["error"]
