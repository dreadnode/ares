"""Tests for blue team operations CLI commands.

Tests for the from-operation command and related helpers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestGetLatestOperationId:
    """Tests for _get_latest_operation_id function."""

    @pytest.fixture
    def mock_redis_setup(self):
        """Create mock Redis setup."""
        mock_client = AsyncMock()
        mock_client.keys = AsyncMock(return_value=[])
        mock_client.hgetall = AsyncMock(return_value={})
        mock_client.aclose = AsyncMock()

        return mock_client

    @pytest.mark.asyncio
    async def test_returns_none_when_no_operations(self, mock_redis_setup):
        """Test that None is returned when no operations exist."""
        mock_client = mock_redis_setup
        mock_client.keys = AsyncMock(return_value=[])

        with patch(
            "ares.cli_blue_ops.create_verified_redis_client",
            new=AsyncMock(return_value=mock_client),
        ):
            from ares.cli_blue_ops import _get_latest_operation_id

            result, is_running = await _get_latest_operation_id("redis://localhost")

        assert result is None
        assert is_running is False

    @pytest.mark.asyncio
    async def test_prefers_running_operation(self, mock_redis_setup):
        """Test that running operations are preferred over completed ones."""
        mock_client = mock_redis_setup

        now = datetime.now(timezone.utc)

        # decode_responses=True means keys are strings
        mock_client.keys = AsyncMock(
            side_effect=[
                ["ares:lock:op-running"],  # Lock keys (running)
                ["ares:op:op-running:meta", "ares:op:op-completed:meta"],  # Meta keys
            ]
        )

        async def mock_hgetall(key):
            if "op-running" in key:
                return {"started_at": now.isoformat()}
            if "op-completed" in key:
                return {"started_at": (now.replace(hour=now.hour - 1)).isoformat()}
            return {}

        mock_client.hgetall = mock_hgetall

        with patch(
            "ares.cli_blue_ops.create_verified_redis_client",
            new=AsyncMock(return_value=mock_client),
        ):
            from ares.cli_blue_ops import _get_latest_operation_id

            result, is_running = await _get_latest_operation_id("redis://localhost")

        assert result == "op-running"
        assert is_running is True

    @pytest.mark.asyncio
    async def test_returns_most_recent_when_no_running(self, mock_redis_setup):
        """Test that most recent operation is returned when none are running."""
        mock_client = mock_redis_setup

        now = datetime.now(timezone.utc)

        # decode_responses=True means keys are strings
        mock_client.keys = AsyncMock(
            side_effect=[
                [],  # No lock keys (no running operations)
                ["ares:op:op-old:meta", "ares:op:op-recent:meta"],
            ]
        )

        async def mock_hgetall(key):
            if "op-recent" in key:
                return {"started_at": now.isoformat()}
            if "op-old" in key:
                return {"started_at": (now.replace(year=now.year - 1)).isoformat()}
            return {}

        mock_client.hgetall = mock_hgetall

        with patch(
            "ares.cli_blue_ops.create_verified_redis_client",
            new=AsyncMock(return_value=mock_client),
        ):
            from ares.cli_blue_ops import _get_latest_operation_id

            result, is_running = await _get_latest_operation_id("redis://localhost")

        assert result == "op-recent"
        assert is_running is False

    @pytest.mark.asyncio
    async def test_handles_bytes_values_in_hgetall(self, mock_redis_setup):
        """Test proper handling of bytes values in hgetall (fallback path)."""
        mock_client = mock_redis_setup

        now = datetime.now(timezone.utc)

        # decode_responses=True but hgetall values might still have bytes in some cases
        mock_client.keys = AsyncMock(
            side_effect=[
                ["ares:lock:op-bytes"],
                ["ares:op:op-bytes:meta"],
            ]
        )

        async def mock_hgetall(key):
            # Some Redis configs return mixed types
            return {b"started_at": now.isoformat().encode()}

        mock_client.hgetall = mock_hgetall

        with patch(
            "ares.cli_blue_ops.create_verified_redis_client",
            new=AsyncMock(return_value=mock_client),
        ):
            from ares.cli_blue_ops import _get_latest_operation_id

            result, is_running = await _get_latest_operation_id("redis://localhost")

        assert result == "op-bytes"
        assert is_running is True

    @pytest.mark.asyncio
    async def test_closes_client(self, mock_redis_setup):
        """Test that Redis client is closed after use."""
        mock_client = mock_redis_setup
        mock_client.keys = AsyncMock(return_value=[])

        with patch(
            "ares.cli_blue_ops.create_verified_redis_client",
            new=AsyncMock(return_value=mock_client),
        ):
            from ares.cli_blue_ops import _get_latest_operation_id

            await _get_latest_operation_id("redis://localhost")

        mock_client.aclose.assert_awaited_once()


class TestFromOperationCommand:
    """Tests for the from-operation CLI command."""

    @pytest.fixture
    def mock_state(self):
        """Create mock operation state."""
        state = MagicMock()
        state.started_at = datetime.now(timezone.utc)
        state.completed_at = None
        state.all_credentials = []
        state.all_hashes = []
        state.all_hosts = []
        state.operation_id = "op-test"
        return state

    @pytest.fixture
    def mock_playbook(self):
        """Create mock detection playbook."""
        playbook = MagicMock()
        playbook.attack_window_start = datetime.now(timezone.utc)
        playbook.attack_window_end = datetime.now(timezone.utc)
        playbook.techniques_used = ["T1078", "T1087"]
        return playbook

    @pytest.mark.asyncio
    async def test_requires_operation_id_or_latest(self):
        """Test that either operation_id or --latest is required."""
        from ares.cli_blue_ops import from_operation

        with pytest.raises(SystemExit):
            await from_operation(operation_id="", latest=False)

    @pytest.mark.asyncio
    async def test_resolves_latest_operation(self, mock_state, mock_playbook):
        """Test that --latest resolves to the latest operation ID."""
        from ares.cli_blue_ops import from_operation

        with (
            patch(
                "ares.cli_blue_ops._get_latest_operation_id",
                new=AsyncMock(return_value=("op-latest", True)),
            ),
            patch(
                "ares.cli_blue_ops.create_verified_redis_client",
                new=AsyncMock(return_value=AsyncMock(aclose=AsyncMock())),
            ),
            patch(
                "ares.cli_ops._load_state_from_redis",
                new=AsyncMock(return_value=mock_state),
            ),
            patch(
                "ares.eval.detection_playbook.create_detection_playbook",
                return_value=mock_playbook,
            ),
            patch.dict(
                "os.environ",
                {
                    "GRAFANA_URL": "http://grafana",
                    "GRAFANA_SERVICE_ACCOUNT_TOKEN": "test-token",  # pragma: allowlist secret
                    "ARES_MODEL": "test-model",
                },
            ),
            patch("ares.tools.blue.GrafanaTools") as mock_grafana,
        ):
            grafana_instance = AsyncMock()
            grafana_instance.get_firing_alerts = AsyncMock(return_value=[])
            grafana_instance.get_alerts_in_time_range = AsyncMock(return_value=[])
            mock_grafana.return_value = grafana_instance

            await from_operation(
                operation_id="",
                latest=True,
                redis_url="redis://localhost",
            )

    @pytest.mark.asyncio
    async def test_submits_investigations_for_alerts(self, mock_state, mock_playbook):
        """Test that investigations are submitted for each alert."""
        from ares.cli_blue_ops import from_operation

        alerts = [
            {"labels": {"alertname": "HighCPU", "severity": "warning"}, "fingerprint": "fp1"},
            {"labels": {"alertname": "MemoryLow", "severity": "critical"}, "fingerprint": "fp2"},
        ]

        submitted_alerts = []

        async def mock_submit(**kwargs):
            submitted_alerts.append(kwargs["alert"])
            return {"investigation_id": f"inv-{len(submitted_alerts)}", "status": "pending"}

        with (
            patch(
                "ares.cli_blue_ops._get_latest_operation_id",
                new=AsyncMock(return_value=("op-test", False)),
            ),
            patch(
                "ares.cli_blue_ops.create_verified_redis_client",
                new=AsyncMock(return_value=AsyncMock(aclose=AsyncMock())),
            ),
            patch(
                "ares.cli_ops._load_state_from_redis",
                new=AsyncMock(return_value=mock_state),
            ),
            patch(
                "ares.eval.detection_playbook.create_detection_playbook",
                return_value=mock_playbook,
            ),
            patch("ares.cli_blue_ops.submit_investigation", side_effect=mock_submit),
            patch.dict(
                "os.environ",
                {
                    "GRAFANA_URL": "http://grafana",
                    "GRAFANA_SERVICE_ACCOUNT_TOKEN": "test-token",  # pragma: allowlist secret
                    "ARES_MODEL": "test-model",
                },
            ),
            patch("ares.tools.blue.GrafanaTools") as mock_grafana,
        ):
            grafana_instance = AsyncMock()
            grafana_instance.get_alerts_in_time_range = AsyncMock(return_value=alerts)
            mock_grafana.return_value = grafana_instance

            await from_operation(
                operation_id="",
                latest=True,
                redis_url="redis://localhost",
            )

        assert len(submitted_alerts) == 2
        # Verify operation context is added to alerts
        for alert in submitted_alerts:
            assert "operation_context" in alert
            assert alert["operation_context"]["operation_id"] == "op-test"

    @pytest.mark.asyncio
    async def test_dedupes_alerts_for_running_operation(self, mock_state, mock_playbook):
        """Test that alerts are deduplicated when combining firing and historical."""
        from ares.cli_blue_ops import from_operation

        # Same alert appears in both firing and historical
        firing = [{"labels": {"alertname": "Test"}, "fingerprint": "fp1"}]
        historical = [
            {"labels": {"alertname": "Test"}, "fingerprint": "fp1"},  # Duplicate
            {"labels": {"alertname": "Other"}, "fingerprint": "fp2"},
        ]

        submitted = []

        async def mock_submit(**kwargs):
            submitted.append(kwargs["alert"])
            return {"investigation_id": "inv-1", "status": "pending"}

        with (
            patch(
                "ares.cli_blue_ops._get_latest_operation_id",
                new=AsyncMock(return_value=("op-running", True)),  # Running
            ),
            patch(
                "ares.cli_blue_ops.create_verified_redis_client",
                new=AsyncMock(return_value=AsyncMock(aclose=AsyncMock())),
            ),
            patch(
                "ares.cli_ops._load_state_from_redis",
                new=AsyncMock(return_value=mock_state),
            ),
            patch(
                "ares.eval.detection_playbook.create_detection_playbook",
                return_value=mock_playbook,
            ),
            patch("ares.cli_blue_ops.submit_investigation", side_effect=mock_submit),
            patch.dict(
                "os.environ",
                {
                    "GRAFANA_URL": "http://grafana",
                    "GRAFANA_SERVICE_ACCOUNT_TOKEN": "test-token",  # pragma: allowlist secret
                    "ARES_MODEL": "test-model",
                },
            ),
            patch("ares.tools.blue.GrafanaTools") as mock_grafana,
        ):
            grafana_instance = AsyncMock()
            grafana_instance.get_firing_alerts = AsyncMock(return_value=firing)
            grafana_instance.get_alerts_in_time_range = AsyncMock(return_value=historical)
            mock_grafana.return_value = grafana_instance

            await from_operation(
                operation_id="",
                latest=True,
                redis_url="redis://localhost",
            )

        # Should only submit 2 alerts (deduped by fingerprint)
        assert len(submitted) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
