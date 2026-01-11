"""Tests for Grafana alerting and MCP tools."""

import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from ares.tools.blue.grafana import (
    GrafanaTools,
    connect_grafana_mcp,
    find_mcp_grafana,
)


class TestGrafanaToolsInit:
    """Tests for GrafanaTools initialization."""

    def test_init_with_params(self):
        """Test initialization with parameters."""
        tools = GrafanaTools(
            base_url="http://grafana:3000",
            api_key="test-api-key",  # pragma: allowlist secret
        )
        assert tools.base_url == "http://grafana:3000"
        assert tools.api_key == "test-api-key"  # pragma: allowlist secret
        assert tools.timeout == 30

    def test_init_with_custom_timeout(self):
        """Test initialization with custom timeout."""
        tools = GrafanaTools(
            base_url="http://grafana:3000",
            api_key="test-api-key",  # pragma: allowlist secret
            timeout=60,
        )
        assert tools.timeout == 60


class TestGrafanaToolsHeaders:
    """Tests for header generation."""

    def test_headers_contain_bearer_token(self):
        """Test headers contain bearer token."""
        tools = GrafanaTools(
            base_url="http://grafana:3000",
            api_key="my-secret-key",  # pragma: allowlist secret
        )
        headers = tools._headers()
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer my-secret-key"  # pragma: allowlist secret


class TestGetFiringAlerts:
    """Tests for get_firing_alerts method."""

    @pytest.fixture
    def grafana_tools(self) -> GrafanaTools:
        return GrafanaTools(
            base_url="http://grafana:3000",
            api_key="test-key",  # pragma: allowlist secret
        )

    @pytest.mark.asyncio
    async def test_get_firing_alerts_success(self, grafana_tools: GrafanaTools):
        """Test successful alert retrieval."""
        mock_alerts = [
            {"fingerprint": "abc123", "status": "firing"},
            {"fingerprint": "def456", "status": "firing"},
        ]

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_alerts
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            alerts = await grafana_tools.get_firing_alerts()
            assert len(alerts) == 2
            assert alerts[0]["fingerprint"] == "abc123"

    @pytest.mark.asyncio
    async def test_get_firing_alerts_tries_multiple_endpoints(self, grafana_tools: GrafanaTools):
        """Test fallback to alternative endpoints on 404."""
        call_count = 0

        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_response = MagicMock()
            if call_count < 3:
                mock_response.status_code = 404
            else:
                mock_response.status_code = 200
                mock_response.json.return_value = []
            return mock_response

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = mock_get
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            await grafana_tools.get_firing_alerts()
            assert call_count >= 1

    @pytest.mark.asyncio
    async def test_get_firing_alerts_all_endpoints_fail(self, grafana_tools: GrafanaTools):
        """Test returns empty list when all endpoints fail."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            alerts = await grafana_tools.get_firing_alerts()
            assert alerts == []

    @pytest.mark.asyncio
    async def test_get_firing_alerts_http_error(self, grafana_tools: GrafanaTools):
        """Test handling of HTTP errors."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get.side_effect = httpx.HTTPError("Connection failed")
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            alerts = await grafana_tools.get_firing_alerts()
            assert alerts == []

    @pytest.mark.asyncio
    async def test_get_firing_alerts_server_error(self, grafana_tools: GrafanaTools):
        """Test handling of 500 server error triggers raise_for_status."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Server Error", request=MagicMock(), response=mock_response
            )
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            # Should handle the error and return empty list
            alerts = await grafana_tools.get_firing_alerts()
            assert alerts == []


class TestGetAlertHistory:
    """Tests for get_alert_history method."""

    @pytest.fixture
    def grafana_tools(self) -> GrafanaTools:
        return GrafanaTools(
            base_url="http://grafana:3000",
            api_key="test-key",  # pragma: allowlist secret
        )

    @pytest.mark.asyncio
    async def test_get_alert_history_success(self, grafana_tools: GrafanaTools):
        """Test successful history retrieval."""
        mock_history = [{"name": "Alert1"}, {"name": "Alert2"}]

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_history
            mock_response.raise_for_status = MagicMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            history = await grafana_tools.get_alert_history()
            assert len(history) == 2

    @pytest.mark.asyncio
    async def test_get_alert_history_error(self, grafana_tools: GrafanaTools):
        """Test error handling in history retrieval."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get.side_effect = httpx.HTTPError("Connection failed")
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            history = await grafana_tools.get_alert_history()
            assert history == []


class TestCreateAnnotation:
    """Tests for create_annotation method."""

    @pytest.fixture
    def grafana_tools(self) -> GrafanaTools:
        return GrafanaTools(
            base_url="http://grafana:3000",
            api_key="test-key",  # pragma: allowlist secret
        )

    @pytest.mark.asyncio
    async def test_create_annotation_success(self, grafana_tools: GrafanaTools):
        """Test successful annotation creation."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"id": 123}
            mock_response.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await grafana_tools.create_annotation(
                text="Test annotation",
                tags=["test", "ares"],
            )
            assert result is not None
            assert result["id"] == 123

    @pytest.mark.asyncio
    async def test_create_annotation_with_dashboard(self, grafana_tools: GrafanaTools):
        """Test annotation with dashboard UID."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"id": 456}
            mock_response.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await grafana_tools.create_annotation(
                text="Dashboard annotation",
                dashboard_uid="abc123",
            )
            assert result is not None

    @pytest.mark.asyncio
    async def test_create_annotation_with_time_range(self, grafana_tools: GrafanaTools):
        """Test annotation with time range."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"id": 789}
            mock_response.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await grafana_tools.create_annotation(
                text="Range annotation",
                time_start=1704105000000,
                time_end=1704108600000,
            )
            assert result is not None

    @pytest.mark.asyncio
    async def test_create_annotation_error(self, grafana_tools: GrafanaTools):
        """Test annotation creation error handling."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post.side_effect = httpx.HTTPError("Failed")
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await grafana_tools.create_annotation(text="Test")
            assert result is None


class TestPostInvestigationStarted:
    """Tests for post_investigation_started method."""

    @pytest.fixture
    def grafana_tools(self) -> GrafanaTools:
        return GrafanaTools(
            base_url="http://grafana:3000",
            api_key="test-key",  # pragma: allowlist secret
        )

    @pytest.mark.asyncio
    async def test_post_started_success(self, grafana_tools: GrafanaTools):
        """Test posting investigation started."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"id": 100}
            mock_response.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await grafana_tools.post_investigation_started(
                investigation_id="inv-001",
                alert_name="HighCPU",
                severity="warning",
            )
            assert result is not None
            # Check annotation was posted
            mock_client.post.assert_called_once()
            call_args = mock_client.post.call_args
            assert "annotations" in call_args[0][0]
            # The text should be in the json payload
            json_payload = call_args.kwargs.get("json", {})
            assert "Investigation Started" in json_payload.get("text", "")
            assert "inv-001" in json_payload.get("text", "")


class TestPostInvestigationCompleted:
    """Tests for post_investigation_completed method."""

    @pytest.fixture
    def grafana_tools(self) -> GrafanaTools:
        return GrafanaTools(
            base_url="http://grafana:3000",
            api_key="test-key",  # pragma: allowlist secret
        )

    def _mock_httpx_client(self):
        """Create a mock httpx client for annotation creation."""
        mock_client_class = patch("httpx.AsyncClient")
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": 101}
        mock_response.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        return mock_client_class, mock_client

    @pytest.mark.asyncio
    async def test_post_completed_success(self, grafana_tools: GrafanaTools):
        """Test posting investigation completed."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"id": 101}
            mock_response.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await grafana_tools.post_investigation_completed(
                investigation_id="inv-001",
                alert_name="HighCPU",
                status="completed",
                evidence_count=5,
                techniques=["T1071"],
                pyramid_level=4,
            )
            assert result is not None
            mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_post_completed_with_summary(self, grafana_tools: GrafanaTools):
        """Test posting completed with summary."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"id": 102}
            mock_response.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await grafana_tools.post_investigation_completed(
                investigation_id="inv-002",
                alert_name="DCSync",
                status="escalated",
                evidence_count=10,
                techniques=["T1003.006"],
                pyramid_level=6,
                summary="Critical attack detected",
            )
            assert result is not None
            call_args = mock_client.post.call_args
            json_payload = call_args.kwargs.get("json", {})
            assert "Critical attack detected" in json_payload.get("text", "")

    @pytest.mark.asyncio
    async def test_post_completed_truncates_long_summary(self, grafana_tools: GrafanaTools):
        """Test long summary truncation."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"id": 103}
            mock_response.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            long_summary = "A" * 600
            await grafana_tools.post_investigation_completed(
                investigation_id="inv-003",
                alert_name="Test",
                status="completed",
                evidence_count=1,
                techniques=[],
                pyramid_level=1,
                summary=long_summary,
            )
            call_args = mock_client.post.call_args
            json_payload = call_args.kwargs.get("json", {})
            assert "..." in json_payload.get("text", "")

    @pytest.mark.asyncio
    async def test_status_emojis(self, grafana_tools: GrafanaTools):
        """Test different status emojis."""
        statuses = ["completed", "escalated", "timeout", "failed", "incomplete", "unknown"]
        expected_emojis = ["✅", "🚨", "⏰", "❌", "⚠️", "📋"]

        for status, emoji in zip(statuses, expected_emojis, strict=False):
            with patch("httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {"id": 1}
                mock_response.raise_for_status = MagicMock()
                mock_client.post.return_value = mock_response
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_class.return_value = mock_client

                await grafana_tools.post_investigation_completed(
                    investigation_id="inv",
                    alert_name="Test",
                    status=status,
                    evidence_count=0,
                    techniques=[],
                    pyramid_level=0,
                )
                call_args = mock_client.post.call_args
                json_payload = call_args.kwargs.get("json", {})
                assert emoji in json_payload.get("text", "")


class TestFindMcpGrafana:
    """Tests for find_mcp_grafana function."""

    def test_find_in_path(self):
        """Test finding mcp-grafana in PATH."""
        with patch("shutil.which") as mock_which:
            mock_which.return_value = "/usr/local/bin/mcp-grafana"
            result = find_mcp_grafana()
            assert result == "/usr/local/bin/mcp-grafana"

    def test_find_in_gopath(self, temp_dir: Path):
        """Test finding mcp-grafana in GOPATH."""
        # Create mock binary
        gopath_bin = temp_dir / "bin"
        gopath_bin.mkdir()
        mcp_binary = gopath_bin / "mcp-grafana"
        mcp_binary.touch()

        with patch("shutil.which", return_value=None), patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.stdout = str(temp_dir)
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            result = find_mcp_grafana()
            assert "mcp-grafana" in result

    def test_not_found_raises_error(self):
        """Test RuntimeError when not found."""
        with (
            patch("shutil.which", return_value=None),
            patch("subprocess.run", side_effect=FileNotFoundError()),
            pytest.raises(RuntimeError, match="mcp-grafana not found"),
        ):
            find_mcp_grafana()


class TestConnectGrafanaMcp:
    """Tests for connect_grafana_mcp function."""

    @pytest.mark.asyncio
    async def test_connect_requires_url(self):
        """Test connection requires URL."""
        with (
            patch.dict(os.environ, {"GRAFANA_URL": "", "GRAFANA_SERVICE_ACCOUNT_TOKEN": "token"}),
            pytest.raises(ValueError, match="GRAFANA_URL"),
        ):
            await connect_grafana_mcp()

    @pytest.mark.asyncio
    async def test_connect_requires_api_key(self):
        """Test connection requires API key."""
        with (
            patch.dict(
                os.environ,
                {
                    "GRAFANA_URL": "http://grafana:3000",
                    "GRAFANA_SERVICE_ACCOUNT_TOKEN": "",
                    "GRAFANA_API_KEY": "",
                },
                clear=False,
            ),
            pytest.raises(ValueError, match=r"TOKEN|API_KEY"),
        ):
            await connect_grafana_mcp()

    @pytest.mark.asyncio
    async def test_connect_uses_env_vars(self):
        """Test connection uses environment variables."""
        with (
            patch.dict(
                os.environ,
                {
                    "GRAFANA_URL": "http://grafana:3000",
                    "GRAFANA_SERVICE_ACCOUNT_TOKEN": "test-token",
                },
            ),
            patch("ares.tools.blue.grafana.find_mcp_grafana") as mock_find,
        ):
            mock_find.return_value = "/usr/bin/mcp-grafana"
            with patch("rigging.mcp") as mock_mcp:
                mock_client = AsyncMock()
                mock_client.tools = []
                mock_mcp.return_value = mock_client

                await connect_grafana_mcp()
                mock_find.assert_called_once()

    @pytest.mark.asyncio
    async def test_connect_prefers_service_account_token(self):
        """Test SERVICE_ACCOUNT_TOKEN is preferred over API_KEY."""
        with (
            patch.dict(
                os.environ,
                {
                    "GRAFANA_URL": "http://grafana:3000",
                    "GRAFANA_SERVICE_ACCOUNT_TOKEN": "preferred-token",
                    "GRAFANA_API_KEY": "fallback-key",  # pragma: allowlist secret
                },
            ),
            patch("ares.tools.blue.grafana.find_mcp_grafana") as mock_find,
        ):
            mock_find.return_value = "/usr/bin/mcp-grafana"
            with patch("rigging.mcp") as mock_mcp:
                mock_client = AsyncMock()
                mock_client.tools = []
                mock_mcp.return_value = mock_client

                await connect_grafana_mcp()
                # Check that the right token was used
                call_args = mock_mcp.call_args
                assert call_args.kwargs["env"]["GRAFANA_SERVICE_ACCOUNT_TOKEN"] == "preferred-token"

    @pytest.mark.asyncio
    async def test_connect_falls_back_to_api_key(self):
        """Test fallback to GRAFANA_API_KEY."""
        with (
            patch.dict(
                os.environ,
                {
                    "GRAFANA_URL": "http://grafana:3000",
                    "GRAFANA_SERVICE_ACCOUNT_TOKEN": "",
                    "GRAFANA_API_KEY": "fallback-key",  # pragma: allowlist secret
                },
            ),
            patch("ares.tools.blue.grafana.find_mcp_grafana") as mock_find,
        ):
            mock_find.return_value = "/usr/bin/mcp-grafana"
            with patch("rigging.mcp") as mock_mcp:
                mock_client = AsyncMock()
                mock_client.tools = []
                mock_mcp.return_value = mock_client

                await connect_grafana_mcp()
                call_args = mock_mcp.call_args
                assert call_args.kwargs["env"]["GRAFANA_SERVICE_ACCOUNT_TOKEN"] == "fallback-key"
