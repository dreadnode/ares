"""Tests for observability tools (Loki and Prometheus)."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from ares.tools.blue.observability import LokiTools, PrometheusTools


class TestLokiToolsInit:
    """Tests for LokiTools initialization."""

    def test_init_with_base_url(self):
        """Test LokiTools initialization with base URL."""
        tools = LokiTools(base_url="http://localhost:3100")
        assert tools.base_url == "http://localhost:3100"
        assert tools.timeout == 30  # default

    def test_init_with_custom_timeout(self):
        """Test LokiTools initialization with custom timeout."""
        tools = LokiTools(base_url="http://localhost:3100", timeout=60)
        assert tools.timeout == 60


class TestLokiQueryLogs:
    """Tests for LokiTools.query_logs method."""

    @pytest.fixture
    def loki_tools(self) -> LokiTools:
        """Create LokiTools instance."""
        return LokiTools(base_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_query_logs_rejects_empty_regex(self, loki_tools: LokiTools):
        """Test query_logs rejects queries with empty-compatible regex."""
        result = await loki_tools.query_logs(
            logql='{job=~".*"}',
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T11:00:00Z",
        )
        assert result["status"] == "error"
        assert "empty-compatible regex" in result["error"]

    @pytest.mark.asyncio
    async def test_query_logs_rejects_single_quote_empty_regex(self, loki_tools: LokiTools):
        """Test query_logs rejects single-quote empty regex."""
        result = await loki_tools.query_logs(
            logql="{job=~'.*'}",
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T11:00:00Z",
        )
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_query_logs_success(self, loki_tools: LokiTools):
        """Test successful query_logs execution."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "success",
            "data": {"result": [{"values": [["1705320000", "log line"]]}]},
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await loki_tools.query_logs(
                logql='{job="syslog"} |= "error"',
                start_time="2024-01-15T10:00:00Z",
                end_time="2024-01-15T11:00:00Z",
                limit=100,
            )

        assert result["status"] == "success"
        assert "data" in result

    @pytest.mark.asyncio
    async def test_query_logs_http_error(self, loki_tools: LokiTools):
        """Test query_logs handles HTTP errors."""
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.HTTPError("Connection failed")
            )
            result = await loki_tools.query_logs(
                logql='{job="syslog"}',
                start_time="2024-01-15T10:00:00Z",
                end_time="2024-01-15T11:00:00Z",
            )

        assert result["status"] == "error"
        assert "Connection failed" in result["error"]
        assert "hint" in result


class TestLokiQueryAroundTimestamp:
    """Tests for LokiTools.query_logs_around_timestamp method."""

    @pytest.fixture
    def loki_tools(self) -> LokiTools:
        return LokiTools(base_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_query_around_timestamp_default_window(self, loki_tools: LokiTools):
        """Test query_logs_around_timestamp with default 30-minute window."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get = AsyncMock(return_value=mock_response)

            await loki_tools.query_logs_around_timestamp(
                logql='{job="syslog"}',
                timestamp="2024-01-15T12:00:00Z",
            )

            # Check that the call was made with correct time window
            call_args = mock_instance.get.call_args
            params = call_args.kwargs.get("params", call_args[1].get("params", {}))
            # The start should be 30 minutes before timestamp
            assert "11:30" in params["start"] or "11:29" in params["start"]

    @pytest.mark.asyncio
    async def test_query_around_timestamp_custom_window(self, loki_tools: LokiTools):
        """Test query_logs_around_timestamp with custom window."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get = AsyncMock(return_value=mock_response)

            await loki_tools.query_logs_around_timestamp(
                logql='{job="syslog"}',
                timestamp="2024-01-15T12:00:00Z",
                window_minutes=60,
            )

            call_args = mock_instance.get.call_args
            params = call_args.kwargs.get("params", call_args[1].get("params", {}))
            # The start should be 60 minutes before timestamp
            assert "11:00" in params["start"] or "10:59" in params["start"]


class TestLokiQueryProgressive:
    """Tests for LokiTools.query_logs_progressive method."""

    @pytest.fixture
    def loki_tools(self) -> LokiTools:
        return LokiTools(base_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_progressive_finds_results_first_window(self, loki_tools: LokiTools):
        """Test progressive query finds results in first window."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "success",
            "data": {"result": [{"values": [["1705320000", "log"]]}]},
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await loki_tools.query_logs_progressive(
                logql='{job="syslog"}',
                reference_timestamp="2024-01-15T12:00:00Z",
            )

        assert result["_window_minutes"] == 30
        assert result["_window_expanded"] is False

    @pytest.mark.asyncio
    async def test_progressive_expands_window(self, loki_tools: LokiTools):
        """Test progressive query expands window when no results."""
        # First 3 calls return empty, 4th returns results
        empty_response = MagicMock()
        empty_response.json.return_value = {"status": "success", "data": {"result": []}}
        empty_response.raise_for_status = MagicMock()

        result_response = MagicMock()
        result_response.json.return_value = {
            "status": "success",
            "data": {"result": [{"values": [["1705320000", "log"]]}]},
        }
        result_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get = AsyncMock(
                side_effect=[
                    empty_response,
                    empty_response,
                    empty_response,
                    result_response,
                ]
            )
            result = await loki_tools.query_logs_progressive(
                logql='{job="syslog"}',
                reference_timestamp="2024-01-15T12:00:00Z",
            )

        assert result["_window_minutes"] == 1440  # 24h
        assert result["_window_expanded"] is True

    @pytest.mark.asyncio
    async def test_progressive_no_results_all_windows(self, loki_tools: LokiTools):
        """Test progressive query returns no results after all windows."""
        empty_response = MagicMock()
        empty_response.json.return_value = {"status": "success", "data": {"result": []}}
        empty_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=empty_response
            )
            result = await loki_tools.query_logs_progressive(
                logql='{job="syslog"}',
                reference_timestamp="2024-01-15T12:00:00Z",
            )

        assert result["_no_results"] is True
        assert result["_window_minutes"] == 1440


class TestLokiQueryRecent:
    """Tests for LokiTools.query_logs_recent method."""

    @pytest.fixture
    def loki_tools(self) -> LokiTools:
        return LokiTools(base_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_query_recent_default_hours(self, loki_tools: LokiTools):
        """Test query_logs_recent with default 1 hour."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await loki_tools.query_logs_recent(logql='{job="syslog"}')

        assert result["_query_type"] == "recent"
        assert result["_hours_back"] == 1

    @pytest.mark.asyncio
    async def test_query_recent_custom_hours(self, loki_tools: LokiTools):
        """Test query_logs_recent with custom hours."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await loki_tools.query_logs_recent(logql='{job="syslog"}', hours_back=6)

        assert result["_hours_back"] == 6


class TestLokiGetLabelValues:
    """Tests for LokiTools.get_label_values method."""

    @pytest.fixture
    def loki_tools(self) -> LokiTools:
        return LokiTools(base_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_get_label_values_success(self, loki_tools: LokiTools):
        """Test successful get_label_values."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": ["host1", "host2", "host3"]}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await loki_tools.get_label_values("hostname")

        assert result == ["host1", "host2", "host3"]

    @pytest.mark.asyncio
    async def test_get_label_values_http_error(self, loki_tools: LokiTools):
        """Test get_label_values handles HTTP errors."""
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.HTTPError("Connection failed")
            )
            result = await loki_tools.get_label_values("hostname")

        assert result == []


class TestLokiExecuteParallelQueries:
    """Tests for LokiTools.execute_parallel_queries method."""

    @pytest.fixture
    def loki_tools(self) -> LokiTools:
        return LokiTools(base_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_parallel_queries_empty_list(self, loki_tools: LokiTools):
        """Test parallel queries with empty list."""
        result = await loki_tools.execute_parallel_queries(
            queries=[],
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T11:00:00Z",
        )
        assert result == []

    @pytest.mark.asyncio
    async def test_parallel_queries_success(self, loki_tools: LokiTools):
        """Test successful parallel queries."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await loki_tools.execute_parallel_queries(
                queries=[
                    {"logql": '{job="syslog"} |= "error"', "description": "Find errors"},
                    {"logql": '{job="auth"}', "description": "Find auth logs"},
                ],
                start_time="2024-01-15T10:00:00Z",
                end_time="2024-01-15T11:00:00Z",
            )

        assert len(result) == 2
        assert result[0]["success"] is True
        assert result[1]["success"] is True

    @pytest.mark.asyncio
    async def test_parallel_queries_empty_query(self, loki_tools: LokiTools):
        """Test parallel queries with empty query string."""
        result = await loki_tools.execute_parallel_queries(
            queries=[{"logql": "", "description": "Empty query"}],
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T11:00:00Z",
        )
        assert len(result) == 1
        assert result[0]["success"] is False
        assert "error" in result[0]["result"]

    @pytest.mark.asyncio
    async def test_parallel_queries_caps_at_ten(self, loki_tools: LokiTools):
        """Test parallel queries caps at 10 queries."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            # Submit 15 queries
            queries = [
                {"logql": f'{{job="test{i}"}}', "description": f"Query {i}"} for i in range(15)
            ]
            result = await loki_tools.execute_parallel_queries(
                queries=queries,
                start_time="2024-01-15T10:00:00Z",
                end_time="2024-01-15T11:00:00Z",
            )

        # Should only execute 10
        assert len(result) == 10

    @pytest.mark.asyncio
    async def test_parallel_queries_handles_exceptions(self, loki_tools: LokiTools):
        """Test parallel queries handles query exceptions."""
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.HTTPError("Failed")
            )
            result = await loki_tools.execute_parallel_queries(
                queries=[{"logql": '{job="syslog"}', "description": "Test"}],
                start_time="2024-01-15T10:00:00Z",
                end_time="2024-01-15T11:00:00Z",
            )

        assert len(result) == 1
        assert result[0]["success"] is False


class TestLokiCombineQueryPatterns:
    """Tests for LokiTools.combine_query_patterns method."""

    @pytest.fixture
    def loki_tools(self) -> LokiTools:
        return LokiTools(base_url="http://localhost:3100")

    def test_combine_empty_patterns(self, loki_tools: LokiTools):
        """Test combining empty patterns returns base selector."""
        result = loki_tools.combine_query_patterns('{job="syslog"}', [])
        assert result == '{job="syslog"}'

    def test_combine_single_pattern(self, loki_tools: LokiTools):
        """Test combining single pattern."""
        result = loki_tools.combine_query_patterns('{job="syslog"}', ["error"])
        assert result == '{job="syslog"} |~ "error"'

    def test_combine_multiple_patterns(self, loki_tools: LokiTools):
        """Test combining multiple patterns."""
        result = loki_tools.combine_query_patterns(
            '{job="syslog"}', ["error", "failed", "critical"]
        )
        assert result == '{job="syslog"} |~ "error|failed|critical"'

    def test_combine_patterns_with_regex(self, loki_tools: LokiTools):
        """Test combining patterns that contain regex."""
        result = loki_tools.combine_query_patterns('{job="auth"}', ["4625|4624", "failed.*"])
        assert "4625|4624" in result
        assert "failed.*" in result


class TestPrometheusToolsInit:
    """Tests for PrometheusTools initialization."""

    def test_init_with_base_url(self):
        """Test PrometheusTools initialization."""
        tools = PrometheusTools(base_url="http://localhost:9090")
        assert tools.base_url == "http://localhost:9090"
        assert tools.timeout == 30

    def test_init_with_custom_timeout(self):
        """Test PrometheusTools with custom timeout."""
        tools = PrometheusTools(base_url="http://localhost:9090", timeout=120)
        assert tools.timeout == 120


class TestPrometheusQueryInstant:
    """Tests for PrometheusTools.query_instant method."""

    @pytest.fixture
    def prom_tools(self) -> PrometheusTools:
        return PrometheusTools(base_url="http://localhost:9090")

    @pytest.mark.asyncio
    async def test_query_instant_success(self, prom_tools: PrometheusTools):
        """Test successful instant query."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "success",
            "data": {"resultType": "vector", "result": []},
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await prom_tools.query_instant(promql="up")

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_query_instant_with_time(self, prom_tools: PrometheusTools):
        """Test instant query with specific time."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get = AsyncMock(return_value=mock_response)

            await prom_tools.query_instant(promql="up", time="2024-01-15T12:00:00Z")

            call_args = mock_instance.get.call_args
            params = call_args.kwargs.get("params", call_args[1].get("params", {}))
            assert params["time"] == "2024-01-15T12:00:00Z"

    @pytest.mark.asyncio
    async def test_query_instant_http_error(self, prom_tools: PrometheusTools):
        """Test instant query handles HTTP errors."""
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.HTTPError("Connection failed")
            )
            result = await prom_tools.query_instant(promql="up")

        assert "error" in result
        assert result["data"]["result"] == []


class TestPrometheusQueryRange:
    """Tests for PrometheusTools.query_range method."""

    @pytest.fixture
    def prom_tools(self) -> PrometheusTools:
        return PrometheusTools(base_url="http://localhost:9090")

    @pytest.mark.asyncio
    async def test_query_range_success(self, prom_tools: PrometheusTools):
        """Test successful range query."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "success",
            "data": {"resultType": "matrix", "result": []},
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await prom_tools.query_range(
                promql="rate(http_requests_total[5m])",
                start_time="2024-01-15T10:00:00Z",
                end_time="2024-01-15T11:00:00Z",
            )

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_query_range_custom_step(self, prom_tools: PrometheusTools):
        """Test range query with custom step."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get = AsyncMock(return_value=mock_response)

            await prom_tools.query_range(
                promql="up",
                start_time="2024-01-15T10:00:00Z",
                end_time="2024-01-15T11:00:00Z",
                step="5m",
            )

            call_args = mock_instance.get.call_args
            params = call_args.kwargs.get("params", call_args[1].get("params", {}))
            assert params["step"] == "5m"

    @pytest.mark.asyncio
    async def test_query_range_http_error(self, prom_tools: PrometheusTools):
        """Test range query handles HTTP errors."""
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.HTTPError("Connection failed")
            )
            result = await prom_tools.query_range(
                promql="up",
                start_time="2024-01-15T10:00:00Z",
                end_time="2024-01-15T11:00:00Z",
            )

        assert "error" in result


class TestPrometheusGetMetricNames:
    """Tests for PrometheusTools.get_metric_names method."""

    @pytest.fixture
    def prom_tools(self) -> PrometheusTools:
        return PrometheusTools(base_url="http://localhost:9090")

    @pytest.mark.asyncio
    async def test_get_metric_names_success(self, prom_tools: PrometheusTools):
        """Test successful get_metric_names."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": ["up", "http_requests_total", "node_cpu_seconds_total"]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await prom_tools.get_metric_names()

        assert "up" in result
        assert "http_requests_total" in result

    @pytest.mark.asyncio
    async def test_get_metric_names_with_search(self, prom_tools: PrometheusTools):
        """Test get_metric_names with search filter."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": ["up", "http_requests_total", "node_cpu_seconds_total"]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await prom_tools.get_metric_names(search="http")

        assert "http_requests_total" in result
        assert "up" not in result
        assert "node_cpu_seconds_total" not in result

    @pytest.mark.asyncio
    async def test_get_metric_names_limits_results(self, prom_tools: PrometheusTools):
        """Test get_metric_names limits to 100 results."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": [f"metric_{i}" for i in range(150)]}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await prom_tools.get_metric_names()

        assert len(result) == 100

    @pytest.mark.asyncio
    async def test_get_metric_names_http_error(self, prom_tools: PrometheusTools):
        """Test get_metric_names handles HTTP errors."""
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.HTTPError("Connection failed")
            )
            result = await prom_tools.get_metric_names()

        assert result == []
