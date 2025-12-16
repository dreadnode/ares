"""Observability tools for querying Loki and Prometheus."""

from datetime import datetime, timedelta

import dreadnode as dn
import httpx
from dreadnode.agent.tools.base import Toolset
from loguru import logger


class LokiTools(Toolset):  # type: ignore[misc]
    """Tools for querying Loki log aggregation system.

    Attributes:
        base_url: Base URL of the Loki instance.
        timeout: HTTP request timeout in seconds.
    """

    base_url: str
    timeout: int = 30

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def query_logs(
        self,
        logql: str,
        start_time: str,
        end_time: str,
        limit: int = 500,
    ) -> dict:
        """Execute a LogQL query against Loki.

        Write your own LogQL queries to investigate the logs.
        No templates - use your knowledge of the query language.

        Args:
            logql: The LogQL query string.
            start_time: ISO8601 timestamp for query start (e.g., "2024-01-15T10:00:00Z").
            end_time: ISO8601 timestamp for query end.
            limit: Maximum number of log lines to return (default 500).

        Returns:
            Query results with log streams and entries.

        Example:
            >>> await query_logs(
            ...     logql='{job="syslog", hostname="web-01"} |= "error"',
            ...     start_time="2024-01-15T10:00:00Z",
            ...     end_time="2024-01-15T11:00:00Z",
            ...     limit=100
            ... )
            {'status': 'success', 'data': {'resultType': 'streams', ...}}

        See Also:
            query_logs_around_timestamp: For time-window queries around a specific event.
            get_label_values: For discovering available log labels.
        """
        dn.log_metric("loki_queries", 1, mode="count")
        logger.info(f"Loki query: {logql}")

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/loki/api/v1/query_range",
                    params={
                        "query": logql,
                        "start": start_time,
                        "end": end_time,
                        "limit": limit,
                    },
                )
                response.raise_for_status()
                result = response.json()

            result_count = len(result.get("data", {}).get("result", []))
            dn.log_metric("loki_results", result_count)

            return result

        except httpx.HTTPError as e:
            logger.error(f"Loki query failed: {e}")
            return {"error": str(e), "data": {"result": []}}

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def query_logs_around_timestamp(
        self,
        logql: str,
        timestamp: str,
        window_minutes: int = 5,
        limit: int = 500,
    ) -> dict:
        """Query logs within a time window around a specific timestamp.

        Useful for investigating what happened before/after a specific event.

        Args:
            logql: The LogQL query string.
            timestamp: ISO8601 timestamp to center the query on.
            window_minutes: Minutes before and after the timestamp (default 5).
            limit: Maximum number of log lines.

        Returns:
            Query results centered on the timestamp.
        """
        center = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        start = (center - timedelta(minutes=window_minutes)).isoformat()
        end = (center + timedelta(minutes=window_minutes)).isoformat()

        return await self.query_logs(
            logql=logql,
            start_time=start,
            end_time=end,
            limit=limit,
        )

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def get_label_values(self, label: str) -> list[str]:
        """Get all values for a specific Loki label.

        Useful for discovering what hosts, jobs, or namespaces exist.

        Args:
            label: The label name (e.g., "hostname", "job", "namespace").

        Returns:
            List of label values.
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/loki/api/v1/label/{label}/values",
                )
                response.raise_for_status()
                return response.json().get("data", [])
        except httpx.HTTPError as e:
            logger.error(f"Failed to get label values: {e}")
            return []


class PrometheusTools(Toolset):  # type: ignore[misc]
    """Tools for querying Prometheus metrics.

    Attributes:
        base_url: Base URL of the Prometheus instance.
        timeout: HTTP request timeout in seconds.
    """

    base_url: str
    timeout: int = 30

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def query_instant(
        self,
        promql: str,
        time: str | None = None,
    ) -> dict:
        """Execute an instant PromQL query.

        Write your own PromQL queries to investigate metrics.
        No templates - use your knowledge of the query language.

        Args:
            promql: The PromQL query string.
            time: Optional evaluation timestamp (ISO8601). If not provided, uses current time.

        Returns:
            Instant query results.

        Example:
            >>> await query_instant(
            ...     promql='rate(http_requests_total{status=~"5.."}[5m])',
            ...     time="2024-01-15T14:30:00Z"
            ... )
            {'status': 'success', 'data': {'resultType': 'vector', ...}}

        See Also:
            query_range: For querying metrics over a time range.
            get_metric_names: For discovering available metrics.
        """
        dn.log_metric("prometheus_queries", 1, mode="count")
        logger.info(f"Prometheus instant query: {promql}")

        params = {"query": promql}
        if time:
            params["time"] = time

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/api/v1/query",
                    params=params,
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Prometheus query failed: {e}")
            return {"error": str(e), "data": {"result": []}}

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def query_range(
        self,
        promql: str,
        start_time: str,
        end_time: str,
        step: str = "1m",
    ) -> dict:
        """Execute a range PromQL query for time series data.

        Args:
            promql: The PromQL query string.
            start_time: ISO8601 start timestamp.
            end_time: ISO8601 end timestamp.
            step: Query resolution step (e.g., "1m", "5m", "1h").

        Returns:
            Range query results with time series.
        """
        dn.log_metric("prometheus_queries", 1, mode="count")
        logger.info(f"Prometheus range query: {promql}")

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/api/v1/query_range",
                    params={
                        "query": promql,
                        "start": start_time,
                        "end": end_time,
                        "step": step,
                    },
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Prometheus range query failed: {e}")
            return {"error": str(e), "data": {"result": []}}

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def get_metric_names(self, search: str | None = None) -> list[str]:
        """Get available Prometheus metric names.

        Args:
            search: Optional search string to filter metric names.

        Returns:
            List of metric names.
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/api/v1/label/__name__/values",
                )
                response.raise_for_status()
                metrics = response.json().get("data", [])

                if search:
                    search_lower = search.lower()
                    metrics = [m for m in metrics if search_lower in m.lower()]

                return metrics[:100]
        except httpx.HTTPError as e:
            logger.error(f"Failed to get metric names: {e}")
            return []
