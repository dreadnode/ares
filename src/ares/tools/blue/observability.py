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

        CRITICAL SYNTAX RULES:

        1. LABEL MATCHERS (must be first, in curly braces):
           - Exact match: {job="varlogs"}
           - Regex match: {app=~"web-.+"}  (NOT .* - see below)
           - Not equal: {env!="prod"}
           - Multiple: {job="syslog", hostname="web-01"}

        2. LINE FILTERS (use |= |! =~ !~ after label matchers):
           - Contains: |= "error"
           - Not contains: != "debug"
           - Regex: |~ "error|failed"
           - Not regex: !~ "info|debug"
           Example: {job="syslog"} |= "error"

        3. PARSER EXPRESSIONS (| json, | logfmt, | pattern, | regexp):
           Example: {job="app"} | json | level="error"

        4. AVOID THESE COMMON ERRORS:
           - ❌ {app=~".*"} - Empty-compatible regex (use .+ instead)
           - ❌ {job="app"} = "error" - Wrong operator (use |= not =)
           - ❌ {job="app"} "error" - Missing operator (add |=)
           - ❌ {job="app"} | "error" - Use |= not |
           - ❌ Quotes inside unescaped strings

        5. VALID COMPLETE EXAMPLES:
           - {job="syslog"} |= "error"
           - {job="syslog", hostname="web-01"} |= "error" |~ "critical"
           - {namespace="default"} | json | status_code="500"
           - {app=~"web-.+"} != "healthcheck"

        Args:
            logql: The LogQL query string. Must start with label matchers {...}.
            start_time: ISO8601 timestamp for query start (e.g., "2024-01-15T10:00:00Z").
            end_time: ISO8601 timestamp for query end.
            limit: Maximum number of log lines to return (default 500).

        Returns:
            Query results with log streams and entries.

        See Also:
            query_logs_around_timestamp: For time-window queries around a specific event.
            get_label_values: For discovering available log labels.
        """
        # Validate query to prevent empty-compatible regex errors
        if '=~".*"' in logql or "=~'.*'" in logql:
            return {
                "status": "error",
                "error": "Query contains empty-compatible regex '.*'. Use '.+' instead to require at least one character, or use specific label values.",
                "suggestion": "Replace =~\".*\" with =~\".+\" or use exact matches like job=\"varlog\"",
            }

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
            logger.error(f"Failed query was: {logql}")
            # Return detailed error for the agent to learn from
            return {
                "status": "error",
                "error": str(e),
                "query": logql,
                "hint": "Check LogQL syntax. Common issues: missing quotes, invalid operators, incorrect label matchers.",
            }

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def query_logs_around_timestamp(
        self,
        logql: str,
        timestamp: str,
        window_minutes: int = 30,
        limit: int = 500,
    ) -> dict:
        """Query logs within a time window around a specific timestamp.

        Useful for investigating what happened before/after a specific event.

        Args:
            logql: The LogQL query string.
            timestamp: ISO8601 timestamp to center the query on.
            window_minutes: Minutes before and after the timestamp (default 30).
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
    async def query_logs_progressive(
        self,
        logql: str,
        reference_timestamp: str,
        limit: int = 500,
    ) -> dict:
        """Query logs with progressive time window expansion.

        Starts with a 30-minute window and expands to 1h, 6h, 24h if no results found.
        This is useful when the alert timestamp may be stale and the actual activity
        occurred at a different time.

        Args:
            logql: The LogQL query string.
            reference_timestamp: ISO8601 timestamp to start searching from.
            limit: Maximum number of log lines.

        Returns:
            Query results with metadata about which time window succeeded.
        """
        windows = [30, 60, 360, 1440]  # 30min, 1h, 6h, 24h
        center = datetime.fromisoformat(reference_timestamp.replace("Z", "+00:00"))

        for window_mins in windows:
            start = (center - timedelta(minutes=window_mins)).isoformat()
            end = (center + timedelta(minutes=window_mins)).isoformat()

            logger.info(f"Progressive query: trying ±{window_mins}min window")
            result = await self.query_logs(
                logql=logql,
                start_time=start,
                end_time=end,
                limit=limit,
            )

            # Check if we got results
            data = result.get("data", {})
            results = data.get("result", [])
            if results:
                total_entries = sum(len(r.get("values", [])) for r in results)
                if total_entries > 0:
                    result["_window_minutes"] = window_mins
                    result["_window_expanded"] = window_mins > 30
                    result["_search_start"] = start
                    result["_search_end"] = end
                    logger.info(f"Progressive query: found {total_entries} entries in ±{window_mins}min window")
                    return result

        # No results in any window
        return {
            "status": "success",
            "data": {"result": []},
            "_window_minutes": 1440,
            "_window_expanded": True,
            "_no_results": True,
            "_message": "No results found in any time window (30min to 24h)",
        }

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def query_logs_recent(
        self,
        logql: str,
        hours_back: int = 1,
        limit: int = 500,
    ) -> dict:
        """Query logs from recent time (relative to NOW, not alert timestamp).

        Use this to check CURRENT activity regardless of alert timestamp.
        Critical for detecting if an alert's startsAt is stale.

        Args:
            logql: The LogQL query string.
            hours_back: How many hours back from now to query (default 1).
            limit: Maximum number of log lines.

        Returns:
            Query results from recent time window.
        """
        from datetime import timezone

        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=hours_back)).isoformat()
        end = now.isoformat()

        logger.info(f"Recent query: last {hours_back}h from now")
        dn.log_metric("loki_recent_queries", 1, mode="count")

        result = await self.query_logs(
            logql=logql,
            start_time=start,
            end_time=end,
            limit=limit,
        )
        result["_query_type"] = "recent"
        result["_hours_back"] = hours_back
        return result

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
