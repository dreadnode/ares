"""Grafana alerting and MCP tools."""

import os
import shutil
import subprocess  # nosec B404
from pathlib import Path
from typing import Any

import dreadnode as dn
import httpx
from dreadnode.agent.tools.base import Toolset
from loguru import logger


class GrafanaTools(Toolset):  # type: ignore[misc]
    """Tools for interacting with Grafana alerting.

    Attributes:
        base_url: Base URL of the Grafana instance.
        api_key: API key for authentication.
        timeout: HTTP request timeout in seconds.
    """

    base_url: str
    api_key: str
    timeout: int = 30

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}"}

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def get_firing_alerts(self) -> list[dict]:
        """Get all currently firing alerts from Grafana.

        Returns:
            List of firing alert instances with labels, annotations, and values.
        """
        # Try multiple Grafana alert API endpoints (depends on Grafana version)
        endpoints = [
            "/api/alertmanager/grafana/api/v2/alerts",  # Grafana 9+
            "/api/v1/alerts",  # Alternative
            "/api/prometheus/grafana/api/v1/alerts",  # Older format
        ]

        for endpoint in endpoints:
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(
                        f"{self.base_url}{endpoint}",
                        headers=self._headers(),
                        params={"active": "true"},
                    )
                    if response.status_code == 200:
                        logger.info(f"Successfully connected to Grafana alerts at {endpoint}")
                        return response.json()
                    if response.status_code == 404:
                        continue  # Try next endpoint
                    response.raise_for_status()

            except httpx.HTTPError as e:
                if "404" not in str(e):
                    logger.error(f"Failed to get alerts from {endpoint}: {e}")
                continue

        logger.warning("Could not find Grafana alerts endpoint. Using empty alerts list.")
        return []

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def get_alert_history(
        self,
        _hours: int = 24,
    ) -> list[dict]:
        """Get alert history from Grafana.

        Args:
            _hours: How many hours of history to retrieve.

        Returns:
            List of historical alert instances.
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/api/v1/provisioning/alert-rules",
                    headers=self._headers(),
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Failed to get alert history: {e}")
            return []

    async def create_annotation(
        self,
        text: str,
        tags: list[str] | None = None,
        dashboard_uid: str | None = None,
        time_start: int | None = None,
        time_end: int | None = None,
    ) -> dict | None:
        """Create an annotation in Grafana.

        Args:
            text: Annotation text/description.
            tags: List of tags for filtering.
            dashboard_uid: Optional dashboard UID to associate annotation with.
            time_start: Start time as epoch milliseconds (defaults to now).
            time_end: End time as epoch milliseconds (optional, for range annotations).

        Returns:
            Created annotation response or None on failure.
        """
        import time

        payload: dict[str, Any] = {
            "text": text,
            "tags": tags or ["ares", "investigation"],
            "time": time_start or int(time.time() * 1000),
        }

        if dashboard_uid:
            payload["dashboardUID"] = dashboard_uid

        if time_end:
            payload["timeEnd"] = time_end

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/annotations",
                    headers=self._headers(),
                    json=payload,
                )
                response.raise_for_status()
                result = response.json()
                logger.info(f"Created Grafana annotation: {result.get('id', 'unknown')}")
                return result
        except httpx.HTTPError as e:
            logger.warning(f"Failed to create annotation: {e}")
            return None

    async def post_investigation_started(
        self,
        investigation_id: str,
        alert_name: str,
        severity: str,
    ) -> dict | None:
        """Post annotation when investigation starts.

        Args:
            investigation_id: Unique investigation identifier.
            alert_name: Name of the alert being investigated.
            severity: Alert severity level.

        Returns:
            Created annotation response or None on failure.
        """
        text = (
            f"🔍 **Investigation Started**\n\n"
            f"- **ID:** {investigation_id}\n"
            f"- **Alert:** {alert_name}\n"
            f"- **Severity:** {severity}\n"
            f"- **Status:** In Progress"
        )
        return await self.create_annotation(
            text=text,
            tags=["ares", "investigation", "started", alert_name, severity],
        )

    async def post_investigation_completed(
        self,
        investigation_id: str,
        alert_name: str,
        status: str,
        evidence_count: int,
        techniques: list[str],
        pyramid_level: int,
        summary: str | None = None,
    ) -> dict | None:
        """Post annotation when investigation completes.

        Args:
            investigation_id: Unique investigation identifier.
            alert_name: Name of the alert investigated.
            status: Final status (completed, escalated, timeout).
            evidence_count: Number of evidence items collected.
            techniques: List of MITRE ATT&CK techniques identified.
            pyramid_level: Highest Pyramid of Pain level reached.
            summary: Optional investigation summary.

        Returns:
            Created annotation response or None on failure.
        """
        status_emoji = {
            "completed": "✅",
            "escalated": "🚨",
            "timeout": "⏰",
            "failed": "❌",
            "incomplete": "⚠️",
        }.get(status, "📋")

        text = (
            f"{status_emoji} **Investigation {status.title()}**\n\n"
            f"- **ID:** {investigation_id}\n"
            f"- **Alert:** {alert_name}\n"
            f"- **Evidence:** {evidence_count} items\n"
            f"- **Techniques:** {', '.join(techniques) if techniques else 'None identified'}\n"
            f"- **Pyramid Level:** {pyramid_level}/6"
        )

        if summary:
            # Truncate summary if too long
            truncated = summary[:500] + "..." if len(summary) > 500 else summary
            text += f"\n\n**Summary:** {truncated}"

        return await self.create_annotation(
            text=text,
            tags=["ares", "investigation", status, alert_name],
        )


def find_mcp_grafana() -> str:
    """Find the mcp-grafana binary.

    Returns:
        Path to mcp-grafana.

    Raises:
        RuntimeError: If mcp-grafana cannot be found.
    """
    # Try to find in PATH
    mcp_path = shutil.which("mcp-grafana")
    if mcp_path:
        return mcp_path

    # Try GOPATH/bin
    try:
        result = subprocess.run(  # nosec B603, B607
            ["go", "env", "GOPATH"],
            capture_output=True,
            text=True,
            check=True,
        )
        gopath = result.stdout.strip()
        if gopath:
            gopath_bin = Path(gopath) / "bin" / "mcp-grafana"
            if gopath_bin.exists():
                return str(gopath_bin)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    msg = (
        "mcp-grafana not found. Install with: "
        "go install github.com/grafana/mcp-grafana/cmd/mcp-grafana@latest"
    )
    raise RuntimeError(msg)


async def connect_grafana_mcp(
    grafana_url: str | None = None,
    grafana_api_key: str | None = None,
) -> Any:
    """
    Connect to Grafana MCP server via Rigging.

    Args:
        grafana_url: Grafana instance URL (default: from GRAFANA_URL env)
        grafana_api_key: Grafana service account token (default: from GRAFANA_SERVICE_ACCOUNT_TOKEN or GRAFANA_API_KEY env)

    Returns:
        Connected MCPClient with Grafana tools loaded

    Raises:
        RuntimeError: If mcp-grafana binary cannot be found
        ValueError: If credentials are not provided
    """
    import rigging as rg

    # Get credentials from environment if not provided
    grafana_url = grafana_url or os.getenv("GRAFANA_URL", "")
    # Prefer GRAFANA_SERVICE_ACCOUNT_TOKEN, fallback to GRAFANA_API_KEY for compatibility
    grafana_api_key = (
        grafana_api_key
        or os.getenv("GRAFANA_SERVICE_ACCOUNT_TOKEN", "")
        or os.getenv("GRAFANA_API_KEY", "")
    )

    if not grafana_url:
        msg = "GRAFANA_URL must be provided or set in environment"
        raise ValueError(msg)

    if not grafana_api_key:
        msg = "GRAFANA_SERVICE_ACCOUNT_TOKEN (or GRAFANA_API_KEY) must be provided or set in environment"
        raise ValueError(msg)

    # Find mcp-grafana binary
    mcp_grafana_path = find_mcp_grafana()
    logger.info(f"Found mcp-grafana at: {mcp_grafana_path}")

    # Connect to MCP server using the new environment variable name
    client = rg.mcp(
        "stdio",
        command=mcp_grafana_path,
        args=[],
        env={
            "GRAFANA_URL": grafana_url,
            "GRAFANA_SERVICE_ACCOUNT_TOKEN": grafana_api_key,
        },
    )

    # Enter the async context to initialize connection
    await client.__aenter__()

    logger.success(f"Connected to Grafana MCP server ({len(client.tools)} tools loaded)")

    return client
