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
