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

from ares.core.exceptions import AuthenticationError, ConfigurationError


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
        if not self.api_key:
            msg = (
                "Grafana API key is empty. Set GRAFANA_SERVICE_ACCOUNT_TOKEN "
                "environment variable or use --args.grafana-api-key CLI argument."
            )
            logger.warning(msg)
            raise ConfigurationError(msg)
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

        try:
            headers = self._headers()
        except ConfigurationError:
            return []

        for endpoint in endpoints:
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(
                        f"{self.base_url}{endpoint}",
                        headers=headers,
                        params={"active": "true"},
                    )
                    if response.status_code == 200:
                        logger.info(f"Successfully connected to Grafana alerts at {endpoint}")
                        return response.json()
                    if response.status_code == 404:
                        continue  # Try next endpoint
                    if response.status_code in (401, 403):
                        msg = f"Authentication failed for Grafana: {response.text}"
                        logger.error(msg)
                        raise AuthenticationError(
                            msg, service="grafana", status_code=response.status_code
                        )
                    response.raise_for_status()

            except AuthenticationError:
                raise  # Re-raise auth errors immediately
            except ConfigurationError:
                return []
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
            try:
                headers = self._headers()
            except ConfigurationError:
                return []
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/api/v1/provisioning/alert-rules",
                    headers=headers,
                )
                if response.status_code in (401, 403):
                    msg = f"Authentication failed for Grafana: {response.text}"
                    logger.error(msg)
                    raise AuthenticationError(
                        msg, service="grafana", status_code=response.status_code
                    )
                response.raise_for_status()
                return response.json()
        except AuthenticationError:
            raise  # Re-raise auth errors immediately
        except ConfigurationError:
            return []
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
            try:
                headers = self._headers()
            except ConfigurationError:
                return None
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/annotations",
                    headers=headers,
                    json=payload,
                )
                if response.status_code in (401, 403):
                    msg = f"Authentication failed for Grafana: {response.text}"
                    logger.error(msg)
                    raise AuthenticationError(
                        msg, service="grafana", status_code=response.status_code
                    )
                response.raise_for_status()
                result = response.json()
                logger.info(f"Created Grafana annotation: {result.get('id', 'unknown')}")
                return result
        except AuthenticationError:
            raise  # Re-raise auth errors immediately
        except ConfigurationError:
            return None
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

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def create_detection_rule(
        self,
        title: str,
        logql_query: str,
        description: str,
        mitre_technique: str | None = None,
        severity: str = "warning",
        evaluation_interval: str = "1m",
        pending_period: str = "5m",
    ) -> dict:
        """Create a Grafana alert rule based on a detection pattern found during investigation.

        Use this when you discover a LogQL query pattern that reliably detects malicious
        activity and should be monitored continuously.

        Args:
            title: Alert rule title (e.g., "DCSync Detection - Replication Request")
            logql_query: The LogQL query that detects the pattern (must use specific labels)
            description: Description of what this rule detects and why it matters
            mitre_technique: Optional MITRE ATT&CK technique ID (e.g., "T1003.006")
            severity: Alert severity - "critical", "warning", or "info" (default: warning)
            evaluation_interval: How often to evaluate the rule (default: 1m)
            pending_period: How long condition must be true before firing (default: 5m)

        Returns:
            Dict with status and rule details or error message
        """
        # Validate the query doesn't use broad selectors
        broad_patterns = ['{job=~".+"}', '{deployment=~".+"}', '{namespace=~".+"}']
        for pattern in broad_patterns:
            if pattern in logql_query:
                return {
                    "status": "error",
                    "error": f"Query contains broad selector '{pattern}' which would cause performance issues. Use specific labels like {{job=\"eventlog\"}}.",
                }

        # Validate severity
        valid_severities = ["critical", "warning", "info"]
        if severity not in valid_severities:
            severity = "warning"

        # Build labels and annotations dicts
        labels: dict[str, str] = {
            "severity": severity,
            "source": "ares-investigation",
        }
        annotations: dict[str, str] = {
            "description": description,
            "summary": f"ARES Detection: {title}",
        }
        if mitre_technique:
            labels["mitre_technique"] = mitre_technique
            annotations["mitre_technique"] = mitre_technique

        # Build the alert rule payload for Grafana provisioning API
        rule_payload = {
            "title": title,
            "ruleGroup": "ares-detections",
            "folderUID": "ares-security",  # Will be created if doesn't exist
            "noDataState": "OK",
            "execErrState": "OK",
            "for": pending_period,
            "annotations": annotations,
            "labels": labels,
            "data": [
                {
                    "refId": "A",
                    "datasourceUid": "loki",
                    "queryType": "range",
                    "model": {
                        "expr": f"count_over_time({logql_query} [5m]) > 0",
                        "queryType": "range",
                        "refId": "A",
                    },
                    "relativeTimeRange": {"from": 300, "to": 0},
                }
            ],
            "condition": "A",
        }

        try:
            await self._ensure_alert_folder()

            try:
                headers = self._headers()
            except ConfigurationError as e:
                return {"status": "error", "error": str(e)}

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/v1/provisioning/alert-rules",
                    headers=headers,
                    json=rule_payload,
                )

                if response.status_code == 201:
                    result = response.json()
                    logger.info(
                        f"Created detection rule: {title} (UID: {result.get('uid', 'unknown')})"
                    )
                    return {
                        "status": "success",
                        "message": f"Alert rule '{title}' created successfully",
                        "uid": result.get("uid"),
                        "rule_group": "ares-detections",
                        "folder": "ares-security",
                    }
                if response.status_code in (401, 403):
                    msg = f"Authentication failed for Grafana: {response.text}"
                    logger.error(msg)
                    raise AuthenticationError(
                        msg, service="grafana", status_code=response.status_code
                    )
                error_text = response.text
                logger.warning(
                    f"Failed to create alert rule: {response.status_code} - {error_text}"
                )
                return {
                    "status": "error",
                    "error": f"Failed to create rule: {error_text}",
                }

        except AuthenticationError:
            raise  # Re-raise auth errors immediately
        except ConfigurationError as e:
            return {"status": "error", "error": str(e)}
        except httpx.HTTPError as e:
            logger.error(f"HTTP error creating alert rule: {e}")
            return {"status": "error", "error": str(e)}

    async def _ensure_alert_folder(self) -> None:
        """Ensure the ares-security folder exists for alert rules."""
        try:
            try:
                headers = self._headers()
            except ConfigurationError:
                return
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/api/folders/ares-security",
                    headers=headers,
                )
                if response.status_code in (401, 403):
                    msg = f"Authentication failed for Grafana: {response.text}"
                    logger.error(msg)
                    raise AuthenticationError(
                        msg, service="grafana", status_code=response.status_code
                    )
                if response.status_code == 200:
                    return

                response = await client.post(
                    f"{self.base_url}/api/folders",
                    headers=headers,
                    json={"uid": "ares-security", "title": "ARES Security Detections"},
                )
                if response.status_code in (401, 403):
                    msg = f"Authentication failed for Grafana: {response.text}"
                    logger.error(msg)
                    raise AuthenticationError(
                        msg, service="grafana", status_code=response.status_code
                    )
                if response.status_code in (200, 201):
                    logger.info("Created ares-security folder for alert rules")
        except AuthenticationError:
            raise  # Re-raise auth errors immediately
        except httpx.HTTPError as e:
            logger.warning(f"Could not ensure alert folder exists: {e}")

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
