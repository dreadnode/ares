"""
Ares SOC Investigation Agent - Entry Point

Run with: uv run python -m ares [OPTIONS]
"""

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path

import cyclopts
import dreadnode as dn
from loguru import logger

app = cyclopts.App(
    name="ares",
    help="Autonomous SOC Investigation Agent - Question-driven threat investigation",
)


@dataclass
class Args:
    """Investigation agent arguments."""

    model: str = "claude-sonnet-4-20250514"
    """LLM model to use (supports litellm format)"""

    grafana_url: str = "http://localhost:3000"
    """Grafana URL for alert polling"""

    grafana_api_key: str = ""
    """Grafana API key (or set GRAFANA_API_KEY env var)"""

    loki_url: str = "http://localhost:3100"
    """Loki URL for log queries"""

    prometheus_url: str = "http://localhost:9090"
    """Prometheus URL for metric queries"""

    poll_interval: int = 30
    """Seconds between alert polling cycles"""

    max_steps: int = 150
    """Maximum agent steps per investigation"""

    report_dir: str = "reports"
    """Directory for markdown reports"""


@dataclass
class DreadnodeArgs:
    """Dreadnode platform arguments."""

    server: str = "https://platform.dev.plundr.ai/"
    """Dreadnode platform server URL"""

    token: str = ""
    """Dreadnode API token (or set DREADNODE_API_KEY env var)"""

    organization: str = "ares"
    """Dreadnode organization name"""

    workspace: str = "ares-protocol"
    """Dreadnode workspace name"""

    project: str = "ares-soc"
    """Dreadnode project name"""

    console: bool = True
    """Enable console output"""


@app.default
async def main(
    *,
    args: Args | None = None,
    dn_args: DreadnodeArgs | None = None,
) -> None:
    """
    Run the Ares SOC Investigation Agent.

    Polls Grafana for alerts and autonomously investigates each one,
    producing threat intelligence reports.

    Example:
        uv run python -m ares --model claude-sonnet-4-20250514 --grafana-url http://grafana:3000

    Environment Variables:
        GRAFANA_API_KEY: Grafana API key
        DREADNODE_API_KEY: Dreadnode platform token
        OPENAI_API_KEY / ANTHROPIC_API_KEY: LLM provider keys
    """
    args = args or Args()
    dn_args = dn_args or DreadnodeArgs()

    # Get API keys from environment if not provided
    grafana_api_key = args.grafana_api_key or os.getenv("GRAFANA_API_KEY", "")
    dreadnode_token = dn_args.token or os.getenv("DREADNODE_API_KEY", "")

    # Configure Dreadnode
    dn.configure(
        server=dn_args.server,
        token=dreadnode_token,
        organization=dn_args.organization,
        workspace=dn_args.workspace,
        project=dn_args.project,
        console=dn_args.console,
    )

    # Log startup
    logger.info("=" * 60)
    logger.info("ARES SOC INVESTIGATION AGENT")
    logger.info("=" * 60)
    logger.info(f"Model: {args.model}")
    logger.info(f"Grafana: {args.grafana_url}")
    logger.info(f"Loki: {args.loki_url}")
    logger.info(f"Prometheus: {args.prometheus_url}")
    logger.info(f"Poll Interval: {args.poll_interval}s")
    logger.info(f"Max Steps: {args.max_steps}")
    logger.info(f"Report Dir: {args.report_dir}")
    logger.info("=" * 60)

    # Import here to avoid circular imports
    from .agent import InvestigationOrchestrator
    from .mitre import MITREAttackClient
    from .tools import GrafanaTools

    # Initialize MITRE client
    logger.info("Loading MITRE ATT&CK data from STIX repository...")
    mitre_client = MITREAttackClient()
    await mitre_client.load()
    techniques_count = len(mitre_client._techniques)  # noqa: SLF001
    tactics_count = len(mitre_client._tactics)  # noqa: SLF001
    logger.success(f"Loaded {techniques_count} techniques, {tactics_count} tactics")

    # Create report directory
    report_dir = Path(args.report_dir)
    report_dir.mkdir(exist_ok=True)

    # Initialize orchestrator
    orchestrator = InvestigationOrchestrator(
        model=args.model,
        grafana_url=args.grafana_url,
        loki_url=args.loki_url,
        prometheus_url=args.prometheus_url,
        grafana_api_key=grafana_api_key,
        mitre_client=mitre_client,
        report_dir=report_dir,
        max_steps=args.max_steps,
    )

    # Initialize Grafana client for polling
    grafana = GrafanaTools(
        base_url=args.grafana_url,
        api_key=grafana_api_key,
    )

    # Track investigated alerts
    investigated_fingerprints: set[str] = set()

    logger.info(f"Polling for alerts every {args.poll_interval}s...")
    logger.info("Press Ctrl+C to stop")
    logger.info("")

    while True:
        try:
            # Poll for firing alerts
            alerts = await grafana.get_firing_alerts()

            for alert in alerts:
                fingerprint = alert.get("fingerprint", "")

                # Skip already investigated
                if fingerprint in investigated_fingerprints:
                    continue

                alert_name = alert.get("labels", {}).get("alertname", "unknown")
                severity = alert.get("labels", {}).get("severity", "unknown")

                logger.info("")
                logger.info("=" * 60)
                logger.info(f"NEW ALERT: {alert_name}")
                logger.info(f"Severity: {severity}")
                logger.info(f"Fingerprint: {fingerprint}")
                logger.info("=" * 60)

                # Mark as being investigated
                investigated_fingerprints.add(fingerprint)

                # Run investigation
                try:
                    result = await orchestrator.investigate(alert)

                    logger.success("")
                    logger.success("INVESTIGATION COMPLETE")
                    logger.success(f"  Status: {result['status']}")
                    logger.success(f"  Evidence: {result['evidence_count']} items")
                    logger.success(f"  Techniques: {len(result['techniques_identified'])}")
                    logger.success(f"  Pyramid Level: {result['highest_pyramid_level']}/6")
                    logger.success(f"  Report: {result['report_path']}")

                except Exception as e:
                    logger.error(f"Investigation failed: {e}")
                    dn.log_metric("investigation_failed", 1, mode="count")

            # Wait before next poll
            await asyncio.sleep(args.poll_interval)

        except KeyboardInterrupt:
            logger.info("")
            logger.info("Shutting down...")
            break

        except Exception as e:
            logger.error(f"Polling error: {e}")
            await asyncio.sleep(args.poll_interval)


@app.command
async def investigate_alert(
    alert_json: str,
    *,
    args: Args | None = None,
    dn_args: DreadnodeArgs | None = None,
) -> None:
    """
    Investigate a specific alert (JSON string or file path).

    Example:
        uv run python -m ares investigate-alert '{"labels": {"alertname": "HighCPU"}}'
        uv run python -m ares investigate-alert ./alert.json
    """
    import json

    args = args or Args()
    dn_args = dn_args or DreadnodeArgs()

    # Parse alert
    if alert_json.startswith("{"):
        alert = json.loads(alert_json)
    else:
        alert = json.loads(Path(alert_json).read_text())

    # Configure Dreadnode
    grafana_api_key = args.grafana_api_key or os.getenv("GRAFANA_API_KEY", "")
    dreadnode_token = dn_args.token or os.getenv("DREADNODE_API_KEY", "")

    dn.configure(
        server=dn_args.server,
        token=dreadnode_token,
        organization=dn_args.organization,
        workspace=dn_args.workspace,
        project=dn_args.project,
        console=dn_args.console,
    )

    from .agent import InvestigationOrchestrator
    from .mitre import MITREAttackClient

    # Load MITRE data
    logger.info("Loading MITRE ATT&CK data...")
    mitre_client = MITREAttackClient()
    await mitre_client.load()

    # Create orchestrator
    report_dir = Path(args.report_dir)
    report_dir.mkdir(exist_ok=True)

    orchestrator = InvestigationOrchestrator(
        model=args.model,
        grafana_url=args.grafana_url,
        loki_url=args.loki_url,
        prometheus_url=args.prometheus_url,
        grafana_api_key=grafana_api_key,
        mitre_client=mitre_client,
        report_dir=report_dir,
        max_steps=args.max_steps,
    )

    # Run investigation
    logger.info(f"Investigating alert: {alert.get('labels', {}).get('alertname', 'unknown')}")

    result = await orchestrator.investigate(alert)

    logger.success("")
    logger.success("INVESTIGATION COMPLETE")
    logger.success(f"  Report: {result['report_path']}")


@app.command
def version() -> None:
    """Print version information."""


if __name__ == "__main__":
    app()
