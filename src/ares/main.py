"""
Ares SOC Investigation Agent - Entry Point

Run with: uv run python -m ares [OPTIONS]
"""

import asyncio
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import cyclopts
import dreadnode as dn
from loguru import logger

if TYPE_CHECKING:
    from ares.core.models import InvestigationState


# Severity levels that trigger multi-agent routing
HIGH_SEVERITY_LEVELS = frozenset({"critical", "high"})


class InvestigationOrchestratorProtocol(Protocol):
    """Protocol for investigation orchestrators (single and multi-agent)."""

    async def investigate(self, alert: dict, *, correlation_context: dict | None = None) -> dict:
        """Run an investigation on an alert."""
        ...

    async def _shutdown_mcp(self) -> None:
        """Shutdown MCP connections."""
        ...


def should_use_multi_agent(severity: str, *, force_multi_agent: bool = False) -> bool:
    """Determine if an alert should use multi-agent based on severity.

    Args:
        severity: Alert severity level (critical, high, medium, low, etc.)
        force_multi_agent: If True, always use multi-agent regardless of severity.

    Returns:
        True if multi-agent should be used for this alert.
    """
    if force_multi_agent:
        return True
    return severity.lower() in HIGH_SEVERITY_LEVELS


async def discover_running_operation(redis_url: str) -> str | None:
    """Discover an active running operation from Redis.

    Args:
        redis_url: Redis connection URL

    Returns:
        Operation ID if found, None otherwise
    """
    from ares.core.redis_client import create_verified_redis_client
    from ares.core.task_queue import RedisTaskQueue

    try:
        client = await create_verified_redis_client(redis_url, decode_responses=True)
        lock_keys = await client.keys(f"{RedisTaskQueue.LOCK_PREFIX}:*")
        await client.aclose()

        if lock_keys:
            # Return the first running operation (or latest if multiple)
            for key in lock_keys:
                parts = key.split(":", 2)
                if len(parts) >= 3:
                    return parts[2]
    except Exception as e:
        logger.debug(f"Failed to discover running operation: {e}")
    return None


async def discover_recent_completed_operation(
    redis_url: str,
    max_age_hours: int = 24,
) -> str | None:
    """Discover the most recently completed operation within time window.

    Args:
        redis_url: Redis connection URL
        max_age_hours: Maximum age of operation to consider (default: 24 hours)

    Returns:
        Operation ID if found, None otherwise
    """
    from datetime import timedelta

    from ares.core.redis_client import create_verified_redis_client
    from ares.core.task_queue import RedisTaskQueue

    try:
        client = await create_verified_redis_client(redis_url, decode_responses=True)

        # Get running operations to exclude
        running_ops: set[str] = set()
        lock_keys = await client.keys(f"{RedisTaskQueue.LOCK_PREFIX}:*")
        for key in lock_keys:
            parts = key.split(":", 2)
            if len(parts) >= 3:
                running_ops.add(parts[2])

        # Find completed operations
        meta_keys = await client.keys("ares:op:*:meta")
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=max_age_hours)

        candidates: list[tuple[datetime, str]] = []
        for key in meta_keys:
            parts = key.split(":")
            if len(parts) < 3:
                continue
            op_id = parts[2]

            # Skip running operations
            if op_id in running_ops:
                continue

            # Get started_at and completed_at from meta
            meta_data = await client.hgetall(f"ares:op:{op_id}:meta")
            if not meta_data:
                continue

            started_raw = meta_data.get("started_at")
            if not started_raw:
                continue

            try:
                started_at = datetime.fromisoformat(started_raw)
            except (ValueError, TypeError):
                continue

            # Check if within time window
            if started_at < cutoff:
                continue

            candidates.append((started_at, op_id))

        await client.aclose()

        if candidates:
            # Return most recent
            candidates.sort(key=lambda x: x[0], reverse=True)
            return candidates[0][1]

    except Exception as e:
        logger.debug(f"Failed to discover recent operation: {e}")
    return None


async def get_operation_time_window(
    redis_url: str,
    operation_id: str,
) -> tuple[datetime, datetime, bool] | None:
    """Get operation time window from Redis.

    Args:
        redis_url: Redis connection URL
        operation_id: Operation ID to look up

    Returns:
        Tuple of (started_at, completed_at_or_now, is_running) or None if not found
    """
    from ares.core.redis_client import create_verified_redis_client
    from ares.core.task_queue import RedisTaskQueue

    try:
        client = await create_verified_redis_client(redis_url, decode_responses=True)

        # Check if running
        lock_key = f"{RedisTaskQueue.LOCK_PREFIX}:{operation_id}"
        is_running = await client.exists(lock_key)

        # Get timestamps from meta
        meta_data = await client.hgetall(f"ares:op:{operation_id}:meta")
        await client.aclose()

        if not meta_data:
            return None

        started_raw = meta_data.get("started_at")
        if not started_raw:
            return None

        try:
            started_at = datetime.fromisoformat(started_raw)
        except Exception:
            return None

        # Get end time
        if is_running:
            end_time = datetime.now(timezone.utc)
        else:
            completed_raw = meta_data.get("completed_at")
            if completed_raw:
                try:
                    end_time = datetime.fromisoformat(completed_raw)
                except Exception:
                    end_time = datetime.now(timezone.utc)
            else:
                end_time = datetime.now(timezone.utc)

        return (started_at, end_time, bool(is_running))

    except Exception as e:
        logger.debug(f"Failed to get operation time window: {e}")
    return None


def merge_alerts(firing: list[dict], historical: list[dict]) -> list[dict]:
    """Merge firing and historical alerts, deduplicating by fingerprint.

    Firing alerts take priority as they are more current.

    Args:
        firing: Currently firing alerts
        historical: Historical alerts from annotations

    Returns:
        Merged list with duplicates removed
    """
    seen_fingerprints: set[str] = set()
    merged = []

    # Firing alerts take priority
    for alert in firing:
        fp = alert.get("fingerprint", "")
        if fp and fp not in seen_fingerprints:
            seen_fingerprints.add(fp)
            merged.append(alert)

    # Add historical alerts not already present
    for alert in historical:
        fp = alert.get("fingerprint", "")
        if fp and fp not in seen_fingerprints:
            seen_fingerprints.add(fp)
            merged.append(alert)

    return merged


app = cyclopts.App(
    name="ares",
    help="Autonomous SOC Investigation Agent - Question-driven threat investigation",
)


def _configure_dreadnode():
    from ares.core.litellm_env import configure_litellm_env

    configure_litellm_env()
    return dn


@dataclass
class Args:
    """Investigation agent arguments.

    Attributes:
        model: LLM model to use (supports litellm format).
        grafana_url: Grafana URL for alert polling and MCP connection.
        grafana_api_key: Grafana API key (or set GRAFANA_SERVICE_ACCOUNT_TOKEN env var).
        poll_interval: Seconds between alert polling cycles.
        max_steps: Maximum agent steps per investigation.
        report_dir: Directory for markdown reports.
        once: Process current alerts once and exit (default: run forever).
        operation_id: Red team operation ID to focus investigation on.
        latest: Use the latest red team operation (prefer running).
        redis_url: Redis URL for loading red team operation state.
        multi_agent: Force multi-agent for ALL alerts (requires Redis).
        auto_route: Enable severity-based routing (multi-agent for HIGH/CRITICAL).
    """

    model: str = ""
    grafana_url: str = "https://grafana.dev.plundr.ai"
    grafana_api_key: str = ""
    poll_interval: int = 30
    max_steps: int = 150
    report_dir: str = "./reports"  # Relative to CWD
    once: bool = False  # Process current alerts once and exit
    operation_id: str = ""  # Red team operation to focus on
    latest: bool = False  # Use latest red team operation
    redis_url: str = ""  # Redis URL for red team state
    multi_agent: bool = False  # Force multi-agent for ALL alerts
    auto_route: bool = True  # Enable severity-based auto-routing


@dataclass
class DreadnodeArgs:
    """Dreadnode platform arguments.

    Attributes:
        server: Dreadnode platform server URL.
        token: Dreadnode API token (or set DREADNODE_API_KEY env var).
        organization: Dreadnode organization name.
        workspace: Dreadnode workspace name.
        project: Dreadnode project name.
        console: Enable console output.
    """

    server: str = "https://platform.dev.plundr.ai/"
    token: str = ""
    organization: str = "ares"
    workspace: str = "ares-protocol"
    project: str = "ares-soc"
    console: bool = True


def _resolve_model(cli_model: str, *, prefer_orchestrator: bool = False) -> str:
    if cli_model:
        return cli_model
    if prefer_orchestrator:
        return os.getenv("ARES_ORCHESTRATOR_MODEL", "") or os.getenv("ARES_MODEL", "")
    return os.getenv("ARES_MODEL", "")


# Cyclopts decorator typing not yet fully supported by type checkers
@app.default  # type: ignore[untyped-decorator]
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
        uv run python -m ares --model YOUR_MODEL --grafana-url http://grafana:3000

    Environment Variables:
        GRAFANA_SERVICE_ACCOUNT_TOKEN: Grafana service account token (preferred)
        GRAFANA_API_KEY: Grafana API key (deprecated, use GRAFANA_SERVICE_ACCOUNT_TOKEN)
        DREADNODE_API_KEY: Dreadnode platform token
        OPENAI_API_KEY / ANTHROPIC_API_KEY: LLM provider keys
    """
    args = args or Args()
    dn_args = dn_args or DreadnodeArgs()

    model = _resolve_model(args.model)
    if not model:
        logger.error("No model specified. Set ARES_MODEL or pass --args.model.")
        return

    model = _resolve_model(args.model)
    if not model:
        logger.error("No model specified. Set ARES_MODEL or pass --args.model.")
        return

    # Prefer GRAFANA_SERVICE_ACCOUNT_TOKEN, fallback to GRAFANA_API_KEY for compatibility
    grafana_api_key = (
        args.grafana_api_key
        or os.getenv("GRAFANA_SERVICE_ACCOUNT_TOKEN", "")
        or os.getenv("GRAFANA_API_KEY", "")
    )
    dreadnode_token = dn_args.token or os.getenv("DREADNODE_API_KEY", "")

    # Configure Dreadnode
    dn = _configure_dreadnode()
    dn.configure(
        server=dn_args.server,
        token=dreadnode_token,
        organization=dn_args.organization,
        workspace=dn_args.workspace,
        project=dn_args.project,
        console=dn_args.console,
    )

    # Validate required credentials
    if not grafana_api_key:
        logger.warning("=" * 60)
        logger.warning("WARNING: No Grafana API key configured!")
        logger.warning("Set GRAFANA_SERVICE_ACCOUNT_TOKEN environment variable,")
        logger.warning("or use --args.grafana-api-key CLI argument.")
        logger.warning("The agent will not be able to retrieve alerts.")
        logger.warning("=" * 60)

    model = _resolve_model(args.model)
    if not model:
        logger.error("No model specified. Set ARES_MODEL or pass --args.model.")
        return

    # Log startup
    logger.info("=" * 60)
    logger.info("ARES SOC INVESTIGATION AGENT")
    logger.info("=" * 60)
    logger.info(f"Model: {model}")
    logger.info(f"Grafana: {args.grafana_url}")
    logger.info(f"API Key: {'configured' if grafana_api_key else 'MISSING'}")
    logger.info(f"Poll Interval: {args.poll_interval}s")
    logger.info(f"Max Steps: {args.max_steps}")
    logger.info(f"Report Dir: {args.report_dir}")
    logger.info("=" * 60)

    from ares.agents.blue import InvestigationOrchestrator
    from ares.core.alert_correlation import AlertCorrelator
    from ares.integrations.mitre import MITREAttackClient
    from ares.tools.blue import GrafanaTools

    logger.info("Loading MITRE ATT&CK data from STIX repository...")
    mitre_client = MITREAttackClient()
    await mitre_client.load()
    # Accessing protected members for logging/diagnostics only - not modifying internal state
    techniques_count = len(mitre_client._techniques)
    tactics_count = len(mitre_client._tactics)
    logger.success(f"Loaded {techniques_count} techniques, {tactics_count} tactics")

    # Track if the operation is currently running (for alert retrieval strategy)
    operation_is_running = False

    # Auto-discover operations if none explicitly specified
    # This makes operation-awareness the default behavior
    if not args.operation_id and not args.latest:
        from ares.core.config import get_redis_url

        auto_redis_url = args.redis_url or get_redis_url()
        if auto_redis_url:
            # First check for running operations
            running_op = await discover_running_operation(auto_redis_url)
            if running_op:
                logger.info(f"Auto-discovered running operation: {running_op}")
                args.operation_id = running_op
                operation_is_running = True
            else:
                # Check for recently completed operations
                recent_op = await discover_recent_completed_operation(auto_redis_url)
                if recent_op:
                    logger.info(f"Auto-discovered recent operation: {recent_op}")
                    args.operation_id = recent_op

    # Load red team operation context if specified or discovered
    attack_context = None
    if args.operation_id or args.latest:
        from ares.core.config import get_redis_url
        from ares.core.redis_client import create_verified_redis_client
        from ares.eval.detection_playbook import create_detection_playbook

        redis_url = args.redis_url or get_redis_url()
        logger.info("Loading red team operation context from Redis...")

        try:
            client = await create_verified_redis_client(redis_url, decode_responses=False)

            # Resolve operation ID
            operation_id = args.operation_id
            if args.latest and not operation_id:
                # Find latest operation (prefer running)
                from ares.core.task_queue import RedisTaskQueue

                lock_keys = await client.keys(f"{RedisTaskQueue.LOCK_PREFIX}:*")
                running_ops: set[str] = set()
                for key in lock_keys:
                    key_str = key.decode() if isinstance(key, bytes) else key
                    parts = key_str.split(":", 2)
                    if len(parts) >= 3:
                        running_ops.add(parts[2])

                meta_keys = await client.keys("ares:op:*:meta")
                if meta_keys:
                    latest_op = None
                    latest_running_op = None
                    for key in meta_keys:
                        key_str = key.decode() if isinstance(key, bytes) else key
                        parts = key_str.split(":")
                        if len(parts) >= 3:
                            op_id = parts[2]
                            if not latest_op or op_id > latest_op:
                                latest_op = op_id
                            if op_id in running_ops and (
                                not latest_running_op or op_id > latest_running_op
                            ):
                                latest_running_op = op_id
                    # Prefer running operation
                    if latest_running_op:
                        operation_id = latest_running_op
                        operation_is_running = True
                    elif latest_op:
                        operation_id = latest_op

            # Check if operation is running (if not already determined)
            if operation_id and not operation_is_running:
                from ares.core.task_queue import RedisTaskQueue

                lock_key = f"{RedisTaskQueue.LOCK_PREFIX}:{operation_id}"
                lock_exists = await client.exists(lock_key)
                operation_is_running = bool(lock_exists)

            if operation_id:
                from ares.cli_ops import _load_state_from_redis
                from ares.core.evidence_validation import (
                    extract_domains_from_red_team_state,
                    set_target_domains,
                )

                state = await _load_state_from_redis(client, operation_id)
                if state:
                    playbook = create_detection_playbook(state)

                    # Extract and set target domain scope for evidence filtering
                    target_domains = extract_domains_from_red_team_state(state)
                    if target_domains:
                        set_target_domains(target_domains)
                        logger.info(f"Evidence scope set to domains: {target_domains}")

                    attack_context = {
                        "operation_id": operation_id,
                        "playbook": playbook,
                        "attack_window_start": playbook.attack_window_start,
                        "attack_window_end": playbook.attack_window_end,
                        "techniques_used": playbook.techniques_used,
                        "priority_queries": playbook.priority_queries[:10],
                        "detection_targets": playbook.detection_targets[:20],
                        "target_domains": list(target_domains),
                    }
                    logger.success(f"Loaded red team operation: {operation_id}")
                    logger.info(
                        f"Attack window: {playbook.attack_window_start.strftime('%Y-%m-%d %H:%M')} "
                        f"to {playbook.attack_window_end.strftime('%Y-%m-%d %H:%M')}"
                    )
                    logger.info(f"Techniques used: {len(playbook.techniques_used)}")
                    logger.info(f"Priority queries: {len(playbook.priority_queries)}")
                else:
                    logger.warning(f"No state found for operation: {operation_id}")
            else:
                logger.warning("No red team operations found in Redis")

            await client.aclose()
        except Exception as e:
            logger.warning(f"Failed to load red team operation: {e}")
            logger.warning("Continuing without attack context")

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Reports: {report_dir}")

    # Determine Redis availability for multi-agent support
    from ares.core.config import get_redis_url

    blue_redis_url = args.redis_url or os.getenv("ARES_REDIS_URL", "") or get_redis_url()

    # Create orchestrators based on configuration
    single_agent_orchestrator: InvestigationOrchestratorProtocol | None = None
    multi_agent_orchestrator: InvestigationOrchestratorProtocol | None = None

    if args.multi_agent:
        # Force multi-agent mode for ALL alerts
        if not blue_redis_url:
            logger.error(
                "Multi-agent mode requires Redis. "
                "Set --args.redis-url or ARES_REDIS_URL environment variable."
            )
            return

        from ares.agents.blue.multi_agent_orchestrator import BlueTeamOrchestrator

        logger.info(f"Mode: MULTI-AGENT (Redis: {blue_redis_url})")
        multi_agent_orchestrator = BlueTeamOrchestrator(
            model=model,
            grafana_url=args.grafana_url,
            grafana_api_key=grafana_api_key,
            mitre_client=mitre_client,
            report_dir=report_dir,
            max_steps=args.max_steps,
            redis_url=blue_redis_url,
            attack_context=attack_context,
        )
    elif args.auto_route and blue_redis_url:
        # Auto-routing mode: create both orchestrators
        from ares.agents.blue.multi_agent_orchestrator import BlueTeamOrchestrator

        logger.info(f"Mode: AUTO-ROUTE (Redis: {blue_redis_url})")
        logger.info("  HIGH/CRITICAL alerts -> multi-agent")
        logger.info("  Other alerts -> single-agent")

        single_agent_orchestrator = InvestigationOrchestrator(
            model=model,
            grafana_url=args.grafana_url,
            grafana_api_key=grafana_api_key,
            mitre_client=mitre_client,
            report_dir=report_dir,
            max_steps=args.max_steps,
            attack_context=attack_context,
        )
        multi_agent_orchestrator = BlueTeamOrchestrator(
            model=model,
            grafana_url=args.grafana_url,
            grafana_api_key=grafana_api_key,
            mitre_client=mitre_client,
            report_dir=report_dir,
            max_steps=args.max_steps,
            redis_url=blue_redis_url,
            attack_context=attack_context,
        )
    else:
        # Single-agent mode only
        if args.auto_route and not blue_redis_url:
            logger.warning(
                "Auto-routing enabled but Redis unavailable. "
                "Using single-agent for all alerts. "
                "Set ARES_REDIS_URL to enable multi-agent for HIGH/CRITICAL alerts."
            )
        logger.info("Mode: SINGLE-AGENT")
        single_agent_orchestrator = InvestigationOrchestrator(
            model=model,
            grafana_url=args.grafana_url,
            grafana_api_key=grafana_api_key,
            mitre_client=mitre_client,
            report_dir=report_dir,
            max_steps=args.max_steps,
            attack_context=attack_context,
        )

    # Helper to get the appropriate orchestrator for an alert
    def get_orchestrator_for_alert(
        alert_severity: str,
    ) -> tuple[InvestigationOrchestratorProtocol, str]:
        """Get the appropriate orchestrator based on alert severity.

        Returns:
            Tuple of (orchestrator, mode_name) for logging.
        """
        if args.multi_agent and multi_agent_orchestrator is not None:
            # Force multi-agent mode
            return multi_agent_orchestrator, "multi-agent"

        if (
            args.auto_route
            and should_use_multi_agent(alert_severity)
            and multi_agent_orchestrator is not None
        ):
            return multi_agent_orchestrator, "multi-agent (auto-routed)"

        # Fallback to single-agent
        if single_agent_orchestrator is not None:
            return single_agent_orchestrator, "single-agent"

        # This should never happen - at least one orchestrator should exist
        raise RuntimeError("No orchestrator available")

    grafana = GrafanaTools(
        base_url=args.grafana_url,
        api_key=grafana_api_key,
    )

    alert_correlator = AlertCorrelator()
    logger.info("Alert correlation enabled - related alerts will be clustered")

    # Track investigated alerts and states for consolidated report
    investigated_fingerprints: set[str] = set()
    completed_investigations: list[InvestigationState] = []
    operation_started_at = datetime.now(timezone.utc)

    if args.once:
        logger.info("Processing current alerts once and exiting...")
    else:
        logger.info(f"Polling for alerts every {args.poll_interval}s...")
        logger.info("Press Ctrl+C to stop")
    logger.info("")

    try:
        while True:
            try:
                # Retrieve alerts using operation-aware strategy
                if attack_context:
                    window_start = attack_context["attack_window_start"]
                    window_end = attack_context["attack_window_end"]

                    if operation_is_running:
                        # Running operation: combine firing + historical alerts
                        firing_alerts = await grafana.get_firing_alerts()
                        historical_alerts = await grafana.get_alerts_in_time_range(
                            window_start, window_end
                        )
                        alerts = merge_alerts(firing_alerts, historical_alerts)
                        logger.debug(
                            f"Operation-aware alerts: {len(firing_alerts)} firing + "
                            f"{len(historical_alerts)} historical = {len(alerts)} total"
                        )
                    else:
                        # Completed operation: historical alerts only
                        alerts = await grafana.get_alerts_in_time_range(window_start, window_end)
                        if not alerts:
                            # Fallback to firing alerts if no historical found
                            logger.info(
                                "No historical alerts found in operation window, "
                                "checking currently firing alerts"
                            )
                            alerts = await grafana.get_firing_alerts()
                        else:
                            logger.info(
                                f"Retrieved {len(alerts)} alerts from operation time window"
                            )
                else:
                    # No operation context: current behavior
                    alerts = await grafana.get_firing_alerts()

                for alert in alerts:
                    fingerprint = alert.get("fingerprint", "")

                    # Skip already investigated
                    if fingerprint in investigated_fingerprints:
                        continue

                    alert_name = alert.get("labels", {}).get("alertname", "unknown")
                    severity = alert.get("labels", {}).get("severity", "unknown")

                    # Skip infrastructure/health alerts - not security events
                    if alert_name == "DatasourceNoData":
                        logger.debug(f"Skipping infrastructure alert: {alert_name}")
                        continue

                    logger.info("")
                    logger.info("=" * 60)
                    logger.info(f"NEW ALERT: {alert_name}")
                    logger.info(f"Severity: {severity}")
                    logger.info(f"Fingerprint: {fingerprint}")
                    logger.info("=" * 60)

                    investigated_fingerprints.add(fingerprint)

                    cluster = alert_correlator.add_alert(alert)
                    correlation_context = alert_correlator.get_cluster_context(alert)
                    related_count = correlation_context.get("related_alerts", 0)
                    if related_count > 0:
                        logger.info(
                            f"Alert correlation: {related_count} related alerts in cluster "
                            f"{cluster.cluster_id}"
                        )

                    # Route alert to appropriate orchestrator based on severity
                    orchestrator, orchestrator_mode = get_orchestrator_for_alert(severity)
                    logger.info(f"Investigation mode: {orchestrator_mode}")

                    # Run investigation with correlation context
                    try:
                        result = await orchestrator.investigate(
                            alert, correlation_context=correlation_context
                        )

                        logger.success("")
                        logger.success("INVESTIGATION COMPLETE")
                        logger.success(f"  Status: {result['status']}")
                        logger.success(f"  Evidence: {result['evidence_count']} items")
                        logger.success(f"  Techniques: {len(result['techniques_identified'])}")
                        logger.success(f"  Pyramid Level: {result['highest_pyramid_level']}/6")

                        # Capture state for consolidated report
                        if result.get("state"):
                            completed_investigations.append(result["state"])

                    except Exception as e:
                        logger.error(f"Investigation failed: {e}")

                # If running in once mode, exit after processing current alerts
                if args.once:
                    logger.info("")
                    logger.info("=" * 60)
                    logger.info(f"Processed {len(investigated_fingerprints)} alerts")
                    logger.info("Exiting (--once mode)")
                    logger.info("=" * 60)
                    break

                # Wait before next poll
                await asyncio.sleep(args.poll_interval)

            except KeyboardInterrupt:
                logger.info("")
                logger.info("Shutting down gracefully...")
                break

            except Exception as e:
                logger.error(f"Polling error: {e}")
                await asyncio.sleep(args.poll_interval)

    finally:
        # Generate consolidated operation report if we have completed investigations
        if completed_investigations:
            try:
                from ares.reports import (
                    create_operation_from_investigations,
                    generate_operation_report,
                )

                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
                operation_id = f"blue-op-{timestamp}"

                operation = create_operation_from_investigations(
                    investigations=completed_investigations,
                    operation_id=operation_id,
                )
                operation.started_at = operation_started_at
                operation.completed_at = datetime.now(timezone.utc)

                report_content = generate_operation_report(operation)

                report_filename = f"blueteam-{operation_id}.md"
                report_path = report_dir / report_filename
                report_path.write_text(report_content)

                logger.info("")
                logger.info("=" * 60)
                logger.success("CONSOLIDATED OPERATION REPORT")
                logger.success(f"  Operation ID: {operation_id}")
                logger.success(f"  Investigations: {len(completed_investigations)}")
                logger.success(f"  Evidence: {len(operation.all_evidence)}")
                logger.success(f"  Techniques: {len(operation.all_techniques)}")
                logger.success(f"  Pyramid Level: {operation.highest_pyramid_level}/6")
                logger.success(f"  Report: {report_path}")
                logger.info("=" * 60)

            except Exception as e:
                logger.error(f"Failed to generate consolidated report: {e}")

        # Clean up MCP connections on shutdown
        logger.info("Cleaning up connections...")
        if single_agent_orchestrator is not None:
            await single_agent_orchestrator._shutdown_mcp()
        if multi_agent_orchestrator is not None:
            await multi_agent_orchestrator._shutdown_mcp()
        logger.success("Shutdown complete")


# Cyclopts decorator typing not yet fully supported by type checkers
@app.command  # type: ignore[untyped-decorator]
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

    model = _resolve_model(args.model)
    if not model:
        logger.error("No model specified. Set ARES_MODEL or pass --args.model.")
        return

    if alert_json.startswith("{"):
        alert = json.loads(alert_json)
    else:
        alert = json.loads(Path(alert_json).read_text())

    # Prefer GRAFANA_SERVICE_ACCOUNT_TOKEN, fallback to GRAFANA_API_KEY for compatibility
    grafana_api_key = (
        args.grafana_api_key
        or os.getenv("GRAFANA_SERVICE_ACCOUNT_TOKEN", "")
        or os.getenv("GRAFANA_API_KEY", "")
    )
    dreadnode_token = dn_args.token or os.getenv("DREADNODE_API_KEY", "")

    dn = _configure_dreadnode()
    dn.configure(
        server=dn_args.server,
        token=dreadnode_token,
        organization=dn_args.organization,
        workspace=dn_args.workspace,
        project=dn_args.project,
        console=dn_args.console,
    )

    from ares.integrations.mitre import MITREAttackClient

    logger.info("Loading MITRE ATT&CK data...")
    mitre_client = MITREAttackClient()
    await mitre_client.load()

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    # Determine Redis availability and routing mode
    from ares.core.config import get_redis_url

    blue_redis_url = args.redis_url or os.getenv("ARES_REDIS_URL", "") or get_redis_url()

    # Extract severity for routing
    severity = alert.get("labels", {}).get("severity", "unknown")
    alert_name = alert.get("labels", {}).get("alertname", "unknown")

    # Determine which orchestrator to use
    use_multi = args.multi_agent or (
        args.auto_route and should_use_multi_agent(severity) and blue_redis_url
    )

    # Create orchestrator based on routing decision
    # Use InvestigationOrchestratorProtocol type to handle both orchestrator types
    orchestrator: InvestigationOrchestratorProtocol
    if use_multi:
        if not blue_redis_url:
            logger.error("Multi-agent mode requires Redis. Set --args.redis-url or ARES_REDIS_URL.")
            return

        from ares.agents.blue.multi_agent_orchestrator import BlueTeamOrchestrator

        orchestrator_mode = "multi-agent" if args.multi_agent else "multi-agent (auto-routed)"
        logger.info(f"Mode: {orchestrator_mode} (severity: {severity})")
        orchestrator = BlueTeamOrchestrator(
            model=model,
            grafana_url=args.grafana_url,
            grafana_api_key=grafana_api_key,
            mitre_client=mitre_client,
            report_dir=report_dir,
            max_steps=args.max_steps,
            redis_url=blue_redis_url,
        )
    else:
        from ares.agents.blue import InvestigationOrchestrator

        logger.info(f"Mode: single-agent (severity: {severity})")
        orchestrator = InvestigationOrchestrator(
            model=model,
            grafana_url=args.grafana_url,
            grafana_api_key=grafana_api_key,
            mitre_client=mitre_client,
            report_dir=report_dir,
            max_steps=args.max_steps,
        )

    # Run investigation
    logger.info(f"Investigating alert: {alert_name}")

    result = await orchestrator.investigate(alert)

    logger.success("")
    logger.success("INVESTIGATION COMPLETE")
    logger.success(f"  Status: {result['status']}")
    logger.success(f"  Evidence: {result['evidence_count']} items")
    logger.success(f"  Techniques: {len(result['techniques_identified'])}")
    logger.success(f"  Pyramid Level: {result['highest_pyramid_level']}/6")


@dataclass
class MultiAgentArgs:
    """Multi-agent red team arguments.

    Attributes:
        target_domain: Target domain (e.g., contoso.local).
        target_ips: Comma-separated list of target IPs.
        config_file: Path to config file (auto-detected if not specified).
        redis_url: Redis URL for state persistence (from config if not specified).
        initial_user: Optional initial username.
        initial_password: Optional initial password.
        initial_domain: Optional initial domain for credentials.
        namespace: Kubernetes namespace for agent pods (from config if not specified).
    """

    target_domain: str = ""
    target_ips: str = ""  # Comma-separated
    config_file: str = ""  # Path to config file (auto-detected if empty)
    redis_url: str = ""  # Empty = use config file
    initial_user: str = ""
    initial_password: str = ""  # pragma: allowlist secret
    initial_domain: str = ""
    namespace: str = ""  # Empty = use config file


# Cyclopts decorator typing not yet fully supported by type checkers
@app.command(name="multi-agent")  # type: ignore[untyped-decorator]
async def multi_agent(
    target_domain: str,
    target_ips: str,
    *,
    multi_args: MultiAgentArgs | None = None,
    args: Args | None = None,
    dn_args: DreadnodeArgs | None = None,
) -> None:
    """
    Execute a multi-agent red team operation.

    This command coordinates multiple specialized agents:
    - Orchestrator (ares-recon): Coordinates operation, does initial recon
    - Credential Access: Active credential attacks (AS-REP roasting, Kerberoasting, LSASS dumping)
    - Cracker: Hash cracking with hashcat/john
    - ACL: BloodHound analysis and ACL abuse
    - PrivEsc: ADCS, delegation, MSSQL exploitation
    - Lateral: Lateral movement and credential harvesting
    - Coercion: Network coercion (responder, mitm6)

    Args:
        target_domain: Target domain (e.g., contoso.local)
        target_ips: Comma-separated list of target IPs

    Example:
        uv run ares multi-agent contoso.local "192.168.58.10,192.168.58.11"
        uv run ares multi-agent contoso.local "192.168.58.1" --multi-args.redis-url redis://redis:6379
    """
    import uuid

    from ares.core.config import load_config

    args = args or Args()
    dn_args = dn_args or DreadnodeArgs()
    multi_args = multi_args or MultiAgentArgs()

    model = _resolve_model(args.model, prefer_orchestrator=True)
    if not model:
        logger.error(
            "No model specified. Set ARES_ORCHESTRATOR_MODEL/ARES_MODEL or pass --args.model."
        )
        return

    # Load config file for defaults
    config = load_config(multi_args.config_file or None)

    # Use config values if CLI args not specified
    redis_url = multi_args.redis_url or config.redis_url
    namespace = multi_args.namespace or config.namespace

    # Parse target IPs
    ips = [ip.strip() for ip in target_ips.split(",") if ip.strip()]
    if not ips:
        logger.error("No target IPs provided")
        return

    # Configure Dreadnode (optional - don't fail if platform unavailable)
    dreadnode_token = dn_args.token or os.getenv("DREADNODE_API_KEY", "")

    try:
        dn = _configure_dreadnode()
        dn.configure(
            server=dn_args.server,
            token=dreadnode_token,
            organization=dn_args.organization,
            workspace=dn_args.workspace,
            project=dn_args.project,
            console=dn_args.console,
        )
    except Exception as e:
        logger.warning(f"Dreadnode platform unavailable, continuing without telemetry: {e}")

    # Log startup
    logger.info("=" * 60)
    logger.info("ARES MULTI-AGENT RED TEAM OPERATION")
    logger.info("=" * 60)
    logger.info(f"Config: {multi_args.config_file or 'auto-detected'}")
    logger.info(f"Target Domain: {target_domain}")
    logger.info(f"Target IPs: {ips}")
    logger.info(f"Model: {model}")
    logger.info(f"Max Steps: {args.max_steps}")
    logger.info(f"Redis: {redis_url}")
    logger.info(f"Namespace: {namespace}")
    logger.info(f"Report Dir: {args.report_dir}")
    logger.info("=" * 60)

    from ares.core.models import Credential
    from ares.core.orchestrator import run_multi_agent_operation

    # Build initial credential if provided
    initial_cred = None
    if multi_args.initial_user and multi_args.initial_password:
        initial_cred = Credential(
            username=multi_args.initial_user,
            password=multi_args.initial_password,
            domain=multi_args.initial_domain or target_domain,
            source="cli_provided",
        )
        logger.info(f"Initial credential: {initial_cred.domain}\\{initial_cred.username}")

    operation_id = f"multiagent-{uuid.uuid4().hex[:8]}"

    logger.info("")
    logger.info(f"Starting multi-agent operation {operation_id}...")
    logger.info("")

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Reports: {report_dir}")

    try:
        result = await run_multi_agent_operation(
            operation_id=operation_id,
            target_domain=target_domain,
            target_ips=ips,
            initial_credential=initial_cred,
            redis_url=redis_url,
            namespace=namespace,
            model=model,
            max_steps=args.max_steps,
            report_dir=report_dir,
        )

        logger.success("")
        logger.success("=" * 60)
        logger.success("MULTI-AGENT OPERATION COMPLETE")
        logger.success("=" * 60)
        logger.success(f"  Operation ID: {result['operation_id']}")
        logger.success(f"  Success: {result['success']}")
        logger.success(f"  Duration: {result['duration_seconds']:.1f}s")
        logger.success(f"  Hosts Discovered: {result['hosts_discovered']}")
        logger.success(f"  Credentials Found: {result['credentials_discovered']}")
        logger.success(f"  Hashes Captured: {result['hashes_discovered']}")
        logger.success(f"  Vulnerabilities: {result['vulnerabilities_discovered']}")
        logger.success(f"  Exploited: {result['vulnerabilities_exploited']}")

        if result.get("domain_admin_achieved"):
            logger.success("  🎯 DOMAIN ADMIN: ACHIEVED")
            logger.success(f"  Attack Path: {result.get('domain_admin_path', 'N/A')}")
        if result.get("golden_ticket_forged"):
            logger.success("  🎫 GOLDEN TICKET: FORGED")

        if result.get("report_path"):
            logger.success(f"  Report: {result['report_path']}")
        logger.success("")

    except Exception as e:
        logger.error("")
        logger.error(f"Multi-agent operation failed: {e}")
        raise


@dataclass
class WorkerArgs:
    """Worker agent arguments.

    Attributes:
        role: Worker role (credential_access, cracker, acl, privesc, lateral, coercion).
        operation_id: Operation ID to join (required).
        config_file: Path to config file (auto-detected if not specified).
        redis_url: Redis URL for dispatcher connection (from config if not specified).
        model: LLM model to use (from config if not specified).
        max_steps: Maximum agent steps per task.
    """

    role: str = ""
    operation_id: str = ""
    config_file: str = ""  # Path to config file (auto-detected if empty)
    redis_url: str = ""  # Empty = use config file
    model: str = ""  # Empty = use config file
    max_steps: int = 0  # 0 = use role default from config


# Cyclopts decorator typing not yet fully supported by type checkers
@app.command(name="worker")  # type: ignore[untyped-decorator]
async def worker(
    role: str,
    operation_id: str = "",
    *,
    worker_args: WorkerArgs | None = None,
    dn_args: DreadnodeArgs | None = None,
) -> None:
    """
    Run a specialized worker agent that processes tasks from the dispatcher.

    This command starts a worker agent that:
    - Connects to Redis and discovers active operations (if operation_id not provided)
    - Registers with the dispatcher
    - Polls for assigned tasks based on its role
    - Processes tasks using specialized toolsets
    - Reports results back to the orchestrator

    Worker roles:
    - recon: Recon and reconnaissance
    - credential_access: Active credential attacks (AS-REP roasting, Kerberoasting, LSASS dumping)
    - cracker: Hash cracking with hashcat/john
    - acl: BloodHound analysis and ACL abuse
    - privesc: ADCS, delegation, MSSQL exploitation
    - lateral: Lateral movement and credential harvesting
    - coercion: Network coercion (responder, mitm6)

    Args:
        role: Worker role (recon, credential_access, cracker, acl, privesc, lateral, coercion)
        operation_id: Operation ID to join (optional - will auto-discover if not provided)

    Example:
        # Join specific operation
        uv run ares worker cracker op-12345678 --worker-args.redis-url redis://redis:6379

        # Auto-discover active operation
        uv run ares worker lateral --worker-args.redis-url redis://redis:6379
    """
    from ares.core.config import get_agent_config, load_config

    worker_args = worker_args or WorkerArgs()
    dn_args = dn_args or DreadnodeArgs()

    # Validate role
    valid_roles = [
        "recon",
        "credential_access",
        "cracker",
        "acl",
        "privesc",
        "lateral",
        "coercion",
    ]
    if role not in valid_roles:
        logger.error(f"Invalid role: {role}. Must be one of: {', '.join(valid_roles)}")
        return

    # Load config file for defaults
    config = load_config(worker_args.config_file or None)
    agent_config = get_agent_config(role)

    # Use config values if CLI args not specified
    redis_url = worker_args.redis_url or config.redis_url
    model = worker_args.model or os.getenv(f"ARES_AGENT_{role.upper()}_MODEL")
    if not model:
        model = os.getenv("ARES_WORKER_MODEL") or os.getenv("ARES_MODEL")
    if not model and operation_id:
        model = agent_config.model
    # If no model specified and no operation_id, the worker will discover an operation
    # from Redis and fetch the model from the operation's configuration. This allows
    # workers to start without ARES_MODEL in the ConfigMap.
    if not model and not operation_id:
        logger.info("No model specified - will fetch from operation config after discovery")
    # max_steps from CLI takes precedence, otherwise use YAML config (single source of truth)
    max_steps = worker_args.max_steps if worker_args.max_steps > 0 else agent_config.max_steps

    # Configure Dreadnode (optional - don't fail if platform unavailable)
    dreadnode_token = dn_args.token or os.getenv("DREADNODE_API_KEY", "")

    try:
        dn = _configure_dreadnode()
        dn.configure(
            server=dn_args.server,
            token=dreadnode_token,
            organization=dn_args.organization,
            workspace=dn_args.workspace,
            project=dn_args.project,
            console=dn_args.console,
        )
    except Exception as e:
        logger.warning(f"Dreadnode platform unavailable, continuing without telemetry: {e}")

    if not operation_id:
        operation_id = os.getenv("OPERATION_ID", "")

    # Log startup
    logger.info("=" * 60)
    logger.info(f"ARES WORKER AGENT: {role.upper()}")
    logger.info("=" * 60)
    logger.info(f"Config: {worker_args.config_file or 'auto-detected'}")
    logger.info(f"Operation ID: {operation_id or '(auto-discover)'}")
    logger.info(f"Role: {role}")
    logger.info(f"Model: {model}")
    logger.info(f"Max Steps: {max_steps}")
    logger.info(f"Redis: {redis_url}")
    logger.info(f"Pod: {os.environ.get('HOSTNAME', 'local')}")
    logger.info("=" * 60)

    from ares.core.models import AgentRole
    from ares.core.worker import run_worker

    # Convert string role to AgentRole enum
    role_mapping = {
        "recon": AgentRole.RECON,
        "credential_access": AgentRole.CREDENTIAL_ACCESS,
        "cracker": AgentRole.CRACKER,
        "acl": AgentRole.ACL,
        "privesc": AgentRole.PRIVESC,
        "lateral": AgentRole.LATERAL,
        "coercion": AgentRole.COERCION,
    }
    agent_role = role_mapping[role]

    try:
        await run_worker(
            role=agent_role,
            operation_id=operation_id or None,
            redis_url=redis_url,
            model=model or None,  # Pass None to let run_worker fetch from Redis
            max_steps=max_steps if max_steps > 0 else None,
        )
    except KeyboardInterrupt:
        logger.info("Worker interrupted by user")
    except Exception as e:
        logger.error(f"Worker failed: {e}")
        raise


@dataclass
class EvalArgs:
    """Evaluation arguments.

    Attributes:
        output_dir: Directory for evaluation results.
        poll_timeout: Seconds to wait for alerts per scenario.
        ci: CI mode - output JSON to stdout and use exit codes.
        synthetic: Use synthetic alerts (don't wait for real Grafana alerts).
        min_score: Minimum overall score to pass (0.0-1.0, CI mode only).
        min_ioc_rate: Minimum IOC detection rate to pass (0.0-1.0, CI mode only).
        min_technique_rate: Minimum technique coverage to pass (0.0-1.0, CI mode only).
        parallel: Number of scenarios to run in parallel (dataset only).
        multi_agent: Force multi-agent for ALL alerts.
        auto_route: Enable severity-based routing (multi-agent for HIGH/CRITICAL).
        redis_url: Redis URL for multi-agent state (required for multi_agent/auto_route).
    """

    output_dir: str = "./eval_results"
    poll_timeout: int = 60
    ci: bool = False
    synthetic: bool = False
    min_score: float = 0.5
    min_ioc_rate: float = 0.5
    min_technique_rate: float = 0.5
    parallel: int = 1
    multi_agent: bool = False
    auto_route: bool = True
    redis_url: str = ""


# Cyclopts decorator typing not yet fully supported by type checkers
@app.command(name="evaluate")  # type: ignore[untyped-decorator]
async def evaluate(
    red_state_file: str,
    *,
    args: Args | None = None,
    eval_args: EvalArgs | None = None,
    dn_args: DreadnodeArgs | None = None,
) -> None:
    """
    Evaluate blue team investigation against a red team operation.

    Takes a red team state file (JSON) and evaluates the blue team's
    ability to detect and investigate the activities. Polls Grafana
    for real alerts - if no alert fired, that's a detection gap finding.

    Args:
        red_state_file: Path to red team state JSON file.

    Example:
        uv run ares evaluate ./red_state.json
        uv run ares evaluate ./red_state.json --args.model claude-sonnet-4-20250514
    """
    args = args or Args()
    eval_args = eval_args or EvalArgs()
    dn_args = dn_args or DreadnodeArgs()

    model = _resolve_model(args.model)
    if not model:
        logger.error("No model specified. Set ARES_MODEL or pass --args.model.")
        return

    # Prefer GRAFANA_SERVICE_ACCOUNT_TOKEN, fallback to GRAFANA_API_KEY for compatibility
    grafana_api_key = (
        args.grafana_api_key
        or os.getenv("GRAFANA_SERVICE_ACCOUNT_TOKEN", "")
        or os.getenv("GRAFANA_API_KEY", "")
    )
    dreadnode_token = dn_args.token or os.getenv("DREADNODE_API_KEY", "")

    # Configure Dreadnode (also configures LiteLLM environment)
    dn = _configure_dreadnode()
    try:
        dn.configure(
            server=dn_args.server,
            token=dreadnode_token,
            organization=dn_args.organization,
            workspace=dn_args.workspace,
            project=dn_args.project,
            console=dn_args.console,
        )
    except Exception as e:
        logger.warning(f"Dreadnode platform unavailable: {e}")

    # Validate inputs
    state_path = Path(red_state_file)
    if not state_path.exists():
        logger.error(f"Red team state file not found: {state_path}")
        return

    from ares.eval import EvaluationRunner, EvaluationScenario

    # Resolve redis_url for multi-agent/auto-route mode
    eval_redis_url = eval_args.redis_url
    if (eval_args.multi_agent or eval_args.auto_route) and not eval_redis_url:
        from ares.core.config import get_redis_url

        eval_redis_url = os.getenv("ARES_REDIS_URL", "") or get_redis_url()

    # Only fail if multi_agent is explicitly set and no Redis
    if eval_args.multi_agent and not eval_redis_url:
        logger.error(
            "Multi-agent mode requires Redis. "
            "Set --eval-args.redis-url or ARES_REDIS_URL environment variable."
        )
        return

    # Determine routing mode for logging
    if eval_args.multi_agent:
        mode_str = "multi-agent (forced)"
    elif eval_args.auto_route and eval_redis_url:
        mode_str = "auto-route (HIGH/CRITICAL -> multi-agent)"
    else:
        mode_str = "single-agent"

    # Log startup
    logger.info("=" * 60)
    logger.info("ARES BLUE TEAM EVALUATION")
    logger.info("=" * 60)
    logger.info(f"Red State: {state_path}")
    logger.info(f"Model: {model}")
    logger.info(f"Grafana: {args.grafana_url}")
    logger.info(f"Poll Timeout: {eval_args.poll_timeout}s")
    logger.info(f"Output Dir: {eval_args.output_dir}")
    logger.info(f"Mode: {mode_str}")
    logger.info("=" * 60)

    runner = EvaluationRunner(
        model=model,
        grafana_url=args.grafana_url,
        grafana_api_key=grafana_api_key,
        max_steps=args.max_steps,
        output_dir=eval_args.output_dir,
        multi_agent=eval_args.multi_agent,
        auto_route=eval_args.auto_route,
        redis_url=eval_redis_url,
    )

    scenario = EvaluationScenario(
        red_state=state_path,
        name=state_path.stem,
    )

    with dn.run(tags=["blue-team-evaluation", state_path.stem]):
        result = await runner.evaluate_scenario(
            scenario,
            poll_timeout_seconds=eval_args.poll_timeout,
            inject_synthetic=eval_args.synthetic,
        )

    # CI mode: JSON output and exit codes
    if eval_args.ci:
        import json
        import sys

        # Check pass/fail against thresholds
        passed = (
            result.overall_score >= eval_args.min_score
            and result.ioc_detection_rate >= eval_args.min_ioc_rate
            and result.technique_coverage >= eval_args.min_technique_rate
        )

        output = {
            "passed": passed,
            "result": result.to_dict(),
            "thresholds": {
                "min_score": eval_args.min_score,
                "min_ioc_rate": eval_args.min_ioc_rate,
                "min_technique_rate": eval_args.min_technique_rate,
            },
        }
        print(json.dumps(output, indent=2, default=str))

        # Exit with appropriate code
        sys.exit(0 if passed else 1)

    logger.success("")
    logger.success("=" * 60)
    logger.success("EVALUATION COMPLETE")
    logger.success("=" * 60)
    logger.success(result.to_summary())
    logger.success("")


# Cyclopts decorator typing not yet fully supported by type checkers
@app.command(name="evaluate-dataset")  # type: ignore[untyped-decorator]
async def evaluate_dataset(
    dataset_path: str,
    *,
    args: Args | None = None,
    eval_args: EvalArgs | None = None,
    dn_args: DreadnodeArgs | None = None,
) -> None:
    """
    Evaluate blue team against a dataset of red team operations.

    Takes either:
    - A directory of red team state JSON files
    - A JSON file defining a dataset of scenarios

    Example:
        uv run ares evaluate-dataset ./red_states/
        uv run ares evaluate-dataset ./scenarios.json --eval-args.output-dir ./results/
    """
    args = args or Args()
    eval_args = eval_args or EvalArgs()
    dn_args = dn_args or DreadnodeArgs()

    model = _resolve_model(args.model)
    if not model:
        logger.error("No model specified. Set ARES_MODEL or pass --args.model.")
        return

    # Prefer GRAFANA_SERVICE_ACCOUNT_TOKEN, fallback to GRAFANA_API_KEY for compatibility
    grafana_api_key = (
        args.grafana_api_key
        or os.getenv("GRAFANA_SERVICE_ACCOUNT_TOKEN", "")
        or os.getenv("GRAFANA_API_KEY", "")
    )
    dreadnode_token = dn_args.token or os.getenv("DREADNODE_API_KEY", "")

    # Configure Dreadnode (also configures LiteLLM environment)
    dn = _configure_dreadnode()
    try:
        dn.configure(
            server=dn_args.server,
            token=dreadnode_token,
            organization=dn_args.organization,
            workspace=dn_args.workspace,
            project=dn_args.project,
            console=dn_args.console,
        )
    except Exception as e:
        logger.warning(f"Dreadnode platform unavailable: {e}")

    # Load dataset
    dataset_path_obj = Path(dataset_path)
    if not dataset_path_obj.exists():
        logger.error(f"Dataset path not found: {dataset_path}")
        return

    from ares.eval import EvaluationDataset, EvaluationRunner

    if dataset_path_obj.is_dir():
        dataset = EvaluationDataset.from_directory(dataset_path_obj)
    elif dataset_path_obj.suffix == ".json":
        dataset = EvaluationDataset.from_json(dataset_path_obj)
    else:
        logger.error("Dataset must be a directory or JSON file")
        return

    if not dataset.scenarios:
        logger.error("No scenarios found in dataset")
        return

    # Resolve redis_url for multi-agent/auto-route mode
    eval_redis_url = eval_args.redis_url
    if (eval_args.multi_agent or eval_args.auto_route) and not eval_redis_url:
        from ares.core.config import get_redis_url

        eval_redis_url = os.getenv("ARES_REDIS_URL", "") or get_redis_url()

    # Only fail if multi_agent is explicitly set and no Redis
    if eval_args.multi_agent and not eval_redis_url:
        logger.error(
            "Multi-agent mode requires Redis. "
            "Set --eval-args.redis-url or ARES_REDIS_URL environment variable."
        )
        return

    # Determine routing mode for logging
    if eval_args.multi_agent:
        mode_str = "multi-agent (forced)"
    elif eval_args.auto_route and eval_redis_url:
        mode_str = "auto-route (HIGH/CRITICAL -> multi-agent)"
    else:
        mode_str = "single-agent"

    # Log startup
    logger.info("=" * 60)
    logger.info("ARES BLUE TEAM DATASET EVALUATION")
    logger.info("=" * 60)
    logger.info(f"Dataset: {dataset.name}")
    logger.info(f"Scenarios: {len(dataset)}")
    logger.info(f"Model: {model}")
    logger.info(f"Grafana: {args.grafana_url}")
    logger.info(f"Poll Timeout: {eval_args.poll_timeout}s")
    logger.info(f"Output Dir: {eval_args.output_dir}")
    logger.info(f"Mode: {mode_str}")
    logger.info("=" * 60)

    runner = EvaluationRunner(
        model=model,
        grafana_url=args.grafana_url,
        grafana_api_key=grafana_api_key,
        max_steps=args.max_steps,
        output_dir=eval_args.output_dir,
        inject_synthetic_alerts=eval_args.synthetic,
        multi_agent=eval_args.multi_agent,
        auto_route=eval_args.auto_route,
        redis_url=eval_redis_url,
    )

    result = await runner.evaluate_dataset(
        dataset,
        poll_timeout_seconds=eval_args.poll_timeout,
        max_concurrent=eval_args.parallel,
    )

    # CI mode: JSON output and exit codes
    if eval_args.ci:
        import json
        import sys

        # Check pass/fail against thresholds
        passed = (
            result.avg_overall_score >= eval_args.min_score
            and result.avg_ioc_detection_rate >= eval_args.min_ioc_rate
            and result.avg_technique_coverage >= eval_args.min_technique_rate
        )

        output = {
            "passed": passed,
            "summary": {
                "count": result.count,
                "pass_rate": result.pass_rate,
                "avg_overall_score": result.avg_overall_score,
                "avg_ioc_detection_rate": result.avg_ioc_detection_rate,
                "avg_technique_coverage": result.avg_technique_coverage,
            },
            "thresholds": {
                "min_score": eval_args.min_score,
                "min_ioc_rate": eval_args.min_ioc_rate,
                "min_technique_rate": eval_args.min_technique_rate,
            },
            "results": result.to_dict(),
        }
        print(json.dumps(output, indent=2, default=str))

        # Exit with appropriate code
        sys.exit(0 if passed else 1)

    logger.success("")
    logger.success("=" * 60)
    logger.success("DATASET EVALUATION COMPLETE")
    logger.success("=" * 60)
    logger.success(result.to_summary())
    logger.success("")


# Cyclopts decorator typing not yet fully supported by type checkers
@app.command  # type: ignore[untyped-decorator]
def version() -> None:
    """Print version information."""


if __name__ == "__main__":
    app()
