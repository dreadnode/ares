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
    """Investigation agent arguments.

    Attributes:
        model: LLM model to use (supports litellm format).
        grafana_url: Grafana URL for alert polling and MCP connection.
        grafana_api_key: Grafana API key (or set GRAFANA_SERVICE_ACCOUNT_TOKEN env var).
        poll_interval: Seconds between alert polling cycles.
        max_steps: Maximum agent steps per investigation.
        report_dir: Directory for markdown reports.
        once: Process current alerts once and exit (default: run forever).
    """

    model: str = "claude-sonnet-4-20250514"
    grafana_url: str = "https://grafana.dev.plundr.ai"
    grafana_api_key: str = ""
    poll_interval: int = 30
    max_steps: int = 150
    report_dir: str = "./reports"  # Relative to CWD
    once: bool = False  # Process current alerts once and exit


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
        uv run python -m ares --model claude-sonnet-4-20250514 --grafana-url http://grafana:3000

    Environment Variables:
        GRAFANA_SERVICE_ACCOUNT_TOKEN: Grafana service account token (preferred)
        GRAFANA_API_KEY: Grafana API key (deprecated, use GRAFANA_SERVICE_ACCOUNT_TOKEN)
        DREADNODE_API_KEY: Dreadnode platform token
        OPENAI_API_KEY / ANTHROPIC_API_KEY: LLM provider keys
    """
    args = args or Args()
    dn_args = dn_args or DreadnodeArgs()

    # Prefer GRAFANA_SERVICE_ACCOUNT_TOKEN, fallback to GRAFANA_API_KEY for compatibility
    grafana_api_key = (
        args.grafana_api_key
        or os.getenv("GRAFANA_SERVICE_ACCOUNT_TOKEN", "")
        or os.getenv("GRAFANA_API_KEY", "")
    )
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

    # Validate required credentials
    if not grafana_api_key:
        logger.warning("=" * 60)
        logger.warning("WARNING: No Grafana API key configured!")
        logger.warning("Set GRAFANA_SERVICE_ACCOUNT_TOKEN environment variable,")
        logger.warning("or use --args.grafana-api-key CLI argument.")
        logger.warning("The agent will not be able to retrieve alerts.")
        logger.warning("=" * 60)

    # Log startup
    logger.info("=" * 60)
    logger.info("ARES SOC INVESTIGATION AGENT")
    logger.info("=" * 60)
    logger.info(f"Model: {args.model}")
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

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Reports: {report_dir}")

    orchestrator = InvestigationOrchestrator(
        model=args.model,
        grafana_url=args.grafana_url,
        grafana_api_key=grafana_api_key,
        mitre_client=mitre_client,
        report_dir=report_dir,
        max_steps=args.max_steps,
    )

    grafana = GrafanaTools(
        base_url=args.grafana_url,
        api_key=grafana_api_key,
    )

    alert_correlator = AlertCorrelator()
    logger.info("Alert correlation enabled - related alerts will be clustered")

    # Track investigated alerts
    investigated_fingerprints: set[str] = set()

    if args.once:
        logger.info("Processing current alerts once and exiting...")
    else:
        logger.info(f"Polling for alerts every {args.poll_interval}s...")
        logger.info("Press Ctrl+C to stop")
    logger.info("")

    try:
        while True:
            try:
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

                    investigated_fingerprints.add(fingerprint)

                    cluster = alert_correlator.add_alert(alert)
                    correlation_context = alert_correlator.get_cluster_context(alert)
                    related_count = correlation_context.get("related_alerts", 0)
                    if related_count > 0:
                        logger.info(
                            f"Alert correlation: {related_count} related alerts in cluster "
                            f"{cluster.cluster_id}"
                        )

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
                        logger.success(f"  Report: {result['report_path']}")

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
        # Clean up MCP connection on shutdown
        logger.info("Cleaning up connections...")
        await orchestrator._shutdown_mcp()
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

    dn.configure(
        server=dn_args.server,
        token=dreadnode_token,
        organization=dn_args.organization,
        workspace=dn_args.workspace,
        project=dn_args.project,
        console=dn_args.console,
    )

    from ares.agents.blue import InvestigationOrchestrator
    from ares.integrations.mitre import MITREAttackClient

    logger.info("Loading MITRE ATT&CK data...")
    mitre_client = MITREAttackClient()
    await mitre_client.load()

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    orchestrator = InvestigationOrchestrator(
        model=args.model,
        grafana_url=args.grafana_url,
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


# Cyclopts decorator typing not yet fully supported by type checkers
@app.command(name="red-team")  # type: ignore[untyped-decorator]
async def redteam(
    target_ip: str,
    *,
    args: Args | None = None,
    dn_args: DreadnodeArgs | None = None,
) -> None:
    """
    Execute a red team operation against a target.

    This command runs an autonomous penetration testing agent that will:
    - Enumerate network hosts, users, and shares
    - Harvest credentials via secretsdump, kerberoasting, and AS-REP roasting
    - Crack password hashes
    - Pilfer SMB shares for credentials
    - Generate golden tickets if krbtgt hash is found
    - Achieve domain admin access if possible

    **WARNING**: Only use this command in authorized penetration testing environments.
    Unauthorized use may be illegal.

    Args:
        target_ip: Primary target IP address for the red team operation

    Example:
        uv run python -m src.main redteam 192.168.1.100
        uv run python -m src.main redteam 192.168.1.100 --args.model claude-sonnet-4-20250514
    """
    args = args or Args()
    dn_args = dn_args or DreadnodeArgs()

    # Configure Dreadnode
    dreadnode_token = dn_args.token or os.getenv("DREADNODE_API_KEY", "")

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
    logger.info("ARES RED TEAM AGENT")
    logger.info("=" * 60)
    logger.info(f"Target: {target_ip}")
    logger.info(f"Model: {args.model}")
    logger.info(f"Max Steps: {args.max_steps}")
    logger.info(f"Report Dir: {args.report_dir}")
    logger.info("=" * 60)

    from ares.agents.red import RedTeamOrchestrator
    from ares.integrations.mitre import MITREAttackClient

    logger.info("Loading MITRE ATT&CK data...")
    mitre_client = MITREAttackClient()
    await mitre_client.load()
    # Accessing protected members for logging/diagnostics only - not modifying internal state
    techniques_count = len(mitre_client._techniques)
    tactics_count = len(mitre_client._tactics)
    logger.success(f"Loaded {techniques_count} techniques, {tactics_count} tactics")

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Reports: {report_dir}")

    orchestrator = RedTeamOrchestrator(
        model=args.model,
        mitre_client=mitre_client,
        report_dir=report_dir,
        max_steps=args.max_steps,
    )

    # Run operation
    logger.info("")
    logger.info(f"Starting red team operation against {target_ip}...")
    logger.info("")

    try:
        result = await orchestrator.execute_operation(target_ip)

        logger.success("")
        logger.success("=" * 60)
        logger.success("RED TEAM OPERATION COMPLETE")
        logger.success("=" * 60)
        logger.success(f"  Status: {result['status']}")
        logger.success(f"  Hosts Discovered: {result.get('host_count', 0)}")
        logger.success(f"  Credentials Obtained: {result.get('credential_count', 0)}")
        logger.success(f"  Admins Found: {result.get('admin_count', 0)}")

        if result.get("has_domain_admin"):
            logger.success("  🎯 DOMAIN ADMIN ACCESS: ACHIEVED")
        if result.get("has_golden_ticket"):
            logger.success("  🎫 GOLDEN TICKET: GENERATED")

        logger.success(f"  Report: {result['report_path']}")
        logger.success("")

    except Exception as e:
        logger.error("")
        logger.error(f"Red team operation failed: {e}")
        raise


@dataclass
class MultiAgentArgs:
    """Multi-agent red team arguments.

    Attributes:
        target_domain: Target domain (e.g., sevenkingdoms.local).
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
    - Orchestrator (enum-agent): Coordinates operation, does initial recon
    - Cracker: Hash cracking with hashcat/john
    - ACL: BloodHound analysis and ACL abuse
    - PrivEsc: ADCS, delegation, MSSQL exploitation
    - Lateral: Lateral movement and credential harvesting
    - Poisoning: Network poisoning (responder, mitm6)

    Args:
        target_domain: Target domain (e.g., sevenkingdoms.local)
        target_ips: Comma-separated list of target IPs

    Example:
        uv run ares multi-agent sevenkingdoms.local "192.168.56.10,192.168.56.11"
        uv run ares multi-agent corp.local "10.0.0.1" --multi-args.redis-url redis://redis:6379
    """
    import uuid

    from ares.core.config import load_config

    args = args or Args()
    dn_args = dn_args or DreadnodeArgs()
    multi_args = multi_args or MultiAgentArgs()

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
    logger.info(f"Model: {args.model}")
    logger.info(f"Max Steps: {args.max_steps}")
    logger.info(f"Redis: {redis_url}")
    logger.info(f"Namespace: {namespace}")
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

    try:
        result = await run_multi_agent_operation(
            operation_id=operation_id,
            target_domain=target_domain,
            target_ips=ips,
            initial_credential=initial_cred,
            redis_url=redis_url,
            namespace=namespace,
            model=args.model,
            max_steps=args.max_steps,
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

        logger.success("")

    except Exception as e:
        logger.error("")
        logger.error(f"Multi-agent operation failed: {e}")
        raise


@dataclass
class WorkerArgs:
    """Worker agent arguments.

    Attributes:
        role: Worker role (cracker, acl, privesc, lateral, poisoning, atomic).
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
    operation_id: str,
    *,
    worker_args: WorkerArgs | None = None,
    dn_args: DreadnodeArgs | None = None,
) -> None:
    """
    Run a specialized worker agent that processes tasks from the dispatcher.

    This command starts a worker agent that:
    - Connects to Redis and registers with the dispatcher
    - Polls for assigned tasks based on its role
    - Processes tasks using specialized toolsets
    - Reports results back to the orchestrator

    Worker roles:
    - cracker: Hash cracking with hashcat/john
    - acl: BloodHound analysis and ACL abuse
    - privesc: ADCS, delegation, MSSQL exploitation
    - lateral: Lateral movement and credential harvesting
    - poisoning: Network poisoning (responder, mitm6)
    - atomic: Atomic Red Team technique execution

    Args:
        role: Worker role (cracker, acl, privesc, lateral, poisoning, atomic)
        operation_id: Operation ID to join

    Example:
        uv run ares worker cracker op-12345678 --worker-args.redis-url redis://redis:6379
        uv run ares worker lateral op-12345678 --worker-args.model claude-sonnet-4-20250514
    """
    from ares.core.config import get_agent_config, load_config

    worker_args = worker_args or WorkerArgs()
    dn_args = dn_args or DreadnodeArgs()

    # Validate role
    valid_roles = ["cracker", "acl", "privesc", "lateral", "poisoning", "atomic"]
    if role not in valid_roles:
        logger.error(f"Invalid role: {role}. Must be one of: {', '.join(valid_roles)}")
        return

    # Load config file for defaults
    config = load_config(worker_args.config_file or None)
    agent_config = get_agent_config(role)

    # Use config values if CLI args not specified
    redis_url = worker_args.redis_url or config.redis_url
    model = worker_args.model or agent_config.model
    max_steps = worker_args.max_steps if worker_args.max_steps > 0 else agent_config.max_steps

    # Configure Dreadnode (optional - don't fail if platform unavailable)
    dreadnode_token = dn_args.token or os.getenv("DREADNODE_API_KEY", "")

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
        logger.warning(f"Dreadnode platform unavailable, continuing without telemetry: {e}")

    # Log startup
    logger.info("=" * 60)
    logger.info(f"ARES WORKER AGENT: {role.upper()}")
    logger.info("=" * 60)
    logger.info(f"Config: {worker_args.config_file or 'auto-detected'}")
    logger.info(f"Operation ID: {operation_id}")
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
        "cracker": AgentRole.CRACKER,
        "acl": AgentRole.ACL,
        "privesc": AgentRole.PRIVESC,
        "lateral": AgentRole.LATERAL,
        "poisoning": AgentRole.POISONING,
        "atomic": AgentRole.ATOMIC,
    }
    agent_role = role_mapping[role]

    try:
        await run_worker(
            role=agent_role,
            operation_id=operation_id,
            redis_url=redis_url,
            model=model,
            max_steps=max_steps if max_steps > 0 else None,
        )
    except KeyboardInterrupt:
        logger.info("Worker interrupted by user")
    except Exception as e:
        logger.error(f"Worker failed: {e}")
        raise


# Cyclopts decorator typing not yet fully supported by type checkers
@app.command  # type: ignore[untyped-decorator]
def version() -> None:
    """Print version information."""


if __name__ == "__main__":
    app()
