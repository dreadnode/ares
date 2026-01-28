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
    InvestigationStage,
    RedTeamState,
    SharedRedTeamState,
    Target,
)
from ares.core.recovery import OperationRecoveryManager
from ares.core.task_queue import RedisTaskQueue
from ares.core.workflows import exploitation_workflow
from ares.reports.redteam import RedTeamReportGenerator
from ares.tools.red import (
    BloodHoundTools,
    CertipyTools,
    CredentialDiscoveryTools,
    CredentialHarvestingTools,
    NetworkEnumerationTools,
    RedTeamReportingTools,
)
from ares.tools.red.orchestrator import OrchestratorTools

# Default max runtime in seconds (30 minutes), configurable via ARES_MAX_RUNTIME env var
DEFAULT_MAX_RUNTIME = float(os.environ.get("ARES_MAX_RUNTIME", "1800"))


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
    state.target = Target(
        ip=target_ips[0] if target_ips else "",
        domain=target_domain,
    )
    if target_domain:
        state.add_domain(target_domain)
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

        # Start mandatory user recon once the operation commences.
        tasks.append(
            asyncio.create_task(
                asyncio.to_thread(
                    _run_mandatory_user_enum,
                    target_ips,
                    target_domain,
                    dispatcher.shared_state,
                ),
                name="mandatory_user_enum",
            )
        )

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
    - OrchestratorTools for dispatching tasks to specialized agents
    - NetworkEnumerationTools for initial reconnaissance
    - CredentialDiscoveryTools for finding quick wins
    - CertipyTools for ADCS recon
    - RedTeamReportingTools for recording findings

    Args:
        dispatcher: The dispatcher for inter-agent communication
        model: LLM model to use
        max_steps: Maximum agent steps
        openai_api_key: Optional OpenAI API key to bind directly to the generator

    Returns:
        Configured orchestrator agent
    """
    shared_state = dispatcher.shared_state

    # Create completion tools that can modify shared state (for stop conditions)
    complete_operation, announce_domain_admin = _create_completion_tools(shared_state, dispatcher)

    # Create orchestrator tools with dispatcher wired in
    orchestrator_tools = OrchestratorTools()
    orchestrator_tools.set_dispatcher(dispatcher)
    orchestrator_tools.set_shared_state(shared_state)

    # Recon tools for initial recon
    # Note: These tools use RedTeamState internally. SharedRedTeamState provides
    # compatibility aliases (hosts, credentials, etc.) so they work in multi-agent mode.
    network_tools = NetworkEnumerationTools()
    cred_discovery_tools = CredentialDiscoveryTools()
    credential_tools = CredentialHarvestingTools()
    certipy_tools = CertipyTools()
    bloodhound_tools = BloodHoundTools()
    reporting_tools = RedTeamReportingTools()

    # Set shared state on all toolsets for state tracking
    # SharedRedTeamState has compatibility properties (hosts, credentials, etc.)
    # that map to all_hosts, all_credentials, etc. for backward compatibility
    network_tools.set_state(shared_state)
    cred_discovery_tools.set_state(shared_state)
    credential_tools.set_state(shared_state)
    certipy_tools.set_state(shared_state)
    bloodhound_tools.set_state(shared_state)
    reporting_tools.set_state(shared_state)

    # Wire dispatcher on credential tools for auto-DA announcement
    credential_tools.set_dispatcher(dispatcher)

    tools = [
        complete_operation,  # Stop condition tool for marking operation complete
        announce_domain_admin,  # Stop condition tool for announcing DA achievement
        orchestrator_tools,  # Coordination tools (dispatch_*, get_*, broadcast_*)
        network_tools,  # nmap, enum4linux, crackmapexec
        cred_discovery_tools,  # ldap_search_descriptions, password_spray, etc.
        credential_tools,  # kerberos_user_enum_noauth, secretsdump, etc.
        certipy_tools,  # certipy_find for ADCS recon
        bloodhound_tools,  # run_bloodhound for attack path discovery
        reporting_tools,  # record_finding, generate_report
    ]

    # Load orchestrator-specific instructions
    instructions = load_agent_instructions(AgentRole.RECON)

    # Create hooks for monitoring and guidance
    hooks = create_role_hooks(
        AgentRole.RECON, dispatcher, shared_state, display_name="orchestrator"
    )

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


async def _auto_credential_access(  # noqa: PLR0912
    dispatcher: RedTeamDispatcher,
    check_interval: float = 60.0,
    min_hosts: int = 1,
) -> None:
    """
    Background task that proactively runs credential access techniques.

    1) If no creds/hashes yet, run no-creds AS-REP roast per domain.
    2) For each new credential/hash, run kerberoast + secretsdump attempts.
    """
    processed_creds: set[tuple[str, str, str]] = set()
    processed_hashes: set[tuple[str, str, str]] = set()
    processed_crack_hashes: set[tuple[str, str, str, str]] = set()
    processed_no_cred_domains: set[str] = set()

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

            if not (has_new_creds or has_new_hashes or has_new_cracks or has_new_domains):
                await dispatcher.wait_for_credential_access_signal(check_interval)
                continue

            if not state.all_credentials and not state.all_hashes:
                for domain in sorted(domains):
                    if domain in processed_no_cred_domains:
                        continue
                    domain_hosts = hosts_by_domain.get(domain.lower(), []) or host_ips
                    task_id = await dispatcher.request_credential_access(
                        source_agent="orchestrator",
                        domain=domain,
                        target_ips=domain_hosts,
                        reason="no_creds_domain",
                        techniques=["asrep_roast"],
                    )
                    if task_id:
                        processed_no_cred_domains.add(domain)
                        logger.info(
                            "Auto credential access (no-creds) dispatched for domain %s",
                            domain,
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
                if key in processed_hashes:
                    continue
                if not _is_pass_the_hash_compatible(hash_obj.hash_value, hash_obj.hash_type):
                    logger.info(
                        "Skipping credential access for {}\\{}: non-NTLM hash type {}",
                        hash_obj.domain or "(unknown)",
                        hash_obj.username,
                        hash_obj.hash_type or "unknown",
                    )
                    processed_hashes.add(key)
                    continue
                domain_name = hash_obj.domain or (state.target.domain if state.target else "")
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
                crack_task_id = await dispatcher.request_crack(
                    hash_value=hash_obj.hash_value,
                    hash_type=hash_obj.hash_type,
                    source_agent="orchestrator",
                    username=hash_obj.username,
                    domain=hash_obj.domain,
                )
                if crack_task_id:
                    processed_crack_hashes.add(crack_key)
                    logger.info(
                        "Auto crack dispatched for {}\\{} ({})",
                        hash_obj.domain or "(unknown)",
                        hash_obj.username,
                        hash_obj.hash_type or "unknown",
                    )

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto credential access error: {e}", exc_info=True)
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
            break

        # Check for domain admin or explicit completion
        if dispatcher.shared_state.has_domain_admin:
            logger.success("Domain Admin achieved! Operation complete.")
            break
        if dispatcher.shared_state.completed:
            logger.success("Operation marked complete.")
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
1. Run nmap_scan on all targets to discover services
2. LOW-HANGING FRUIT (do these early!):
   - ldap_search_descriptions: Find passwords stored in user description fields
   - password_spray with common passwords (Password1, Welcome1, Summer2024, etc.)
   - username_as_password: Test if users have username as password (e.g., user1:user1)
3. Enumerate users and shares with netexec/enum4linux-ng/rpcclient/smbclient
4. If no creds, run Kerberos user recon with kerberos_user_enum_noauth
5. Run certipy_find to discover ADCS vulnerabilities
6. Run run_bloodhound for ACL analysis and attack path discovery
7. **CRITICAL CREDENTIAL EXPANSION (run IMMEDIATELY after finding ANY credentials):**
   - Use secretsdump on ALL domain controllers to dump hashes
   - Use kerberoast to find service accounts with weak passwords
   - Use asrep_roast to find accounts without Kerberos pre-auth
   - Check secretsdump output for krbtgt or Administrator hashes
   - If krbtgt hash found → Generate golden ticket → Announce Domain Admin
   - If Administrator hash found → Test DA access → Announce Domain Admin
8. Coordinate with specialized agents to exploit discovered vulnerabilities
9. Use trigger_credential_expansion after getting new credentials
10. Continue until Domain Admin access achieved

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

Let's begin the operation!
"""


def _run_mandatory_user_enum(  # noqa: PLR0912
    target_ips: list[str],
    target_domain: str,
    shared_state: SharedRedTeamState,
) -> None:
    if not target_ips:
        logger.warning("No target IPs provided for mandatory user recon")
        return

    network_tools = NetworkEnumerationTools()
    network_tools.set_state(shared_state)  # type: ignore[arg-type]
    logger.info("Running mandatory user recon on all targets")

    targets_str = " ".join(target_ips)
    if targets_str:
        try:
            output = network_tools.smb_sweep(targets_str)
            if output:
                logger.info("Mandatory SMB sweep output:\n%s", output)
        except Exception as exc:
            logger.warning(f"Mandatory SMB sweep failed: {exc}")

    if target_domain and target_ips:
        try:
            output = network_tools.resolve_domain_controllers(target_domain, target_ips[0])
            if output:
                logger.info("Mandatory SRV lookup output:\n%s", output)
        except Exception as exc:
            logger.warning(f"Mandatory SRV lookup failed: {exc}")

    for target in target_ips:
        try:
            output = network_tools.enumerate_users(target, "", "", target_domain)
            if output:
                logger.info(f"Mandatory user recon output for {target}:\n{output}")
            else:
                logger.info(f"Mandatory user recon produced no output for {target}")
        except Exception as exc:  # noqa: PERF203
            logger.warning(f"Mandatory user recon failed for {target}: {exc}")

    if shared_state.hosts:
        hostnames: set[str] = set()
        host_ip_map: dict[str, str] = {}
        for host in shared_state.hosts:
            hostname = (host.hostname or "").strip()
            if not hostname:
                continue
            lower = hostname.lower()
            if lower.startswith("ip-") and "compute.internal" in lower:
                continue
            if "." not in hostname and target_domain:
                hostname = f"{hostname.lower()}.{target_domain.lower()}"
            hostnames.add(hostname)
            if host.ip:
                host_ip_map[hostname] = host.ip
        for hostname in sorted(hostnames):
            try:
                target_ip = host_ip_map.get(hostname, "")
                output = network_tools.smbclient_kerberos_shares(hostname, target_ip=target_ip)
                if output:
                    logger.info(f"Mandatory smbclient shares output for {hostname}:\n{output}")
            except Exception as exc:  # noqa: PERF203
                logger.warning(f"Mandatory smbclient shares failed for {hostname}: {exc}")


__all__ = [
    "run_multi_agent_operation",
]
