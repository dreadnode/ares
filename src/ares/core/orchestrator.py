"""Main orchestrator for multi-agent red team operations.

This module provides the entry point for coordinating multi-agent
red team operations in a Kubernetes environment.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import dreadnode as dn
from dreadnode.agent import Agent, Thread
from dreadnode.agent.stop import tool_use
from loguru import logger

from ares.core.config import get_namespace, get_redis_url
from ares.core.dispatcher import RedTeamDispatcher
from ares.core.factories.red_agents import (
    create_role_hooks,
    load_agent_instructions,
)
from ares.core.models import (
    AgentInfo,
    AgentRole,
    Credential,
    Target,
)
from ares.core.recovery import OperationRecoveryManager
from ares.core.task_queue import RedisTaskQueue
from ares.core.workflows import exploitation_workflow
from ares.tools.red.network import (
    BloodHoundTools,
    CertipyTools,
    CredentialDiscoveryTools,
    NetworkEnumerationTools,
    RedTeamReportingTools,
)
from ares.tools.red.orchestrator import OrchestratorTools


async def _wait_for_required_workers(
    dispatcher: RedTeamDispatcher,
    required_roles: list[str],
    timeout: float = 120.0,
) -> bool:
    """
    Wait for required worker agents to come online.

    Args:
        dispatcher: The dispatcher instance
        required_roles: List of roles that must be online (e.g., ["enum"])
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
    logger.success(f"🎯 Multi-agent operation completed: {summary}")
    return f"✓ Operation marked as complete. Summary: {summary}"


async def run_multi_agent_operation(
    operation_id: str,
    target_domain: str,
    target_ips: list[str],
    initial_credential: Credential | None = None,
    resume_from_checkpoint: bool = False,
    redis_url: str | None = None,
    namespace: str | None = None,
    model: str = "claude-sonnet-4-20250514",
    max_steps: int = 200,
    checkpoint_interval: int = 60,
) -> dict[str, Any]:
    """
    Main entry point for multi-agent red team operations.

    Args:
        operation_id: Unique identifier for this operation
        target_domain: Target domain (e.g., "sevenkingdoms.local")
        target_ips: List of target IPs to scan
        initial_credential: Optional initial credential
        resume_from_checkpoint: Resume from previous checkpoint
        redis_url: Redis URL for state persistence (default: derived from config)
        namespace: Kubernetes namespace (default: from config)
        model: LLM model to use
        max_steps: Maximum agent steps
        checkpoint_interval: Seconds between checkpoints

    Returns:
        Operation results summary
    """
    # Resolve config defaults
    redis_url = redis_url or get_redis_url()
    namespace = namespace or get_namespace()

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
    if resume_from_checkpoint:
        state = await recovery.recover_operation(operation_id)
        if state:
            dispatcher._shared_state = state
            logger.info(f"Resumed operation {operation_id} from checkpoint")
        else:
            logger.warning(f"No checkpoint found for {operation_id}, starting fresh")
            resume_from_checkpoint = False

    if not resume_from_checkpoint:
        state = dispatcher.shared_state
        state.target = Target(
            ip=target_ips[0] if target_ips else "",
            domain=target_domain,
        )
        if initial_credential:
            state.add_credential(initial_credential, "initial")

    # Create agent ensemble
    agents = await _create_agent_ensemble(
        dispatcher=dispatcher,
        model=model,
        max_steps=max_steps,
        namespace=namespace,
    )

    # Register all agents with dispatcher
    for agent_info in agents.values():
        await dispatcher.register(agent_info)

    # Wait for required workers before starting
    if not await _wait_for_required_workers(dispatcher, ["enum"], timeout=120.0):
        raise RuntimeError(
            "Required workers (enum) did not come online within 120 seconds. "
            "Ensure worker pods are deployed and running."
        )

    # Start background tasks
    tasks = [
        asyncio.create_task(recovery.start_periodic_checkpoint(dispatcher), name="checkpoint"),
        asyncio.create_task(_monitor_agent_health(dispatcher), name="health_monitor"),
        asyncio.create_task(exploitation_workflow(dispatcher), name="exploitation_workflow"),
        asyncio.create_task(_extend_operation_lock(task_queue, operation_id), name="lock_extender"),
    ]

    # Build initial prompt for orchestrator
    initial_prompt = _build_orchestrator_prompt(
        target_domain=target_domain,
        target_ips=target_ips,
        initial_credential=initial_credential,
    )

    try:
        # Create the orchestrator agent with tools
        orchestrator_agent = await _create_orchestrator_agent(
            dispatcher=dispatcher,
            model=model,
            max_steps=max_steps,
        )

        logger.info(f"Starting orchestrator for {target_domain}")
        logger.info(f"Initial prompt:\n{initial_prompt}")

        # Run the orchestrator agent - this drives the entire operation
        with dn.run(tags=["multi-agent-operation", target_domain]):
            dn.log_params(
                model=model,
                operation_id=operation_id,
                target_domain=target_domain,
                target_ips=target_ips,  # type: ignore[arg-type]
                max_steps=max_steps,
            )

            # Run the orchestrator agent
            logger.info(f"🤖 Connecting to {model}...")
            result = await orchestrator_agent.run(initial_prompt)

            # Log model connection and completion status
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

        # Wait for any remaining background tasks
        await _wait_for_completion(dispatcher, tasks, max_runtime=300.0)

        # Get final state
        final_state = dispatcher.shared_state
        end_time = datetime.now(timezone.utc)

        return {
            "operation_id": operation_id,
            "success": final_state.has_domain_admin,
            "domain_admin_achieved": final_state.has_domain_admin,
            "domain_admin_path": final_state.domain_admin_path,
            "golden_ticket_forged": final_state.has_golden_ticket,
            "credentials_discovered": len(final_state.all_credentials),
            "hashes_discovered": len(final_state.all_hashes),
            "hosts_discovered": len(final_state.all_hosts),
            "vulnerabilities_discovered": len(final_state.discovered_vulnerabilities),
            "vulnerabilities_exploited": len(final_state.exploited_vulnerabilities),
            "tasks_completed": len(final_state.completed_tasks),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": (end_time - start_time).total_seconds(),
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
) -> Agent:
    """
    Create the orchestrator agent that coordinates the multi-agent operation.

    The orchestrator has:
    - OrchestratorTools for dispatching tasks to specialized agents
    - NetworkEnumerationTools for initial reconnaissance
    - CredentialDiscoveryTools for finding quick wins
    - CertipyTools for ADCS enumeration
    - RedTeamReportingTools for recording findings

    Args:
        dispatcher: The dispatcher for inter-agent communication
        model: LLM model to use
        max_steps: Maximum agent steps

    Returns:
        Configured orchestrator agent
    """
    shared_state = dispatcher.shared_state

    # Create orchestrator tools with dispatcher wired in
    orchestrator_tools = OrchestratorTools()
    orchestrator_tools.set_dispatcher(dispatcher)
    orchestrator_tools.set_shared_state(shared_state)

    # Enumeration tools for initial recon
    # Note: These tools use RedTeamState internally. SharedRedTeamState provides
    # compatibility aliases (hosts, credentials, etc.) so they work in multi-agent mode.
    network_tools = NetworkEnumerationTools()
    cred_discovery_tools = CredentialDiscoveryTools()
    certipy_tools = CertipyTools()
    bloodhound_tools = BloodHoundTools()
    reporting_tools = RedTeamReportingTools()

    # Set shared state on all toolsets for state tracking
    # SharedRedTeamState has compatibility properties (hosts, credentials, etc.)
    # that map to all_hosts, all_credentials, etc. for backward compatibility
    network_tools.set_state(shared_state)  # type: ignore[arg-type]
    cred_discovery_tools.set_state(shared_state)  # type: ignore[arg-type]
    certipy_tools.set_state(shared_state)  # type: ignore[arg-type]
    bloodhound_tools.set_state(shared_state)  # type: ignore[arg-type]
    reporting_tools.set_state(shared_state)  # type: ignore[arg-type]

    tools = [
        orchestrator_tools,  # Coordination tools (dispatch_*, get_*, broadcast_*)
        network_tools,  # nmap, enum4linux, crackmapexec
        cred_discovery_tools,  # ldap_search_descriptions, password_spray, etc.
        certipy_tools,  # certipy_find for ADCS enumeration
        bloodhound_tools,  # run_bloodhound for attack path discovery
        reporting_tools,  # record_finding, generate_report
        complete_operation,  # Stop condition tool
    ]

    # Load orchestrator-specific instructions
    instructions = load_agent_instructions(AgentRole.ENUM)

    # Create hooks for monitoring and guidance
    hooks = create_role_hooks(AgentRole.ENUM, dispatcher, shared_state)

    logger.info(f"Creating orchestrator agent with {len(tools)} toolsets, max_steps={max_steps}")

    return dn.Agent(
        name="ares-orchestrator",
        model=model,
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


async def _create_agent_ensemble(
    dispatcher: RedTeamDispatcher,
    model: str,
    max_steps: int,
    namespace: str,
) -> dict[AgentRole, AgentInfo]:
    """
    Create the agent ensemble with role-specific configurations.

    Args:
        dispatcher: The dispatcher instance
        model: LLM model to use
        max_steps: Maximum agent steps
        namespace: Kubernetes namespace

    Returns:
        Dict mapping roles to agent info
    """
    agents: dict[AgentRole, AgentInfo] = {}

    # Define agent configurations
    agent_configs: list[dict[str, AgentRole | str | set[str]]] = [
        {
            "role": AgentRole.ENUM,
            "name": "ares-enum",
            "pod_selector": "ares.dreadnode.io/role=enum",
            "capabilities": {
                "nmap",
                "crackmapexec",
                "ldapsearch",
                "certipy",
                "bloodhound",
                "secretsdump",
                "enum4linux",
            },
        },
        {
            "role": AgentRole.CRACKER,
            "name": "ares-cracker",
            "pod_selector": "ares.dreadnode.io/role=cracker",
            "capabilities": {"hashcat", "john", "ntlmrelayx"},
        },
        {
            "role": AgentRole.ACL,
            "name": "ares-acl",
            "pod_selector": "ares.dreadnode.io/role=acl",
            "capabilities": {"bloodhound", "dacledit", "owneredit"},
        },
        {
            "role": AgentRole.PRIVESC,
            "name": "ares-privesc",
            "pod_selector": "ares.dreadnode.io/role=privesc",
            "capabilities": {
                "certipy",
                "kerberoast",
                "asreproast",
                "constrained_delegation",
                "unconstrained_delegation",
            },
        },
        {
            "role": AgentRole.LATERAL,
            "name": "ares-lateral",
            "pod_selector": "ares.dreadnode.io/role=lateral",
            "capabilities": {
                "psexec",
                "wmiexec",
                "smbexec",
                "winrm",
                "secretsdump",
                "pass_the_hash",
            },
        },
        {
            "role": AgentRole.POISONING,
            "name": "ares-poisoning",
            "pod_selector": "ares.dreadnode.io/role=poison",
            "capabilities": {"responder", "mitm6", "ntlmrelayx"},
        },
    ]

    for config in agent_configs:
        role = config["role"]
        name = config["name"]
        capabilities = config["capabilities"]
        # Type narrowing for mypy
        if not isinstance(role, AgentRole):
            continue
        if not isinstance(name, str):
            continue
        if not isinstance(capabilities, set):
            continue
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

        # Check for domain admin
        if dispatcher.shared_state.has_domain_admin:
            logger.success("Domain Admin achieved! Operation complete.")
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
    cred_info = "None (start with unauthenticated enumeration)"
    if initial_credential:
        cred_info = f"{initial_credential.domain}\\{initial_credential.username}"

    return f"""Begin red team operation for {target_domain}.

Target IPs: {", ".join(target_ips)}
Initial credential: {cred_info}

Your objectives:
1. Run nmap_scan on all targets to discover services
2. Enumerate users and shares with enum4linux/crackmapexec
3. Run certipy_find to discover ADCS vulnerabilities
4. Run run_bloodhound for ACL analysis and attack path discovery
5. Coordinate with specialized agents to exploit discovered vulnerabilities
6. Use trigger_credential_expansion after getting new credentials
7. Continue until Domain Admin access achieved

Priority vulnerabilities to look for:
- ADCS ESC1-ESC8 (highest priority)
- Kerberoastable accounts
- AS-REP roastable accounts
- Unconstrained/Constrained delegation
- ACL abuse paths (GenericAll, WriteDACL, etc.)
- MSSQL linked servers

Remember:
- Use dispatch_* tools to route tasks to specialized agents
- Use queue_vulnerability_for_exploitation to queue discovered vulnerabilities
- Use trigger_credential_expansion after finding new credentials
- Monitor progress with get_operation_summary
- Announce domain admin when achieved with announce_domain_admin

Let's begin the operation!
"""


__all__ = [
    "run_multi_agent_operation",
]
