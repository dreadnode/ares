"""Factory for creating specialized multi-agent red team agents.

This module provides factories for creating role-specific agents
that work together in a distributed Kubernetes environment.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

import dreadnode as dn
from dreadnode.agent import Agent, Thread
from dreadnode.agent.events import AgentStalled, ToolEnd, ToolStart
from dreadnode.agent.hooks import retry_with_feedback
from dreadnode.agent.stop import tool_use
from loguru import logger

from ares.core.dispatcher import RedTeamDispatcher
from ares.core.models import AgentInfo, AgentRole, SharedRedTeamState
from ares.core.templates import get_template_loader
from ares.tools.red.network import (
    ACLExploitTools,
    BloodHoundTools,
    CertipyTools,
    CoercionTools,
    CrackingTools,
    CredentialDiscoveryTools,
    CredentialHarvestingTools,
    CVEExploitTools,
    DelegationTools,
    GoldenTicketTools,
    LateralMovementTools,
    MSSQLTools,
    NetworkEnumerationTools,
    PoisoningTools,
    RedTeamReportingTools,
    SharePilferingTools,
)

if TYPE_CHECKING:
    from ares.core.k8s_executor import KubernetesPodExecutor


# Tool assignments per agent role
ROLE_TOOLSETS: dict[AgentRole, list[type]] = {
    AgentRole.ENUM: [
        NetworkEnumerationTools,
        CredentialDiscoveryTools,
        RedTeamReportingTools,
        # OrchestratorTools added separately (needs dispatcher)
    ],
    AgentRole.CRACKER: [
        CrackingTools,
        # CrackerCallbackTools added separately
    ],
    AgentRole.ACL: [
        BloodHoundTools,
        ACLExploitTools,
        # ACLCallbackTools added separately
    ],
    AgentRole.PRIVESC: [
        CertipyTools,
        DelegationTools,
        MSSQLTools,
        CVEExploitTools,
        GoldenTicketTools,
        # PrivEscCallbackTools added separately
    ],
    AgentRole.LATERAL: [
        LateralMovementTools,
        CredentialHarvestingTools,
        SharePilferingTools,
        # LateralCallbackTools added separately
    ],
    AgentRole.POISONING: [
        CoercionTools,
        PoisoningTools,
        # PoisonCallbackTools added separately
    ],
    AgentRole.ATOMIC: [
        # AtomicRedTeamTools, AtomicCallbackTools added separately
    ],
}


# System instruction templates per role
ROLE_INSTRUCTIONS: dict[AgentRole, str] = {
    AgentRole.ENUM: "redteam/agents/enum.md.jinja",
    AgentRole.CRACKER: "redteam/agents/cracker.md.jinja",
    AgentRole.ACL: "redteam/agents/acl.md.jinja",
    AgentRole.PRIVESC: "redteam/agents/privesc.md.jinja",
    AgentRole.LATERAL: "redteam/agents/lateral.md.jinja",
    AgentRole.POISONING: "redteam/agents/poisoning.md.jinja",
    AgentRole.ATOMIC: "redteam/agents/atomic.md.jinja",
}


# Default max steps per role
ROLE_MAX_STEPS: dict[AgentRole, int] = {
    AgentRole.ENUM: 200,
    AgentRole.CRACKER: 50,
    AgentRole.ACL: 100,
    AgentRole.PRIVESC: 100,
    AgentRole.LATERAL: 100,
    AgentRole.POISONING: 30,
    AgentRole.ATOMIC: 50,
}


def load_agent_instructions(role: AgentRole) -> str:
    """
    Load role-specific system instructions from template.

    Falls back to generic red team instructions if role-specific not found.
    """
    template_path = ROLE_INSTRUCTIONS.get(role)
    if template_path:
        try:
            return get_template_loader().render(template_path)
        except Exception as e:
            logger.warning(f"Failed to load template {template_path}: {e}")

    # Fallback to generic red team instructions
    return get_template_loader().render("redteam/agents/system_instructions.md.jinja")


def create_role_hooks(
    role: AgentRole,
    dispatcher: RedTeamDispatcher,
    shared_state: SharedRedTeamState,
) -> list:
    """
    Create hooks for a specific agent role.

    Args:
        role: The agent role.
        dispatcher: The dispatcher for inter-agent communication.
        shared_state: The shared state object.

    Returns:
        List of hook functions.
    """
    hooks = []

    # Common logging hooks
    async def log_tool_usage(event: ToolStart):
        """Log tool calls for observability."""
        if hasattr(event, "tool_call") and event.tool_call:
            logger.info(f"🔧 [{role.value}] Tool: {event.tool_call.name}")
            dn.log_metric(f"multiagent_{role.value}_tool_{event.tool_call.name}", 1, mode="count")

    async def log_tool_result(event: ToolEnd):
        """Log tool results."""
        if not isinstance(event, ToolEnd):
            return

        if hasattr(event, "tool_call") and event.tool_call:
            if hasattr(event, "error") and event.error:
                logger.warning(f"❌ [{role.value}] {event.tool_call.name} failed: {event.error}")
            else:
                content = (
                    str(event.message.content) if event.message and event.message.content else ""
                )
                if not content:
                    logger.info(f"✅ [{role.value}] {event.tool_call.name}: (empty)")
                else:
                    # Show first 5 lines, max 500 chars
                    lines = content.split("\n")[:5]
                    result = "\n".join(lines)
                    truncated = len(lines) < len(content.split("\n")) or len(content) > 500
                    if len(result) > 500:
                        result = result[:500]
                        truncated = True
                    suffix = " ..." if truncated else ""
                    if "\n" in result:
                        logger.info(f"✅ [{role.value}] {event.tool_call.name}:\n{result}{suffix}")
                    else:
                        logger.info(f"✅ [{role.value}] {event.tool_call.name}: {result}{suffix}")

    hooks.extend([log_tool_usage, log_tool_result])

    # Role-specific hooks
    if role == AgentRole.ENUM:
        # Orchestrator monitors for domain admin achievement
        async def check_domain_admin(event: ToolEnd):
            if not isinstance(event, ToolEnd):
                return None

            if not event.message or not event.message.content:
                return None

            result = str(event.message.content).lower()
            tool_name = (
                event.tool_call.name if hasattr(event, "tool_call") and event.tool_call else ""
            )

            if tool_name == "domain_admin_checker" and "success" in result:
                return (
                    "🎉 DOMAIN ADMIN CONFIRMED!\n"
                    "→ Broadcast this achievement to all agents\n"
                    "→ Run secretsdump on all targets\n"
                    "→ Generate golden ticket if possible"
                )
            return None

        hooks.append(check_domain_admin)

    elif role == AgentRole.CRACKER:
        # Cracker broadcasts cracked credentials
        async def broadcast_cracked(event: ToolEnd):
            if not isinstance(event, ToolEnd):
                return None

            if not event.message or not event.message.content:
                return None

            result = str(event.message.content)
            tool_name = (
                event.tool_call.name if hasattr(event, "tool_call") and event.tool_call else ""
            )

            if tool_name in ["hashcat_crack", "john_crack"] and "cracked" in result.lower():
                return (
                    "🔓 PASSWORD CRACKED!\n"
                    "→ Use report_cracked_credential to broadcast to all agents\n"
                    "→ Include username, password, and original hash"
                )
            return None

        hooks.append(broadcast_cracked)

    elif role == AgentRole.PRIVESC:
        # PrivEsc monitors for successful exploitation
        async def track_exploitation(event: ToolEnd):
            if not isinstance(event, ToolEnd):
                return None

            if not event.message or not event.message.content:
                return None

            result = str(event.message.content)
            tool_name = (
                event.tool_call.name if hasattr(event, "tool_call") and event.tool_call else ""
            )

            # Check for successful ADCS exploitation
            if "certipy" in tool_name and (
                "success" in result.lower() or "certificate" in result.lower()
            ):
                return (
                    "✅ ADCS EXPLOITATION SUCCESSFUL!\n"
                    "→ Report the obtained credential/certificate\n"
                    "→ Use certipy_auth to get NTLM hash if needed"
                )
            return None

        hooks.append(track_exploitation)

    # Unstall hook for all roles
    role_feedback = {
        AgentRole.ENUM: (
            "You seem stuck. As orchestrator, focus on:\n"
            "1. Check pending tasks with get_pending_tasks()\n"
            "2. Review unexploited vulnerabilities with get_exploitation_status()\n"
            "3. Dispatch work to specialized agents\n"
            "4. Don't do exploitation yourself - delegate!"
        ),
        AgentRole.CRACKER: (
            "You seem stuck. As cracker, focus on:\n"
            "1. Process pending crack requests from your queue\n"
            "2. Try different wordlists or rules\n"
            "3. Report results back to orchestrator"
        ),
        AgentRole.ACL: (
            "You seem stuck. As ACL exploiter, focus on:\n"
            "1. Run BloodHound collection if not done\n"
            "2. Find shortest paths to Domain Admins\n"
            "3. Execute ACL abuse: shadow credentials, targeted kerberoast, password change"
        ),
        AgentRole.PRIVESC: (
            "You seem stuck. As privesc agent, focus on:\n"
            "1. Process pending exploit requests\n"
            "2. ADCS exploitation: certipy_req_esc1, certipy_auth\n"
            "3. Delegation attacks: constrained_delegation_s4u\n"
            "4. Report successful exploitations"
        ),
        AgentRole.LATERAL: (
            "You seem stuck. As lateral agent, focus on:\n"
            "1. Process lateral movement requests\n"
            "2. Try different methods: psexec, evil-winrm, wmi\n"
            "3. Run secretsdump on successful access\n"
            "4. Report new credentials back"
        ),
        AgentRole.POISONING: (
            "You seem stuck. As poisoner, focus on:\n"
            "1. Start responder/mitm6 if not running\n"
            "2. Use coercion techniques (petitpotam, coercer)\n"
            "3. Report captured hashes"
        ),
        AgentRole.ATOMIC: (
            "You seem stuck. As atomic agent, focus on:\n"
            "1. Execute requested T-code tests\n"
            "2. Report test results"
        ),
    }

    unstall_hook = retry_with_feedback(
        event_type=AgentStalled,
        feedback=role_feedback.get(role, "Try a different approach."),
    )
    hooks.append(unstall_hook)

    return hooks


def create_specialized_agent(
    role: AgentRole,
    model: str,
    shared_state: SharedRedTeamState,
    dispatcher: RedTeamDispatcher,
    pod_executor: KubernetesPodExecutor | None = None,
    pod_name: str = "",
    max_steps: int | None = None,
    additional_tools: list | None = None,
) -> Agent:
    """
    Create a specialized agent for a specific role.

    Args:
        role: Agent specialization.
        model: LLM model to use.
        shared_state: Reference to cluster-wide state.
        dispatcher: Message dispatcher for coordination.
        pod_executor: Executor for the agent's pod (optional).
        pod_name: Name of the pod this agent runs in.
        max_steps: Override default max steps for role.
        additional_tools: Additional tools to include.

    Returns:
        Configured Dreadnode Agent.
    """
    # Get toolsets for this role
    toolset_classes = ROLE_TOOLSETS.get(role, [])
    tools: list[Any] = []

    for cls in toolset_classes:
        try:
            toolset = cls()
            # Set shared state if toolset supports it
            if hasattr(toolset, "set_shared_state"):
                toolset.set_shared_state(shared_state)
            if hasattr(toolset, "set_dispatcher"):
                toolset.set_dispatcher(dispatcher)
            if hasattr(toolset, "set_executor") and pod_executor:
                toolset.set_executor(pod_executor)
            tools.append(toolset)
        except Exception as e:  # noqa: PERF203
            logger.warning(f"Failed to initialize toolset {cls.__name__}: {e}")

    # Add additional tools
    if additional_tools:
        tools.extend(additional_tools)

    # Load role-specific instructions
    instructions = load_agent_instructions(role)

    # Create hooks for this role
    hooks = create_role_hooks(role, dispatcher, shared_state)

    # Determine stop conditions based on role
    stop_conditions = []
    if role == AgentRole.ENUM:
        stop_conditions.append(tool_use("complete_operation"))
    else:
        # Worker agents stop when task is complete or they need assistance
        stop_conditions.extend(
            [
                tool_use("task_complete"),
                tool_use("request_assistance"),
            ]
        )

    agent_name = f"ares-{role.value}"
    max_steps = max_steps or ROLE_MAX_STEPS.get(role, 100)

    logger.info(f"Creating {agent_name} agent with {len(tools)} toolsets, max_steps={max_steps}")

    return dn.Agent(
        name=agent_name,
        model=model,
        instructions=instructions,
        max_steps=max_steps,
        tools=tools,
        hooks=hooks,
        stop_conditions=stop_conditions,
        thread=Thread(),  # type: ignore[call-arg]
    )


def create_agent_info(
    role: AgentRole,
    pod_name: str,
) -> AgentInfo:
    """
    Create AgentInfo for registration with dispatcher.

    Args:
        role: The agent role.
        pod_name: Name of the Kubernetes pod.

    Returns:
        AgentInfo object.
    """
    # Define capabilities per role
    role_capabilities: dict[AgentRole, set[str]] = {
        AgentRole.ENUM: {
            "enumeration",
            "coordination",
            "task_dispatch",
            "reporting",
        },
        AgentRole.CRACKER: {
            "hash_cracking",
            "hashcat",
            "john",
        },
        AgentRole.ACL: {
            "bloodhound",
            "acl_abuse",
            "shadow_credentials",
            "targeted_kerberoast",
        },
        AgentRole.PRIVESC: {
            "adcs_exploitation",
            "delegation_abuse",
            "mssql_exploitation",
            "cve_exploitation",
        },
        AgentRole.LATERAL: {
            "lateral_movement",
            "credential_harvesting",
            "psexec",
            "evil_winrm",
        },
        AgentRole.POISONING: {
            "network_poisoning",
            "coercion",
            "responder",
            "ntlm_relay",
        },
        AgentRole.ATOMIC: {
            "atomic_red_team",
            "technique_execution",
        },
    }

    return AgentInfo(
        name=f"ares-{role.value}",
        pod_name=pod_name,
        role=role,
        capabilities=role_capabilities.get(role, set()),
    )


async def create_multi_agent_ensemble(
    operation_id: str,
    target_ip: str,
    model: str | None = None,
    orchestrator_model: str | None = None,
    worker_model: str | None = None,
    dispatcher: RedTeamDispatcher | None = None,
    pod_executor: KubernetesPodExecutor | None = None,
    roles: list[AgentRole] | None = None,
) -> dict[AgentRole, Agent]:
    """
    Create a full ensemble of specialized agents.

    Args:
        operation_id: Unique operation identifier.
        target_ip: Primary target IP.
        model: Default LLM model.
        orchestrator_model: Override model for orchestrator.
        worker_model: Override model for workers.
        dispatcher: Pre-configured dispatcher (created if None).
        pod_executor: Pre-configured pod executor.
        roles: Specific roles to create (all if None).

    Returns:
        Dict mapping role to agent.
    """
    from ares.core.models import Target

    # Default roles if not specified
    if roles is None:
        roles = [
            AgentRole.ENUM,
            AgentRole.CRACKER,
            AgentRole.ACL,
            AgentRole.PRIVESC,
            AgentRole.LATERAL,
        ]

    # Create dispatcher if not provided
    if dispatcher is None:
        dispatcher = RedTeamDispatcher()
        await dispatcher.start(operation_id)

    # Create shared state
    shared_state = dispatcher.shared_state
    shared_state.target = Target(ip=target_ip)

    agents: dict[AgentRole, Agent] = {}

    base_model = model or os.getenv("ARES_MODEL")
    orch_model = orchestrator_model or os.getenv("ARES_ORCHESTRATOR_MODEL")
    work_model = worker_model or os.getenv("ARES_WORKER_MODEL")

    if not (base_model or orch_model or work_model):
        raise ValueError(
            "No model specified for multi-agent ensemble. Provide model args or set "
            "ARES_MODEL/ARES_ORCHESTRATOR_MODEL/ARES_WORKER_MODEL in the environment."
        )

    for role in roles:
        # Determine model for this role
        if role == AgentRole.ENUM:
            agent_model = orch_model or base_model
        else:
            agent_model = work_model or base_model
        if not agent_model:
            raise ValueError(
                f"No model specified for role {role.value}. "
                "Provide model args or set ARES_MODEL/ARES_ORCHESTRATOR_MODEL/ARES_WORKER_MODEL."
            )

        # Create agent
        agent = create_specialized_agent(
            role=role,
            model=agent_model,
            shared_state=shared_state,
            dispatcher=dispatcher,
            pod_executor=pod_executor,
            pod_name=f"ares-{role.value}-0",  # Default pod naming
        )

        agents[role] = agent

        # Register with dispatcher
        agent_info = create_agent_info(role, pod_name=f"ares-{role.value}-0")
        await dispatcher.register(agent_info)

    logger.info(f"Created multi-agent ensemble with {len(agents)} agents")
    return agents


# Completion tools for worker agents


@dn.tool
def task_complete(task_id: str, result: str) -> str:
    """
    Mark the current task as complete.

    Use this when you have successfully completed the assigned task.

    Args:
        task_id: The task ID that was assigned
        result: Summary of what was accomplished

    Returns:
        Confirmation message
    """
    logger.info(f"Task {task_id} completed: {result}")
    return f"✓ Task {task_id} marked as complete"


@dn.tool
def request_assistance(issue: str, context: str = "") -> str:
    """
    Request assistance from the orchestrator.

    Use this when you encounter an issue you cannot resolve.

    Args:
        issue: Description of the problem
        context: Additional context about what you were trying to do

    Returns:
        Confirmation that assistance was requested
    """
    logger.warning(f"Assistance requested: {issue}")
    return f"⚠️ Assistance requested for: {issue}"


__all__ = [
    "ROLE_INSTRUCTIONS",
    "ROLE_MAX_STEPS",
    "ROLE_TOOLSETS",
    "create_agent_info",
    "create_multi_agent_ensemble",
    "create_role_hooks",
    "create_specialized_agent",
    "load_agent_instructions",
    "request_assistance",
    "task_complete",
]
