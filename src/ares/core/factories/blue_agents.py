"""Factory for creating blue team multi-agent workers.

Creates role-specific dreadnode Agents with appropriate tools,
instructions, and stop conditions for each BlueRole.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import dreadnode as dn
from dreadnode.agent import Agent, Thread
from dreadnode.agent.events import ToolEnd, ToolStart
from dreadnode.agent.stop import StopCondition, tool_use
from loguru import logger

from ares.core.factories.blue_factory import (
    filter_essential_mcp_tools,
    max_tool_calls_stop,
    wrap_mcp_query_tools,
)
from ares.core.models import BlueRole
from ares.core.templates import get_template_loader
from ares.tools.blue.callbacks import BlueWorkerCallbackTools
from ares.tools.blue.shared_wrappers import SharedInvestigationTools

if TYPE_CHECKING:
    from ares.core.blue_dispatcher import BlueTeamDispatcher
    from ares.core.blue_state_backend import BlueStateBackend
    from ares.integrations.mitre import MITREAttackClient


# MCP tools needed by each worker role
_TRIAGE_MCP_TOOLS = {
    "query_loki_logs",
    "list_loki_label_names",
    "list_loki_label_values",
}

_HUNTER_MCP_TOOLS = {
    "query_loki_logs",
    "query_loki_patterns",
    "query_loki_stats",
}

_LATERAL_MCP_TOOLS = {
    "query_loki_logs",
}


def create_blue_agent(
    role: BlueRole,
    model: str,
    backend: BlueStateBackend,
    dispatcher: BlueTeamDispatcher,
    mitre_client: MITREAttackClient,
    mcp_tools: list | None = None,
    max_steps: int = 20,
) -> tuple[Agent, BlueWorkerCallbackTools]:
    """Create a role-specific blue team agent.

    Args:
        role: The agent's specialized role.
        model: LLM model identifier.
        backend: BlueStateBackend for shared state.
        dispatcher: BlueTeamDispatcher for coordination.
        mitre_client: MITRE ATT&CK client.
        mcp_tools: Optional list of MCP tools from Grafana.
        max_steps: Maximum agent steps.

    Returns:
        Tuple of (Agent, BlueWorkerCallbackTools).
    """
    instructions = load_blue_instructions(role)
    tools = _build_tools_for_role(role, backend, dispatcher, mitre_client, mcp_tools)
    callback_tools = tools[-1]  # Last tool is always the callback
    stop_conditions = get_blue_stop_conditions(role)
    hooks = create_blue_hooks(role)

    agent_name = _role_to_name(role)

    agent = dn.Agent(
        name=agent_name,
        model=model,
        instructions=instructions,
        max_steps=max_steps,
        tools=tools,
        hooks=hooks,
        stop_conditions=stop_conditions,
        thread=Thread(),  # type: ignore[call-arg]
    )

    return agent, callback_tools


def load_blue_instructions(role: BlueRole) -> str:
    """Load role-specific system instructions from Jinja template.

    Args:
        role: The agent role.

    Returns:
        Rendered system instructions string.
    """
    template_map = {
        BlueRole.ORCHESTRATOR: "blueteam/agents/orchestrator.md.jinja",
        BlueRole.TRIAGE: "blueteam/agents/triage.md.jinja",
        BlueRole.THREAT_HUNTER: "blueteam/agents/threat_hunter.md.jinja",
        BlueRole.LATERAL_ANALYST: "blueteam/agents/lateral_analyst.md.jinja",
    }

    template_name = template_map.get(role)
    if not template_name:
        return f"You are a blue team {role.value} agent."

    try:
        loader = get_template_loader()
        return loader.render(template_name)
    except Exception as e:
        logger.warning(f"Failed to load template for {role.value}: {e}")
        return f"You are a blue team {role.value} agent. Investigate security alerts and record evidence."


def _build_tools_for_role(
    role: BlueRole,
    backend: BlueStateBackend,
    dispatcher: BlueTeamDispatcher,
    mitre_client: MITREAttackClient,
    mcp_tools: list | None = None,
) -> list:
    """Build the tool list for a specific role.

    Returns:
        List of tool instances. The last element is always BlueWorkerCallbackTools.
    """
    tools: list = []

    # Shared investigation tools for all worker roles
    shared_tools = SharedInvestigationTools()
    shared_tools.set_backend(backend)
    shared_tools.set_shared_state(dispatcher.shared_state)
    shared_tools.set_mitre_client(mitre_client)

    if role == BlueRole.TRIAGE:
        tools = _build_triage_tools(shared_tools, mitre_client, mcp_tools)
    elif role == BlueRole.THREAT_HUNTER:
        tools = _build_hunter_tools(shared_tools, mitre_client, mcp_tools)
    elif role == BlueRole.LATERAL_ANALYST:
        tools = _build_lateral_tools(shared_tools, mitre_client, mcp_tools)
    else:
        tools = [shared_tools]

    # Callback tools always last
    callback = BlueWorkerCallbackTools()
    tools.append(callback)

    # Log tool count
    tool_count = 0
    for t in tools:
        if hasattr(t, "get_tools"):
            tool_count += len(t.get_tools())
        else:
            tool_count += 1
    logger.info(f"[{role.value}] Built {tool_count} tools from {len(tools)} entries")

    return tools


def _build_triage_tools(
    shared_tools: SharedInvestigationTools,
    mitre_client: MITREAttackClient,
    mcp_tools: list | None,
) -> list:
    """Build tools for triage worker: MCP query + investigation tools."""
    tools: list = [shared_tools]

    # Add filtered MCP tools (just Loki query + label discovery)
    if mcp_tools:
        filtered = _filter_mcp_for_role(mcp_tools, _TRIAGE_MCP_TOOLS)
        tools.extend(filtered)

    return tools


def _build_hunter_tools(
    shared_tools: SharedInvestigationTools,
    mitre_client: MITREAttackClient,
    mcp_tools: list | None,
) -> list:
    """Build tools for threat hunter: detection queries + MCP + MITRE."""
    from ares.tools.blue import QueryTemplateTools
    from ares.tools.shared import MITRELookupTools

    tools: list = [shared_tools]

    # QueryTemplateTools for detection queries
    query_tools = QueryTemplateTools()
    tools.append(query_tools)

    # MITRE lookup tools
    mitre_tools = MITRELookupTools()
    mitre_tools.set_client(mitre_client)
    tools.append(mitre_tools)

    # Add filtered MCP tools
    if mcp_tools:
        filtered = _filter_mcp_for_role(mcp_tools, _HUNTER_MCP_TOOLS)
        tools.extend(filtered)

    return tools


def _build_lateral_tools(
    shared_tools: SharedInvestigationTools,
    mitre_client: MITREAttackClient,
    mcp_tools: list | None,
) -> list:
    """Build tools for lateral analyst: host/user activity + MCP."""
    from ares.tools.blue import QueryTemplateTools

    tools: list = [shared_tools]

    # QueryTemplateTools for host/user activity queries
    query_tools = QueryTemplateTools()
    tools.append(query_tools)

    # Add filtered MCP tools
    if mcp_tools:
        filtered = _filter_mcp_for_role(mcp_tools, _LATERAL_MCP_TOOLS)
        tools.extend(filtered)

    return tools


def _filter_mcp_for_role(mcp_tools: list, allowed_names: set[str]) -> list:
    """Filter MCP tools to only those needed by a specific role."""
    filtered = []
    for tool in mcp_tools:
        tool_name = getattr(tool, "name", "") or getattr(tool, "__name__", str(tool))
        if tool_name in allowed_names:
            filtered.append(tool)
    return filtered


def get_blue_stop_conditions(role: BlueRole) -> list[StopCondition]:
    """Get stop conditions for a specific role.

    Args:
        role: The agent role.

    Returns:
        List of stop conditions.
    """
    if role == BlueRole.TRIAGE:
        return [
            tool_use("triage_complete"),
            max_tool_calls_stop(max_calls=30),
        ]
    elif role == BlueRole.THREAT_HUNTER:
        return [
            tool_use("hunt_complete"),
            max_tool_calls_stop(max_calls=40),
        ]
    elif role == BlueRole.LATERAL_ANALYST:
        return [
            tool_use("lateral_complete"),
            max_tool_calls_stop(max_calls=35),
        ]
    elif role == BlueRole.ORCHESTRATOR:
        return [
            tool_use("complete_investigation"),
            tool_use("escalate_investigation"),
            max_tool_calls_stop(max_calls=60),
        ]
    return [max_tool_calls_stop(max_calls=30)]


def create_blue_hooks(role: BlueRole) -> list:
    """Create hooks for a blue team agent.

    Args:
        role: The agent role.

    Returns:
        List of hook functions.
    """

    async def log_tool_usage(event: ToolStart):
        """Log tool calls for observability."""
        tool_name = event.tool_call.name if event.tool_call else "unknown"
        dn.log_metric(f"blue_{role.value}_tool_calls", 1, mode="count")
        logger.debug(f"[{role.value}] Tool call: {tool_name}")

    async def log_tool_result(event: ToolEnd):
        """Log tool results for observability."""
        tool_name = event.tool_call.name if event.tool_call else "unknown"
        result_len = len(str(event.tool_result)) if event.tool_result else 0
        logger.debug(f"[{role.value}] Tool result: {tool_name} ({result_len} chars)")

    return [log_tool_usage, log_tool_result]


def _role_to_name(role: BlueRole) -> str:
    """Convert role to human-readable agent name."""
    names = {
        BlueRole.ORCHESTRATOR: "Blue Team Orchestrator",
        BlueRole.TRIAGE: "Triage Analyst",
        BlueRole.THREAT_HUNTER: "Threat Hunter",
        BlueRole.LATERAL_ANALYST: "Lateral Analyst",
    }
    return names.get(role, f"Blue Agent ({role.value})")
