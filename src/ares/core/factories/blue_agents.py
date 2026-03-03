"""Factory for creating blue team multi-agent workers.

Creates role-specific dreadnode Agents with appropriate tools,
instructions, and stop conditions for each BlueRole.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import dreadnode as dn
from dreadnode.agent import Agent, Thread
from dreadnode.agent.stop import StopCondition, tool_use
from loguru import logger

from ares.core.factories.blue_factory import max_tool_calls_stop
from ares.core.factories.mcp_utils import parse_mcp_text_content
from ares.core.models import BlueRole
from ares.core.templates import get_template_loader
from ares.core.tracing import trace_tool_call
from ares.tools.blue.callbacks import BlueWorkerCallbackTools
from ares.tools.blue.shared_wrappers import SharedInvestigationTools

if TYPE_CHECKING:
    from dreadnode.agent.events import ToolEnd, ToolStart

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
    grafana_url: str = "",
    alert: dict | None = None,
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
        grafana_url: Grafana/Loki URL for QueryTemplateTools.
        alert: Alert dict for deriving label selectors.

    Returns:
        Tuple of (Agent, BlueWorkerCallbackTools).
    """
    instructions = load_blue_instructions(role)
    tools = _build_tools_for_role(
        role,
        backend,
        dispatcher,
        mitre_client,
        mcp_tools,
        grafana_url=grafana_url,
        alert=alert,
    )
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
    grafana_url: str = "",
    alert: dict | None = None,
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

    # Extract MCP query function and build QueryTemplateTools config
    loki_url = grafana_url.rstrip("/") if grafana_url else "http://localhost:3100"
    mcp_query_fn = _extract_mcp_query_fn(mcp_tools)
    deployment = (alert or {}).get("labels", {}).get("deployment", "")
    default_selector = (
        f'{{deployment="{deployment}"}}' if deployment else '{job="windows-security"}'
    )

    if role == BlueRole.TRIAGE:
        tools = _build_triage_tools(shared_tools, mitre_client, mcp_tools)
    elif role == BlueRole.THREAT_HUNTER:
        tools = _build_hunter_tools(
            shared_tools,
            mitre_client,
            mcp_tools,
            loki_url=loki_url,
            mcp_query_fn=mcp_query_fn,
            default_selector=default_selector,
        )
    elif role == BlueRole.LATERAL_ANALYST:
        tools = _build_lateral_tools(
            shared_tools,
            mitre_client,
            mcp_tools,
            loki_url=loki_url,
            mcp_query_fn=mcp_query_fn,
            default_selector=default_selector,
        )
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
    loki_url: str = "http://localhost:3100",
    mcp_query_fn: Any = None,
    default_selector: str = '{job="windows-security"}',
) -> list:
    """Build tools for threat hunter: detection queries + MCP + MITRE."""
    from ares.tools.blue import QueryTemplateTools
    from ares.tools.shared import MITRELookupTools

    tools: list = [shared_tools]

    # Pass specific QueryTemplateTools methods instead of whole toolset
    # (39 detect_* methods → 4 selective methods = massive context reduction)
    query_tools = QueryTemplateTools(
        loki_url=loki_url,
        default_label_selector=default_selector,
        mcp_query_fn=mcp_query_fn,
    )
    tools.append(query_tools.run_detection_query)
    tools.append(query_tools.list_query_templates)
    tools.append(query_tools.get_host_activity)
    tools.append(query_tools.get_user_activity)

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
    loki_url: str = "http://localhost:3100",
    mcp_query_fn: Any = None,
    default_selector: str = '{job="windows-security"}',
) -> list:
    """Build tools for lateral analyst: host/user activity + MCP."""
    from ares.tools.blue import QueryTemplateTools

    tools: list = [shared_tools]

    # Pass specific QueryTemplateTools methods for lateral analysis
    query_tools = QueryTemplateTools(
        loki_url=loki_url,
        default_label_selector=default_selector,
        mcp_query_fn=mcp_query_fn,
    )
    tools.append(query_tools.run_detection_query)
    tools.append(query_tools.get_host_activity)
    tools.append(query_tools.get_user_activity)

    # Add filtered MCP tools
    if mcp_tools:
        filtered = _filter_mcp_for_role(mcp_tools, _LATERAL_MCP_TOOLS)
        tools.extend(filtered)

    return tools


def _extract_mcp_query_fn(mcp_tools: list | None) -> Any:
    """Extract MCP query_loki_logs function from MCP tools.

    Returns a wrapper function compatible with QueryTemplateTools.mcp_query_fn,
    or None if no query_loki_logs tool found.
    """
    if not mcp_tools:
        return None

    for tool in mcp_tools:
        tool_name = getattr(tool, "name", "") or getattr(tool, "__name__", "")
        if "query_loki_logs" in tool_name:
            tool_fn = getattr(tool, "fn", None)
            if tool_fn is None and callable(tool):
                tool_fn = tool

            if tool_fn:

                async def mcp_loki_wrapper(
                    datasource_uid: str,
                    logql: str,
                    start_time: str,
                    end_time: str,
                    limit: int,
                    _fn=tool_fn,
                ):
                    result = await _fn(
                        datasourceUid=datasource_uid,
                        logql=logql,
                        startRfc3339=start_time,
                        endRfc3339=end_time,
                        limit=limit,
                    )
                    return parse_mcp_text_content(result)

                logger.info(
                    "QueryTemplateTools will use MCP query_loki_logs for authenticated queries"
                )
                return mcp_loki_wrapper
    return None


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
    if role == BlueRole.THREAT_HUNTER:
        return [
            tool_use("hunt_complete"),
            max_tool_calls_stop(max_calls=40),
        ]
    if role == BlueRole.LATERAL_ANALYST:
        return [
            tool_use("lateral_complete"),
            max_tool_calls_stop(max_calls=35),
        ]
    if role == BlueRole.ORCHESTRATOR:
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
        if not hasattr(event, "tool_call") or not event.tool_call:
            return
        tool_name = event.tool_call.name
        dn.log_metric(f"blue_{role.value}_tool_calls", 1, mode="count")
        logger.debug(f"[{role.value}] Tool call: {tool_name}")

    async def log_tool_result(event: ToolEnd):
        """Log tool results for observability with tracing."""
        if not hasattr(event, "tool_call") or not event.tool_call:
            return
        tool_name = event.tool_call.name
        result_len = (
            len(str(event.tool_result))
            if hasattr(event, "tool_result") and event.tool_result
            else 0
        )
        logger.debug(f"[{role.value}] Tool result: {tool_name} ({result_len} chars)")

        # Determine if tool had an error
        is_error = hasattr(event, "error") and event.error is not None
        error_msg = str(event.error)[:500] if is_error else None

        # Extract target info from tool arguments for span metrics
        target_host = None
        target_domain = None
        target_user = None
        if hasattr(event, "tool_call") and event.tool_call and event.tool_call.arguments:
            try:
                import json

                args = json.loads(event.tool_call.arguments)
                # Try common argument names for target host/IP
                target_host = (
                    args.get("target")
                    or args.get("target_ip")
                    or args.get("host")
                    or args.get("hostname")
                    or args.get("ip")
                )
                # Extract domain for attack.target.domain attribute
                target_domain = args.get("domain") or args.get("target_domain")
                # Extract username for user.name attribute
                target_user = args.get("username") or args.get("user") or args.get("target_user")
            except Exception:
                pass

        # Create trace span for blue team tool execution
        trace_tool_call(
            role.value,
            "blue",
            tool_name,
            is_error=is_error,
            error_message=error_msg,
            target_host=target_host,
            target_domain=target_domain,
            target_user=target_user,
        )

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


def create_triage_agent(
    model: str,
    backend: BlueStateBackend,
    shared_state: Any,
    max_steps: int = 10,
) -> Agent:
    """Create an escalation triage agent.

    The triage agent evaluates escalated investigations to determine
    if they truly require human review.

    Args:
        model: LLM model identifier.
        backend: BlueStateBackend for state persistence.
        shared_state: SharedBlueTeamState with investigation data.
        max_steps: Maximum agent steps (default 10).

    Returns:
        Configured Agent for escalation triage.
    """
    from ares.core.templates import get_template_loader
    from ares.tools.blue.triage_tools import EscalationTriageTools

    # Load triage instructions
    try:
        loader = get_template_loader()
        instructions = loader.render("blueteam/agents/escalation_triage.md.jinja")
    except Exception as e:
        logger.warning(f"Failed to load triage template: {e}")
        instructions = (
            "You are an escalation triage agent. Evaluate the investigation and "
            "call one of: confirm_escalation, downgrade_escalation, "
            "request_reinvestigation, or route_to_team."
        )

    # Create and configure tools
    triage_tools = EscalationTriageTools()
    triage_tools.set_backend(backend)
    triage_tools.set_shared_state(shared_state)

    # Stop conditions: any decision tool ends the agent
    stop_conditions = [
        tool_use("confirm_escalation"),
        tool_use("downgrade_escalation"),
        tool_use("request_reinvestigation"),
        tool_use("route_to_team"),
        max_tool_calls_stop(max_calls=15),
    ]

    return dn.Agent(
        name="Escalation Triage",
        model=model,
        instructions=instructions,
        max_steps=max_steps,
        tools=[triage_tools],
        stop_conditions=stop_conditions,
        thread=Thread(),  # type: ignore[call-arg]
    )
