"""Factory for creating investigation agents with presets."""

import dreadnode as dn
from dreadnode.agent import Agent
from dreadnode.agent.events import AgentStalled, ToolEnd, ToolStart
from dreadnode.agent.hooks import retry_with_feedback
from dreadnode.agent.stop import tool_use
from dreadnode.agent.thread import Thread
from loguru import logger

from src.mitre import MITREAttackClient
from src.models import InvestigationState
from src.templates import get_template_loader
from src.tools import (
    GrafanaTools,
    InvestigationTools,
    MITRELookupTools,
    QuestionEngineTools,
    complete_investigation,
    escalate_investigation,
)

# Load system instructions from template
SYSTEM_INSTRUCTIONS = get_template_loader().render("agent/system_instructions.md.jinja")


async def log_tool_usage(event: ToolStart):
    """Log tool calls for observability."""
    if hasattr(event, "tool_call") and event.tool_call:
        logger.info(f"🔧 Tool call: {event.tool_call.name}")
        dn.log_metric(f"tool_{event.tool_call.name}", 1, mode="count")


async def log_tool_result(event: ToolEnd):
    """Log tool results."""
    if hasattr(event, "tool_call") and event.tool_call:
        if hasattr(event, "error") and event.error:
            logger.warning(f"❌ Tool {event.tool_call.name} failed: {event.error}")
            dn.log_metric("tool_errors", 1, mode="count")
        else:
            logger.info(f"✅ Tool {event.tool_call.name} completed")


unstall_hook = retry_with_feedback(
    event_type=AgentStalled,
    feedback=(
        "You seem stuck. Remember:\n"
        "1. Call get_combined_questions() to get next questions\n"
        "2. Execute queries in PARALLEL to answer those questions\n"
        "3. Record evidence with record_evidence()\n"
        "4. When done, call complete_investigation() or escalate_investigation()"
    ),
)


def create_investigation_agent(
    model: str,
    grafana_url: str,
    grafana_api_key: str,
    mitre_client: MITREAttackClient,
    state: InvestigationState,
    grafana_mcp_tools: list | None = None,
    max_steps: int = 150,
) -> Agent:
    """
    Create a configured investigation agent.

    Args:
        model: LLM model to use
        grafana_url: Grafana base URL
        grafana_api_key: Grafana API key
        mitre_client: Initialized MITRE ATT&CK client
        state: Investigation state object
        grafana_mcp_tools: Optional list of Grafana MCP tools (from MCPClient)
        max_steps: Maximum agent steps

    Returns:
        Configured agent ready to investigate
    """
    grafana_tools = GrafanaTools(
        base_url=grafana_url,
        api_key=grafana_api_key,
    )

    investigation_tools = InvestigationTools()
    investigation_tools.set_state(state)

    question_tools = QuestionEngineTools()
    question_tools.set_engines(mitre_client, state)

    mitre_tools = MITRELookupTools()
    mitre_tools.set_client(mitre_client)

    # Build tool list
    tools: list = [
        grafana_tools,
        investigation_tools,
        question_tools,
        mitre_tools,
        complete_investigation,
        escalate_investigation,
    ]

    # Add Grafana MCP tools if available
    if grafana_mcp_tools:
        logger.info(f"Adding {len(grafana_mcp_tools)} Grafana MCP tools to agent")
        tools.extend(grafana_mcp_tools)
    else:
        logger.warning(
            "No Grafana MCP tools available - agent will have limited query capabilities"
        )

    return dn.Agent(
        name="Ares SOC Investigator",
        model=model,
        instructions=SYSTEM_INSTRUCTIONS,
        max_steps=max_steps,
        tools=tools,
        hooks=[
            log_tool_usage,
            log_tool_result,
            unstall_hook,
        ],
        stop_conditions=[
            tool_use("complete_investigation"),
            tool_use("escalate_investigation"),
        ],
        thread=Thread(),  # type: ignore[call-arg]
    )
