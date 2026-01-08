"""Factory for creating investigation agents with presets."""

import dreadnode as dn
from dreadnode.agent import Agent
from dreadnode.agent.events import AgentStalled, ToolEnd, ToolStart
from dreadnode.agent.hooks import retry_with_feedback
from dreadnode.agent.stop import tool_use
from dreadnode.agent.thread import Thread
from loguru import logger

from ares.core.models import InvestigationState
from ares.core.templates import get_template_loader
from ares.integrations.mitre import MITREAttackClient
from ares.tools.blue import (
    CompletionTools,
    GrafanaTools,
    InvestigationTools,
    QuestionEngineTools,
    escalate_investigation,
)
from ares.tools.shared import MITRELookupTools

# Load system instructions from template
SYSTEM_INSTRUCTIONS = get_template_loader().render("agent/system_instructions.md.jinja")

# Track consecutive query calls without workflow progress
_consecutive_queries = []


async def log_tool_usage(event: ToolStart):
    """Log tool calls for observability and detect loops."""
    if hasattr(event, "tool_call") and event.tool_call:
        tool_name = event.tool_call.name
        logger.info(f"🔧 Tool call: {tool_name}")
        dn.log_metric(f"tool_{tool_name}", 1, mode="count")

        # Track if agent is stuck in query loop
        if "query_loki" in tool_name or "query_prometheus" in tool_name:
            _consecutive_queries.append(tool_name)
            # Keep only last 5 calls
            if len(_consecutive_queries) > 5:
                _consecutive_queries.pop(0)

            # If last 3 calls are all queries, warn
            if len(_consecutive_queries) >= 3 and all(
                "query_loki" in t or "query_prometheus" in t for t in _consecutive_queries[-3:]
            ):
                logger.warning(
                    "⚠️ DETECTED QUERY LOOP: 3+ consecutive queries without recording evidence"
                )
                logger.warning(
                    "Agent should call record_evidence() or get_combined_questions() next"
                )
        elif "record_evidence" in tool_name or "get_combined_questions" in tool_name:
            # Reset counter when workflow tools are called
            _consecutive_queries.clear()


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
        "3. Record evidence with record_evidence() for EVERY finding\n"
        "4. When done, call complete_investigation() or escalate_investigation()\n\n"
        "If queries return empty results, document that and try broader queries OR move forward."
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

    completion_tools = CompletionTools()
    completion_tools.set_state(state)

    # Build tool list
    tools: list = [
        grafana_tools,
        investigation_tools,
        question_tools,
        mitre_tools,
        completion_tools,
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
