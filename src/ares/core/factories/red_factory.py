"""Factory for creating red team agents with presets."""

import dreadnode as dn
from dreadnode.agent import Agent
from dreadnode.agent.events import (
    AgentEnd,
    AgentError,
    AgentStalled,
    GenerationEnd,
    StepStart,
    ToolEnd,
    ToolStart,
)
from dreadnode.agent.hooks import retry_with_feedback
from dreadnode.agent.stop import tool_use
from dreadnode.agent.thread import Thread
from loguru import logger

from ares.core.models import RedTeamState
from ares.core.templates import get_template_loader
from ares.integrations.mitre import MITREAttackClient
from ares.tools.red.network import (
    BloodHoundTools,
    CertipyTools,
    CrackingTools,
    CredentialHarvestingTools,
    DelegationTools,
    GoldenTicketTools,
    NetworkEnumerationTools,
    RedTeamReportingTools,
    SharePilferingTools,
)

# Load system instructions from template
REDTEAM_SYSTEM_INSTRUCTIONS = get_template_loader().render(
    "redteam/agents/system_instructions.md.jinja"
)


async def log_step_start(event: StepStart):
    """Log step start for debugging."""
    logger.info(f"📍 Step started: step_number={getattr(event, 'step_number', '?')}")


async def log_generation_end(event: GenerationEnd):
    """Log generation end with details."""
    logger.info("📍 Generation ended")
    # Log the message if available
    if hasattr(event, "message") and event.message:
        msg = event.message
        logger.info(f"📍 Message type: {type(msg).__name__}")
        if hasattr(msg, "content"):
            logger.info(f"📍 Message content (first 500 chars): {str(msg.content)[:500]}")
        if hasattr(msg, "tool_calls") and msg.tool_calls:
            logger.info(f"📍 Tool calls requested: {[tc.name for tc in msg.tool_calls]}")


async def log_agent_error(event: AgentError):
    """Log agent errors."""
    error = getattr(event, "error", None)
    logger.error(f"🚨 Agent error: {error}")
    if hasattr(event, "traceback"):
        logger.error(f"🚨 Traceback: {event.traceback}")


async def log_agent_end(event: AgentEnd):
    """Log agent end."""
    stop_reason = getattr(event, "stop_reason", None)
    logger.info(f"📍 Agent ended: stop_reason={stop_reason}")


async def log_tool_usage(event: ToolStart):
    """Log tool calls for observability."""
    if hasattr(event, "tool_call") and event.tool_call:
        logger.info(f"🔧 Red Team Tool: {event.tool_call.name}")
        logger.info(f"🔧 Tool args: {getattr(event.tool_call, 'arguments', {})}")
        dn.log_metric(f"redteam_tool_{event.tool_call.name}", 1, mode="count")


async def log_tool_result(event: ToolEnd):
    """Log tool results."""
    if hasattr(event, "tool_call") and event.tool_call:
        if hasattr(event, "error") and event.error:
            logger.warning(f"❌ Tool {event.tool_call.name} failed: {event.error}")
            dn.log_metric("redteam_tool_errors", 1, mode="count")
        else:
            result = getattr(event, "result", None)
            result_preview = str(result)[:200] if result else "None"
            logger.info(f"✅ Tool {event.tool_call.name} completed: {result_preview}")


unstall_hook = retry_with_feedback(
    event_type=AgentStalled,
    feedback=(
        "You seem stuck. Remember the priority workflow:\n"
        "1. PRIORITY 1: krbtgt hash found? → Use golden_ticket tool immediately\n"
        "2. PRIORITY 2: Administrator hash found? → domain_admin_checker on ALL targets\n"
        "3. PRIORITY 3: New password found? → Re-enumerate users, shares, kerberoast, asrep_roast\n"
        "4. PRIORITY 4: Share access found? → Pilfer shares for credentials\n"
        "5. Use record_finding to report EVERY discovery\n"
        "6. Continue autonomous execution - don't stop for direction"
    ),
)


@dn.tool
def complete_operation(summary: str) -> str:
    """
    Mark the red team operation as complete and generate final report.

    Use this tool when you have:
    - Exhausted all credential sources
    - Attempted enumeration on all discovered targets
    - Cracked all obtainable hashes
    - Generated golden ticket (if krbtgt hash was found)
    - Achieved domain admin access (or determined it's not possible)

    Args:
        summary: Executive summary of the operation including:
            - All local administrators found
            - All domain administrators found
            - Attack paths for each admin compromise
            - Total credentials obtained
            - Success metrics achieved

    Returns:
        Confirmation message

    Example:
        >>> complete_operation("Operation successful. Domain admin achieved via...")
    """
    logger.success(f"🎯 Red team operation completed: {summary}")
    return f"✓ Operation marked as complete. Summary: {summary}"


def create_redteam_agent(
    model: str,
    mitre_client: MITREAttackClient,
    state: RedTeamState,
    max_steps: int = 200,
) -> Agent:
    """
    Create a configured red team agent.

    Args:
        model: LLM model to use
        mitre_client: Initialized MITRE ATT&CK client
        state: Red team operation state object
        max_steps: Maximum agent steps (default: 200 for complex operations)

    Returns:
        Configured agent ready for penetration testing operations
    """
    # Initialize toolsets
    network_tools = NetworkEnumerationTools()
    network_tools.set_state(state)

    credential_tools = CredentialHarvestingTools()
    credential_tools.set_state(state)

    cracking_tools = CrackingTools()
    cracking_tools.set_state(state)

    share_tools = SharePilferingTools()
    share_tools.set_state(state)

    golden_ticket_tools = GoldenTicketTools()
    golden_ticket_tools.set_state(state)

    # New GOAD-based toolsets
    bloodhound_tools = BloodHoundTools()
    bloodhound_tools.set_state(state)

    certipy_tools = CertipyTools()
    certipy_tools.set_state(state)

    delegation_tools = DelegationTools()
    delegation_tools.set_state(state)

    reporting_tools = RedTeamReportingTools()
    reporting_tools.set_state(state)

    # Build tool list
    tools: list = [
        network_tools,
        credential_tools,
        cracking_tools,
        share_tools,
        golden_ticket_tools,
        bloodhound_tools,
        certipy_tools,
        delegation_tools,
        reporting_tools,
        complete_operation,
    ]

    logger.info(f"Creating red team agent with {len(tools)} toolsets")

    return dn.Agent(
        name="Ares Red Team Operator",
        model=model,
        instructions=REDTEAM_SYSTEM_INSTRUCTIONS,
        max_steps=max_steps,
        tools=tools,
        hooks=[
            log_step_start,
            log_generation_end,
            log_agent_error,
            log_agent_end,
            log_tool_usage,
            log_tool_result,
            unstall_hook,
        ],
        stop_conditions=[
            tool_use("complete_operation"),
        ],
        thread=Thread(),  # type: ignore[call-arg]
    )
