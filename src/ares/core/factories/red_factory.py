"""Factory for creating red team agents with presets."""

import time

import dreadnode as dn
from dreadnode.agent import Agent, Thread
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

# Event deduplication state
_last_event_times: dict[str, float] = {}
_last_step_number: int | None = None
_DEBOUNCE_WINDOW = 0.1  # 100ms debounce window


def reset_event_tracking():
    """Reset event tracking state for a new agent run."""
    global _last_event_times, _last_step_number
    _last_event_times = {}
    _last_step_number = None


def _should_log_event(event_type: str) -> bool:
    """Check if event should be logged (debounce rapid duplicates)."""
    now = time.time()
    last_time = _last_event_times.get(event_type, 0)
    if now - last_time < _DEBOUNCE_WINDOW:
        return False
    _last_event_times[event_type] = now
    return True


async def log_step_start(event: StepStart):
    """Log step start for debugging - only when step number is meaningful."""
    global _last_step_number
    step_num = getattr(event, "step_number", None)

    # Skip if no real step number or if it's the same as last logged step
    if step_num is None or step_num == _last_step_number:
        return

    if not _should_log_event("step_start"):
        return

    _last_step_number = step_num
    logger.info(f"📍 Step {step_num} started")


async def log_generation_end(event: GenerationEnd):
    """Log generation end - only when there's meaningful content."""
    # Skip empty/spurious generation events
    if not hasattr(event, "message") or not event.message:
        return

    msg = event.message
    has_content = hasattr(msg, "content") and msg.content and str(msg.content).strip()
    has_tool_calls = hasattr(msg, "tool_calls") and msg.tool_calls

    # Only log if there's actual content or tool calls
    if not has_content and not has_tool_calls:
        return

    if not _should_log_event("generation_end"):
        return

    # Log concise summary
    if has_tool_calls:
        tool_names = [tc.name for tc in msg.tool_calls]
        logger.info(f"🤖 Agent requesting tools: {tool_names}")
    elif has_content:
        content_preview = str(msg.content)[:200].replace("\n", " ")
        logger.info(f"🤖 Agent: {content_preview}...")


async def log_agent_error(event: AgentError):
    """Log agent errors - only real errors, not spurious SDK events."""
    error = getattr(event, "error", None)
    # Only log if there's an actual error (SDK emits AgentError with None frequently)
    if error is None:
        return  # Silently ignore spurious events

    logger.error(f"🚨 Agent error: {error}")
    if hasattr(event, "traceback") and event.traceback:
        logger.error(f"🚨 Traceback: {event.traceback}")


async def log_agent_end(event: AgentEnd):
    """Log agent end - only when there's a meaningful stop reason."""
    stop_reason = getattr(event, "stop_reason", None)

    # Skip spurious end events with no stop reason
    if stop_reason is None:
        return

    if not _should_log_event("agent_end"):
        return

    logger.info(f"🏁 Agent ended: {stop_reason}")


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
    # Reset event tracking for fresh agent run
    reset_event_tracking()

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
