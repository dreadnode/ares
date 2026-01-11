"""Factory for creating investigation agents with presets."""

import functools
from typing import Any

import dreadnode as dn
from dreadnode.agent import Agent
from dreadnode.agent.events import AgentEvent, AgentStalled, ToolEnd, ToolStart
from dreadnode.agent.hooks import retry_with_feedback
from dreadnode.agent.stop import StopCondition, tool_use
from dreadnode.agent.thread import Thread
from loguru import logger

from ares.core.models import InvestigationState
from ares.core.query_resilience import QueryResilientExecutor, get_resilient_executor
from ares.core.templates import get_template_loader
from ares.integrations.mitre import MITREAttackClient
from ares.tools.blue import (
    CompletionTools,
    GrafanaTools,
    InvestigationTools,
    LearningTools,
    QueryTemplateTools,
    QuestionEngineTools,
    escalate_investigation,
)
from ares.tools.shared import MITRELookupTools

SYSTEM_INSTRUCTIONS = get_template_loader().render("agent/system_instructions.md.jinja")

# Track query calls - reset per investigation via reset_query_tracking()
_total_queries = 0
_consecutive_queries: list[str] = []
_query_limit_hit = False
_executed_queries: list[dict] = []
_seen_queries: dict[str, int] = {}  # Track query -> count to detect loops
_current_state: "InvestigationState | None" = None
MAX_QUERIES_PER_INVESTIGATION = 5
MAX_QUERIES_CRITICAL = 8  # Higher limit for critical alerts
MAX_DUPLICATE_QUERIES = 2  # Max times same query can run before blocking


def reset_query_tracking():
    """Reset query tracking for a new investigation."""
    from ares.core.query_resilience import reset_resilient_executor

    global \
        _total_queries, \
        _consecutive_queries, \
        _query_limit_hit, \
        _executed_queries, \
        _seen_queries, \
        _current_state
    _total_queries = 0
    _consecutive_queries = []
    _query_limit_hit = False
    _executed_queries = []
    _seen_queries = {}
    _current_state = None
    reset_resilient_executor()


def set_investigation_state(state: "InvestigationState"):
    """Set the current investigation state for query recording."""
    global _current_state
    _current_state = state


def _get_query_limit() -> int:
    """Get the query limit based on alert severity."""
    if _current_state:
        severity = _current_state.alert.get("labels", {}).get("severity", "").lower()
        if severity == "critical":
            return MAX_QUERIES_CRITICAL
    return MAX_QUERIES_PER_INVESTIGATION


def _check_query_limit() -> str | None:
    """Check if query limit is reached. Returns error message if limit hit, None otherwise."""
    global _query_limit_hit
    limit = _get_query_limit()
    if _query_limit_hit or _total_queries >= limit:
        _query_limit_hit = True
        return (
            f"🛑 QUERY LIMIT REACHED ({_total_queries}/{limit}). You have exceeded the maximum number of queries.\n\n"
            "You MUST call complete_investigation(summary='...', attack_synopsis='...', recommendations=[...]) NOW.\n\n"
            "Summarize what you found from previous queries and complete the investigation.\n"
            "Do NOT attempt any more queries - they will all be blocked.\n\n"
            "REMEMBER: Include attack_synopsis (narrative of what happened) and recommendations (list of actions).\n\n"
            "Example:\n"
            "complete_investigation(\n"
            "    summary='Investigated [alert name]. Found [evidence/no evidence]. Confidence: [level].',\n"
            "    attack_synopsis='At [time], [user/IP] performed [action] against [target]...',\n"
            "    recommendations=['Reset compromised passwords', 'Block source IP', ...]\n"
            ")"
        )
    return None


def _check_duplicate_query(query: str) -> str | None:
    """Check if query is a duplicate. Returns error message if duplicate limit hit."""
    # Normalize query for comparison (strip whitespace, lowercase)
    normalized = query.strip().lower()

    count = _seen_queries.get(normalized, 0)
    if count >= MAX_DUPLICATE_QUERIES:
        logger.warning(f"🔁 Duplicate query blocked (run {count + 1} times): {query[:100]}...")
        return (
            f"🔁 DUPLICATE QUERY BLOCKED. You've already run this query {count} times.\n\n"
            "**DO NOT re-run the same query.** Instead:\n\n"
            "1. **PARSE THE RESULTS** you already received\n"
            "2. **EXTRACT IOCs** from the JSON:\n"
            "   - Look for 'computer' field → record as hostname\n"
            "   - Look for 'TargetUserName' in event_data → record as user\n"
            "   - Look for 'IpAddress' in event_data → record as IP\n"
            "3. **CALL record_evidence()** for each IOC found\n"
            "4. **Then try a DIFFERENT query** or call complete_investigation()\n\n"
            "Example extraction from previous results:\n"
            "```\n"
            "record_evidence(evidence_type='hostname', value='winterfell.north.sevenkingdoms.local', ...)\n"
            "record_evidence(evidence_type='user', value='robb.stark', ...)\n"
            "```"
        )

    # Increment count
    _seen_queries[normalized] = count + 1
    return None


def _increment_query_count(tool_name: str):
    """Increment query counter and log."""
    global _total_queries
    _total_queries += 1
    _consecutive_queries.append(tool_name)
    if len(_consecutive_queries) > 5:
        _consecutive_queries.pop(0)
    limit = _get_query_limit()
    logger.info(f"📊 Query count: {_total_queries}/{limit}")


def _record_query(tool_name: str, kwargs: dict, result_count: int | None = None):
    """Record a query to the investigation state."""
    from datetime import datetime, timezone

    query_record = {
        "type": tool_name,
        "query": kwargs.get("logql") or kwargs.get("expr") or str(kwargs),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "result_count": result_count,
        "datasource": kwargs.get("datasourceUid", "unknown"),
    }
    _executed_queries.append(query_record)

    if _current_state:
        _current_state.executed_queries.append(query_record)


def create_rate_limited_mcp_tool(
    original_tool: Any, resilient_executor: QueryResilientExecutor | None = None
) -> Any:
    """
    Wrap an MCP tool with rate limiting and resilient execution.

    The wrapper checks the global query counter BEFORE executing.
    If limit is reached, returns an error message instead of executing.
    This ensures the LLM sees the limit message even when batching queries.

    Features:
    - Rate limiting to prevent query abuse
    - Duplicate query detection
    - Automatic retry with exponential backoff (via resilient executor)
    - Automatic time range reduction on timeout
    """
    tool_name = getattr(original_tool, "name", "") or getattr(original_tool, "__name__", "")

    # Only wrap query tools
    if "query_loki" not in tool_name and "query_prometheus" not in tool_name:
        return original_tool

    logger.debug(f"Wrapping MCP tool with rate limiting and resilience: {tool_name}")

    original_fn = getattr(original_tool, "fn", None)
    if original_fn is None and callable(original_tool):
        original_fn = original_tool

    if original_fn is None:
        logger.warning(f"Could not find callable for tool {tool_name}, not wrapping")
        return original_tool

    executor = resilient_executor or get_resilient_executor()

    @functools.wraps(original_fn)
    async def rate_limited_wrapper(*args, **kwargs):
        error_msg = _check_query_limit()
        if error_msg:
            logger.critical(f"🛑 Blocking query tool {tool_name} - limit reached")
            return error_msg

        query_str = kwargs.get("logql") or kwargs.get("expr") or ""
        if query_str:
            dup_msg = _check_duplicate_query(query_str)
            if dup_msg:
                logger.warning(f"🔁 Blocking duplicate query: {query_str[:50]}...")
                return dup_msg

        # Increment counter
        _increment_query_count(tool_name)

        # Extract time parameters for resilient execution
        start_time = kwargs.get("startRfc3339") or kwargs.get("start_time") or kwargs.get("start")
        end_time = kwargs.get("endRfc3339") or kwargs.get("end_time") or kwargs.get("end")

        # If we have time parameters, use resilient executor
        if start_time and end_time and query_str:
            logger.info(f"Using resilient executor for {tool_name}")
            try:

                async def query_wrapper(logql: str, start_time: str, end_time: str, **kw):
                    updated_kwargs = {**kwargs}
                    if "startRfc3339" in kwargs:
                        updated_kwargs["startRfc3339"] = start_time
                        updated_kwargs["endRfc3339"] = end_time
                    elif "start_time" in kwargs:
                        updated_kwargs["start_time"] = start_time
                        updated_kwargs["end_time"] = end_time
                    elif "start" in kwargs:
                        updated_kwargs["start"] = start_time
                        updated_kwargs["end"] = end_time
                    if "logql" in updated_kwargs:
                        updated_kwargs["logql"] = logql
                    elif "expr" in updated_kwargs:
                        updated_kwargs["expr"] = logql
                    return await original_fn(*args, **updated_kwargs)

                result = await executor.execute_with_resilience(
                    query_wrapper,
                    query_str,
                    start_time,
                    end_time,
                )

                # Record the query with result count
                result_count = _extract_result_count(result)
                _record_query(tool_name, kwargs, result_count)

                # Log resilience metadata if present
                if isinstance(result, dict) and "_resilience_metadata" in result:
                    meta = result["_resilience_metadata"]
                    if meta.get("time_range_reduced"):
                        logger.info(
                            f"Query succeeded with reduced time range "
                            f"({meta.get('time_range_factor', 1.0) * 100:.0f}%)"
                        )
                    if meta.get("retry_count", 0) > 0:
                        logger.info(f"Query succeeded after {meta['retry_count']} retries")

                return result

            except Exception as e:
                logger.error(f"Resilient execution failed: {e}")
                _record_query(tool_name, kwargs, result_count=0)
                return {
                    "status": "error",
                    "error": str(e),
                    "suggestion": "Try a shorter time range or more specific filters.",
                }

        # Fallback to original execution without resilience (no time params)
        try:
            result = await original_fn(*args, **kwargs)
            result_count = _extract_result_count(result)
            _record_query(tool_name, kwargs, result_count)
            return result
        except Exception as e:
            error_str = str(e)
            # Handle gRPC timeout from mcp-grafana (10s default timeout)
            if "grpc" in error_str.lower() and "connection is closing" in error_str:
                logger.warning(f"Query tool {tool_name} timed out (mcp-grafana 10s limit)")
                _record_query(tool_name, kwargs, result_count=0)
                return {
                    "error": "Query timed out due to mcp-grafana 10s limit. "
                    "Try a shorter time range (e.g., last 1 hour instead of 24 hours) "
                    "or add more specific label filters to reduce the query scope."
                }
            logger.error(f"Query tool {tool_name} failed: {e}")
            _record_query(tool_name, kwargs, result_count=0)
            raise

    if hasattr(original_tool, "fn"):
        # It's a Tool object with a .fn attribute
        original_tool.fn = rate_limited_wrapper
        return original_tool
    # It's a callable, just return the wrapper
    rate_limited_wrapper.__name__ = tool_name
    return rate_limited_wrapper


def _extract_result_count(result: Any) -> int | None:
    """Extract result count from various result formats."""
    if isinstance(result, list):
        return len(result)
    if isinstance(result, dict):
        if "results" in result:
            return len(result.get("results", []))
        if "data" in result:
            data = result.get("data", {})
            if isinstance(data, dict) and "result" in data:
                streams = data.get("result", [])
                if isinstance(streams, list):
                    total = 0
                    for stream in streams:
                        values = stream.get("values", [])
                        total += len(values) if isinstance(values, list) else 0
                    return total
    if isinstance(result, str):
        return result.count("\n") if result else 0
    return None


def wrap_mcp_query_tools(mcp_tools: list) -> list:
    """
    Wrap all query-related MCP tools with rate limiting.

    Args:
        mcp_tools: List of MCP tools from Grafana MCPClient

    Returns:
        List of tools with query tools wrapped for rate limiting
    """
    wrapped = []
    wrapped_count = 0

    for tool in mcp_tools:
        tool_name = getattr(tool, "name", "") or getattr(tool, "__name__", str(tool))

        if "query_loki" in tool_name or "query_prometheus" in tool_name:
            wrapped_tool = create_rate_limited_mcp_tool(tool)
            wrapped.append(wrapped_tool)
            wrapped_count += 1
            logger.info(f"✅ Wrapped query tool: {tool_name}")
        else:
            wrapped.append(tool)

    logger.info(f"Wrapped {wrapped_count} query tools with rate limiting")
    return wrapped


async def log_tool_usage(event: ToolStart):
    """Log tool calls for observability."""
    # Note: Query counting is now handled by the rate-limited wrapper (create_rate_limited_mcp_tool)
    # This hook only handles logging and metrics
    if hasattr(event, "tool_call") and event.tool_call:
        tool_name = event.tool_call.name
        logger.info(f"🔧 Tool call: {tool_name}")
        dn.log_metric(f"tool_{tool_name}", 1, mode="count")

        # Clear consecutive queries on completion
        if "complete_investigation" in tool_name or "escalate_investigation" in tool_name:
            _consecutive_queries.clear()


async def log_tool_result(event: ToolEnd):
    """Log tool results for observability."""
    # Note: Query limit enforcement is now handled by the rate-limited wrapper
    # The wrapper returns an error message BEFORE execution, so the LLM sees it
    if hasattr(event, "tool_call") and event.tool_call:
        tool_name = event.tool_call.name
        if hasattr(event, "error") and event.error:
            logger.warning(f"❌ Tool {tool_name} failed: {event.error}")
            dn.log_metric("tool_errors", 1, mode="count")
        else:
            logger.info(f"✅ Tool {tool_name} completed")


unstall_hook = retry_with_feedback(
    event_type=AgentStalled,
    feedback=(
        "🛑 YOU ARE STUCK. You MUST call complete_investigation() NOW with ALL parameters.\n\n"
        "Required parameters:\n"
        "1. summary: What you found (or 'No malicious activity confirmed' if nothing)\n"
        "2. attack_synopsis: Narrative of what happened chronologically\n"
        "3. recommendations: List of actions to take (check alert annotations for 'response' guidance)\n\n"
        "Example:\n"
        "complete_investigation(\n"
        "    summary='Investigated DCSync alert. No matching events in time window. Confidence: Low.',\n"
        "    attack_synopsis='Alert triggered at [time] for potential DCSync activity. "
        "Investigation found no corroborating evidence in Loki logs.',\n"
        "    recommendations=['Continue monitoring for Event 4662', 'Review DC access logs manually']\n"
        ")\n\n"
        "DO NOT make more queries. Call complete_investigation() NOW."
    ),
)


def max_queries_stop(max_queries: int = 5) -> StopCondition:
    """Stop condition that fires after max_queries Loki/Prometheus queries."""
    from collections.abc import Sequence

    def stop(events: Sequence[AgentEvent]) -> bool:
        query_count = sum(
            1
            for e in events
            if isinstance(e, ToolEnd)
            and hasattr(e, "tool_call")
            and e.tool_call
            and ("query_loki" in e.tool_call.name or "query_prometheus" in e.tool_call.name)
        )
        if query_count >= max_queries:
            logger.critical(
                f"🛑 STOP CONDITION: Max queries ({max_queries}) reached. Forcing stop."
            )
            return True
        return False

    return StopCondition(stop, name="stop_on_max_queries")


def max_tool_calls_stop(max_calls: int = 20) -> StopCondition:
    """Stop condition that fires after max_calls TOTAL tool calls without completion.

    This is a safety net to prevent infinite loops when the agent keeps calling
    non-query tools (record_evidence, get_combined_questions, etc.) without
    ever calling complete_investigation.
    """
    from collections.abc import Sequence

    def stop(events: Sequence[AgentEvent]) -> bool:
        tool_count = sum(
            1 for e in events if isinstance(e, ToolEnd) and hasattr(e, "tool_call") and e.tool_call
        )
        if tool_count >= max_calls:
            logger.critical(
                f"🛑 STOP CONDITION: Max tool calls ({max_calls}) reached without completion. "
                "Agent must call complete_investigation() or escalate_investigation()."
            )
            return True
        return False

    return StopCondition(stop, name="stop_on_max_tool_calls")


def create_investigation_agent(
    model: str,
    grafana_url: str,
    grafana_api_key: str,
    mitre_client: MITREAttackClient,
    state: InvestigationState,
    grafana_mcp_tools: list | None = None,
    max_steps: int = 30,
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
    set_investigation_state(state)

    grafana_tools = GrafanaTools(
        base_url=grafana_url,
        api_key=grafana_api_key,
    )

    investigation_tools = InvestigationTools()
    investigation_tools.set_state(state)
    investigation_tools.set_mitre_client(mitre_client)

    question_tools = QuestionEngineTools()
    question_tools.set_engines(mitre_client, state)

    mitre_tools = MITRELookupTools()
    mitre_tools.set_client(mitre_client)

    completion_tools = CompletionTools()
    completion_tools.set_state(state)

    loki_url = grafana_url.rstrip("/")
    query_template_tools = QueryTemplateTools(loki_url=loki_url)

    learning_tools = LearningTools()

    tools: list = [
        grafana_tools,
        investigation_tools,
        question_tools,
        mitre_tools,
        completion_tools,
        query_template_tools,
        learning_tools,
        escalate_investigation,
    ]

    if grafana_mcp_tools:
        logger.info(f"Adding {len(grafana_mcp_tools)} Grafana MCP tools to agent")
        # Wrap query tools with rate limiting to prevent infinite query loops
        wrapped_tools = wrap_mcp_query_tools(grafana_mcp_tools)
        tools.extend(wrapped_tools)
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
            max_queries_stop(max_queries=5),  # Force stop after 5 queries
            max_tool_calls_stop(max_calls=20),  # Force stop after 20 total tool calls
        ],
        thread=Thread(),  # type: ignore[call-arg]
    )
