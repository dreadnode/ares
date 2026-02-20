"""Factory for creating investigation agents with presets."""

import functools
import json as json_mod
import re
import uuid
from typing import Any

import dreadnode as dn
from dreadnode.agent import Agent, Thread
from dreadnode.agent.events import AgentEvent, AgentStalled, ToolEnd, ToolStart
from dreadnode.agent.hooks import retry_with_feedback
from dreadnode.agent.stop import StopCondition, tool_use
from loguru import logger

from ares.core.config import (
    get_bonus_queries_for_evidence,
    get_bonus_queries_for_pyramid_l4,
    get_max_duplicate_queries,
    get_max_queries_critical,
    get_max_queries_per_investigation,
    get_max_total_queries,
    get_query_limits_by_stage,
)
from ares.core.evidence_validation import (
    auto_extract_evidence_from_query,
    reset_evidence_validation,
    store_query_result,
)
from ares.core.models import Evidence, InvestigationState, PyramidLevel
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
_total_queries = 0  # Only counts queries that returned results
_total_queries_attempted = 0  # All queries attempted (including failed)
_consecutive_queries: list[str] = []
_query_limit_hit = False
_executed_queries: list[dict] = []
_seen_queries: dict[str, int] = {}  # Track query -> count to detect loops
_current_state: "InvestigationState | None" = None
_bonus_queries_granted = 0  # Track bonus queries granted
_in_resilient_execution = False  # Flag to bypass duplicate check during retries/chunks

# Evidence type to follow-up detection methods mapping for auto-chaining
EVIDENCE_CHAIN_MAP: dict[str, list[str]] = {
    # Evidence type → follow-up detection methods to queue
    "kerberoast_hash": ["detect_pass_the_hash", "detect_lateral_movement"],
    "dcsync": ["detect_golden_ticket", "detect_lateral_movement"],
    "s4u_delegation": ["detect_dcsync_replication", "detect_lsa_secrets_access"],
    "credential": ["detect_pass_the_hash", "detect_lateral_movement"],
    "service_creation": ["detect_impacket_psexec", "detect_suspicious_execution"],
    "pass_the_hash": ["detect_lateral_movement", "detect_remote_execution"],
    "golden_ticket": ["detect_lateral_movement", "detect_dcsync_replication"],
    "lateral_movement": ["detect_service_creation", "detect_scheduled_task"],
    "psexec": ["detect_service_creation", "detect_lateral_movement"],
    "wmiexec": ["detect_lateral_movement", "detect_service_creation"],
    "smbexec": ["detect_service_creation", "detect_lateral_movement"],
}

# LogQL optimization patterns - broad selectors that cause timeouts
_BROAD_SELECTOR_PATTERNS = [
    '{job=~".+"}',
    '{deployment=~".+"}',
    '{namespace=~".+"}',
    '{app=~".+"}',
    '{hostname=~".+"}',
]


def _extract_hosts_from_results(result_data: dict) -> set[str]:
    """Extract target hosts from lateral movement detection results.

    Args:
        result_data: Query result containing lateral movement detections

    Returns:
        Set of lowercase hostnames discovered in the results
    """
    hosts: set[str] = set()
    results = result_data.get("results", [])
    if not isinstance(results, list):
        return hosts

    host_fields = [
        "target_host",
        "TargetHost",
        "computer",
        "Computer",
        "dest_host",
        "destination",
        "TargetComputer",
    ]
    event_fields = ["TargetServerName", "TargetComputer", "IpAddress"]

    for item in results:
        if not isinstance(item, dict):
            continue
        for field in host_fields:
            if item.get(field):
                hosts.add(str(item[field]).lower())
        event_data = item.get("event_data", {})
        if isinstance(event_data, dict):
            for field in event_fields:
                if event_data.get(field):
                    hosts.add(str(event_data[field]).lower())
    return hosts


def _queue_pivot_queries(state: "InvestigationState", result_data: dict) -> None:
    """Queue pivot queries for hosts discovered via lateral movement detection.

    When lateral movement is detected, this function extracts target hosts
    from the results and queues follow-up queries to investigate those hosts.

    Args:
        state: Current investigation state
        result_data: Query result containing lateral movement detections
    """
    if not state or not result_data:
        return

    # Extract hosts from various result formats
    hosts_to_investigate = _extract_hosts_from_results(result_data)

    # Remove already-queried hosts
    hosts_to_investigate -= state.queried_hosts

    if not hosts_to_investigate:
        return

    # Queue pivot queries for each new host
    for host in hosts_to_investigate:
        # Add host to pending in lateral graph if available
        if state.lateral_graph and hasattr(state.lateral_graph, "pending_hosts"):
            state.lateral_graph.pending_hosts.add(host)

        # Queue follow-up queries for this host
        pivot_query = {
            "type": "pivot",
            "host": host,
            "reason": "Discovered via lateral movement detection",
            "suggested_methods": [
                "detect_lateral_movement",
                "detect_service_creation",
                "detect_suspicious_execution",
            ],
        }
        if pivot_query not in state.queued_pivot_queries:
            state.queued_pivot_queries.append(pivot_query)

    if hosts_to_investigate:
        logger.info(
            f"🔄 Auto-queued pivot investigation for {len(hosts_to_investigate)} hosts: "
            f"{', '.join(list(hosts_to_investigate)[:3])}{'...' if len(hosts_to_investigate) > 3 else ''}"
        )


def _queue_chained_queries(evidence_type: str, state: "InvestigationState") -> None:
    """Queue follow-up detection methods based on evidence type.

    When evidence is found, this function determines what follow-up
    detection methods should be run to expand investigation scope.

    Args:
        evidence_type: Type of evidence found (e.g., "kerberoast_hash", "dcsync")
        state: Current investigation state
    """
    if not state or not evidence_type:
        return

    # Normalize evidence type for lookup
    normalized_type = evidence_type.lower().replace("-", "_").replace(" ", "_")

    # Look up chained queries for this evidence type
    chain = EVIDENCE_CHAIN_MAP.get(normalized_type, [])

    if not chain:
        return

    # Queue methods that haven't been executed yet
    new_methods = []
    for method_name in chain:
        if (
            method_name not in state.executed_query_types
            and method_name not in state.queued_chain_queries
        ):
            state.queued_chain_queries.append(method_name)
            new_methods.append(method_name)

    if new_methods:
        logger.info(
            f"🔗 Auto-queued {len(new_methods)} chained queries for {evidence_type}: "
            f"{', '.join(new_methods)}"
        )


def _optimize_logql_query(query: str) -> tuple[str, bool]:
    """Optimize a LogQL query by rewriting broad selectors to prevent timeouts.

    Per Grafana Loki best practices:
    - Label selectors are the most important filter
    - Avoid {job=~".+"} which scans all streams
    - Put selective filters (event IDs) before regex patterns

    Uses the deployment label from the current alert context when available,
    falling back to {job="eventlog"} if no deployment context exists.

    Args:
        query: The original LogQL query string.

    Returns:
        Tuple of (optimized_query, was_modified).
    """
    was_modified = False
    optimized = query

    # Determine best replacement from alert context
    deployment = None
    if _current_state and _current_state.alert:
        deployment = _current_state.alert.get("labels", {}).get("deployment")

    replacement = f'{{deployment="{deployment}"}}' if deployment else '{job="eventlog"}'

    # Auto-rewrite broad selectors to use specific label
    for pattern in _BROAD_SELECTOR_PATTERNS:
        if pattern in query:
            logger.warning(
                f"Query contains broad selector '{pattern}' - auto-rewriting to "
                f"'{replacement}' to prevent timeout."
            )
            optimized = optimized.replace(pattern, replacement)
            was_modified = True
            # Continue checking for other broad patterns

    if "|~" in optimized and "|=" not in optimized:
        # Query only uses regex, no simple contains
        logger.debug(
            "Query uses only regex filters (|~). Consider using contains (|=) "
            "for literal strings - it's faster."
        )

    return optimized, was_modified


def reset_query_tracking():
    """Reset query tracking for a new investigation."""
    from ares.core.query_resilience import reset_resilient_executor

    global \
        _total_queries, \
        _total_queries_attempted, \
        _consecutive_queries, \
        _query_limit_hit, \
        _executed_queries, \
        _seen_queries, \
        _current_state, \
        _bonus_queries_granted, \
        _in_resilient_execution
    _total_queries = 0
    _total_queries_attempted = 0
    _consecutive_queries = []
    _query_limit_hit = False
    _executed_queries = []
    _seen_queries = {}
    _current_state = None
    _bonus_queries_granted = 0
    _in_resilient_execution = False
    reset_resilient_executor()
    reset_evidence_validation()  # Reset evidence validation state


def set_investigation_state(state: "InvestigationState"):
    """Set the current investigation state for query recording."""
    global _current_state
    _current_state = state


def _calculate_bonus_queries() -> int:
    """Calculate bonus queries based on investigation progress.

    Grants bonus queries for:
    - Finding evidence (+2 queries)
    - Reaching pyramid level 4+ (+2 queries)

    Returns:
        Number of bonus queries to grant (0, 2, or 4)
    """
    global _bonus_queries_granted

    if not _current_state:
        return 0

    new_bonus = 0
    bonus_for_evidence = get_bonus_queries_for_evidence()
    bonus_for_pyramid = get_bonus_queries_for_pyramid_l4()

    if _current_state.evidence_count > 0 and _bonus_queries_granted < bonus_for_evidence:
        new_bonus += bonus_for_evidence
        logger.info(f"🎁 Granting +{bonus_for_evidence} bonus queries for finding evidence")

    if (
        _current_state.highest_pyramid_level >= 4
        and _bonus_queries_granted < bonus_for_evidence + bonus_for_pyramid
    ):
        # Only grant pyramid bonus if not already at max bonus
        pyramid_bonus = min(
            bonus_for_pyramid,
            bonus_for_evidence + bonus_for_pyramid - _bonus_queries_granted,
        )
        if pyramid_bonus > 0:
            new_bonus += pyramid_bonus
            logger.info(f"🎁 Granting +{pyramid_bonus} bonus queries for reaching pyramid level 4+")

    if new_bonus > 0:
        _bonus_queries_granted += new_bonus

    return _bonus_queries_granted


def _get_query_limit() -> int:
    """Get the adaptive query limit based on investigation state.

    The limit is determined by:
    1. Base limit from alert severity (normal vs critical)
    2. Stage-based limits (triage, causation, lateral, synthesis)
    3. Bonus queries for productive investigations
    4. Hard cap at max_total_queries

    Returns:
        Current query limit
    """
    # Start with stage-based limit
    base_limit = get_max_queries_per_investigation()

    if _current_state:
        # Use stage-based limit
        stage_name = _current_state.stage.value
        base_limit = get_query_limits_by_stage().get(
            stage_name, get_max_queries_per_investigation()
        )

        # Override with critical severity limit if higher
        severity = _current_state.alert.get("labels", {}).get("severity", "").lower()
        if severity == "critical":
            base_limit = max(base_limit, get_max_queries_critical())

    bonus = _calculate_bonus_queries()
    total_limit = base_limit + bonus

    # Cap at maximum to prevent runaway
    return min(total_limit, get_max_total_queries())


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


def _check_duplicate_query(query: str, bypass_for_resilience: bool = False) -> str | None:
    """Check if query is a duplicate. Returns error message if duplicate limit hit.

    Args:
        query: The query string to check
        bypass_for_resilience: If True, skip the duplicate check (used during
            resilient execution retries/chunks to avoid blocking internal retries)

    Returns:
        Error message if duplicate limit hit, None otherwise
    """
    # Skip duplicate check during resilient execution (retries, time range reduction, chunks)
    # This prevents internal retry mechanisms from being blocked
    if bypass_for_resilience or _in_resilient_execution:
        logger.debug("Bypassing duplicate check during resilient execution")
        return None

    # Normalize query for comparison (strip whitespace, lowercase)
    normalized = query.strip().lower()

    count = _seen_queries.get(normalized, 0)
    if count >= get_max_duplicate_queries():
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
            "record_evidence(evidence_type='hostname', value='dc01.child.contoso.local', ...)\n"
            "record_evidence(evidence_type='user', value='bob.jones', ...)\n"
            "```"
        )

    # Increment count
    _seen_queries[normalized] = count + 1
    return None


def _increment_query_attempt(tool_name: str):
    """Increment query attempt counter (called before query execution)."""
    global _total_queries_attempted
    _total_queries_attempted += 1
    _consecutive_queries.append(tool_name)
    if len(_consecutive_queries) > 5:
        _consecutive_queries.pop(0)
    limit = _get_query_limit()
    logger.info(
        f"📊 Query attempt: {_total_queries_attempted} (successful: {_total_queries}/{limit})"
    )


def _count_successful_query(result_count: int | None):
    """Count a query as successful if it returned results.

    Only queries that return data count against the limit.
    Failed queries (0 results) get a "free retry".
    """
    global _total_queries

    if result_count is not None and result_count > 0:
        _total_queries += 1
        limit = _get_query_limit()
        logger.info(
            f"📊 Successful query count: {_total_queries}/{limit} (returned {result_count} results)"
        )
    else:
        logger.info("📊 Query returned 0 results - not counting against limit")


def _record_query(
    tool_name: str,
    kwargs: dict,
    result_count: int | None = None,
    result_data: Any = None,
):
    """Record a query to the investigation state and store for evidence validation."""
    from datetime import datetime, timezone

    query_string = kwargs.get("logql") or kwargs.get("expr") or str(kwargs)

    query_record = {
        "type": tool_name,
        "query": query_string,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "result_count": result_count,
        "datasource": kwargs.get("datasourceUid", "unknown"),
    }
    _executed_queries.append(query_record)

    if _current_state:
        _current_state.executed_queries.append(query_record)

    # Store query result for evidence validation (if we have results)
    if result_data is not None and result_count and result_count > 0:
        store_query_result(
            query_type=tool_name,
            query_string=query_string,
            result_data=result_data,
            result_count=result_count,
        )

        # AUTO-EXTRACTION: Automatically extract IOCs from query results
        if _current_state:
            try:
                extracted = auto_extract_evidence_from_query(
                    query_result=result_data,
                    source_description=f"{tool_name}: {query_string[:100]}",
                    mitre_technique=None,  # Will be enriched if agent provides context
                )

                if extracted:
                    existing_values = {e.value for e in _current_state.evidence}
                    added_count = 0

                    for item in extracted:
                        if item["value"] in existing_values:
                            continue

                        evidence = Evidence(
                            id=f"auto-{uuid.uuid4().hex[:8]}",
                            type=item["type"],
                            value=item["value"],
                            source=item["source"],
                            timestamp=None,
                            pyramid_level=PyramidLevel(item["pyramid_level"]),
                            mitre_techniques=item.get("mitre_techniques", []),
                            confidence=item["confidence"],
                            validated=item.get("validated", True),
                        )
                        _current_state.evidence.append(evidence)
                        existing_values.add(item["value"])  # Track for this batch
                        added_count += 1

                    if added_count > 0:
                        logger.info(
                            f"🔍 Auto-extracted {added_count} IOCs from query results "
                            f"(total evidence: {len(_current_state.evidence)})"
                        )

                        # AUTO-CHAIN: Queue follow-up queries based on evidence types
                        for item in extracted:
                            _queue_chained_queries(item["type"], _current_state)

            except Exception as e:
                logger.warning(f"Auto-extraction failed: {e}")

            # AUTO-PIVOT: Queue pivot queries for lateral movement detections
            if result_data and isinstance(result_data, dict) and result_data.get("_auto_pivot"):
                _queue_pivot_queries(_current_state, result_data)

            # Track executed query type for deduplication
            _current_state.executed_query_types.add(tool_name)


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

    # Prevent double-wrapping: if already wrapped, return as-is
    # This is critical because _mcp_tools persists across investigations,
    # and double-wrapping causes recursive calls to execute_with_resilience
    if getattr(original_tool, "_ares_rate_limited", False):
        logger.debug(f"Tool {tool_name} already wrapped, skipping")
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
            optimized_query, was_modified = _optimize_logql_query(query_str)
            if was_modified:
                # Update kwargs with optimized query
                query_key = "logql" if "logql" in kwargs else "expr"
                kwargs[query_key] = optimized_query
                query_str = optimized_query

            dup_msg = _check_duplicate_query(query_str)
            if dup_msg:
                logger.warning(f"🔁 Blocking duplicate query: {query_str[:50]}...")
                return dup_msg

        _increment_query_attempt(tool_name)

        start_time = kwargs.get("startRfc3339") or kwargs.get("start_time") or kwargs.get("start")
        end_time = kwargs.get("endRfc3339") or kwargs.get("end_time") or kwargs.get("end")

        # If we have time parameters, use resilient executor
        if start_time and end_time and query_str:
            global _in_resilient_execution
            logger.info(f"Using resilient executor for {tool_name}")
            try:
                # Set flag to bypass duplicate detection during resilient execution
                # This allows internal retries, time range reductions, and chunking
                # to proceed without being blocked by duplicate detection
                _in_resilient_execution = True

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

                # Record the query with result count and data for validation
                result_count = _extract_result_count(result)
                _record_query(tool_name, kwargs, result_count, result_data=result)
                # Only count successful queries against the limit
                _count_successful_query(result_count)

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

                return _compact_loki_result(result)

            except Exception as e:
                logger.error(f"Resilient execution failed: {e}")
                _record_query(tool_name, kwargs, result_count=0)
                return {
                    "status": "error",
                    "error": str(e),
                    "suggestion": "Try a shorter time range or more specific filters.",
                }
            finally:
                # Always reset the flag after resilient execution completes
                _in_resilient_execution = False

        # Fallback to original execution without resilience (no time params)
        try:
            result = await original_fn(*args, **kwargs)
            result_count = _extract_result_count(result)
            _record_query(tool_name, kwargs, result_count, result_data=result)
            # Only count successful queries against the limit
            _count_successful_query(result_count)
            return _compact_loki_result(result)
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
        # Mark as wrapped to prevent double-wrapping on subsequent investigations
        original_tool._ares_rate_limited = True
        return original_tool
    # It's a callable, just return the wrapper
    rate_limited_wrapper.__name__ = tool_name
    rate_limited_wrapper._ares_rate_limited = True
    return rate_limited_wrapper


def _compact_loki_result(result: Any) -> Any:
    """Remove redundant data from Loki MCP responses to reduce token usage.

    Windows Security Event logs contain the same data three times:
    1. event_data: raw XML fields (<Data Name='X'>val</Data>)
    2. message: human-readable prose with the same fields
    3. JSON metadata (event_id, computer, etc.)

    This function parses event_data XML into a clean dict and drops
    the redundant 'message' and raw XML, cutting ~60-70% of tokens
    while keeping all security-relevant fields.
    """
    # MCP tools return list[ContentText] — extract the text payload
    if isinstance(result, list) and len(result) > 0:
        item = result[0]
        text = getattr(item, "text", None)
        if text is None:
            return result
    elif isinstance(result, str):
        text = result
    else:
        return result

    try:
        data = json_mod.loads(text)
    except (json_mod.JSONDecodeError, TypeError):
        return result

    if not isinstance(data, dict) or "data" not in data:
        return result

    entries = data.get("data", [])
    if not isinstance(entries, list):
        return result

    compacted = []
    for entry in entries:
        line_str = entry.get("line", "")
        timestamp = entry.get("timestamp", "")

        # Parse the log line JSON
        try:
            line = json_mod.loads(line_str) if isinstance(line_str, str) else line_str
        except (json_mod.JSONDecodeError, TypeError):
            compacted.append(entry)
            continue

        if not isinstance(line, dict):
            compacted.append(entry)
            continue

        # Parse event_data XML into clean key-value pairs
        event_data_xml = line.get("event_data", "")
        parsed_fields = {}
        if event_data_xml:
            for match in re.finditer(r"<Data Name='([^']+)'[^>]*>([^<]*)</Data>", event_data_xml):
                parsed_fields[match.group(1)] = match.group(2)

        # Keep all fields EXCEPT the two redundant blobs
        # "message" = prose rendering of event_data (duplicate)
        # "event_data" = raw XML (replaced by parsed key-value "fields")
        compact_line = {k: v for k, v in line.items() if k not in ("message", "event_data")}
        if parsed_fields:
            compact_line["fields"] = parsed_fields

        compacted.append({"timestamp": timestamp, "line": compact_line})

    original_chars = len(text)
    compact_json = json_mod.dumps({"data": compacted, "count": len(compacted)})
    saved_pct = (1 - len(compact_json) / original_chars) * 100 if original_chars else 0
    logger.info(
        f"📦 Compacted Loki result: {original_chars:,} → {len(compact_json):,} chars "
        f"({saved_pct:.0f}% reduction, {len(compacted)} entries)"
    )

    # Return in the same format the SDK expects
    if isinstance(result, list) and hasattr(result[0], "text"):
        # Reconstruct ContentText
        result[0].text = compact_json
        return result
    return compact_json


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


# MCP tools essential for SOC investigation - everything else is bloat
# (dashboard mgmt, alert mgmt, user mgmt, org mgmt, etc.)
_ESSENTIAL_MCP_TOOLS = {
    # Loki log queries
    "query_loki_logs",
    "query_loki_patterns",
    "query_loki_stats",
    # Loki label discovery
    "list_loki_label_names",
    "list_loki_label_values",
    # Prometheus metrics
    "query_prometheus",
    "query_prometheus_histogram",
    # Datasource discovery
    "list_datasources",
    "get_datasource_by_name",
    "get_datasource_by_uid",
}


def filter_essential_mcp_tools(mcp_tools: list) -> list:
    """Filter MCP tools to only those essential for SOC investigation.

    Reduces context window usage by removing ~47 unnecessary tools
    (dashboard management, alert management, user management, etc.)
    that consume ~35K+ tokens of tool schema definitions.

    Args:
        mcp_tools: All MCP tools from Grafana MCPClient

    Returns:
        Filtered list containing only investigation-essential tools
    """
    filtered = []
    removed = []
    for tool in mcp_tools:
        tool_name = getattr(tool, "name", "") or getattr(tool, "__name__", str(tool))
        if tool_name in _ESSENTIAL_MCP_TOOLS:
            filtered.append(tool)
        else:
            removed.append(tool_name)

    logger.info(
        f"Filtered MCP tools: kept {len(filtered)}/{len(mcp_tools)} essential tools, "
        f"removed {len(removed)}: {removed[:5]}{'...' if len(removed) > 5 else ''}"
    )
    return filtered


def wrap_mcp_query_tools(mcp_tools: list) -> list:
    """
    Filter to essential tools, then wrap query tools with rate limiting.

    Args:
        mcp_tools: List of MCP tools from Grafana MCPClient

    Returns:
        Filtered list with query tools wrapped for rate limiting
    """
    # First filter to essential tools only
    essential_tools = filter_essential_mcp_tools(mcp_tools)

    wrapped = []
    wrapped_count = 0

    for tool in essential_tools:
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


def query_limit_hit_stop() -> StopCondition:
    """Stop condition that fires when the query limit has been hit.

    This is critical because when queries are blocked by the rate limiter,
    the MCP tool never actually runs, so max_queries_stop doesn't count them.
    This condition checks the global _query_limit_hit flag directly.
    """
    from collections.abc import Sequence

    def stop(events: Sequence[AgentEvent]) -> bool:
        if _query_limit_hit:
            logger.critical(
                "🛑 STOP CONDITION: Query limit hit flag is set. "
                "All queries are being blocked - forcing agent to stop."
            )
            return True
        return False

    return StopCondition(stop, name="stop_on_query_limit_hit")


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
    # Extract MCP query_loki_logs function if available (fixes auth issues with direct HTTP)
    mcp_query_fn = None
    if grafana_mcp_tools:
        for tool in grafana_mcp_tools:
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
                        return await _fn(
                            datasourceUid=datasource_uid,
                            logql=logql,
                            startRfc3339=start_time,
                            endRfc3339=end_time,
                            limit=limit,
                        )

                    mcp_query_fn = mcp_loki_wrapper
                    logger.info(
                        "QueryTemplateTools will use MCP query_loki_logs for authenticated queries"
                    )
                break

    # Derive label selector from alert context for scoped queries
    deployment = state.alert.get("labels", {}).get("deployment", "")
    default_selector = f'{{deployment="{deployment}"}}' if deployment else '{job="eventlog"}'
    query_template_tools = QueryTemplateTools(
        loki_url=loki_url, default_label_selector=default_selector, mcp_query_fn=mcp_query_fn
    )

    learning_tools = LearningTools()

    # Pass specific QueryTemplateTools methods instead of the whole toolset
    # to reduce context window usage (~35 tools → 4 tools).
    # The dispatcher run_detection_query() internally calls any detect_* method,
    # preserving dn.log_metric() observability on each detection query.
    tools: list = [
        grafana_tools,
        investigation_tools,
        question_tools,
        mitre_tools,
        completion_tools,
        query_template_tools.run_detection_query,
        query_template_tools.list_query_templates,
        query_template_tools.get_host_activity,
        query_template_tools.get_user_activity,
        learning_tools,
        escalate_investigation,
    ]

    if grafana_mcp_tools:
        logger.info(f"Received {len(grafana_mcp_tools)} Grafana MCP tools")
        # Filter to essential tools only (prevents context window overflow)
        filtered_tools = filter_essential_mcp_tools(grafana_mcp_tools)
        # Wrap query tools with rate limiting to prevent infinite query loops
        wrapped_tools = wrap_mcp_query_tools(filtered_tools)
        tools.extend(wrapped_tools)
        logger.info(f"Final tool count: {len(tools)}")
    else:
        logger.warning(
            "No Grafana MCP tools available - agent will have limited query capabilities"
        )

    # Log total tool count for context window debugging
    tool_count = 0
    for t in tools:
        if hasattr(t, "get_tools"):
            tool_count += len(t.get_tools())
        else:
            tool_count += 1
    logger.info(f"📊 Total tools for agent: {tool_count} (from {len(tools)} entries)")

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
            query_limit_hit_stop(),  # Stop immediately when query limit is hit
            max_queries_stop(max_queries=12),  # Was 5 - force stop after 12 queries
            max_tool_calls_stop(max_calls=50),  # Was 20 - force stop after 50 total tool calls
        ],
        thread=Thread(),  # type: ignore[call-arg]
    )
