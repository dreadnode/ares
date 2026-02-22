"""Tests for the blue team agent factory."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from ares.core.config import (
    get_bonus_queries_for_evidence,
    get_bonus_queries_for_pyramid_l4,
    get_max_duplicate_queries,
    get_max_queries_critical,
    get_max_queries_per_investigation,
    get_max_total_queries,
    get_query_limits_by_stage,
)
from ares.core.factories.blue_factory import (
    EVIDENCE_CHAIN_MAP,
    _calculate_bonus_queries,
    _check_duplicate_query,
    _check_query_limit,
    _compact_evidence,
    _compact_loki_result,
    _compact_timeline,
    _count_successful_query,
    _extract_result_count,
    _get_query_limit,
    _increment_query_attempt,
    _optimize_logql_query,
    _queue_chained_queries,
    _queue_pivot_queries,
    _record_query,
    create_investigation_agent,
    create_rate_limited_mcp_tool,
    filter_essential_mcp_tools,
    log_tool_result,
    log_tool_usage,
    low_medium_severity_early_exit_stop,
    max_queries_stop,
    max_tool_calls_stop,
    periodic_context_compaction,
    query_limit_hit_stop,
    reset_query_tracking,
    set_investigation_state,
    wrap_mcp_query_tools,
)
from ares.core.lateral_analyzer import LateralGraph
from ares.core.models import (
    Evidence,
    InvestigationStage,
    InvestigationState,
    PyramidLevel,
)


class TestQueryTrackingReset:
    """Tests for reset_query_tracking function."""

    def test_reset_clears_counters(self):
        """Test that reset clears all tracking state."""
        # Set some state first
        import ares.core.factories.blue_factory as factory

        factory._total_queries = 10
        factory._total_queries_attempted = 15
        factory._query_limit_hit = True
        factory._executed_queries = [{"query": "test"}]
        factory._seen_queries = {"test": 5}
        factory._bonus_queries_granted = 3

        reset_query_tracking()

        assert factory._total_queries == 0
        assert factory._total_queries_attempted == 0
        assert factory._query_limit_hit is False
        assert factory._executed_queries == []
        assert factory._seen_queries == {}
        assert factory._bonus_queries_granted == 0


class TestSetInvestigationState:
    """Tests for set_investigation_state function."""

    def test_sets_current_state(self, investigation_state: InvestigationState):
        """Test setting current state."""
        import ares.core.factories.blue_factory as factory

        set_investigation_state(investigation_state)
        assert factory._current_state == investigation_state


class TestCalculateBonusQueries:
    """Tests for _calculate_bonus_queries function."""

    def test_no_bonus_without_state(self):
        """Test no bonus when no state set."""
        import ares.core.factories.blue_factory as factory

        factory._current_state = None
        factory._bonus_queries_granted = 0
        bonus = _calculate_bonus_queries()
        assert bonus == 0

    def test_bonus_for_evidence(self, investigation_state: InvestigationState):
        """Test bonus granted for finding evidence."""

        reset_query_tracking()
        investigation_state.evidence = [
            Evidence(
                id="ev-1",
                type="ip",
                value="192.168.58.1",
                source="test",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=[],
                confidence=0.8,
                validated=True,
            )
        ]
        set_investigation_state(investigation_state)

        bonus = _calculate_bonus_queries()
        assert bonus == get_bonus_queries_for_evidence()

    def test_bonus_for_pyramid_level_4(self, investigation_state: InvestigationState):
        """Test bonus granted for reaching pyramid level 4+."""

        reset_query_tracking()
        # Add TTP-level evidence to reach level 6
        investigation_state.evidence = [
            Evidence(
                id="ev-1",
                type="ttp",
                value="Attack behavior",
                source="test",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.TTPS,
                mitre_techniques=["T1003"],
                confidence=0.9,
                validated=True,
            )
        ]
        set_investigation_state(investigation_state)

        bonus = _calculate_bonus_queries()
        # Should get both evidence bonus and pyramid bonus
        assert bonus >= get_bonus_queries_for_evidence()


class TestGetQueryLimit:
    """Tests for _get_query_limit function."""

    def test_default_limit_without_state(self):
        """Test default limit when no state."""
        import ares.core.factories.blue_factory as factory

        factory._current_state = None
        factory._bonus_queries_granted = 0
        limit = _get_query_limit()
        assert limit == get_max_queries_per_investigation()

    def test_stage_based_limit(self, investigation_state: InvestigationState):
        """Test limit based on investigation stage."""

        reset_query_tracking()
        investigation_state.stage = InvestigationStage.TRIAGE
        set_investigation_state(investigation_state)

        limit = _get_query_limit()
        assert limit == get_query_limits_by_stage()["triage"]

    def test_critical_severity_higher_limit(self, critical_alert: dict):
        """Test higher limit for critical severity."""

        reset_query_tracking()
        state = InvestigationState(
            investigation_id="test",
            alert=critical_alert,
            started_at=datetime.now(timezone.utc),
            stage=InvestigationStage.TRIAGE,
            evidence=[],
            timeline=[],
            questions=[],
            identified_techniques=set(),
            identified_tactics=set(),
            technique_names={},
            technique_to_tactic={},
            queried_hosts=set(),
            queried_users=set(),
            executed_queries=[],
            escalated=False,
            escalation_reason=None,
            attack_synopsis=None,
            recommendations=[],
            lateral_graph=LateralGraph(),
        )
        set_investigation_state(state)

        limit = _get_query_limit()
        assert limit >= get_max_queries_critical()

    def test_limit_capped_at_max(self, investigation_state: InvestigationState):
        """Test limit is capped at get_max_total_queries()."""
        import ares.core.factories.blue_factory as factory

        reset_query_tracking()
        # Grant maximum bonuses
        factory._bonus_queries_granted = 100
        set_investigation_state(investigation_state)

        limit = _get_query_limit()
        assert limit <= get_max_total_queries()


class TestCheckQueryLimit:
    """Tests for _check_query_limit function."""

    def test_no_error_under_limit(self, investigation_state: InvestigationState):
        """Test no error when under limit."""

        reset_query_tracking()
        set_investigation_state(investigation_state)

        result = _check_query_limit()
        assert result is None

    def test_error_at_limit(self, investigation_state: InvestigationState):
        """Test error returned when at limit."""
        import ares.core.factories.blue_factory as factory

        reset_query_tracking()
        set_investigation_state(investigation_state)
        # Set queries to limit
        factory._total_queries = get_max_total_queries() + 10

        result = _check_query_limit()
        assert result is not None
        assert "QUERY LIMIT REACHED" in result

    def test_error_when_limit_hit_flag_set(self, investigation_state: InvestigationState):
        """Test error when limit hit flag is set."""
        import ares.core.factories.blue_factory as factory

        reset_query_tracking()
        set_investigation_state(investigation_state)
        factory._query_limit_hit = True

        result = _check_query_limit()
        assert result is not None


class TestCheckDuplicateQuery:
    """Tests for _check_duplicate_query function."""

    def test_first_query_allowed(self):
        """Test first occurrence of query is allowed."""

        reset_query_tracking()
        result = _check_duplicate_query("SELECT * FROM logs")
        assert result is None

    def test_duplicate_allowed_up_to_max(self):
        """Test duplicates allowed up to get_max_duplicate_queries()."""

        reset_query_tracking()
        query = "SELECT * FROM logs"

        for _ in range(get_max_duplicate_queries()):
            result = _check_duplicate_query(query)
            assert result is None

    def test_duplicate_blocked_at_max(self):
        """Test duplicate blocked when at max."""
        import ares.core.factories.blue_factory as factory

        reset_query_tracking()
        query = "SELECT * FROM logs"
        factory._seen_queries[query.strip().lower()] = get_max_duplicate_queries()

        result = _check_duplicate_query(query)
        assert result is not None
        assert "DUPLICATE QUERY BLOCKED" in result

    def test_query_normalized(self):
        """Test query is normalized for comparison."""
        import ares.core.factories.blue_factory as factory

        reset_query_tracking()
        _check_duplicate_query("  SELECT * FROM logs  ")
        _check_duplicate_query("SELECT * FROM LOGS")  # Different case

        # Both should be treated as same query
        assert factory._seen_queries.get("select * from logs", 0) == 2

    def test_bypass_for_resilience_parameter(self):
        """Test bypass_for_resilience parameter skips duplicate check."""
        import ares.core.factories.blue_factory as factory

        reset_query_tracking()
        query = "SELECT * FROM logs"
        factory._seen_queries[query.strip().lower()] = get_max_duplicate_queries()

        # Without bypass - should be blocked
        result = _check_duplicate_query(query, bypass_for_resilience=False)
        assert result is not None
        assert "DUPLICATE QUERY BLOCKED" in result

        # With bypass - should be allowed
        result = _check_duplicate_query(query, bypass_for_resilience=True)
        assert result is None

    def test_in_resilient_execution_flag_bypasses_check(self):
        """Test _in_resilient_execution flag bypasses duplicate check."""
        import ares.core.factories.blue_factory as factory

        reset_query_tracking()
        query = "SELECT * FROM logs"
        factory._seen_queries[query.strip().lower()] = get_max_duplicate_queries()

        # Without flag - should be blocked
        factory._in_resilient_execution = False
        result = _check_duplicate_query(query)
        assert result is not None
        assert "DUPLICATE QUERY BLOCKED" in result

        # With flag set - should be allowed even at max duplicates
        factory._in_resilient_execution = True
        result = _check_duplicate_query(query)
        assert result is None

        # Clean up
        factory._in_resilient_execution = False

    def test_reset_clears_in_resilient_execution_flag(self):
        """Test reset_query_tracking clears _in_resilient_execution flag."""
        import ares.core.factories.blue_factory as factory

        factory._in_resilient_execution = True
        reset_query_tracking()
        assert factory._in_resilient_execution is False


class TestIncrementQueryAttempt:
    """Tests for _increment_query_attempt function."""

    def test_increments_counter(self, investigation_state: InvestigationState):
        """Test counter is incremented."""
        import ares.core.factories.blue_factory as factory

        reset_query_tracking()
        set_investigation_state(investigation_state)

        _increment_query_attempt("query_loki")

        assert factory._total_queries_attempted == 1

    def test_adds_to_consecutive_queries(self, investigation_state: InvestigationState):
        """Test tool name added to consecutive queries."""
        import ares.core.factories.blue_factory as factory

        reset_query_tracking()
        set_investigation_state(investigation_state)

        _increment_query_attempt("query_loki")

        assert "query_loki" in factory._consecutive_queries


class TestCountSuccessfulQuery:
    """Tests for _count_successful_query function."""

    def test_counts_successful_query(self, investigation_state: InvestigationState):
        """Test successful query is counted."""
        import ares.core.factories.blue_factory as factory

        reset_query_tracking()
        set_investigation_state(investigation_state)

        _count_successful_query(10)

        assert factory._total_queries == 1

    def test_does_not_count_empty_result(self, investigation_state: InvestigationState):
        """Test empty result not counted."""
        import ares.core.factories.blue_factory as factory

        reset_query_tracking()
        set_investigation_state(investigation_state)

        _count_successful_query(0)

        assert factory._total_queries == 0

    def test_does_not_count_none_result(self, investigation_state: InvestigationState):
        """Test None result not counted."""
        import ares.core.factories.blue_factory as factory

        reset_query_tracking()
        set_investigation_state(investigation_state)

        _count_successful_query(None)

        assert factory._total_queries == 0


class TestRecordQuery:
    """Tests for _record_query function."""

    def test_records_query_details(self, investigation_state: InvestigationState):
        """Test query details are recorded."""
        import ares.core.factories.blue_factory as factory

        reset_query_tracking()
        set_investigation_state(investigation_state)

        _record_query(
            "query_loki",
            {"logql": '{job="test"}', "datasourceUid": "loki-1"},
            result_count=5,
        )

        assert len(factory._executed_queries) == 1
        assert factory._executed_queries[0]["type"] == "query_loki"

    def test_records_to_state(self, investigation_state: InvestigationState):
        """Test query recorded to investigation state."""
        reset_query_tracking()
        set_investigation_state(investigation_state)

        _record_query(
            "query_loki",
            {"logql": '{job="test"}'},
            result_count=3,
        )

        assert len(investigation_state.executed_queries) == 1


class TestExtractResultCount:
    """Tests for _extract_result_count function."""

    def test_extract_from_list(self):
        """Test extraction from list result."""
        result = [1, 2, 3, 4, 5]
        count = _extract_result_count(result)
        assert count == 5

    def test_extract_from_dict_results(self):
        """Test extraction from dict with results key."""
        result = {"results": [{"a": 1}, {"b": 2}]}
        count = _extract_result_count(result)
        assert count == 2

    def test_extract_from_loki_format(self):
        """Test extraction from Loki response format."""
        result = {
            "data": {
                "result": [
                    {"values": [[1, "a"], [2, "b"]]},
                    {"values": [[3, "c"]]},
                ]
            }
        }
        count = _extract_result_count(result)
        assert count == 3  # Total values across all streams

    def test_extract_from_string(self):
        """Test extraction from string (count newlines)."""
        result = "line1\nline2\nline3"
        count = _extract_result_count(result)
        assert count == 2  # Number of newlines

    def test_extract_returns_none_for_unknown(self):
        """Test returns None for unknown format."""
        result = 12345
        count = _extract_result_count(result)
        assert count is None


class TestCreateRateLimitedMcpTool:
    """Tests for create_rate_limited_mcp_tool function."""

    def test_non_query_tool_unchanged(self):
        """Test non-query tools are not wrapped."""

        def my_tool():
            pass

        my_tool.__name__ = "list_alerts"
        result = create_rate_limited_mcp_tool(my_tool)
        assert result == my_tool

    def test_query_tool_wrapped(self, investigation_state: InvestigationState):
        """Test query tools are wrapped."""
        reset_query_tracking()
        set_investigation_state(investigation_state)

        async def query_loki_logs(**kwargs):
            return {"results": []}

        query_loki_logs.__name__ = "query_loki_logs"
        wrapped = create_rate_limited_mcp_tool(query_loki_logs)

        # Should be wrapped (different function)
        assert wrapped != query_loki_logs or hasattr(wrapped, "__wrapped__")

    def test_prevents_double_wrapping(self, investigation_state: InvestigationState):
        """Test that tools are not wrapped twice (prevents recursive execution)."""
        reset_query_tracking()
        set_investigation_state(investigation_state)

        # Create a mock tool object that mimics MCP tool structure
        mock_tool = MagicMock()
        mock_tool.name = "query_loki_logs"
        mock_tool.fn = MagicMock()
        mock_tool._ares_rate_limited = False  # Not yet wrapped

        # First wrap
        wrapped_once = create_rate_limited_mcp_tool(mock_tool)
        assert wrapped_once is mock_tool  # Same object, fn replaced
        assert hasattr(wrapped_once, "_ares_rate_limited")
        assert wrapped_once._ares_rate_limited is True

        # Store the wrapped fn
        first_wrapper = mock_tool.fn

        # Second wrap attempt - should be a no-op
        wrapped_twice = create_rate_limited_mcp_tool(mock_tool)
        assert wrapped_twice is mock_tool
        # fn should NOT have changed - same wrapper as before
        assert mock_tool.fn is first_wrapper

    def test_wrap_mcp_query_tools_prevents_double_wrap(
        self, investigation_state: InvestigationState
    ):
        """Test wrap_mcp_query_tools handles tools that persist across investigations."""
        reset_query_tracking()
        set_investigation_state(investigation_state)

        # Simulate MCP tools that persist across investigations
        mock_tool = MagicMock()
        mock_tool.name = "query_loki_logs"
        mock_tool.fn = MagicMock()

        tools = [mock_tool]

        # First investigation wraps the tools
        _wrapped1 = wrap_mcp_query_tools(tools)
        first_wrapper = mock_tool.fn

        # Second investigation with same tool objects
        _wrapped2 = wrap_mcp_query_tools(tools)

        # The wrapper should be unchanged (no double wrapping)
        assert mock_tool.fn is first_wrapper


class TestWrapMcpQueryTools:
    """Tests for wrap_mcp_query_tools function."""

    def test_wraps_query_tools(self):
        """Test that wrap_mcp_query_tools filters to essential tools and wraps query tools."""

        class MockTool:
            def __init__(self, name):
                self.name = name

        tools = [
            MockTool("list_alerts"),
            MockTool("query_loki_logs"),
            MockTool("get_datasources"),
            MockTool("query_prometheus"),
        ]

        wrapped = wrap_mcp_query_tools(tools)

        # Only essential tools survive filtering (query_loki_logs, query_prometheus)
        assert len(wrapped) == 2
        names = [t.name for t in wrapped]
        assert "query_loki_logs" in names
        assert "query_prometheus" in names


class TestLogToolUsage:
    """Tests for log_tool_usage hook."""

    @pytest.mark.asyncio
    async def test_logs_tool_call(self):
        """Test tool call is logged."""
        mock_event = MagicMock()
        mock_tool_call = MagicMock()
        mock_tool_call.name = "query_loki"
        mock_event.tool_call = mock_tool_call

        await log_tool_usage(mock_event)
        # Should not raise

    @pytest.mark.asyncio
    async def test_clears_consecutive_on_completion(self):
        """Test consecutive queries cleared on completion."""
        import ares.core.factories.blue_factory as factory

        factory._consecutive_queries = ["query1", "query2"]

        mock_event = MagicMock()
        mock_tool_call = MagicMock()
        mock_tool_call.name = "complete_investigation"
        mock_event.tool_call = mock_tool_call

        await log_tool_usage(mock_event)

        assert factory._consecutive_queries == []


class TestLogToolResult:
    """Tests for log_tool_result hook."""

    @pytest.mark.asyncio
    async def test_logs_success(self):
        """Test successful tool result is logged."""
        mock_event = MagicMock()
        mock_tool_call = MagicMock()
        mock_tool_call.name = "query_loki"
        mock_event.tool_call = mock_tool_call
        mock_event.error = None

        await log_tool_result(mock_event)
        # Should not raise

    @pytest.mark.asyncio
    async def test_logs_error(self):
        """Test tool error is logged."""
        mock_event = MagicMock()
        mock_tool_call = MagicMock()
        mock_tool_call.name = "query_loki"
        mock_event.tool_call = mock_tool_call
        mock_event.error = "Query failed"

        await log_tool_result(mock_event)
        # Should not raise


class TestMaxQueriesStop:
    """Tests for max_queries_stop stop condition."""

    def test_returns_stop_condition(self):
        """Test that a StopCondition is returned."""
        from dreadnode.agent.stop import StopCondition

        stop_condition = max_queries_stop(max_queries=5)
        assert isinstance(stop_condition, StopCondition)
        assert callable(stop_condition.func)

    def test_empty_events_does_not_stop(self):
        """Test does not stop when events list is empty."""
        stop_condition = max_queries_stop(max_queries=5)
        result = stop_condition.func([])
        assert result is False

    def test_non_tool_events_do_not_count(self):
        """Test that non-ToolEnd events don't count toward the limit."""
        stop_condition = max_queries_stop(max_queries=1)
        # Pass events that are not ToolEnd instances
        events = [MagicMock(), MagicMock(), MagicMock()]
        result = stop_condition.func(events)
        assert result is False


class TestMaxToolCallsStop:
    """Tests for max_tool_calls_stop stop condition."""

    def test_returns_stop_condition(self):
        """Test that a StopCondition is returned."""
        from dreadnode.agent.stop import StopCondition

        stop_condition = max_tool_calls_stop(max_calls=20)
        assert isinstance(stop_condition, StopCondition)
        assert callable(stop_condition.func)

    def test_empty_events_does_not_stop(self):
        """Test does not stop when events list is empty."""
        stop_condition = max_tool_calls_stop(max_calls=20)
        result = stop_condition.func([])
        assert result is False

    def test_non_tool_events_do_not_count(self):
        """Test that non-ToolEnd events don't count toward the limit."""
        stop_condition = max_tool_calls_stop(max_calls=1)
        # Pass events that are not ToolEnd instances
        events = [MagicMock(), MagicMock(), MagicMock()]
        result = stop_condition.func(events)
        assert result is False


class TestQueryLimitHitStop:
    """Tests for query_limit_hit_stop stop condition."""

    def test_returns_stop_condition(self):
        """Test that a StopCondition is returned."""
        from dreadnode.agent.stop import StopCondition

        stop_condition = query_limit_hit_stop()
        assert isinstance(stop_condition, StopCondition)
        assert callable(stop_condition.func)

    def test_does_not_stop_when_limit_not_hit(self):
        """Test does not stop when query limit flag is not set."""
        import ares.core.factories.blue_factory as factory

        reset_query_tracking()  # Ensure flag is cleared
        assert factory._query_limit_hit is False

        stop_condition = query_limit_hit_stop()
        result = stop_condition.func([])
        assert result is False

    def test_stops_when_limit_hit(self):
        """Test stops when query limit flag is set."""
        import ares.core.factories.blue_factory as factory

        reset_query_tracking()
        factory._query_limit_hit = True  # Simulate limit being hit

        stop_condition = query_limit_hit_stop()
        result = stop_condition.func([])
        assert result is True

        # Cleanup
        reset_query_tracking()


class TestCreateInvestigationAgent:
    """Tests for create_investigation_agent function."""

    def test_creates_agent(
        self, investigation_state: InvestigationState, mock_mitre_client: MagicMock
    ):
        """Test agent creation."""
        reset_query_tracking()

        agent = create_investigation_agent(
            model="claude-3-sonnet",
            grafana_url="http://grafana:3000",
            grafana_api_key="test-key",  # pragma: allowlist secret
            mitre_client=mock_mitre_client,
            state=investigation_state,
            grafana_mcp_tools=None,
            max_steps=30,
        )

        assert agent is not None

    def test_creates_agent_with_empty_mcp_tools(
        self, investigation_state: InvestigationState, mock_mitre_client: MagicMock
    ):
        """Test agent creation with empty MCP tools list."""
        reset_query_tracking()

        # Pass empty list - the code path handling MCP tools will still be exercised
        # but without the dreadnode tool discovery issues from mocks
        agent = create_investigation_agent(
            model="claude-3-sonnet",
            grafana_url="http://grafana:3000",
            grafana_api_key="test-key",  # pragma: allowlist secret
            mitre_client=mock_mitre_client,
            state=investigation_state,
            grafana_mcp_tools=[],
            max_steps=30,
        )

        assert agent is not None


class TestConstants:
    """Tests for module constants."""

    def test_query_limits_reasonable(self):
        """Test query limits are reasonable values."""
        assert get_max_queries_per_investigation() > 0
        assert get_max_queries_critical() > get_max_queries_per_investigation()
        assert get_max_total_queries() > get_max_queries_critical()

    def test_bonus_queries_positive(self):
        """Test bonus queries are positive."""
        assert get_bonus_queries_for_evidence() > 0
        assert get_bonus_queries_for_pyramid_l4() > 0

    def test_duplicate_limit_reasonable(self):
        """Test duplicate limit is reasonable."""
        assert get_max_duplicate_queries() >= 1

    def test_stage_limits_progressive(self):
        """Test stage limits increase through investigation."""
        assert get_query_limits_by_stage()["triage"] <= get_query_limits_by_stage()["causation"]
        assert get_query_limits_by_stage()["causation"] <= get_query_limits_by_stage()["lateral"]


class TestOptimizeLogqlQuery:
    """Tests for _optimize_logql_query function."""

    def test_optimize_query_broad_selector(self):
        """Test warning for broad selectors."""
        query = '{job=~".*"}'
        optimized, was_modified = _optimize_logql_query(query)
        # Function warns but doesn't modify
        assert was_modified is False
        assert optimized == query

    def test_optimize_query_regex_only(self):
        """Test warning for regex-only queries."""
        query = '{job="syslog"} |~ "error"'
        optimized, was_modified = _optimize_logql_query(query)
        assert was_modified is False
        assert optimized == query

    def test_optimize_query_with_contains(self):
        """Test query with contains filter (efficient)."""
        query = '{job="syslog"} |= "error"'
        optimized, was_modified = _optimize_logql_query(query)
        assert was_modified is False
        assert optimized == query

    def test_optimize_query_normal_query(self):
        """Test normal query without issues."""
        query = '{job="windows-security"} |= "4688"'
        optimized, was_modified = _optimize_logql_query(query)
        assert was_modified is False
        assert optimized == query


class TestExtractResultCountEdgeCases:
    """Additional edge case tests for _extract_result_count function."""

    def test_extract_from_empty_list(self):
        """Test extracting count from empty list."""
        result = []
        assert _extract_result_count(result) == 0

    def test_extract_from_dict_with_results_key(self):
        """Test extracting count from dict with 'results' key."""
        result = {"results": [{"a": 1}, {"b": 2}, {"c": 3}]}
        assert _extract_result_count(result) == 3

    def test_extract_from_dict_with_empty_results(self):
        """Test extracting count from dict with empty 'results'."""
        result = {"results": []}
        assert _extract_result_count(result) == 0

    def test_extract_from_dict_with_data_and_result_streams(self):
        """Test extracting count from Loki-style result format."""
        # This is the typical Loki response format with streams
        result = {
            "data": {
                "result": [
                    {"values": [["ts1", "line1"], ["ts2", "line2"]]},
                    {"values": [["ts3", "line3"]]},
                ]
            }
        }
        assert _extract_result_count(result) == 3  # 2 + 1 values

    def test_extract_from_dict_with_data_but_not_dict(self):
        """Test extracting count when data is not a dict."""
        result = {"data": [1, 2, 3]}
        # data is a list, not dict, so won't find result key
        assert _extract_result_count(result) is None

    def test_extract_from_dict_with_data_dict_but_no_result(self):
        """Test extracting count when data dict has no result key."""
        result = {"data": {"something": "else"}}
        assert _extract_result_count(result) is None

    def test_extract_from_dict_with_empty_streams(self):
        """Test extracting count from streams with no values."""
        result = {
            "data": {
                "result": [
                    {"values": []},
                    {"values": []},
                ]
            }
        }
        assert _extract_result_count(result) == 0

    def test_extract_from_string_with_newlines(self):
        """Test extracting count from string counts newlines."""
        result = "line1\nline2\nline3"
        assert _extract_result_count(result) == 2

    def test_extract_from_empty_string(self):
        """Test extracting count from empty string."""
        result = ""
        assert _extract_result_count(result) == 0

    def test_extract_from_string_no_newlines(self):
        """Test extracting count from string without newlines."""
        result = "single line"
        assert _extract_result_count(result) == 0

    def test_extract_from_none(self):
        """Test extracting count from None."""
        result = None
        assert _extract_result_count(result) is None

    def test_extract_from_int(self):
        """Test extracting count from int returns None."""
        result = 42
        assert _extract_result_count(result) is None

    def test_extract_from_empty_dict(self):
        """Test extracting count from empty dict."""
        result = {}
        assert _extract_result_count(result) is None

    def test_extract_from_dict_without_known_keys(self):
        """Test extracting count from dict without known keys."""
        result = {"unknown": "value", "count": 10}
        assert _extract_result_count(result) is None

    def test_extract_from_dict_with_stream_values_not_list(self):
        """Test extracting count when stream values is not a list."""
        result = {
            "data": {
                "result": [
                    {"values": "not a list"},
                ]
            }
        }
        assert _extract_result_count(result) == 0


class TestQueuePivotQueries:
    """Tests for _queue_pivot_queries function."""

    def test_queue_pivot_queries_extracts_hosts(self, investigation_state: InvestigationState):
        """Test that pivot queries are queued for discovered hosts."""
        reset_query_tracking()
        set_investigation_state(investigation_state)

        result_data = {
            "_auto_pivot": True,
            "results": [
                {"target_host": "dc01.contoso.local", "event_id": 4624},
                {"TargetHost": "sql01.contoso.local", "event_id": 4648},
                {"computer": "ws01.contoso.local", "event_id": 7045},
            ],
        }

        _queue_pivot_queries(investigation_state, result_data)

        # Should have 3 pivot queries queued
        assert len(investigation_state.queued_pivot_queries) == 3

        # Check that hosts are correctly extracted
        queued_hosts = {q["host"] for q in investigation_state.queued_pivot_queries}
        assert "dc01.contoso.local" in queued_hosts
        assert "sql01.contoso.local" in queued_hosts
        assert "ws01.contoso.local" in queued_hosts

    def test_queue_pivot_queries_skips_already_queried_hosts(
        self, investigation_state: InvestigationState
    ):
        """Test that already-queried hosts are not re-queued."""
        reset_query_tracking()

        # Mark a host as already queried
        investigation_state.queried_hosts.add("dc01.contoso.local")
        set_investigation_state(investigation_state)

        result_data = {
            "_auto_pivot": True,
            "results": [
                {"target_host": "dc01.contoso.local"},
                {"target_host": "ws01.contoso.local"},
            ],
        }

        _queue_pivot_queries(investigation_state, result_data)

        # Only ws01 should be queued (dc01 was already queried)
        assert len(investigation_state.queued_pivot_queries) == 1
        assert investigation_state.queued_pivot_queries[0]["host"] == "ws01.contoso.local"

    def test_queue_pivot_queries_extracts_from_event_data(
        self, investigation_state: InvestigationState
    ):
        """Test extraction from nested event_data field."""
        reset_query_tracking()
        set_investigation_state(investigation_state)

        result_data = {
            "_auto_pivot": True,
            "results": [
                {
                    "event_id": 4624,
                    "event_data": {
                        "TargetServerName": "fs01.contoso.local",
                        "IpAddress": "192.168.58.50",
                    },
                },
            ],
        }

        _queue_pivot_queries(investigation_state, result_data)

        queued_hosts = {q["host"] for q in investigation_state.queued_pivot_queries}
        assert "fs01.contoso.local" in queued_hosts
        assert "192.168.58.50" in queued_hosts

    def test_queue_pivot_queries_empty_result(self, investigation_state: InvestigationState):
        """Test no error with empty result data."""
        reset_query_tracking()
        set_investigation_state(investigation_state)

        _queue_pivot_queries(investigation_state, {})
        _queue_pivot_queries(investigation_state, None)  # type: ignore[arg-type]

        assert len(investigation_state.queued_pivot_queries) == 0

    def test_queue_pivot_queries_no_duplicates(self, investigation_state: InvestigationState):
        """Test that duplicate hosts are not queued multiple times."""
        reset_query_tracking()
        set_investigation_state(investigation_state)

        result_data = {
            "_auto_pivot": True,
            "results": [
                {"target_host": "DC01.contoso.local"},
                {"target_host": "dc01.contoso.local"},  # Same host, different case
            ],
        }

        _queue_pivot_queries(investigation_state, result_data)

        # Should only have 1 unique host (lowercase normalized)
        assert len(investigation_state.queued_pivot_queries) == 1


class TestQueueChainedQueries:
    """Tests for _queue_chained_queries function."""

    def test_queue_chained_queries_dcsync(self, investigation_state: InvestigationState):
        """Test that DCSync evidence queues related detections."""
        reset_query_tracking()
        set_investigation_state(investigation_state)

        _queue_chained_queries("dcsync", investigation_state)

        # Should queue golden ticket and lateral movement detections
        assert "detect_golden_ticket" in investigation_state.queued_chain_queries
        assert "detect_lateral_movement" in investigation_state.queued_chain_queries

    def test_queue_chained_queries_pass_the_hash(self, investigation_state: InvestigationState):
        """Test that pass-the-hash evidence queues related detections."""
        reset_query_tracking()
        set_investigation_state(investigation_state)

        _queue_chained_queries("pass_the_hash", investigation_state)

        assert "detect_lateral_movement" in investigation_state.queued_chain_queries
        assert "detect_remote_execution" in investigation_state.queued_chain_queries

    def test_queue_chained_queries_skips_executed(self, investigation_state: InvestigationState):
        """Test that already-executed queries are not re-queued."""
        reset_query_tracking()

        # Mark a query type as already executed
        investigation_state.executed_query_types.add("detect_golden_ticket")
        set_investigation_state(investigation_state)

        _queue_chained_queries("dcsync", investigation_state)

        # Golden ticket should not be queued (already executed)
        assert "detect_golden_ticket" not in investigation_state.queued_chain_queries
        # But lateral movement should be queued
        assert "detect_lateral_movement" in investigation_state.queued_chain_queries

    def test_queue_chained_queries_unknown_type(self, investigation_state: InvestigationState):
        """Test that unknown evidence types don't cause errors."""
        reset_query_tracking()
        set_investigation_state(investigation_state)

        _queue_chained_queries("unknown_evidence_type", investigation_state)

        # Should not queue anything
        assert len(investigation_state.queued_chain_queries) == 0

    def test_queue_chained_queries_normalizes_type(self, investigation_state: InvestigationState):
        """Test that evidence type is normalized for lookup."""
        reset_query_tracking()
        set_investigation_state(investigation_state)

        # Try with different formats
        _queue_chained_queries("pass-the-hash", investigation_state)  # With dashes

        # Should still match pass_the_hash
        assert len(investigation_state.queued_chain_queries) > 0

    def test_queue_chained_queries_no_duplicates(self, investigation_state: InvestigationState):
        """Test that the same query is not queued twice."""
        reset_query_tracking()
        set_investigation_state(investigation_state)

        _queue_chained_queries("dcsync", investigation_state)
        initial_count = len(investigation_state.queued_chain_queries)

        _queue_chained_queries("dcsync", investigation_state)

        # Count should not increase
        assert len(investigation_state.queued_chain_queries) == initial_count


class TestEvidenceChainMap:
    """Tests for EVIDENCE_CHAIN_MAP constant."""

    def test_evidence_chain_map_has_expected_keys(self):
        """Test that EVIDENCE_CHAIN_MAP has expected evidence types."""
        expected_types = [
            "kerberoast_hash",
            "dcsync",
            "s4u_delegation",
            "credential",
            "service_creation",
            "pass_the_hash",
            "golden_ticket",
            "lateral_movement",
            "psexec",
            "wmiexec",
            "smbexec",
        ]

        for evidence_type in expected_types:
            assert evidence_type in EVIDENCE_CHAIN_MAP, f"Missing {evidence_type}"

    def test_evidence_chain_map_values_are_lists(self):
        """Test that all EVIDENCE_CHAIN_MAP values are lists of strings."""
        for key, value in EVIDENCE_CHAIN_MAP.items():
            assert isinstance(value, list), f"{key} value is not a list"
            for method in value:
                assert isinstance(method, str), f"{key} contains non-string method"

    def test_evidence_chain_map_methods_look_like_detect_methods(self):
        """Test that chained methods follow naming convention."""
        for key, methods in EVIDENCE_CHAIN_MAP.items():
            for method in methods:
                assert method.startswith("detect_"), (
                    f"{key} has method {method} that doesn't start with 'detect_'"
                )


class TestInvestigationStateQueueFields:
    """Tests for new queue fields on InvestigationState."""

    def test_state_has_queued_pivot_queries(self, investigation_state: InvestigationState):
        """Test state has queued_pivot_queries field."""
        assert hasattr(investigation_state, "queued_pivot_queries")
        assert isinstance(investigation_state.queued_pivot_queries, list)

    def test_state_has_queued_chain_queries(self, investigation_state: InvestigationState):
        """Test state has queued_chain_queries field."""
        assert hasattr(investigation_state, "queued_chain_queries")
        assert isinstance(investigation_state.queued_chain_queries, list)

    def test_state_has_executed_query_types(self, investigation_state: InvestigationState):
        """Test state has executed_query_types field."""
        assert hasattr(investigation_state, "executed_query_types")
        assert isinstance(investigation_state.executed_query_types, set)

    def test_queued_fields_default_to_empty(self, investigation_state: InvestigationState):
        """Test queue fields default to empty collections."""
        assert len(investigation_state.queued_pivot_queries) == 0
        assert len(investigation_state.queued_chain_queries) == 0
        assert len(investigation_state.executed_query_types) == 0


class TestFilterEssentialMcpTools:
    """Tests for filter_essential_mcp_tools function to prevent 128-tool limit."""

    def test_keeps_query_loki_tools(self):
        """Test that query_loki tools are kept."""

        mock_tools = [
            MagicMock(name="query_loki_logs"),
            MagicMock(name="query_loki_stats"),
            MagicMock(name="create_dashboard"),
        ]
        for t in mock_tools:
            t.name = t._mock_name

        filtered = filter_essential_mcp_tools(mock_tools)
        names = [t.name for t in filtered]

        assert "query_loki_logs" in names
        assert "query_loki_stats" in names
        assert "create_dashboard" not in names

    def test_keeps_query_prometheus_tools(self):
        """Test that query_prometheus tools are kept."""

        mock_tools = [
            MagicMock(name="query_prometheus"),
            MagicMock(name="create_alert"),
        ]
        for t in mock_tools:
            t.name = t._mock_name

        filtered = filter_essential_mcp_tools(mock_tools)
        names = [t.name for t in filtered]

        assert "query_prometheus" in names
        assert "create_alert" not in names

    def test_keeps_list_datasources(self):
        """Test that list_datasources tool is kept."""

        mock_tools = [
            MagicMock(name="list_datasources"),
            MagicMock(name="list_folders"),
        ]
        for t in mock_tools:
            t.name = t._mock_name

        filtered = filter_essential_mcp_tools(mock_tools)
        names = [t.name for t in filtered]

        assert "list_datasources" in names
        assert "list_folders" not in names

    def test_filters_non_essential_tools(self):
        """Test that non-essential tools are filtered out."""

        mock_tools = [
            MagicMock(name="create_dashboard"),
            MagicMock(name="update_dashboard"),
            MagicMock(name="delete_dashboard"),
            MagicMock(name="create_annotation"),
            MagicMock(name="list_alerts"),
            MagicMock(name="query_loki_logs"),  # This one should be kept
        ]
        for t in mock_tools:
            t.name = t._mock_name

        filtered = filter_essential_mcp_tools(mock_tools)

        assert len(filtered) == 1
        assert filtered[0].name == "query_loki_logs"

    def test_empty_input_returns_empty(self):
        """Test that empty input returns empty list."""

        filtered = filter_essential_mcp_tools([])
        assert filtered == []


class TestExtractUsersFromResults:
    """Tests for _extract_users_from_results function."""

    def test_extracts_target_user_name(self):
        """Test extraction of TargetUserName field."""
        from ares.core.factories.blue_factory import _extract_users_from_results

        result_data = {
            "results": [
                {"TargetUserName": "jon.snow"},
                {"TargetUserName": "samwell.tarly"},
            ]
        }
        users = _extract_users_from_results(result_data)
        assert "jon.snow" in users
        assert "samwell.tarly" in users

    def test_extracts_subject_user_name(self):
        """Test extraction of SubjectUserName field."""
        from ares.core.factories.blue_factory import _extract_users_from_results

        result_data = {
            "results": [
                {"SubjectUserName": "admin"},
            ]
        }
        users = _extract_users_from_results(result_data)
        assert "admin" in users

    def test_extracts_from_event_data(self):
        """Test extraction from nested event_data."""
        from ares.core.factories.blue_factory import _extract_users_from_results

        result_data = {
            "results": [
                {"event_data": {"TargetUserName": "svc_backup"}},
            ]
        }
        users = _extract_users_from_results(result_data)
        assert "svc_backup" in users

    def test_extracts_from_fields(self):
        """Test extraction from nested fields dict."""
        from ares.core.factories.blue_factory import _extract_users_from_results

        result_data = {
            "results": [
                {"fields": {"User": "testuser"}},
            ]
        }
        users = _extract_users_from_results(result_data)
        assert "testuser" in users

    def test_filters_system_accounts(self):
        """Test that system accounts are filtered out."""
        from ares.core.factories.blue_factory import _extract_users_from_results

        result_data = {
            "results": [
                {"TargetUserName": "SYSTEM"},
                {"TargetUserName": "LOCAL SERVICE"},
                {"TargetUserName": "NETWORK SERVICE"},
                {"TargetUserName": "-"},
                {"TargetUserName": "COMPUTER$"},  # Machine accounts
                {"TargetUserName": "realuser"},
            ]
        }
        users = _extract_users_from_results(result_data)
        assert "system" not in users
        assert "local service" not in users
        assert "network service" not in users
        assert "-" not in users
        assert "computer$" not in users
        assert "realuser" in users

    def test_normalizes_to_lowercase(self):
        """Test that usernames are normalized to lowercase."""
        from ares.core.factories.blue_factory import _extract_users_from_results

        result_data = {
            "results": [
                {"TargetUserName": "Jon.Snow"},
            ]
        }
        users = _extract_users_from_results(result_data)
        assert "jon.snow" in users

    def test_empty_results(self):
        """Test handling of empty results."""
        from ares.core.factories.blue_factory import _extract_users_from_results

        users = _extract_users_from_results({})
        assert len(users) == 0

        users = _extract_users_from_results({"results": []})
        assert len(users) == 0


class TestQueueUserInvestigation:
    """Tests for _queue_user_investigation function."""

    def test_queues_user_investigation(self, investigation_state: InvestigationState):
        """Test that user investigation is queued."""
        from ares.core.factories.blue_factory import _queue_user_investigation

        result_data = {
            "results": [
                {"TargetUserName": "jon.snow"},
            ]
        }
        _queue_user_investigation(investigation_state, result_data)

        # Should have a queued pivot query for user investigation
        user_queries = [
            q
            for q in investigation_state.queued_pivot_queries
            if q.get("type") == "user_investigation"
        ]
        assert len(user_queries) == 1
        assert user_queries[0]["user"] == "jon.snow"

    def test_skips_already_investigated_users(self, investigation_state: InvestigationState):
        """Test that already investigated users are skipped."""
        from ares.core.factories.blue_factory import _queue_user_investigation

        investigation_state.queried_users.add("jon.snow")
        result_data = {
            "results": [
                {"TargetUserName": "jon.snow"},
            ]
        }
        _queue_user_investigation(investigation_state, result_data)

        # Should not have a queued pivot query since user is already investigated
        user_queries = [
            q for q in investigation_state.queued_pivot_queries if q.get("user") == "jon.snow"
        ]
        assert len(user_queries) == 0

    def test_no_duplicates(self, investigation_state: InvestigationState):
        """Test that duplicate user queries are not added."""
        from ares.core.factories.blue_factory import _queue_user_investigation

        result_data = {
            "results": [
                {"TargetUserName": "jon.snow"},
            ]
        }
        _queue_user_investigation(investigation_state, result_data)
        _queue_user_investigation(investigation_state, result_data)

        user_queries = [
            q for q in investigation_state.queued_pivot_queries if q.get("user") == "jon.snow"
        ]
        assert len(user_queries) == 1


class TestCheckCriticalUsers:
    """Tests for _check_critical_users function."""

    def test_detects_krbtgt(self, investigation_state: InvestigationState):
        """Test that krbtgt triggers aggressive investigation."""
        from ares.core.factories.blue_factory import _check_critical_users

        result_data = {
            "results": [
                {"TargetUserName": "krbtgt"},
            ]
        }
        _check_critical_users(investigation_state, result_data)

        # Should have queued golden ticket and dcsync detection
        assert "detect_golden_ticket" in investigation_state.queued_chain_queries
        assert "detect_dcsync" in investigation_state.queued_chain_queries

    def test_detects_administrator(self, investigation_state: InvestigationState):
        """Test that administrator triggers investigation."""
        from ares.core.factories.blue_factory import _check_critical_users

        result_data = {
            "results": [
                {"TargetUserName": "administrator"},
            ]
        }
        _check_critical_users(investigation_state, result_data)

        # Should have queued lateral movement detection
        assert "detect_lateral_movement" in investigation_state.queued_chain_queries

    def test_does_not_trigger_for_normal_users(self, investigation_state: InvestigationState):
        """Test that normal users don't trigger critical alerts."""
        from ares.core.factories.blue_factory import _check_critical_users

        result_data = {
            "results": [
                {"TargetUserName": "jon.snow"},
            ]
        }
        _check_critical_users(investigation_state, result_data)

        # Should not have queued any critical investigation
        assert len(investigation_state.queued_chain_queries) == 0


class TestCheckCredentialDumpingEvidence:
    """Tests for _check_credential_dumping_evidence function."""

    def test_detects_t1003(self, investigation_state: InvestigationState):
        """Test that T1003 technique triggers comprehensive investigation."""
        from ares.core.factories.blue_factory import _check_credential_dumping_evidence

        result_data = {
            "_mitre_technique": "T1003.006",
            "_query_template": "dcsync",
        }
        _check_credential_dumping_evidence(investigation_state, result_data)

        # Should have queued multiple T1003 variants
        assert len(investigation_state.queued_chain_queries) > 0

    def test_detects_secretsdump(self, investigation_state: InvestigationState):
        """Test that secretsdump triggers comprehensive investigation."""
        from ares.core.factories.blue_factory import _check_credential_dumping_evidence

        result_data = {
            "_query_template": "secretsdump",
        }
        _check_credential_dumping_evidence(investigation_state, result_data)

        assert len(investigation_state.queued_chain_queries) > 0

    def test_does_not_trigger_for_non_t1003(self, investigation_state: InvestigationState):
        """Test that non-T1003 techniques don't trigger orchestration."""
        from ares.core.factories.blue_factory import _check_credential_dumping_evidence

        result_data = {
            "_mitre_technique": "T1046",  # Network service discovery
            "_query_template": "port_scanning",
        }
        _check_credential_dumping_evidence(investigation_state, result_data)

        assert len(investigation_state.queued_chain_queries) == 0


class TestCriticalUsers:
    """Tests for CRITICAL_USERS set."""

    def test_critical_users_contains_krbtgt(self):
        """Test that krbtgt is in critical users."""
        from ares.core.factories.blue_factory import CRITICAL_USERS

        assert "krbtgt" in CRITICAL_USERS

    def test_critical_users_contains_administrator(self):
        """Test that administrator is in critical users."""
        from ares.core.factories.blue_factory import CRITICAL_USERS

        assert "administrator" in CRITICAL_USERS


class TestUserChainMap:
    """Tests for USER_CHAIN_MAP."""

    def test_krbtgt_has_golden_ticket_chain(self):
        """Test that krbtgt chains to golden ticket detection."""
        from ares.core.factories.blue_factory import USER_CHAIN_MAP

        assert "krbtgt" in USER_CHAIN_MAP
        assert "detect_golden_ticket" in USER_CHAIN_MAP["krbtgt"]

    def test_administrator_has_lateral_movement_chain(self):
        """Test that administrator chains to lateral movement detection."""
        from ares.core.factories.blue_factory import USER_CHAIN_MAP

        assert "administrator" in USER_CHAIN_MAP
        assert "detect_lateral_movement" in USER_CHAIN_MAP["administrator"]


# ============================================================================
# Context Compaction Tests (new blue-compaction feature)
# ============================================================================


class TestCompactEvidence:
    """Tests for _compact_evidence function."""

    def test_empty_evidence_returns_zero(self, investigation_state: InvestigationState):
        """Test that empty evidence list returns 0."""

        investigation_state.evidence = []
        removed = _compact_evidence(investigation_state)
        assert removed == 0

    def test_no_duplicates_returns_zero(self, investigation_state: InvestigationState):
        """Test that no duplicates means nothing removed."""

        investigation_state.evidence = [
            Evidence(
                id="ev-1",
                type="ip",
                value="192.168.1.1",
                source="test",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=[],
                confidence=0.8,
            ),
            Evidence(
                id="ev-2",
                type="ip",
                value="192.168.1.2",
                source="test",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=[],
                confidence=0.8,
            ),
        ]
        removed = _compact_evidence(investigation_state)
        assert removed == 0
        assert len(investigation_state.evidence) == 2

    def test_removes_duplicate_by_type_value(self, investigation_state: InvestigationState):
        """Test that duplicates are detected by type:value key."""

        investigation_state.evidence = [
            Evidence(
                id="ev-1",
                type="ip",
                value="192.168.1.1",
                source="test1",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=[],
                confidence=0.8,
            ),
            Evidence(
                id="ev-2",
                type="ip",
                value="192.168.1.1",  # Same value
                source="test2",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=[],
                confidence=0.7,
            ),
        ]
        removed = _compact_evidence(investigation_state)
        assert removed == 1
        assert len(investigation_state.evidence) == 1

    def test_keeps_higher_confidence(self, investigation_state: InvestigationState):
        """Test that higher confidence evidence is kept."""

        investigation_state.evidence = [
            Evidence(
                id="ev-1",
                type="ip",
                value="192.168.1.1",
                source="test1",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=[],
                confidence=0.5,  # Lower confidence
            ),
            Evidence(
                id="ev-2",
                type="ip",
                value="192.168.1.1",
                source="test2",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=[],
                confidence=0.9,  # Higher confidence - should be kept
            ),
        ]
        removed = _compact_evidence(investigation_state)
        assert removed == 1
        assert investigation_state.evidence[0].id == "ev-2"
        assert investigation_state.evidence[0].confidence == 0.9

    def test_keeps_more_mitre_techniques(self, investigation_state: InvestigationState):
        """Test that evidence with more MITRE techniques is kept when confidence is equal."""

        investigation_state.evidence = [
            Evidence(
                id="ev-1",
                type="hash",
                value="abc123",
                source="test1",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.HASH_VALUES,
                mitre_techniques=["T1003"],  # Fewer techniques
                confidence=0.8,
            ),
            Evidence(
                id="ev-2",
                type="hash",
                value="ABC123",  # Same (case-insensitive)
                source="test2",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.HASH_VALUES,
                mitre_techniques=["T1003", "T1059", "T1078"],  # More techniques - should be kept
                confidence=0.8,
            ),
        ]
        removed = _compact_evidence(investigation_state)
        assert removed == 1
        assert investigation_state.evidence[0].id == "ev-2"
        assert len(investigation_state.evidence[0].mitre_techniques) == 3

    def test_case_insensitive_value_comparison(self, investigation_state: InvestigationState):
        """Test that value comparison is case-insensitive."""

        investigation_state.evidence = [
            Evidence(
                id="ev-1",
                type="user",
                value="JOHN.DOE",
                source="test1",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.NETWORK_HOST_ARTIFACTS,
                mitre_techniques=[],
                confidence=0.8,
            ),
            Evidence(
                id="ev-2",
                type="user",
                value="john.doe",  # Same user, different case
                source="test2",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.NETWORK_HOST_ARTIFACTS,
                mitre_techniques=[],
                confidence=0.7,
            ),
        ]
        removed = _compact_evidence(investigation_state)
        assert removed == 1
        assert len(investigation_state.evidence) == 1

    def test_different_types_not_deduplicated(self, investigation_state: InvestigationState):
        """Test that same value with different types are not considered duplicates."""

        investigation_state.evidence = [
            Evidence(
                id="ev-1",
                type="ip",
                value="192.168.1.1",
                source="test1",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=[],
                confidence=0.8,
            ),
            Evidence(
                id="ev-2",
                type="host",  # Different type
                value="192.168.1.1",
                source="test2",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=[],
                confidence=0.8,
            ),
        ]
        removed = _compact_evidence(investigation_state)
        assert removed == 0
        assert len(investigation_state.evidence) == 2


class TestCompactTimeline:
    """Tests for _compact_timeline function."""

    def test_no_compaction_under_threshold(self, investigation_state: InvestigationState):
        """Test that no compaction happens when under threshold."""
        from ares.core.models import TimelineEvent

        investigation_state.timeline = [
            TimelineEvent(
                id=f"tl-{i}",
                timestamp=datetime.now(timezone.utc),
                description=f"Event {i}",
                mitre_techniques=[],
                confidence=0.8,
                source="test",
            )
            for i in range(10)
        ]
        compacted = _compact_timeline(investigation_state, max_events=30)
        assert compacted == 0
        assert len(investigation_state.timeline) == 10

    def test_no_compaction_at_keep_count(self, investigation_state: InvestigationState):
        """Test no compaction when timeline equals head+tail count (15)."""
        from ares.core.models import TimelineEvent

        # head_count=5, tail_count=10, so 15 events won't trigger compaction
        investigation_state.timeline = [
            TimelineEvent(
                id=f"tl-{i}",
                timestamp=datetime.now(timezone.utc),
                description=f"Event {i}",
                mitre_techniques=[],
                confidence=0.8,
                source="test",
            )
            for i in range(15)
        ]
        compacted = _compact_timeline(investigation_state, max_events=10)
        assert compacted == 0

    def test_compacts_middle_events(self, investigation_state: InvestigationState):
        """Test that middle events are compacted into a summary."""
        from ares.core.models import TimelineEvent

        # Create 25 events - should compact middle (events 5-14)
        investigation_state.timeline = [
            TimelineEvent(
                id=f"tl-{i}",
                timestamp=datetime.now(timezone.utc),
                description=f"Event {i} happened here with details",
                evidence_ids=[f"ev-{i}"],
                mitre_techniques=[f"T100{i % 10}"],
                confidence=0.8,
                source="test",
            )
            for i in range(25)
        ]
        compacted = _compact_timeline(investigation_state, max_events=20)
        assert compacted == 10  # Middle 10 events compacted

        # Should have: 5 head + 1 summary + 10 tail = 16 events
        assert len(investigation_state.timeline) == 16

        # Verify summary event exists
        summary = investigation_state.timeline[5]
        assert summary.id == "tl-compact-summary"
        assert summary.source == "compaction"
        assert "10 events compacted" in summary.description

    def test_preserves_head_and_tail(self, investigation_state: InvestigationState):
        """Test that head and tail events are preserved."""
        from ares.core.models import TimelineEvent

        investigation_state.timeline = [
            TimelineEvent(
                id=f"tl-{i}",
                timestamp=datetime.now(timezone.utc),
                description=f"Event {i}",
                mitre_techniques=[],
                confidence=0.8,
                source="test",
            )
            for i in range(30)
        ]
        _compact_timeline(investigation_state, max_events=20)

        # First 5 should be preserved
        for i in range(5):
            assert investigation_state.timeline[i].id == f"tl-{i}"

        # Last 10 should be preserved (indices 20-29 from original)
        for i, orig_idx in enumerate(range(20, 30)):
            # Account for summary event at index 5
            timeline_idx = 6 + i
            assert investigation_state.timeline[timeline_idx].id == f"tl-{orig_idx}"

    def test_summary_aggregates_techniques(self, investigation_state: InvestigationState):
        """Test that summary event aggregates MITRE techniques."""
        from ares.core.models import TimelineEvent

        investigation_state.timeline = [
            TimelineEvent(
                id=f"tl-{i}",
                timestamp=datetime.now(timezone.utc),
                description=f"Event {i}",
                mitre_techniques=[f"T100{i}"] if i >= 5 and i < 15 else [],
                confidence=0.8,
                source="test",
            )
            for i in range(25)
        ]
        _compact_timeline(investigation_state, max_events=20)

        summary = investigation_state.timeline[5]
        # Should have aggregated techniques from middle events (capped at 5)
        assert len(summary.mitre_techniques) <= 5
        assert len(summary.mitre_techniques) > 0

    def test_summary_aggregates_evidence_ids(self, investigation_state: InvestigationState):
        """Test that summary event aggregates evidence IDs."""
        from ares.core.models import TimelineEvent

        investigation_state.timeline = [
            TimelineEvent(
                id=f"tl-{i}",
                timestamp=datetime.now(timezone.utc),
                description=f"Event {i}",
                evidence_ids=[f"ev-{i}"],
                mitre_techniques=[],
                confidence=0.8,
                source="test",
            )
            for i in range(25)
        ]
        _compact_timeline(investigation_state, max_events=20)

        summary = investigation_state.timeline[5]
        # Should have aggregated evidence IDs from middle events (capped at 10)
        assert len(summary.evidence_ids) <= 10
        assert len(summary.evidence_ids) > 0


class TestCompactLokiResultTruncation:
    """Tests for _compact_loki_result truncation logic."""

    def test_no_truncation_under_limit(self):
        """Test that results under the limit are not truncated."""
        import json

        # Create result with 10 entries (under default 40)
        entries = [
            {"timestamp": f"2024-01-01T{i:02d}:00:00Z", "line": f'{{"event_id": 4624, "idx": {i}}}'}
            for i in range(10)
        ]
        result_text = json.dumps({"data": entries})

        # Mock ContentText-like object
        mock_content = MagicMock()
        mock_content.text = result_text

        compacted = _compact_loki_result([mock_content])
        compacted_data = json.loads(compacted[0].text)

        assert compacted_data.get("truncated") is None
        assert "dropped_count" not in compacted_data

    def test_truncation_over_limit(self, monkeypatch):
        """Test that results over the limit are truncated with head+tail."""
        import json

        # Mock config to use a smaller limit for testing
        monkeypatch.setattr("ares.core.factories.blue_factory.get_max_result_entries", lambda: 10)

        # Create result with 25 entries (over limit of 10)
        entries = [
            {"timestamp": f"2024-01-01T{i:02d}:00:00Z", "line": f'{{"event_id": 4624, "idx": {i}}}'}
            for i in range(25)
        ]
        result_text = json.dumps({"data": entries})

        mock_content = MagicMock()
        mock_content.text = result_text

        compacted = _compact_loki_result([mock_content])
        compacted_data = json.loads(compacted[0].text)

        assert compacted_data["truncated"] is True
        assert compacted_data["total_entries"] == 25
        assert compacted_data["dropped_count"] == 15  # 25 - 10

    def test_truncation_preserves_head_and_tail(self, monkeypatch):
        """Test that truncation keeps head (75%) and tail (25%) entries."""
        import json

        monkeypatch.setattr("ares.core.factories.blue_factory.get_max_result_entries", lambda: 8)

        # Create 20 entries with unique identifiers
        entries = [
            {"timestamp": f"2024-01-01T{i:02d}:00:00Z", "line": f'{{"idx": {i}}}'}
            for i in range(20)
        ]
        result_text = json.dumps({"data": entries})

        mock_content = MagicMock()
        mock_content.text = result_text

        compacted = _compact_loki_result([mock_content])
        compacted_data = json.loads(compacted[0].text)

        # With limit 8: head=6 (75%), tail=2 (25%)
        data = compacted_data["data"]
        # Should have 6 head + 1 truncation marker + 2 tail = 9 entries
        assert len(data) == 9

        # Verify head entries (indices 0-5)
        for i in range(6):
            assert data[i]["line"]["idx"] == i

        # Verify truncation marker
        assert data[6]["line"]["_truncated"] is True
        assert "entries omitted" in data[6]["line"]["_message"]

        # Verify tail entries (indices 18, 19 from original)
        assert data[7]["line"]["idx"] == 18
        assert data[8]["line"]["idx"] == 19

    def test_returns_original_for_non_json(self):
        """Test that non-JSON results are returned unchanged."""

        result = "not json data"
        compacted = _compact_loki_result(result)
        assert compacted == result

    def test_returns_original_for_empty_list(self):
        """Test that empty list is returned unchanged."""

        result = []
        compacted = _compact_loki_result(result)
        assert compacted == result


class TestLowMediumSeverityEarlyExitStop:
    """Tests for low_medium_severity_early_exit_stop stop condition."""

    def test_returns_stop_condition(self):
        """Test that a StopCondition is returned."""
        from dreadnode.agent.stop import StopCondition

        stop_condition = low_medium_severity_early_exit_stop()
        assert isinstance(stop_condition, StopCondition)
        assert callable(stop_condition.func)
        assert stop_condition.name == "stop_on_low_medium_early_exit"

    def test_does_not_stop_without_state(self):
        """Test does not stop when no investigation state is set."""
        import ares.core.factories.blue_factory as factory
        from ares.core.factories.blue_factory import (
            reset_query_tracking,
        )

        reset_query_tracking()
        factory._current_state = None

        stop_condition = low_medium_severity_early_exit_stop()
        result = stop_condition.func([])
        assert result is False

    def test_does_not_stop_for_critical_severity(self, investigation_state: InvestigationState):
        """Test does not stop for CRITICAL severity alerts."""
        from dreadnode.agent.events import ToolEnd

        from ares.core.factories.blue_factory import (
            reset_query_tracking,
            set_investigation_state,
        )

        reset_query_tracking()
        investigation_state.alert["labels"]["severity"] = "critical"
        set_investigation_state(investigation_state)

        # Create mock tool end events
        events = []
        for i in range(15):
            mock_event = MagicMock(spec=ToolEnd)
            mock_tool_call = MagicMock()
            mock_tool_call.name = f"tool_{i}"
            mock_event.tool_call = mock_tool_call
            events.append(mock_event)

        stop_condition = low_medium_severity_early_exit_stop()
        result = stop_condition.func(events)
        assert result is False

    def test_does_not_stop_for_high_severity(self, investigation_state: InvestigationState):
        """Test does not stop for HIGH severity alerts."""
        from dreadnode.agent.events import ToolEnd

        from ares.core.factories.blue_factory import (
            reset_query_tracking,
            set_investigation_state,
        )

        reset_query_tracking()
        investigation_state.alert["labels"]["severity"] = "high"
        set_investigation_state(investigation_state)

        events = [MagicMock(spec=ToolEnd) for _ in range(15)]
        for e in events:
            e.tool_call = MagicMock()
            e.tool_call.name = "test"

        stop_condition = low_medium_severity_early_exit_stop()
        result = stop_condition.func(events)
        assert result is False

    def test_stops_for_low_severity_with_evidence(self, investigation_state: InvestigationState):
        """Test stops for LOW severity when min steps and evidence reached."""
        from dreadnode.agent.events import ToolEnd

        from ares.core.factories.blue_factory import (
            reset_query_tracking,
            set_investigation_state,
        )

        reset_query_tracking()
        investigation_state.alert["labels"]["severity"] = "low"
        investigation_state.evidence = [
            Evidence(
                id="ev-1",
                type="ip",
                value="192.168.1.1",
                source="test",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=[],
                confidence=0.8,
            ),
            Evidence(
                id="ev-2",
                type="ip",
                value="192.168.1.2",
                source="test",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=[],
                confidence=0.8,
            ),
        ]
        set_investigation_state(investigation_state)

        # Create 10 mock tool end events (above min_steps=8)
        events = []
        for i in range(10):
            mock_event = MagicMock(spec=ToolEnd)
            mock_event.tool_call = MagicMock()
            mock_event.tool_call.name = f"tool_{i}"
            events.append(mock_event)

        stop_condition = low_medium_severity_early_exit_stop()
        result = stop_condition.func(events)
        assert result is True

    def test_stops_for_medium_severity_with_queries(self, investigation_state: InvestigationState):
        """Test stops for MEDIUM severity when min queries reached."""
        from dreadnode.agent.events import ToolEnd

        import ares.core.factories.blue_factory as factory
        from ares.core.factories.blue_factory import (
            reset_query_tracking,
            set_investigation_state,
        )

        reset_query_tracking()
        investigation_state.alert["labels"]["severity"] = "medium"
        investigation_state.evidence = []  # No evidence
        set_investigation_state(investigation_state)

        # Set _total_queries to meet threshold
        factory._total_queries = 5  # Above min_queries=4

        events = [MagicMock(spec=ToolEnd) for _ in range(10)]
        for e in events:
            e.tool_call = MagicMock()
            e.tool_call.name = "test"

        stop_condition = low_medium_severity_early_exit_stop()
        result = stop_condition.func(events)
        assert result is True

    def test_does_not_stop_under_min_steps(self, investigation_state: InvestigationState):
        """Test does not stop when under minimum steps."""
        from dreadnode.agent.events import ToolEnd

        from ares.core.factories.blue_factory import (
            reset_query_tracking,
            set_investigation_state,
        )

        reset_query_tracking()
        investigation_state.alert["labels"]["severity"] = "low"
        investigation_state.evidence = [
            Evidence(
                id="ev-1",
                type="ip",
                value="192.168.1.1",
                source="test",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=[],
                confidence=0.8,
            ),
        ] * 5  # Plenty of evidence
        set_investigation_state(investigation_state)

        # Only 3 steps (under min_steps=8)
        events = [MagicMock(spec=ToolEnd) for _ in range(3)]
        for e in events:
            e.tool_call = MagicMock()
            e.tool_call.name = "test"

        stop_condition = low_medium_severity_early_exit_stop()
        result = stop_condition.func(events)
        assert result is False

    def test_stops_for_warning_severity(self, investigation_state: InvestigationState):
        """Test stops for WARNING severity (treated like LOW/MEDIUM)."""
        from dreadnode.agent.events import ToolEnd

        import ares.core.factories.blue_factory as factory
        from ares.core.factories.blue_factory import (
            reset_query_tracking,
            set_investigation_state,
        )

        reset_query_tracking()
        investigation_state.alert["labels"]["severity"] = "warning"
        factory._total_queries = 5
        set_investigation_state(investigation_state)

        events = [MagicMock(spec=ToolEnd) for _ in range(10)]
        for e in events:
            e.tool_call = MagicMock()
            e.tool_call.name = "test"

        stop_condition = low_medium_severity_early_exit_stop()
        result = stop_condition.func(events)
        assert result is True

    def test_stops_for_info_severity(self, investigation_state: InvestigationState):
        """Test stops for INFO severity (treated like LOW/MEDIUM)."""
        from dreadnode.agent.events import ToolEnd

        import ares.core.factories.blue_factory as factory
        from ares.core.factories.blue_factory import (
            reset_query_tracking,
            set_investigation_state,
        )

        reset_query_tracking()
        investigation_state.alert["labels"]["severity"] = "info"
        factory._total_queries = 5
        set_investigation_state(investigation_state)

        events = [MagicMock(spec=ToolEnd) for _ in range(10)]
        for e in events:
            e.tool_call = MagicMock()
            e.tool_call.name = "test"

        stop_condition = low_medium_severity_early_exit_stop()
        result = stop_condition.func(events)
        assert result is True


class TestPeriodicContextCompaction:
    """Tests for periodic_context_compaction hook."""

    @pytest.mark.asyncio
    async def test_increments_step_count(self, investigation_state: InvestigationState):
        """Test that step count is incremented on each call."""
        import ares.core.factories.blue_factory as factory
        from ares.core.factories.blue_factory import (
            reset_query_tracking,
            set_investigation_state,
        )

        reset_query_tracking()
        set_investigation_state(investigation_state)

        mock_event = MagicMock()
        mock_event.tool_call = MagicMock()

        initial_count = factory._compaction_step_count

        await periodic_context_compaction(mock_event)

        assert factory._compaction_step_count == initial_count + 1

    @pytest.mark.asyncio
    async def test_no_compaction_without_state(self):
        """Test that compaction doesn't happen without investigation state."""
        import ares.core.factories.blue_factory as factory
        from ares.core.factories.blue_factory import (
            reset_query_tracking,
        )

        reset_query_tracking()
        factory._current_state = None

        mock_event = MagicMock()
        await periodic_context_compaction(mock_event)
        # Should not raise

    @pytest.mark.asyncio
    async def test_no_compaction_when_disabled(
        self, investigation_state: InvestigationState, monkeypatch
    ):
        """Test that compaction is skipped when interval is 0."""
        from ares.core.factories.blue_factory import (
            reset_query_tracking,
            set_investigation_state,
        )

        reset_query_tracking()
        set_investigation_state(investigation_state)
        monkeypatch.setattr(
            "ares.core.factories.blue_factory.get_context_compaction_interval", lambda: 0
        )

        mock_event = MagicMock()
        await periodic_context_compaction(mock_event)
        # Should not raise, compaction disabled

    @pytest.mark.asyncio
    async def test_no_compaction_before_interval(
        self, investigation_state: InvestigationState, monkeypatch
    ):
        """Test that compaction doesn't happen before interval steps."""
        from ares.core.factories.blue_factory import (
            reset_query_tracking,
            set_investigation_state,
        )

        reset_query_tracking()
        set_investigation_state(investigation_state)
        monkeypatch.setattr(
            "ares.core.factories.blue_factory.get_context_compaction_interval", lambda: 10
        )

        # Add lots of evidence to trigger compaction if interval was met
        investigation_state.evidence = [
            Evidence(
                id=f"ev-{i}",
                type="ip",
                value=f"192.168.1.{i}",
                source="test",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=[],
                confidence=0.8,
            )
            for i in range(100)
        ]

        mock_event = MagicMock()
        # Only 3 steps - under interval of 10
        for _ in range(3):
            await periodic_context_compaction(mock_event)

        # Evidence should not be compacted yet
        assert len(investigation_state.evidence) == 100

    @pytest.mark.asyncio
    async def test_no_compaction_under_threshold(
        self, investigation_state: InvestigationState, monkeypatch
    ):
        """Test that compaction doesn't happen when under thresholds."""
        from ares.core.factories.blue_factory import (
            reset_query_tracking,
            set_investigation_state,
        )

        reset_query_tracking()
        set_investigation_state(investigation_state)
        monkeypatch.setattr(
            "ares.core.factories.blue_factory.get_context_compaction_interval", lambda: 1
        )
        monkeypatch.setattr(
            "ares.core.factories.blue_factory.get_max_evidence_before_compaction", lambda: 100
        )
        monkeypatch.setattr(
            "ares.core.factories.blue_factory.get_max_timeline_before_compaction", lambda: 100
        )

        # Add small amount of evidence (under threshold)
        investigation_state.evidence = [
            Evidence(
                id=f"ev-{i}",
                type="ip",
                value=f"192.168.1.{i}",
                source="test",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=[],
                confidence=0.8,
            )
            for i in range(10)
        ]

        mock_event = MagicMock()
        await periodic_context_compaction(mock_event)

        # No compaction should have happened
        assert len(investigation_state.evidence) == 10


class TestCompactionStateReset:
    """Tests for compaction state reset in reset_query_tracking."""

    def test_reset_clears_compaction_counters(self):
        """Test that reset_query_tracking clears compaction counters."""
        import ares.core.factories.blue_factory as factory
        from ares.core.factories.blue_factory import reset_query_tracking

        # Set some compaction state
        factory._compaction_step_count = 50
        factory._last_compaction_step = 45

        reset_query_tracking()

        assert factory._compaction_step_count == 0
        assert factory._last_compaction_step == 0


class TestCompactionConfigGetters:
    """Tests for new config getter functions."""

    def test_get_max_result_entries(self):
        """Test get_max_result_entries returns positive integer."""
        from ares.core.config import get_max_result_entries

        value = get_max_result_entries()
        assert isinstance(value, int)
        assert value > 0

    def test_get_context_compaction_interval(self):
        """Test get_context_compaction_interval returns non-negative integer."""
        from ares.core.config import get_context_compaction_interval

        value = get_context_compaction_interval()
        assert isinstance(value, int)
        assert value >= 0

    def test_get_max_evidence_before_compaction(self):
        """Test get_max_evidence_before_compaction returns positive integer."""
        from ares.core.config import get_max_evidence_before_compaction

        value = get_max_evidence_before_compaction()
        assert isinstance(value, int)
        assert value > 0

    def test_get_max_timeline_before_compaction(self):
        """Test get_max_timeline_before_compaction returns positive integer."""
        from ares.core.config import get_max_timeline_before_compaction

        value = get_max_timeline_before_compaction()
        assert isinstance(value, int)
        assert value > 0

    def test_get_low_medium_early_exit_min_steps(self):
        """Test get_low_medium_early_exit_min_steps returns positive integer."""
        from ares.core.config import get_low_medium_early_exit_min_steps

        value = get_low_medium_early_exit_min_steps()
        assert isinstance(value, int)
        assert value > 0

    def test_get_low_medium_early_exit_min_evidence(self):
        """Test get_low_medium_early_exit_min_evidence returns positive integer."""
        from ares.core.config import get_low_medium_early_exit_min_evidence

        value = get_low_medium_early_exit_min_evidence()
        assert isinstance(value, int)
        assert value > 0

    def test_get_low_medium_early_exit_min_queries(self):
        """Test get_low_medium_early_exit_min_queries returns positive integer."""
        from ares.core.config import get_low_medium_early_exit_min_queries

        value = get_low_medium_early_exit_min_queries()
        assert isinstance(value, int)
        assert value > 0
