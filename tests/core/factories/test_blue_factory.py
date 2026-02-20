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
    max_queries_stop,
    max_tool_calls_stop,
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
