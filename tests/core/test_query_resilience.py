"""Tests for the Query Resilience module."""

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest

from ares.core.query_resilience import (
    QueryAttempt,
    QueryResilientExecutor,
    QueryStats,
    QueryTimeoutError,
    get_resilient_executor,
    reset_resilient_executor,
)


class TestQueryAttempt:
    """Tests for QueryAttempt dataclass."""

    def test_create_successful_attempt(self) -> None:
        """Test creating a successful query attempt."""
        attempt = QueryAttempt(
            query="{job='test'}",
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T11:00:00Z",
            attempt_number=1,
            success=True,
            result_count=100,
            duration_ms=500,
        )

        assert attempt.success is True
        assert attempt.error is None
        assert attempt.result_count == 100

    def test_create_failed_attempt(self) -> None:
        """Test creating a failed query attempt."""
        attempt = QueryAttempt(
            query="{job='test'}",
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T11:00:00Z",
            attempt_number=2,
            success=False,
            error="Timeout after 30s",
            duration_ms=30000,
        )

        assert attempt.success is False
        assert attempt.error == "Timeout after 30s"
        assert attempt.result_count == 0


class TestQueryStats:
    """Tests for QueryStats dataclass."""

    def test_default_values(self) -> None:
        """Test default values for QueryStats."""
        stats = QueryStats()

        assert stats.total_attempts == 0
        assert stats.successful_attempts == 0
        assert stats.timeout_count == 0
        assert stats.retry_count == 0
        assert stats.time_range_reductions == 0
        assert stats.attempts == []

    def test_success_rate_calculation(self) -> None:
        """Test success rate calculation."""
        stats = QueryStats(total_attempts=10, successful_attempts=7)

        assert stats.success_rate == 0.7

    def test_success_rate_zero_attempts(self) -> None:
        """Test success rate with zero attempts."""
        stats = QueryStats(total_attempts=0, successful_attempts=0)

        assert stats.success_rate == 0.0


class TestQueryResilientExecutor:
    """Tests for QueryResilientExecutor."""

    def test_init_default_values(self) -> None:
        """Test default initialization values."""
        executor = QueryResilientExecutor()

        assert executor.max_retries == 3
        assert executor.initial_timeout == 8.0
        assert executor.enable_chunking is True
        assert executor.chunk_size_minutes == 15

    def test_init_custom_values(self) -> None:
        """Test initialization with custom values."""
        executor = QueryResilientExecutor(
            max_retries=5,
            initial_timeout=60.0,
            enable_chunking=False,
            chunk_size_minutes=15,
        )

        assert executor.max_retries == 5
        assert executor.initial_timeout == 60.0
        assert executor.enable_chunking is False
        assert executor.chunk_size_minutes == 15

    @pytest.mark.asyncio
    async def test_execute_with_resilience_success(self) -> None:
        """Test successful query execution."""
        executor = QueryResilientExecutor()

        mock_query_fn = AsyncMock(
            return_value={
                "status": "success",
                "data": {"result": [{"values": [[1, "log1"], [2, "log2"]]}]},
            }
        )

        result = await executor.execute_with_resilience(
            query_fn=mock_query_fn,
            query="{job='test'}",
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T11:00:00Z",
        )

        assert result["status"] == "success"
        assert "_resilience_metadata" in result
        assert result["_resilience_metadata"]["retry_count"] == 0
        assert executor.stats.successful_attempts == 1

    @pytest.mark.asyncio
    async def test_execute_with_resilience_timeout_retry(self) -> None:
        """Test retry behavior on timeout."""
        executor = QueryResilientExecutor(max_retries=2, initial_timeout=0.1)

        call_count = 0

        async def timeout_then_success(**kwargs: Any) -> dict[str, Any]:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                await asyncio.sleep(1)
            return {"status": "success", "data": {"result": []}}

        mock_query_fn = AsyncMock(side_effect=timeout_then_success)

        result = await executor.execute_with_resilience(
            query_fn=mock_query_fn,
            query="{job='test'}",
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T10:30:00Z",
        )

        assert result["status"] == "success"
        assert executor.stats.timeout_count >= 1

    @pytest.mark.asyncio
    async def test_execute_with_resilience_all_retries_fail(self) -> None:
        """Test behavior when all retries fail."""
        executor = QueryResilientExecutor(max_retries=2, initial_timeout=0.1)

        async def always_timeout(**kwargs: Any) -> dict[str, Any]:
            await asyncio.sleep(1)
            return {"status": "success", "data": {"result": []}}

        mock_query_fn = AsyncMock(side_effect=always_timeout)

        result = await executor.execute_with_resilience(
            query_fn=mock_query_fn,
            query="{job='test'}",
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T10:30:00Z",
        )

        assert result["status"] == "error"
        assert "suggestion" in result
        assert executor.stats.timeout_count > 0

    @pytest.mark.asyncio
    async def test_execute_with_resilience_error_response(self) -> None:
        """Test handling of timeout-like error responses from query function."""
        executor = QueryResilientExecutor(max_retries=2)

        mock_query_fn = AsyncMock(
            return_value={
                "status": "error",
                "error": "timeout exceeded while executing query",
            }
        )

        await executor.execute_with_resilience(
            query_fn=mock_query_fn,
            query="{job='test'}",
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T10:30:00Z",
        )

        assert executor.stats.timeout_count > 0

    @pytest.mark.asyncio
    async def test_execute_with_resilience_time_range_reduction(self) -> None:
        """Test time range reduction on persistent failures."""
        executor = QueryResilientExecutor(max_retries=1, initial_timeout=0.05)

        call_count = 0
        received_time_ranges: list[tuple[str, str]] = []

        async def track_time_ranges(**kwargs: Any) -> dict[str, Any]:
            nonlocal call_count
            call_count += 1
            received_time_ranges.append((kwargs.get("start_time", ""), kwargs.get("end_time", "")))
            if call_count < 3:
                await asyncio.sleep(1)
            return {"status": "success", "data": {"result": []}}

        mock_query_fn = AsyncMock(side_effect=track_time_ranges)

        await executor.execute_with_resilience(
            query_fn=mock_query_fn,
            query="{job='test'}",
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T11:00:00Z",
        )

        assert executor.stats.time_range_reductions > 0
        assert len(received_time_ranges) >= 3

    @pytest.mark.asyncio
    async def test_execute_chunked_for_large_range(self) -> None:
        """Test that large time ranges trigger chunked execution."""
        executor = QueryResilientExecutor(chunk_size_minutes=30)

        call_times: list[str] = []

        async def track_chunks(**kwargs: Any) -> dict[str, Any]:
            call_times.append(kwargs.get("start_time", ""))
            return {"status": "success", "data": {"result": [{"values": [[1, "log"]]}]}}

        mock_query_fn = AsyncMock(side_effect=track_chunks)

        result = await executor.execute_with_resilience(
            query_fn=mock_query_fn,
            query="{job='test'}",
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T13:00:00Z",
        )

        assert len(call_times) >= 4
        assert "_chunked_execution" in result

    @pytest.mark.asyncio
    async def test_execute_chunked_disabled(self) -> None:
        """Test that chunking can be disabled."""
        executor = QueryResilientExecutor(enable_chunking=False)

        call_count = 0

        async def count_calls(**kwargs: Any) -> dict[str, Any]:
            nonlocal call_count
            call_count += 1
            return {"status": "success", "data": {"result": []}}

        mock_query_fn = AsyncMock(side_effect=count_calls)

        await executor.execute_with_resilience(
            query_fn=mock_query_fn,
            query="{job='test'}",
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T13:00:00Z",
        )

        assert call_count == 1

    @pytest.mark.asyncio
    async def test_execute_chunked_merge_results(self) -> None:
        """Test that chunked results are properly merged."""
        executor = QueryResilientExecutor(chunk_size_minutes=30)

        chunk_num = 0

        async def return_chunk_results(**kwargs: Any) -> dict[str, Any]:
            nonlocal chunk_num
            chunk_num += 1
            return {
                "status": "success",
                "data": {"result": [{"stream": {}, "values": [[chunk_num, f"log{chunk_num}"]]}]},
            }

        mock_query_fn = AsyncMock(side_effect=return_chunk_results)

        result = await executor.execute_with_resilience(
            query_fn=mock_query_fn,
            query="{job='test'}",
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T13:00:00Z",
        )

        assert "data" in result
        assert len(result["data"]["result"]) >= 2

    @pytest.mark.asyncio
    async def test_execute_chunked_collects_partial_results_after_exception_group(self) -> None:
        """Test chunked execution preserves completed chunk results when one task fails."""
        executor = QueryResilientExecutor(chunk_size_minutes=120, max_retries=1)

        started_chunks: list[str] = []

        async def chunk_query(**kwargs: Any) -> dict[str, Any]:
            started_chunks.append(kwargs["start_time"])
            if kwargs["start_time"].startswith("2024-01-15T12:00:00"):
                raise RuntimeError("chunk failed")
            return {
                "status": "success",
                "data": {"result": [{"stream": {}, "values": [[1, kwargs["start_time"]]]}]},
            }

        result = await executor.execute_with_resilience(
            query_fn=AsyncMock(side_effect=chunk_query),
            query="{job='test'}",
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T16:00:00Z",
        )

        assert result["status"] == "success"
        assert result["_chunked_execution"]["total_chunks"] == 3
        assert result["_chunked_execution"]["failed_chunks"] >= 1
        assert len(result["data"]["result"]) >= 1

    @pytest.mark.asyncio
    async def test_execute_with_tenacity_returns_none_for_non_retryable_error(self) -> None:
        """Test non-timeout exceptions are treated as non-retryable failures."""
        executor = QueryResilientExecutor(max_retries=2)

        async def fail_non_retryable(**kwargs: Any) -> dict[str, Any]:
            raise ValueError("bad query")

        result = await executor._execute_with_tenacity(
            fail_non_retryable,
            "{job='test'}",
            "2024-01-15T10:00:00Z",
            "2024-01-15T11:00:00Z",
            1.0,
            "2024-01-15T10:00:00Z",
            "2024-01-15T11:00:00Z",
        )

        assert result is None
        assert executor.stats.total_attempts == 1

    @pytest.mark.asyncio
    async def test_execute_with_tenacity_retries_query_timeout_error(self) -> None:
        """Test QueryTimeoutError is retried and counted via tenacity."""
        executor = QueryResilientExecutor(max_retries=2, initial_timeout=5)
        call_count = 0

        async def timeout_then_success(**kwargs: Any) -> dict[str, Any]:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"status": "error", "error": "deadline exceeded"}
            return {"status": "success", "data": {"result": []}}

        result = await executor._execute_with_tenacity(
            AsyncMock(side_effect=timeout_then_success),
            "{job='test'}",
            "2024-01-15T10:00:00Z",
            "2024-01-15T11:00:00Z",
            1.0,
            "2024-01-15T10:00:00Z",
            "2024-01-15T11:00:00Z",
        )

        assert result is not None
        assert executor.stats.timeout_count == 1
        assert executor.stats.retry_count == 1

    def test_count_results_list(self) -> None:
        """Test counting results from a list."""
        executor = QueryResilientExecutor()

        result = [1, 2, 3, 4, 5]
        count = executor._count_results(result)

        assert count == 5

    def test_count_results_dict_with_streams(self) -> None:
        """Test counting results from Loki-style response."""
        executor = QueryResilientExecutor()

        result = {
            "data": {
                "result": [
                    {"stream": {}, "values": [[1, "a"], [2, "b"]]},
                    {"stream": {}, "values": [[3, "c"]]},
                ]
            }
        }
        count = executor._count_results(result)

        assert count == 3

    def test_count_results_empty(self) -> None:
        """Test counting results from empty response."""
        executor = QueryResilientExecutor()

        assert executor._count_results({}) == 0
        assert executor._count_results({"data": {}}) == 0
        assert executor._count_results({"data": {"result": []}}) == 0

    def test_count_results_ignores_non_list_values(self) -> None:
        """Test counting ignores malformed stream values payloads."""
        executor = QueryResilientExecutor()

        result = {"data": {"result": [{"values": "not-a-list"}]}}

        assert executor._count_results(result) == 0

    def test_get_stats_summary(self) -> None:
        """Test getting stats summary."""
        executor = QueryResilientExecutor()
        executor.stats.total_attempts = 10
        executor.stats.successful_attempts = 8
        executor.stats.timeout_count = 2
        executor.stats.retry_count = 3
        executor.stats.time_range_reductions = 1

        summary = executor.get_stats_summary()

        assert summary["total_attempts"] == 10
        assert summary["successful_attempts"] == 8
        assert summary["success_rate"] == "80.0%"
        assert summary["timeout_count"] == 2
        assert summary["retry_count"] == 3
        assert summary["time_range_reductions"] == 1

    def test_merge_chunk_results_empty(self) -> None:
        """Test merging empty chunk results."""
        executor = QueryResilientExecutor()

        result = executor._merge_chunk_results([])

        assert result["status"] == "success"
        assert result["data"]["result"] == []

    def test_merge_chunk_results_multiple(self) -> None:
        """Test merging multiple chunk results."""
        executor = QueryResilientExecutor()

        chunks = [
            {"data": {"result": [{"stream": "a", "values": [1, 2]}]}},
            {"data": {"result": [{"stream": "b", "values": [3, 4]}]}},
            {"data": {"result": [{"stream": "c", "values": [5]}]}},
        ]

        result = executor._merge_chunk_results(chunks)

        assert result["status"] == "success"
        assert len(result["data"]["result"]) == 3


class TestGlobalExecutor:
    """Tests for global executor functions."""

    def test_get_resilient_executor_creates_default(self) -> None:
        """Test that get_resilient_executor creates a default instance."""
        reset_resilient_executor()

        executor = get_resilient_executor()

        assert executor is not None
        assert isinstance(executor, QueryResilientExecutor)

        reset_resilient_executor()

    def test_get_resilient_executor_returns_same_instance(self) -> None:
        """Test that get_resilient_executor returns the same instance."""
        reset_resilient_executor()

        executor1 = get_resilient_executor()
        executor2 = get_resilient_executor()

        assert executor1 is executor2

        reset_resilient_executor()

    def test_reset_resilient_executor(self) -> None:
        """Test resetting the global executor."""
        reset_resilient_executor()

        executor1 = get_resilient_executor()
        reset_resilient_executor()
        executor2 = get_resilient_executor()

        assert executor1 is not executor2

        reset_resilient_executor()


class TestTimeRangeFactors:
    """Tests for time range reduction factors."""

    def test_time_range_factors_order(self) -> None:
        """Test that time range factors are in descending order."""
        factors = QueryResilientExecutor.TIME_RANGE_FACTORS

        assert factors == tuple(sorted(factors, reverse=True))
        assert factors[0] == 1.0
        assert factors[-1] <= 0.1


class TestEdgeCases:
    """Tests for edge cases."""

    @pytest.mark.asyncio
    async def test_execute_with_z_suffix_timestamps(self) -> None:
        """Test handling of Z suffix in timestamps."""
        executor = QueryResilientExecutor()

        mock_query_fn = AsyncMock(return_value={"status": "success", "data": {"result": []}})

        result = await executor.execute_with_resilience(
            query_fn=mock_query_fn,
            query="{job='test'}",
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T11:00:00Z",
        )

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_execute_with_offset_timestamps(self) -> None:
        """Test handling of offset timestamps."""
        executor = QueryResilientExecutor()

        mock_query_fn = AsyncMock(return_value={"status": "success", "data": {"result": []}})

        result = await executor.execute_with_resilience(
            query_fn=mock_query_fn,
            query="{job='test'}",
            start_time="2024-01-15T10:00:00+00:00",
            end_time="2024-01-15T11:00:00+00:00",
        )

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_execute_with_grpc_error(self) -> None:
        """Test handling of gRPC errors."""
        executor = QueryResilientExecutor(max_retries=3)

        mock_query_fn = AsyncMock(side_effect=Exception("grpc: connection failed"))

        result = await executor.execute_with_resilience(
            query_fn=mock_query_fn,
            query="{job='test'}",
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T10:30:00Z",
        )

        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_execute_with_non_timeout_error_response(self) -> None:
        """Test handling of non-timeout error responses."""
        executor = QueryResilientExecutor()

        mock_query_fn = AsyncMock(
            return_value={
                "status": "error",
                "error": "invalid query syntax",
            }
        )

        await executor.execute_with_resilience(
            query_fn=mock_query_fn,
            query="{job='test'}",
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T10:30:00Z",
        )

        assert executor.stats.timeout_count == 0

    def test_query_timeout_error_is_custom_exception(self) -> None:
        """Test QueryTimeoutError is a distinct exception type."""
        error = QueryTimeoutError("timed out")

        assert isinstance(error, Exception)
        assert str(error) == "timed out"
