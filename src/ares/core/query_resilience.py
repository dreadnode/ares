"""
Query resilience module using tenacity for retry logic.

Provides automatic retry with exponential backoff and jitter,
time range reduction, and query chunking for large time ranges.
"""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import dreadnode as dn
from loguru import logger
from tenacity import (
    AsyncRetrying,
    RetryError,
    retry_if_exception_type,
    stop_after_attempt,
    wait_random_exponential,
)


@dataclass
class QueryAttempt:
    """Record of a query attempt."""

    query: str
    start_time: str
    end_time: str
    attempt_number: int
    success: bool
    error: str | None = None
    result_count: int = 0
    duration_ms: int = 0


@dataclass
class QueryStats:
    """Statistics for query execution."""

    total_attempts: int = 0
    successful_attempts: int = 0
    timeout_count: int = 0
    retry_count: int = 0
    time_range_reductions: int = 0
    attempts: list[QueryAttempt] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        """Return the fraction of query attempts that succeeded."""
        if self.total_attempts == 0:
            return 0.0
        return self.successful_attempts / self.total_attempts


class QueryTimeoutError(Exception):
    """Raised when a query times out."""


class NonRetryableQueryError(Exception):
    """Raised when a query fails in a non-retryable way."""


class QueryResilientExecutor:
    """Executes queries with tenacity-based retry and time range reduction.

    Features:
    - Automatic retry with exponential backoff + jitter (tenacity)
    - Time range reduction on persistent failures
    - Query chunking for large time ranges
    - Statistics tracking for monitoring
    """

    # Time range reduction factors (try progressively smaller windows)
    TIME_RANGE_FACTORS = (1.0, 0.5, 0.25, 0.1)

    def __init__(
        self,
        max_retries: int = 3,
        initial_timeout: float = 8.0,
        enable_chunking: bool = True,
        chunk_size_minutes: int = 15,
    ):
        """Initialize the resilient executor.

        Args:
            max_retries: Maximum retry attempts per time range
            initial_timeout: Initial timeout in seconds
            enable_chunking: Enable query chunking for large ranges
            chunk_size_minutes: Size of each chunk in minutes
        """
        self.max_retries = max_retries
        self.initial_timeout = initial_timeout
        self.enable_chunking = enable_chunking
        self.chunk_size_minutes = chunk_size_minutes
        self.stats = QueryStats()

    async def execute_with_resilience(
        self,
        query_fn: Callable[..., Any],
        query: str,
        start_time: str,
        end_time: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Execute a query with automatic retry and time range reduction.

        Uses tenacity for exponential backoff with jitter to prevent
        thundering herd problems when multiple queries retry.

        Args:
            query_fn: The async query function to call
            query: The query string (LogQL or PromQL)
            start_time: ISO8601 start timestamp
            end_time: ISO8601 end timestamp
            **kwargs: Additional arguments for the query function

        Returns:
            Query result dict with resilience metadata
        """
        start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
        original_range = end_dt - start_dt

        # Use chunked execution for large time ranges
        if self.enable_chunking and original_range > timedelta(hours=2):
            logger.info(f"Query range ({original_range}) exceeds 2h, using chunked execution")
            return await self._execute_chunked(query_fn, query, start_dt, end_dt, **kwargs)

        # Try with progressively smaller time ranges
        last_error: str | None = None

        for factor in self.TIME_RANGE_FACTORS:
            if factor < 1.0:
                self.stats.time_range_reductions += 1

            # Calculate reduced time range (centered on end time)
            reduced_range = original_range * factor
            new_start = end_dt - reduced_range
            new_start_str = new_start.isoformat().replace("+00:00", "Z")
            new_end_str = end_dt.isoformat().replace("+00:00", "Z")

            if factor < 1.0:
                logger.info(f"Reducing time range to {factor * 100:.0f}% ({reduced_range})")

            # Try with tenacity retry
            try:
                result = await self._execute_with_tenacity(
                    query_fn,
                    query,
                    new_start_str,
                    new_end_str,
                    factor,
                    start_time,
                    end_time,
                    raise_non_retryable=True,
                    **kwargs,
                )
            except NonRetryableQueryError as exc:
                last_error = str(exc)
                break

            if result is not None:
                return result

            last_error = f"All retries failed for {factor * 100:.0f}% time range"

        # All attempts failed
        dn.log_metric("query_all_retries_failed", 1, mode="count")
        logger.error(f"All query attempts failed after {self.stats.total_attempts} attempts")

        return {
            "status": "error",
            "error": f"Query failed after all retries. Last error: {last_error}",
            "_resilience_metadata": {
                "total_attempts": self.stats.total_attempts,
                "timeout_count": self.stats.timeout_count,
                "time_range_reductions": self.stats.time_range_reductions,
            },
            "suggestion": (
                "The query consistently times out. Try:\n"
                "1. Use more specific label filters\n"
                "2. Query a shorter time range\n"
                "3. Simplify regex patterns"
            ),
        }

    async def _execute_with_tenacity(
        self,
        query_fn: Callable[..., Any],
        query: str,
        start_time: str,
        end_time: str,
        time_range_factor: float,
        original_start: str,
        original_end: str,
        *,
        raise_non_retryable: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        """Execute query with tenacity retry logic.

        Uses wait_random_exponential for jitter to prevent thundering herd.

        Returns:
            Query result or None if all retries failed
        """
        attempt_count = 0

        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(self.max_retries),
                wait=wait_random_exponential(multiplier=0.5, max=10),
                retry=retry_if_exception_type((QueryTimeoutError, asyncio.TimeoutError)),
                reraise=True,
            ):
                with attempt:
                    attempt_count += 1
                    self.stats.total_attempts += 1
                    attempt_start = datetime.now(timezone.utc)

                    if attempt_count > 1:
                        self.stats.retry_count += 1
                        logger.info(f"Retry attempt {attempt_count}/{self.max_retries}")

                    # Calculate timeout with slight increase on retries
                    timeout = self.initial_timeout * (1 + (attempt_count - 1) * 0.5)

                    try:
                        result = await asyncio.wait_for(
                            query_fn(
                                logql=query,
                                start_time=start_time,
                                end_time=end_time,
                                **kwargs,
                            ),
                            timeout=timeout,
                        )

                        # Check for error response
                        if isinstance(result, dict) and result.get("status") == "error":
                            error_msg = result.get("error", "Unknown error")
                            if "timeout" in error_msg.lower() or "deadline" in error_msg.lower():
                                self.stats.timeout_count += 1
                                raise QueryTimeoutError(error_msg)

                        # Success
                        self.stats.successful_attempts += 1
                        duration_ms = int(
                            (datetime.now(timezone.utc) - attempt_start).total_seconds() * 1000
                        )

                        self.stats.attempts.append(
                            QueryAttempt(
                                query=query[:100],
                                start_time=start_time,
                                end_time=end_time,
                                attempt_number=attempt_count,
                                success=True,
                                result_count=self._count_results(result),
                                duration_ms=duration_ms,
                            )
                        )

                        if isinstance(result, dict):
                            result["_resilience_metadata"] = {
                                "original_start": original_start,
                                "original_end": original_end,
                                "actual_start": start_time,
                                "actual_end": end_time,
                                "time_range_factor": time_range_factor,
                                "retry_count": attempt_count - 1,
                                "time_range_reduced": time_range_factor < 1.0,
                            }

                        dn.log_metric("query_success", 1, mode="count")
                        return result

                    except asyncio.TimeoutError:
                        self.stats.timeout_count += 1
                        duration_ms = int(
                            (datetime.now(timezone.utc) - attempt_start).total_seconds() * 1000
                        )
                        logger.warning(
                            f"Query timed out after {timeout}s (attempt {attempt_count})"
                        )

                        self.stats.attempts.append(
                            QueryAttempt(
                                query=query[:100],
                                start_time=start_time,
                                end_time=end_time,
                                attempt_number=attempt_count,
                                success=False,
                                error=f"Timeout after {timeout}s",
                                duration_ms=duration_ms,
                            )
                        )
                        raise

        except RetryError:
            logger.warning(
                f"All {self.max_retries} retries exhausted for time range factor {time_range_factor}"
            )
            return None
        except (QueryTimeoutError, asyncio.TimeoutError):
            # reraise=True surfaces the last timeout exception after retries are exhausted
            return None

        except Exception as e:
            # Non-retryable error
            logger.error(f"Query failed with non-retryable error: {e}")
            if raise_non_retryable:
                raise NonRetryableQueryError(str(e)) from e
            return None

        return None

    async def _execute_chunked(
        self,
        query_fn: Callable[..., Any],
        query: str,
        start_dt: datetime,
        end_dt: datetime,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Execute a query in parallel chunks and merge results.

        Uses asyncio.TaskGroup for concurrent chunk execution.
        """
        chunk_delta = timedelta(minutes=self.chunk_size_minutes)
        chunks = []
        current_start = start_dt

        while current_start < end_dt:
            current_end = min(current_start + chunk_delta, end_dt)
            chunks.append((current_start, current_end))
            current_start = current_end

        logger.info(
            f"Executing query in {len(chunks)} parallel chunks of {self.chunk_size_minutes}min"
        )

        # Execute chunks in parallel
        async def execute_chunk(chunk_start: datetime, chunk_end: datetime) -> dict[str, Any]:
            return await self.execute_with_resilience(
                query_fn,
                query,
                chunk_start.isoformat().replace("+00:00", "Z"),
                chunk_end.isoformat().replace("+00:00", "Z"),
                **kwargs,
            )

        tasks: list[asyncio.Task[dict[str, Any]]] = []
        try:
            async with asyncio.TaskGroup() as task_group:
                for chunk_start, chunk_end in chunks:
                    tasks.append(task_group.create_task(execute_chunk(chunk_start, chunk_end)))
        except Exception as exc:
            exceptions = getattr(exc, "exceptions", (exc,))
            for raised in exceptions:
                logger.warning(f"Chunk execution failed: {raised}")

            results: list[dict[str, Any] | BaseException] = []
            for task in tasks:
                if task.cancelled():
                    results.append(asyncio.CancelledError())
                    continue
                if task.done():
                    try:
                        results.append(task.result())
                    except (
                        Exception
                    ) as task_exc:  # pragma: no cover - covered via exception group path
                        results.append(task_exc)
                else:
                    results.append(asyncio.CancelledError())
        else:
            results = [task.result() for task in tasks]

        # Separate successful results from failures
        successful_results: list[dict[str, Any]] = []
        failed_chunks: list[int] = []

        for i, result in enumerate(results):
            if isinstance(result, BaseException):
                failed_chunks.append(i)
                logger.warning(f"Chunk {i + 1} failed: {result}")
            elif isinstance(result, dict) and result.get("status") == "error":
                failed_chunks.append(i)
                logger.warning(f"Chunk {i + 1} error: {result.get('error')}")
            elif isinstance(result, dict):
                successful_results.append(result)

        # Merge results
        merged = self._merge_chunk_results(successful_results)

        if isinstance(merged, dict):
            merged["_chunked_execution"] = {
                "total_chunks": len(chunks),
                "successful_chunks": len(successful_results),
                "failed_chunks": len(failed_chunks),
                "chunk_size_minutes": self.chunk_size_minutes,
                "parallel": True,
            }

        if failed_chunks:
            logger.warning(f"{len(failed_chunks)}/{len(chunks)} chunks failed")

        return merged

    def _merge_chunk_results(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        """Merge results from multiple chunks."""
        if not results:
            return {"status": "success", "data": {"result": []}}

        merged_streams = []
        for result in results:
            if isinstance(result, dict):
                data = result.get("data", {})
                streams = data.get("result", [])
                merged_streams.extend(streams)

        return {
            "status": "success",
            "data": {"result": merged_streams},
        }

    def _count_results(self, result: Any) -> int:
        """Count the number of results in a query response."""
        if isinstance(result, list):
            return len(result)
        if isinstance(result, dict):
            data = result.get("data", {})
            streams = data.get("result", [])
            if isinstance(streams, list):
                total = 0
                for stream in streams:
                    values = stream.get("values", [])
                    total += len(values) if isinstance(values, list) else 0
                return total
        return 0

    def get_stats_summary(self) -> dict[str, Any]:
        """Get a summary of query statistics."""
        return {
            "total_attempts": self.stats.total_attempts,
            "successful_attempts": self.stats.successful_attempts,
            "success_rate": f"{self.stats.success_rate * 100:.1f}%",
            "timeout_count": self.stats.timeout_count,
            "retry_count": self.stats.retry_count,
            "time_range_reductions": self.stats.time_range_reductions,
        }


# Singleton instance for global use
_resilient_executor: QueryResilientExecutor | None = None


def get_resilient_executor() -> QueryResilientExecutor:
    """Return the shared query executor instance for the current process."""
    global _resilient_executor
    if _resilient_executor is None:
        _resilient_executor = QueryResilientExecutor()
    return _resilient_executor


def reset_resilient_executor() -> None:
    """Reset the shared query executor instance."""
    global _resilient_executor
    _resilient_executor = None
