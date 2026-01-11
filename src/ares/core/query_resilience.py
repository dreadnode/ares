"""
Query resilience module for handling timeouts and retries.

Provides automatic time range reduction, retry with backoff,
and query chunking for large time ranges.
"""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

import dreadnode as dn
from loguru import logger


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
        if self.total_attempts == 0:
            return 0.0
        return self.successful_attempts / self.total_attempts


class QueryResilientExecutor:
    """Executes queries with automatic retry and time range reduction.

    Features:
    - Automatic time range reduction on timeout
    - Exponential backoff for retries
    - Query chunking for large time ranges
    - Statistics tracking for monitoring
    """

    # Start with smaller time ranges to avoid mcp-grafana 10s timeout
    TIME_RANGE_FACTORS: ClassVar[list[float]] = [0.5, 0.25, 0.1, 0.05]
    BACKOFF_DELAYS: ClassVar[list[int]] = [1, 2, 4]

    def __init__(
        self,
        max_retries: int = 3,
        initial_timeout: float = 8.0,  # Must be under mcp-grafana's 10s limit
        enable_chunking: bool = True,
        chunk_size_minutes: int = 15,  # Smaller chunks for faster queries
    ):
        """Initialize the resilient executor.

        Args:
            max_retries: Maximum number of retry attempts
            initial_timeout: Initial timeout in seconds
            enable_chunking: Whether to enable query chunking for large ranges
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

        Args:
            query_fn: The async query function to call
            query: The query string (LogQL or PromQL)
            start_time: ISO8601 start timestamp
            end_time: ISO8601 end timestamp
            **kwargs: Additional arguments for the query function

        Returns:
            Query result dict with additional metadata about retries
        """
        start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
        original_range = end_dt - start_dt

        if self.enable_chunking and original_range > timedelta(hours=2):
            logger.info(f"Query range ({original_range}) exceeds 2h, using chunked execution")
            return await self._execute_chunked(query_fn, query, start_dt, end_dt, **kwargs)

        # Try with progressively smaller time ranges
        last_error = None
        for _factor_idx, factor in enumerate(self.TIME_RANGE_FACTORS):
            if factor < 1.0:
                self.stats.time_range_reductions += 1

            # Calculate reduced time range (centered on end time since recent data is usually more relevant)
            reduced_range = original_range * factor
            new_start = end_dt - reduced_range
            new_start_str = new_start.isoformat().replace("+00:00", "Z")
            new_end_str = end_dt.isoformat().replace("+00:00", "Z")

            if factor < 1.0:
                logger.info(
                    f"Reducing time range to {factor * 100:.0f}% ({reduced_range}) for retry"
                )

            # Try with retries at this time range
            for attempt in range(self.max_retries):
                self.stats.total_attempts += 1
                attempt_start = datetime.now(timezone.utc)

                try:
                    if attempt > 0:
                        self.stats.retry_count += 1
                        delay = self.BACKOFF_DELAYS[min(attempt - 1, len(self.BACKOFF_DELAYS) - 1)]
                        logger.info(
                            f"Retry attempt {attempt + 1}/{self.max_retries} after {delay}s backoff"
                        )
                        await asyncio.sleep(delay)

                    # Execute the query with timeout
                    timeout = self.initial_timeout * (
                        1 + attempt * 0.5
                    )  # Increase timeout on retries
                    result = await asyncio.wait_for(
                        query_fn(
                            logql=query,
                            start_time=new_start_str,
                            end_time=new_end_str,
                            **kwargs,
                        ),
                        timeout=timeout,
                    )

                    if isinstance(result, dict) and result.get("status") == "error":
                        error_msg = result.get("error", "Unknown error")
                        if "timeout" in error_msg.lower() or "deadline" in error_msg.lower():
                            self.stats.timeout_count += 1
                            last_error = error_msg
                            logger.warning(f"Query timeout: {error_msg}")
                            continue  # Try next retry
                        # Other errors, still return but log
                        logger.warning(f"Query error (non-timeout): {error_msg}")

                    # Success!
                    self.stats.successful_attempts += 1
                    duration_ms = int(
                        (datetime.now(timezone.utc) - attempt_start).total_seconds() * 1000
                    )

                    # Record attempt
                    self.stats.attempts.append(
                        QueryAttempt(
                            query=query[:100],
                            start_time=new_start_str,
                            end_time=new_end_str,
                            attempt_number=attempt + 1,
                            success=True,
                            result_count=self._count_results(result),
                            duration_ms=duration_ms,
                        )
                    )

                    if isinstance(result, dict):
                        result["_resilience_metadata"] = {
                            "original_start": start_time,
                            "original_end": end_time,
                            "actual_start": new_start_str,
                            "actual_end": new_end_str,
                            "time_range_factor": factor,
                            "retry_count": attempt,
                            "time_range_reduced": factor < 1.0,
                        }

                    dn.log_metric("query_success", 1, mode="count")
                    return result

                except asyncio.TimeoutError:
                    self.stats.timeout_count += 1
                    duration_ms = int(
                        (datetime.now(timezone.utc) - attempt_start).total_seconds() * 1000
                    )
                    last_error = f"Timeout after {timeout}s"
                    logger.warning(f"Query timed out after {timeout}s (attempt {attempt + 1})")

                    self.stats.attempts.append(
                        QueryAttempt(
                            query=query[:100],
                            start_time=new_start_str,
                            end_time=new_end_str,
                            attempt_number=attempt + 1,
                            success=False,
                            error=last_error,
                            duration_ms=duration_ms,
                        )
                    )

                except Exception as e:
                    duration_ms = int(
                        (datetime.now(timezone.utc) - attempt_start).total_seconds() * 1000
                    )
                    last_error = str(e)
                    logger.error(f"Query failed: {e}")

                    self.stats.attempts.append(
                        QueryAttempt(
                            query=query[:100],
                            start_time=new_start_str,
                            end_time=new_end_str,
                            attempt_number=attempt + 1,
                            success=False,
                            error=last_error,
                            duration_ms=duration_ms,
                        )
                    )

                    # Check for gRPC errors (non-retryable in most cases)
                    if "grpc" in str(e).lower():
                        break  # Move to next time range factor

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
                "final_time_range_factor": self.TIME_RANGE_FACTORS[-1],
            },
            "suggestion": (
                "The query consistently times out. Try:\n"
                "1. Use more specific label filters to reduce data volume\n"
                "2. Query a shorter time range manually\n"
                "3. Simplify the regex patterns in the query"
            ),
        }

    async def _execute_chunked(
        self,
        query_fn: Callable[..., Any],
        query: str,
        start_dt: datetime,
        end_dt: datetime,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Execute a query in chunks and merge results.

        Args:
            query_fn: The async query function
            query: The query string
            start_dt: Start datetime
            end_dt: End datetime
            **kwargs: Additional query arguments

        Returns:
            Merged results from all chunks
        """
        chunk_delta = timedelta(minutes=self.chunk_size_minutes)
        chunks = []
        current_start = start_dt

        while current_start < end_dt:
            current_end = min(current_start + chunk_delta, end_dt)
            chunks.append((current_start, current_end))
            current_start = current_end

        logger.info(f"Executing query in {len(chunks)} chunks of {self.chunk_size_minutes}min each")

        all_results = []
        failed_chunks = []

        for i, (chunk_start, chunk_end) in enumerate(chunks):
            logger.debug(f"Executing chunk {i + 1}/{len(chunks)}")

            chunk_result = await self.execute_with_resilience(
                query_fn,
                query,
                chunk_start.isoformat().replace("+00:00", "Z"),
                chunk_end.isoformat().replace("+00:00", "Z"),
                **kwargs,
            )

            if isinstance(chunk_result, dict) and chunk_result.get("status") == "error":
                failed_chunks.append(i)
                logger.warning(f"Chunk {i + 1} failed: {chunk_result.get('error')}")
            else:
                all_results.append(chunk_result)

        # Merge results
        merged = self._merge_chunk_results(all_results)

        if isinstance(merged, dict):
            merged["_chunked_execution"] = {
                "total_chunks": len(chunks),
                "successful_chunks": len(all_results),
                "failed_chunks": len(failed_chunks),
                "chunk_size_minutes": self.chunk_size_minutes,
            }

        if failed_chunks:
            logger.warning(f"{len(failed_chunks)}/{len(chunks)} chunks failed")

        return merged

    def _merge_chunk_results(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        """Merge results from multiple chunks.

        Args:
            results: List of query results from chunks

        Returns:
            Merged result dict
        """
        if not results:
            return {"status": "success", "data": {"result": []}}

        # For Loki-style results, merge the streams
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
        """Get a summary of query statistics.

        Returns:
            Dict with query execution statistics
        """
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
    """Get or create the global resilient executor instance."""
    global _resilient_executor
    if _resilient_executor is None:
        _resilient_executor = QueryResilientExecutor()
    return _resilient_executor


def reset_resilient_executor() -> None:
    """Reset the global executor (for testing or new investigations)."""
    global _resilient_executor
    _resilient_executor = None
