"""Redis client helpers.

Environment Variables:
    REDIS_URL: Redis connection URL (e.g., "redis://:password@redis:6379/0")
    REDIS_PASSWORD: Password for Redis auth
    REDIS_SOCKET_TIMEOUT: Socket timeout in seconds (default: 10.0)
    REDIS_SOCKET_CONNECT_TIMEOUT: Connection timeout (default: 5.0)
    REDIS_HEALTH_CHECK_INTERVAL: Health check interval (default: 10.0)
    REDIS_WRITE_TIMEOUT: Write operation timeout (default: 10.0)
"""

from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import EllipsisType

from loguru import logger

from ares.core.config import get_redis_url


def _parse_int(value: str | None, default: int) -> int:
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _parse_optional_float(value: str | None, default: float | None) -> float | None:
    if value is None or value == "":
        return default
    if value.lower() == "none":
        return None
    try:
        return float(value)
    except ValueError:
        return default


def _get_redis_timeouts() -> tuple[float | None, float | None, float | None]:
    """Get Redis timeout configuration from environment."""
    default_socket_timeout = 10.0
    socket_timeout = _parse_optional_float(
        os.getenv("REDIS_SOCKET_TIMEOUT"), default_socket_timeout
    )
    socket_connect_timeout = _parse_optional_float(os.getenv("REDIS_SOCKET_CONNECT_TIMEOUT"), 5.0)
    health_check_interval = _parse_optional_float(os.getenv("REDIS_HEALTH_CHECK_INTERVAL"), 10.0)
    return socket_timeout, socket_connect_timeout, health_check_interval


# Connection error keywords for detecting Redis connection issues.
# Case-insensitive matching against exception messages.
_CONNECTION_ERROR_KEYWORDS = frozenset(
    {
        "connection",
        "connect",
        "closed",
        "timeout",
        "broken pipe",
        "reset",
        "refused",
        "unreachable",
        "reset by peer",
        "no route",
        "network",
        "eof",
        "errno",
        "socket",
        # DNS resolution failures
        "name or service not known",
        "getaddrinfo",
        "temporary failure in name resolution",
        "no address associated",
    }
)


def is_connection_error(error: BaseException) -> bool:
    """Check if an exception indicates a Redis connection error.

    Used to determine if an operation should trigger reconnection logic.
    Matches against common connection error keywords in a case-insensitive manner.

    Args:
        error: The exception to check.

    Returns:
        True if the error appears to be a connection-related issue.
    """
    error_str = str(error).lower()
    return any(keyword in error_str for keyword in _CONNECTION_ERROR_KEYWORDS)


def get_retry_delay(attempt: int, base_delay: float = 1.0, max_delay: float = 10.0) -> float:
    """Calculate exponential backoff delay for retry attempt.

    Uses the idiomatic pattern from redis-py best practices:
    - ExponentialBackoff(cap=10, base=1) - delay doubles each retry, capped at max

    Args:
        attempt: Zero-based attempt number (0 for first retry delay).
        base_delay: Initial delay in seconds (default: 1.0).
        max_delay: Maximum delay cap in seconds (default: 10.0).

    Returns:
        Delay in seconds before the next retry.

    Example:
        >>> [get_retry_delay(i) for i in range(6)]
        [1.0, 2.0, 4.0, 8.0, 10.0, 10.0]
    """
    return min(base_delay * (2**attempt), max_delay)


# Default timeout for Redis write operations (seconds)
_DEFAULT_WRITE_TIMEOUT = float(os.getenv("REDIS_WRITE_TIMEOUT", "10.0"))


async def timed_redis_write(
    coro,
    timeout: float | None = None,
    operation_name: str = "redis_write",
):
    """Execute a Redis write operation with a timeout.

    Wraps Redis write operations (set, hset, xadd, lpush, etc.) with asyncio.wait_for()
    to prevent indefinite blocking when Redis is unavailable.

    Args:
        coro: The coroutine to execute (e.g., client.set(...))
        timeout: Timeout in seconds (default: REDIS_WRITE_TIMEOUT env var or 10s)
        operation_name: Name for logging (e.g., "set_domain_admin")

    Returns:
        The result of the Redis operation.

    Raises:
        asyncio.TimeoutError: If operation exceeds timeout.
        Exception: Any Redis exception from the operation.

    Example:
        await timed_redis_write(
            client.hset("key", "field", "value"),
            timeout=5.0,
            operation_name="persist_credential"
        )
    """
    if timeout is None:
        timeout = _DEFAULT_WRITE_TIMEOUT

    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        logger.error(f"Redis write timed out after {timeout}s: {operation_name}")
        raise


async def create_redis_client(
    redis_url: str | None = None,
    *,
    decode_responses: bool = False,
    direct_connection: bool = False,
    socket_timeout: float | None | EllipsisType = ...,  # ... means "use default from env"
):
    """
    Create an async Redis client.

    Args:
        redis_url: Redis URL (falls back to REDIS_URL env var)
        decode_responses: Whether to decode responses to strings
        direct_connection: If True, create a single-connection client (no pool sharing).
            Use this for threads with separate event loops.
        socket_timeout: Socket timeout in seconds. Use None to disable (for blocking
            operations like XREADGROUP/BRPOP). Use ... (default) to use env var setting.

    Returns:
        Async Redis client
    """
    try:
        import redis.asyncio as redis_async
    except ImportError as e:
        raise RuntimeError("redis package required: pip install redis") from e

    default_socket_timeout, socket_connect_timeout, health_check_interval = _get_redis_timeouts()

    # Use explicit socket_timeout if provided, otherwise use default from env
    effective_socket_timeout = default_socket_timeout if socket_timeout is ... else socket_timeout

    url = redis_url or get_redis_url()

    if direct_connection:
        return redis_async.from_url(
            url,
            decode_responses=decode_responses,
            socket_timeout=effective_socket_timeout,
            socket_connect_timeout=socket_connect_timeout,
            health_check_interval=0,
            single_connection_client=True,
        )

    return redis_async.from_url(
        url,
        decode_responses=decode_responses,
        socket_timeout=effective_socket_timeout,
        socket_connect_timeout=socket_connect_timeout,
        health_check_interval=health_check_interval,
    )


async def create_verified_redis_client(
    redis_url: str | None = None,
    *,
    decode_responses: bool = False,
    verify_role: bool = True,
    max_retries: int = 3,
    retry_delay: float = 0.5,
):
    """
    Create a Redis client, optionally verifying it is a master.

    Args:
        redis_url: Redis URL (falls back to REDIS_URL env var)
        decode_responses: Whether to decode responses to strings
        verify_role: If True, verify connected to master using ROLE command
        max_retries: Maximum retry attempts if connected to wrong instance
        retry_delay: Seconds to wait between retries

    Returns:
        Async Redis client

    Raises:
        RuntimeError: If unable to connect after retries
    """
    return await create_redis_client(redis_url, decode_responses=decode_responses)
