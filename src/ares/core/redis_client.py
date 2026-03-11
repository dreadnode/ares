"""Redis client helpers, including optional Sentinel support.

Sentinel Configuration:
    REDIS_SENTINEL_HOST: Comma-separated Sentinel hosts or headless service DNS
        Examples:
        - "redis-sentinel-headless.ns.svc.cluster.local" (single headless, resolves to multiple IPs)
        - "sentinel-0:26379,sentinel-1:26379,sentinel-2:26379" (explicit list)
    REDIS_SENTINEL_PORT: Port for Sentinels (default: 26379)
    REDIS_SENTINEL_MASTER: Master name (e.g., "aresmaster")
    REDIS_SENTINEL_PASSWORD: Password for Sentinel auth (defaults to REDIS_PASSWORD)
    REDIS_PASSWORD: Password for Redis auth

Read Replicas:
    Use create_redis_replica_client() for read-only operations to distribute
    load across replicas. The replica client automatically handles replica
    discovery via Sentinel.

ROLE Verification:
    Use create_verified_redis_client() for CLI and read operations where stale
    data from a demoted master would be problematic. This follows the official
    Redis Sentinel client spec: https://redis.io/docs/latest/develop/reference/sentinel-clients/
"""

from __future__ import annotations

import asyncio
import os
import socket
import threading
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from types import EllipsisType

from loguru import logger

from ares.core.config import get_redis_url

# Thread-local Sentinel client storage
# Each thread needs its own Sentinel client because asyncio futures are bound to
# the event loop that created them. The threaded result consumer creates a new
# event loop, so it needs its own Sentinel client.
_thread_local = threading.local()

# Sentinel client TTL in seconds - after this time, re-resolve DNS for fresh IPs
# This handles Sentinel pod restarts that change pod IPs
# NOTE: This TTL only applies when creating NEW connections. Existing connections
# via SentinelConnectionPool are NOT affected by this TTL - they use their own
# internal connection management. Use ping_or_reconnect() for health checks.
_SENTINEL_CLIENT_TTL = float(os.getenv("REDIS_SENTINEL_CLIENT_TTL", "30"))


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


def _resolve_sentinel_hosts(host_config: str, default_port: int) -> list[tuple[str, int]]:
    """
    Resolve Sentinel hosts from configuration string.

    Supports:
    - Comma-separated hosts: "host1:26379,host2:26379,host3:26379"
    - Single host with port: "host:26379"
    - Headless service DNS (resolves to multiple IPs): "redis-sentinel-headless.ns.svc"

    Args:
        host_config: Host configuration string
        default_port: Default Sentinel port if not specified

    Returns:
        List of (host, port) tuples for Sentinel connections
    """
    sentinels: list[tuple[str, int]] = []

    # Check for comma-separated hosts
    if "," in host_config:
        for raw_host in host_config.split(","):
            host_part = raw_host.strip()
            if not host_part:
                continue
            if ":" in host_part:
                h, p = host_part.rsplit(":", 1)
                sentinels.append((h.strip(), int(p)))
            else:
                sentinels.append((host_part, default_port))
    else:
        # Single host - might be headless service, try DNS resolution
        host = host_config.strip()
        port = default_port
        if ":" in host:
            host, port_str = host.rsplit(":", 1)
            port = int(port_str)

        # Try to resolve DNS to get all IPs (headless service returns multiple)
        try:
            # getaddrinfo returns all IPs for a hostname
            results = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
            ips: list[str] = list({str(result[4][0]) for result in results})  # Dedupe IPs

            if len(ips) > 1:
                # Headless service - use all resolved IPs
                logger.info(f"Resolved {host} to {len(ips)} Sentinel IPs: {ips}")
                for ip in ips:
                    sentinels.append((ip, port))
            else:
                # Single IP or couldn't resolve multiple
                sentinels.append((host, port))
        except socket.gaierror:
            # DNS resolution failed, use hostname as-is
            logger.debug(f"Could not resolve {host}, using hostname directly")
            sentinels.append((host, port))

    return sentinels


def get_redis_sentinel_config() -> dict[str, Any] | None:
    """
    Return Sentinel config from env, or None when not configured.

    Environment variables:
        REDIS_SENTINEL_HOST: Sentinel host(s) - comma-separated or headless DNS
        REDIS_SENTINEL_PORT: Sentinel port (default: 26379)
        REDIS_SENTINEL_MASTER: Master name (required)
        REDIS_SENTINEL_PASSWORD: Sentinel auth password
        REDIS_PASSWORD: Redis auth password
        REDIS_DB: Redis database number (default: 0)

    Returns:
        Config dict with 'sentinels' list, or None if not configured
    """
    host = os.getenv("REDIS_SENTINEL_HOST")
    master = os.getenv("REDIS_SENTINEL_MASTER")
    if not host or not master:
        return None

    port = _parse_int(os.getenv("REDIS_SENTINEL_PORT"), 26379)
    sentinel_password = os.getenv("REDIS_SENTINEL_PASSWORD") or os.getenv("REDIS_PASSWORD")
    redis_password = os.getenv("REDIS_PASSWORD") or sentinel_password
    db = _parse_int(os.getenv("REDIS_DB"), 0)

    # Resolve hosts (supports multiple sentinels)
    sentinels = _resolve_sentinel_hosts(host, port)

    logger.info(f"Sentinel config: {len(sentinels)} sentinel(s), master={master}")

    return {
        "sentinels": sentinels,
        "master": master,
        "sentinel_password": sentinel_password,
        "redis_password": redis_password,
        "db": db,
    }


def _get_redis_timeouts() -> tuple[float | None, float | None, float | None]:
    """Get Redis timeout configuration from environment."""
    # Use 10s socket timeout to detect stale connections faster
    # This is important when Sentinel pods restart with new IPs - the old
    # connections will hang until socket timeout triggers
    default_socket_timeout = 10.0
    socket_timeout = _parse_optional_float(
        os.getenv("REDIS_SOCKET_TIMEOUT"), default_socket_timeout
    )
    socket_connect_timeout = _parse_optional_float(os.getenv("REDIS_SOCKET_CONNECT_TIMEOUT"), 5.0)
    health_check_interval = _parse_optional_float(os.getenv("REDIS_HEALTH_CHECK_INTERVAL"), 10.0)
    return socket_timeout, socket_connect_timeout, health_check_interval


def _get_or_create_sentinel():
    """Get or create a thread-local Sentinel client.

    Each thread needs its own Sentinel client because the underlying asyncio
    futures are bound to the event loop that created them. When the threaded
    result consumer creates a new event loop, reusing a Sentinel client from
    the main thread causes "Future attached to a different loop" errors.

    The client is cached with a TTL to handle Sentinel pod restarts that change
    pod IPs. After the TTL expires, we re-resolve DNS to get fresh IPs.
    """
    # Check thread-local storage for existing client
    sentinel_client = getattr(_thread_local, "sentinel_client", None)
    sentinel_created_at = getattr(_thread_local, "sentinel_created_at", 0)

    # Check if client exists and is still valid (within TTL)
    if sentinel_client is not None:
        age = time.monotonic() - sentinel_created_at
        if age < _SENTINEL_CLIENT_TTL:
            return sentinel_client
        # TTL expired - invalidate and recreate with fresh DNS resolution
        thread_name = threading.current_thread().name
        logger.info(
            f"Sentinel client TTL expired for thread '{thread_name}' (age: {age:.1f}s), "
            f"re-resolving DNS for fresh Sentinel IPs"
        )
        _thread_local.sentinel_client = None

    try:
        import redis.asyncio as redis_async
    except ImportError as e:
        raise RuntimeError("redis package required: pip install redis") from e

    sentinel_config = get_redis_sentinel_config()
    if not sentinel_config:
        return None

    socket_timeout, socket_connect_timeout, health_check_interval = _get_redis_timeouts()

    sentinels = sentinel_config["sentinels"]
    thread_name = threading.current_thread().name
    logger.info(
        f"Creating Sentinel client for thread '{thread_name}' with {len(sentinels)} sentinel(s): "
        f"{[f'{h}:{p}' for h, p in sentinels]} (master: {sentinel_config['master']})"
    )

    sentinel_client = redis_async.Sentinel(
        sentinels,
        password=sentinel_config["sentinel_password"],
        socket_timeout=socket_timeout,
        socket_connect_timeout=socket_connect_timeout,
        health_check_interval=health_check_interval,
        # Note: decode_responses is set per-client, not on Sentinel
    )

    # Store in thread-local storage with creation timestamp
    _thread_local.sentinel_client = sentinel_client
    _thread_local.sentinel_created_at = time.monotonic()

    return sentinel_client


def invalidate_sentinel_client():
    """Invalidate the cached Sentinel client to force fresh DNS resolution.

    Call this when connection errors suggest Sentinel pods may have restarted.
    """
    if hasattr(_thread_local, "sentinel_client"):
        thread_name = threading.current_thread().name
        logger.warning(f"Invalidating Sentinel client for thread '{thread_name}'")
        _thread_local.sentinel_client = None
        _thread_local.sentinel_created_at = 0


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

    Wraps Redis write operations (set, hset, lpush, etc.) with asyncio.wait_for()
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
    Create a Redis client, using Sentinel master if configured.

    When Sentinel is configured (via REDIS_SENTINEL_HOST and REDIS_SENTINEL_MASTER),
    this returns a client connected to the current master.

    Args:
        redis_url: Direct Redis URL (used when Sentinel not configured)
        decode_responses: Whether to decode responses to strings
        direct_connection: If True, create a direct connection to the discovered
            master instead of using SentinelConnectionPool. Use this for threads
            with separate event loops to avoid cross-loop Future errors.
            The client won't auto-failover but avoids SentinelConnectionPool's
            internal async state sharing issues.
        socket_timeout: Socket timeout in seconds. Use None to disable (for blocking
            operations like BRPOP). Use ... (default) to use env var setting.

    Returns:
        Async Redis client connected to master
    """
    try:
        import redis.asyncio as redis_async
    except ImportError as e:
        raise RuntimeError("redis package required: pip install redis") from e

    sentinel_config = get_redis_sentinel_config()
    default_socket_timeout, socket_connect_timeout, health_check_interval = _get_redis_timeouts()

    # Use explicit socket_timeout if provided, otherwise use default from env
    effective_socket_timeout = default_socket_timeout if socket_timeout is ... else socket_timeout

    thread_name = threading.current_thread().name
    logger.debug(
        f"Redis client config for thread '{thread_name}': socket_timeout={effective_socket_timeout}, "
        f"connect_timeout={socket_connect_timeout}, health_check={health_check_interval}, "
        f"direct_connection={direct_connection}"
    )

    if sentinel_config:
        if direct_connection:
            # For direct connections (threaded consumers), create a FRESH Sentinel client
            # rather than reusing the thread-local one. This avoids cross-loop Future errors
            # that can occur if the Sentinel client's internal connection state was created
            # on a previous event loop (e.g., after reconnection or error recovery).
            import redis.asyncio as redis_async

            # Use default timeout for Sentinel discovery (short operation)
            sentinel_socket_timeout, _, _ = _get_redis_timeouts()
            fresh_sentinel = redis_async.Sentinel(
                sentinel_config["sentinels"],
                password=sentinel_config["sentinel_password"],
                socket_timeout=sentinel_socket_timeout,
                socket_connect_timeout=socket_connect_timeout,
            )
            try:
                master_addr = await fresh_sentinel.discover_master(sentinel_config["master"])
            finally:
                # Close the Sentinel's internal Redis clients to avoid leaking connections.
                # We only needed it to find the master address.
                for sentinel_client in fresh_sentinel.sentinels:
                    try:
                        await sentinel_client.aclose()
                    except Exception:
                        pass
            logger.info(
                f"Creating direct Redis connection for thread '{thread_name}' "
                f"to {master_addr[0]}:{master_addr[1]} (fresh Sentinel discovery, "
                f"socket_timeout={effective_socket_timeout})"
            )
            # Use single_connection_client=True to avoid connection pool's asyncio state
            # sharing issues. This creates a dedicated connection that doesn't share any
            # asyncio primitives (locks, futures) with other clients.
            # Also disable health_check_interval to prevent background tasks.
            password = sentinel_config["redis_password"]
            db = sentinel_config["db"]
            redis_url = f"redis://:{password}@{master_addr[0]}:{master_addr[1]}/{db}"
            return redis_async.from_url(
                redis_url,
                decode_responses=decode_responses,
                socket_timeout=effective_socket_timeout,
                socket_connect_timeout=socket_connect_timeout,
                health_check_interval=0,
                single_connection_client=True,  # Dedicated connection, no pool sharing
            )

        # Non-direct connection: use thread-local Sentinel client
        sentinel_client = _get_or_create_sentinel()
        if sentinel_client:
            # Discover master NOW in this async context
            master_addr = await sentinel_client.discover_master(sentinel_config["master"])
            logger.debug(
                f"Sentinel discovered master for thread '{thread_name}': "
                f"{master_addr[0]}:{master_addr[1]} (socket_timeout={effective_socket_timeout})"
            )

            # Use SentinelConnectionPool for automatic failover detection
            return sentinel_client.master_for(
                sentinel_config["master"],
                password=sentinel_config["redis_password"],
                db=sentinel_config["db"],
                decode_responses=decode_responses,
                socket_timeout=effective_socket_timeout,
                socket_connect_timeout=socket_connect_timeout,
                health_check_interval=health_check_interval,
            )

    return redis_async.from_url(
        redis_url or get_redis_url(),
        decode_responses=decode_responses,
        socket_timeout=effective_socket_timeout,
        socket_connect_timeout=socket_connect_timeout,
        health_check_interval=health_check_interval,
    )


async def create_redis_replica_client(*, decode_responses: bool = False):
    """
    Create a Redis client connected to a replica for read operations.

    When Sentinel is configured, this returns a client that connects to one of
    the replica instances. Use this for read-heavy operations like:
    - Checking task results
    - Polling discoveries
    - Reading heartbeats
    - State queries

    The client automatically handles replica failover and load balancing.
    If no replicas are available, it falls back to master.

    Args:
        decode_responses: Whether to decode responses to strings

    Returns:
        Async Redis client connected to a replica, or None if Sentinel not configured
    """
    sentinel_config = get_redis_sentinel_config()
    if not sentinel_config:
        logger.debug("Replica client requested but Sentinel not configured")
        return None

    sentinel_client = _get_or_create_sentinel()
    if not sentinel_client:
        return None

    socket_timeout, socket_connect_timeout, health_check_interval = _get_redis_timeouts()

    logger.debug(f"Creating replica client for master: {sentinel_config['master']}")

    return sentinel_client.slave_for(
        sentinel_config["master"],
        password=sentinel_config["redis_password"],
        db=sentinel_config["db"],
        decode_responses=decode_responses,
        socket_timeout=socket_timeout,
        socket_connect_timeout=socket_connect_timeout,
        health_check_interval=health_check_interval,
    )


async def _verify_redis_role(client, expected_role: str = "master") -> bool:
    """
    Verify Redis instance role using ROLE command.

    Per the Redis Sentinel client spec, clients should verify the instance role
    after connecting via Sentinel to detect stale Sentinel data:
    https://redis.io/docs/latest/develop/reference/sentinel-clients/

    The ROLE command returns:
    - Master: ['master', replication_offset, [[replica_ip, port, offset], ...]]
    - Slave:  ['slave', master_ip, master_port, state, replication_offset]

    Args:
        client: Redis client to verify
        expected_role: Expected role ('master' or 'slave')

    Returns:
        True if role matches expected, False otherwise
    """
    try:
        role_info = await client.execute_command("ROLE")
        actual_role = role_info[0]
        # Handle both bytes and string responses
        if isinstance(actual_role, bytes):
            actual_role = actual_role.decode()
        return actual_role == expected_role
    except Exception as e:
        logger.warning(f"ROLE command failed: {e}")
        return False


async def create_verified_redis_client(
    redis_url: str | None = None,
    *,
    decode_responses: bool = False,
    verify_role: bool = True,
    max_retries: int = 3,
    retry_delay: float = 0.5,
):
    """
    Create a Redis client with ROLE verification per Redis Sentinel client spec.

    This follows the official Redis Sentinel client specification:
    https://redis.io/docs/latest/develop/reference/sentinel-clients/

    After connecting via Sentinel, the ROLE command verifies the instance is
    actually a master. This prevents reading stale data from a demoted master
    (now slave) that has broken replication.

    Use this for:
    - CLI operations reading state (loot, runtime, report)
    - Any read operation where stale data would be problematic
    - Operations after suspected failover

    For write-heavy workloads, use create_redis_client() instead - redis-py's
    ReadOnlyError detection will catch writes to replicas.

    Args:
        redis_url: Direct Redis URL (used when Sentinel not configured)
        decode_responses: Whether to decode responses to strings
        verify_role: If True, verify connected to master using ROLE command
        max_retries: Maximum retry attempts if connected to wrong instance
        retry_delay: Seconds to wait between retries (allows Sentinel to update)

    Returns:
        Async Redis client verified to be connected to master

    Raises:
        RuntimeError: If unable to connect to verified master after retries
    """
    sentinel_config = get_redis_sentinel_config()

    # No Sentinel = no verification needed (direct connection)
    if not sentinel_config or not verify_role:
        return await create_redis_client(redis_url, decode_responses=decode_responses)

    last_error: Exception | None = None

    for attempt in range(1, max_retries + 1):
        client = None
        try:
            client = await create_redis_client(redis_url, decode_responses=decode_responses)

            # Verify we're connected to master using ROLE command
            if await _verify_redis_role(client, expected_role="master"):
                logger.debug(f"ROLE verification passed (attempt {attempt})")
                return client

            # Connected to wrong instance type (likely demoted master with stale data)
            logger.warning(
                f"ROLE verification failed: not master (attempt {attempt}/{max_retries}). "
                "Sentinel may have stale data or failover in progress."
            )
            await client.aclose()
            client = None

            # Invalidate Sentinel client to force fresh discovery
            invalidate_sentinel_client()

            if attempt < max_retries:
                # Wait for Sentinel to potentially update its view
                await asyncio.sleep(retry_delay)

        except Exception as e:
            last_error = e
            logger.warning(f"Redis connection attempt {attempt} failed: {e}")
            if client:
                try:
                    await client.aclose()
                except Exception:
                    pass
            invalidate_sentinel_client()
            if attempt < max_retries:
                await asyncio.sleep(retry_delay)

    error_msg = f"Failed to connect to verified Redis master after {max_retries} attempts"
    if last_error:
        error_msg += f": {last_error}"
    raise RuntimeError(error_msg)
