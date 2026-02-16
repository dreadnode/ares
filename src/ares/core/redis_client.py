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
"""

from __future__ import annotations

import os
import socket
from typing import Any

from loguru import logger

from ares.core.config import get_redis_url

# Module-level Sentinel client for reuse (avoids creating multiple connections)
_sentinel_client = None


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
    # Always use 30s socket timeout - None causes hangs during Redis failover
    default_socket_timeout = 30.0
    socket_timeout = _parse_optional_float(
        os.getenv("REDIS_SOCKET_TIMEOUT"), default_socket_timeout
    )
    socket_connect_timeout = _parse_optional_float(os.getenv("REDIS_SOCKET_CONNECT_TIMEOUT"), 5.0)
    health_check_interval = _parse_optional_float(os.getenv("REDIS_HEALTH_CHECK_INTERVAL"), 10.0)
    return socket_timeout, socket_connect_timeout, health_check_interval


def _get_or_create_sentinel():
    """Get or create a shared Sentinel client."""
    global _sentinel_client

    if _sentinel_client is not None:
        return _sentinel_client

    try:
        import redis.asyncio as redis_async
    except ImportError as e:
        raise RuntimeError("redis package required: pip install redis") from e

    sentinel_config = get_redis_sentinel_config()
    if not sentinel_config:
        return None

    socket_timeout, socket_connect_timeout, health_check_interval = _get_redis_timeouts()

    sentinels = sentinel_config["sentinels"]
    logger.info(
        f"Creating Sentinel client with {len(sentinels)} sentinel(s): "
        f"{[f'{h}:{p}' for h, p in sentinels]} (master: {sentinel_config['master']})"
    )

    _sentinel_client = redis_async.Sentinel(
        sentinels,
        password=sentinel_config["sentinel_password"],
        socket_timeout=socket_timeout,
        socket_connect_timeout=socket_connect_timeout,
        health_check_interval=health_check_interval,
        # Note: decode_responses is set per-client, not on Sentinel
    )

    return _sentinel_client


async def create_redis_client(redis_url: str | None = None, *, decode_responses: bool = False):
    """
    Create a Redis client, using Sentinel master if configured.

    When Sentinel is configured (via REDIS_SENTINEL_HOST and REDIS_SENTINEL_MASTER),
    this returns a client connected to the current master. The client automatically
    handles master failover via Sentinel discovery.

    Args:
        redis_url: Direct Redis URL (used when Sentinel not configured)
        decode_responses: Whether to decode responses to strings

    Returns:
        Async Redis client connected to master
    """
    try:
        import redis.asyncio as redis_async
    except ImportError as e:
        raise RuntimeError("redis package required: pip install redis") from e

    sentinel_config = get_redis_sentinel_config()
    socket_timeout, socket_connect_timeout, health_check_interval = _get_redis_timeouts()

    logger.debug(
        f"Redis client config: socket_timeout={socket_timeout}, "
        f"connect_timeout={socket_connect_timeout}, health_check={health_check_interval}"
    )

    if sentinel_config:
        sentinel_client = _get_or_create_sentinel()
        if sentinel_client:
            return sentinel_client.master_for(
                sentinel_config["master"],
                password=sentinel_config["redis_password"],
                db=sentinel_config["db"],
                decode_responses=decode_responses,
                socket_timeout=socket_timeout,
                socket_connect_timeout=socket_connect_timeout,
                health_check_interval=health_check_interval,
            )

    return redis_async.from_url(
        redis_url or get_redis_url(),
        decode_responses=decode_responses,
        socket_timeout=socket_timeout,
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
