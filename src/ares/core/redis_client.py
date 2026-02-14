"""Redis client helpers, including optional Sentinel support."""

from __future__ import annotations

import os
from typing import Any

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


def get_redis_sentinel_config() -> dict[str, Any] | None:
    """Return Sentinel config from env, or None when not configured."""
    host = os.getenv("REDIS_SENTINEL_HOST")
    master = os.getenv("REDIS_SENTINEL_MASTER")
    if not host or not master:
        return None

    port = _parse_int(os.getenv("REDIS_SENTINEL_PORT"), 26379)
    sentinel_password = os.getenv("REDIS_SENTINEL_PASSWORD") or os.getenv("REDIS_PASSWORD")
    redis_password = os.getenv("REDIS_PASSWORD") or sentinel_password
    db = _parse_int(os.getenv("REDIS_DB"), 0)

    return {
        "host": host,
        "port": port,
        "master": master,
        "sentinel_password": sentinel_password,
        "redis_password": redis_password,
        "db": db,
    }


async def create_redis_client(redis_url: str | None = None, *, decode_responses: bool = False):
    """Create a Redis client, using Sentinel if configured."""
    try:
        import redis.asyncio as redis_async
    except ImportError as e:
        raise RuntimeError("redis package required: pip install redis") from e

    sentinel = get_redis_sentinel_config()
    # Always use 30s socket timeout - None causes hangs during Redis failover
    default_socket_timeout = 30.0
    socket_timeout = _parse_optional_float(
        os.getenv("REDIS_SOCKET_TIMEOUT"), default_socket_timeout
    )
    socket_connect_timeout = _parse_optional_float(os.getenv("REDIS_SOCKET_CONNECT_TIMEOUT"), 5.0)
    health_check_interval = _parse_optional_float(os.getenv("REDIS_HEALTH_CHECK_INTERVAL"), 10.0)
    logger.debug(
        f"Redis client config: socket_timeout={socket_timeout}, connect_timeout={socket_connect_timeout}, health_check={health_check_interval}"
    )
    if sentinel:
        logger.info(
            f"Connecting to Redis via Sentinel {sentinel['host']}:{sentinel['port']} (master: {sentinel['master']})"
        )
        sentinel_client = redis_async.Sentinel(
            [(sentinel["host"], sentinel["port"])],
            password=sentinel["sentinel_password"],
            socket_timeout=socket_timeout,
            socket_connect_timeout=socket_connect_timeout,
            health_check_interval=health_check_interval,
            decode_responses=decode_responses,
        )
        return sentinel_client.master_for(
            sentinel["master"],
            password=sentinel["redis_password"],
            db=sentinel["db"],
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
