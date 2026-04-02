"""Base class for Redis task queues with shared connection and resilience patterns.

This module provides the common infrastructure for RedisTaskQueue (red team)
and BlueTaskQueue (blue team), including:
- Connection management with thread-aware handling
- Ping/reconnect for stale connection detection
- Shared constants for TTLs and key prefixes

The red team task queue uses Redis Streams with consumer groups for reliable
task distribution (XADD/XREADGROUP/XACK). Result queues remain List-based.
"""

from __future__ import annotations

import abc
import asyncio
import threading
from typing import TYPE_CHECKING

from loguru import logger

from ares.core.config import get_agent_heartbeat_timeout, get_redis_url
from ares.core.redis_client import create_redis_client

if TYPE_CHECKING:
    from redis.asyncio import Redis


class BaseTaskQueue(abc.ABC):
    """Base class with shared Redis task queue patterns.

    Provides:
    - Connection management (connect, disconnect, ping_or_reconnect)
    - Thread-aware connection handling for non-main thread consumers
    - Connection error handling with state reset
    - Key building helpers

    Subclasses must implement:
    - _result_queue_key(): Build result queue key for a task
    - _heartbeat_key(): Build heartbeat key for an agent
    """

    # TTLs
    RESULT_TTL = 86400  # 24 hours - results kept for long operations, recovery, debugging
    HEARTBEAT_TTL = 60  # 60 seconds

    def __init__(
        self,
        redis_url: str | None = None,
    ) -> None:
        """Initialize the task queue.

        Args:
            redis_url: Redis URL (defaults to config)
        """
        self.redis_url = redis_url or get_redis_url()
        self._client: Redis | None = None
        self._connected = False
        self._heartbeat_ttl = max(self.HEARTBEAT_TTL, get_agent_heartbeat_timeout() * 2)

    @property
    def redis(self) -> Redis:
        """Expose the underlying Redis client.

        Raises:
            RuntimeError: If not connected
        """
        if self._client is None:
            raise RuntimeError("Not connected to Redis")
        return self._client

    async def connect(self) -> None:
        """Connect to Redis.

        When called from a non-main thread (e.g., threaded result consumer),
        uses direct connection to avoid cross-loop Future issues.

        Uses socket_timeout=None to allow blocking operations (XREADGROUP, BRPOP)
        to wait for extended periods without hitting socket timeout. Timeout
        control is handled at the application level via asyncio.wait_for.
        """
        if self._connected:
            return

        # Use direct connection when in a non-main thread to avoid
        # connection pool async state being shared across event loops
        is_main_thread = threading.current_thread() is threading.main_thread()
        direct_connection = not is_main_thread

        try:
            self._client = await create_redis_client(
                self.redis_url,
                decode_responses=True,  # Auto-decode to strings
                direct_connection=direct_connection,
                # Disable socket_timeout for blocking operations (BRPOP).
                # The default 10s socket_timeout breaks BRPOP which may need to
                # wait minutes for tool execution results. Timeout control is
                # handled via asyncio.wait_for in wait_for_result/poll_task.
                socket_timeout=None,
            )
            await self._client.ping()
            self._connected = True

            logger.info(f"{self.__class__.__name__} connected to Redis at {self.redis_url}")

        except Exception as e:
            raise RuntimeError(f"Failed to connect to Redis: {e}") from e

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._client:
            await self._client.aclose()
            self._connected = False
            logger.info(f"{self.__class__.__name__} disconnected")

    async def ping_or_reconnect(self, timeout: float = 5.0) -> bool:
        """Ping Redis and reconnect if the connection is stale.

        Args:
            timeout: Max seconds to wait for ping response

        Returns:
            True if ping succeeded, False if reconnection was needed
        """
        if not self._client:
            await self.connect()
            return False

        try:
            await asyncio.wait_for(self._client.ping(), timeout=timeout)
            return True
        except Exception as e:
            logger.warning(f"Redis ping failed ({type(e).__name__}: {e}), forcing reconnection")
            self._connected = False
            try:
                if self._client:
                    await self._client.aclose()
            except Exception:
                pass
            self._client = None
            # Reconnect
            await self.connect()
            logger.info("Reconnected to Redis after ping failure")
            return False

    def _handle_connection_error(self, error: Exception) -> None:
        """Handle Redis connection errors by resetting connection state.

        This allows the next operation to attempt reconnection.

        Args:
            error: The connection error
        """
        self._connected = False
        if self._client:
            # Don't await here since we're in a sync context
            # The client will be recreated on next connect()
            self._client = None
        logger.warning(f"Redis connection error, will retry: {error}")

    @abc.abstractmethod
    def _result_queue_key(self, task_id: str) -> str:
        """Build result queue key for a task.

        Args:
            task_id: Task ID

        Returns:
            Full Redis key for the result queue
        """
        ...

    @abc.abstractmethod
    def _heartbeat_key(self, agent_name: str) -> str:
        """Build heartbeat key for an agent.

        Args:
            agent_name: Agent name

        Returns:
            Full Redis key for the heartbeat
        """
        ...


__all__ = [
    "BaseTaskQueue",
]
