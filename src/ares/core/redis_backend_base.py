"""Base class for Redis state backends with shared resilience patterns.

This module provides the common infrastructure for RedisStateBackend (red team)
and BlueStateBackend (blue team), including:
- Circuit breaker + tenacity retry for transient Redis connection issues
- Key building and TTL management
- Shared constants and exception types

The pattern follows redis-py's ExponentialBackoff(cap=10, base=1).
"""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING, Any

from tenacity import (
    AsyncRetrying,
    RetryError,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ares.core.circuit_breaker import (
    CircuitBreakerError,
    get_error_debouncer,
    get_redis_circuit,
)
from ares.core.redis_client import is_connection_error

if TYPE_CHECKING:
    from redis.asyncio import Redis

    from ares.core.circuit_breaker import CircuitBreaker, ErrorDebouncer

# Redis connection error types for retry logic
# Matches redis-py's default retry_on_error list
REDIS_RETRY_EXCEPTIONS = (
    ConnectionError,
    TimeoutError,
    OSError,  # Includes ConnectionRefusedError, BrokenPipeError
)


class BaseRedisBackend(abc.ABC):
    """Base class with shared Redis resilience patterns for state backends.

    Provides:
    - Circuit breaker integration for fail-fast when Redis is unavailable
    - Tenacity retry with exponential backoff for transient failures
    - Key building with prefix management
    - TTL management for key expiration

    Subclasses must implement:
    - _build_key_prefix(): Define the Redis key prefix pattern
    - _log_prefix: Property for logging context in _with_retry

    Thread Safety:
        This class is designed to be used from async contexts. All methods are
        async and use the provided Redis client.
    """

    # TTL for all keys (24 hours)
    DEFAULT_TTL = 86400

    # Retry configuration matching redis-py's ExponentialBackoff(cap=10, base=1)
    # See: https://redis.io/docs/latest/develop/connect/clients/python/redis-py/
    RETRY_MAX_ATTEMPTS = 3
    RETRY_MULTIPLIER = 1.0  # base delay in seconds
    RETRY_MAX_DELAY = 10.0  # cap in seconds

    def __init__(
        self,
        redis_client: Redis,
        entity_id: str,
        *,
        use_circuit_breaker: bool = True,
    ) -> None:
        """Initialize the backend.

        Args:
            redis_client: Async Redis client (from create_redis_client)
            entity_id: Unique entity identifier (operation_id or investigation_id)
            use_circuit_breaker: Enable circuit breaker + retry for resilience
        """
        self._redis = redis_client
        self._entity_id = entity_id
        self._key_prefix = self._build_key_prefix(entity_id)
        self._use_circuit_breaker = use_circuit_breaker
        # Use shared circuit breaker and debouncer instances
        self._circuit: CircuitBreaker | None = get_redis_circuit() if use_circuit_breaker else None
        self._debouncer: ErrorDebouncer | None = (
            get_error_debouncer() if use_circuit_breaker else None
        )

    @abc.abstractmethod
    def _build_key_prefix(self, entity_id: str) -> str:
        """Build the Redis key prefix for this backend.

        Subclasses define their key prefix pattern, e.g.:
        - RedisStateBackend: "ares:op:{entity_id}"
        - BlueStateBackend: "ares:blue:inv:{entity_id}"

        Args:
            entity_id: The operation or investigation ID

        Returns:
            Full key prefix string
        """
        ...

    @property
    @abc.abstractmethod
    def _log_prefix(self) -> str:
        """Logging prefix for _with_retry error messages.

        Used to distinguish between red team and blue team backend logs.

        Returns:
            Log prefix string (e.g., "state_backend" or "blue_state_backend")
        """
        ...

    def _key(self, suffix: str) -> str:
        """Build full Redis key.

        Args:
            suffix: Key suffix (e.g., "credentials", "meta")

        Returns:
            Full Redis key (e.g., "ares:op:123:credentials")
        """
        return f"{self._key_prefix}:{suffix}"

    async def _set_ttl(self, key: str) -> None:
        """Set TTL on a key.

        Args:
            key: Full Redis key
        """
        await self._redis.expire(key, self.DEFAULT_TTL)

    async def _with_retry(self, operation_name: str, operation) -> Any:
        """Execute a Redis operation with circuit breaker + tenacity retry.

        Provides resilience for transient Redis connection issues (e.g.,
        pod restarts, network blips). Pattern follows:
        - redis-py's ExponentialBackoff(cap=10, base=1)
        - tenacity's AsyncRetrying for async retry logic
        - Shared circuit breaker for fail-fast when Redis is known to be down

        Args:
            operation_name: Name for logging (e.g., "add_credential")
            operation: Async callable that performs the Redis operation

        Returns:
            Result of the operation

        Raises:
            CircuitBreakerError: If circuit is open (fail-fast)
            Exception: If all retries exhausted
        """
        # Fast path: no circuit breaker configured
        if not self._circuit:
            return await operation()

        # Check circuit breaker FIRST - fail fast if Redis is known to be down
        if not self._circuit.allow_request_sync():
            remaining = self._circuit._get_remaining_open_time()
            raise CircuitBreakerError(self._circuit.name, remaining)

        last_exception: Exception | None = None

        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(self.RETRY_MAX_ATTEMPTS),
                wait=wait_exponential(
                    multiplier=self.RETRY_MULTIPLIER,
                    max=self.RETRY_MAX_DELAY,
                ),
                retry=retry_if_exception_type(REDIS_RETRY_EXCEPTIONS),
                reraise=True,
            ):
                with attempt:
                    result = await operation()
                    # Success - record and close circuit if half-open
                    self._circuit.record_success_sync()
                    return result

        except RetryError as e:
            # All retries exhausted
            last_exception = e.last_attempt.exception()
            if self._debouncer:
                self._debouncer.log_error_sync(
                    f"{self._log_prefix}_{operation_name}",
                    f"Redis {operation_name} failed after {self.RETRY_MAX_ATTEMPTS} "
                    f"retries: {last_exception}",
                    level="warning",
                )
            # Record failure to potentially open circuit
            if is_connection_error(last_exception):
                self._circuit.record_failure_sync(last_exception)
            raise last_exception from e

        except Exception as e:
            # Non-retryable error or retry logic raised
            last_exception = e
            if is_connection_error(e):
                self._circuit.record_failure_sync(e)
                if self._debouncer:
                    self._debouncer.log_error_sync(
                        f"{self._log_prefix}_{operation_name}",
                        f"Redis {operation_name} connection error: {e}",
                        level="warning",
                    )
            raise

        # Should not reach here, but satisfy type checker
        return None


__all__ = [
    "REDIS_RETRY_EXCEPTIONS",
    "BaseRedisBackend",
]
