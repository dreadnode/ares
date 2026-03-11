"""Circuit breaker and error debouncing for Redis resilience.

This module provides:
- A shared circuit breaker for Redis operations that prevents thundering herd
- Debounced error logging to reduce log spam during outages
- Coordinated health monitoring across multiple background tasks

Circuit Breaker States:
- CLOSED: Normal operation, calls pass through
- OPEN: Fast-fail mode after threshold breaches (no Redis calls)
- HALF-OPEN: Testing recovery with single probe

Configuration (environment variables):
- REDIS_CIRCUIT_FAIL_MAX: Failures before opening (default: 5)
- REDIS_CIRCUIT_RESET_TIMEOUT: Seconds before half-open (default: 30)
- REDIS_ERROR_DEBOUNCE_WINDOW: Seconds to group similar errors (default: 10)
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from enum import Enum
from typing import TYPE_CHECKING, Any

from loguru import logger

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

# Configuration
_CIRCUIT_FAIL_MAX = int(os.getenv("REDIS_CIRCUIT_FAIL_MAX", "5"))
_CIRCUIT_RESET_TIMEOUT = float(os.getenv("REDIS_CIRCUIT_RESET_TIMEOUT", "30"))
_ERROR_DEBOUNCE_WINDOW = float(os.getenv("REDIS_ERROR_DEBOUNCE_WINDOW", "10"))


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerError(Exception):
    """Raised when circuit is open and calls are rejected."""

    def __init__(self, circuit_name: str, remaining_time: float):
        self.circuit_name = circuit_name
        self.remaining_time = remaining_time
        super().__init__(
            f"Circuit breaker '{circuit_name}' is OPEN. Retry after {remaining_time:.1f}s"
        )


class RedisCircuitBreaker:
    """Circuit breaker for Redis operations.

    Shared across all background tasks (heartbeat monitor, result consumer,
    deferred queue processor) to coordinate recovery. When one task detects
    Redis is down, all tasks fail-fast instead of hammering Redis.

    Thread-safe: Uses threading.Lock for state transitions so it works
    across the main thread and the threaded result consumer.

    Usage:
        circuit = RedisCircuitBreaker("redis")

        async with circuit.protect():
            await redis.ping()

        # Or manually:
        circuit.record_failure(exception)
        circuit.record_success()
    """

    def __init__(
        self,
        name: str = "redis",
        fail_max: int | None = None,
        reset_timeout: float | None = None,
    ):
        self.name = name
        self.fail_max = fail_max or _CIRCUIT_FAIL_MAX
        self.reset_timeout = reset_timeout or _CIRCUIT_RESET_TIMEOUT

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0
        self._opened_at: float = 0
        # Use threading.Lock instead of asyncio.Lock for cross-thread safety
        # The threaded result consumer runs on a different event loop
        self._lock = threading.Lock()

        # Event listeners for monitoring
        self._listeners: list[CircuitBreakerListener] = []

    @property
    def state(self) -> CircuitState:
        """Current circuit state."""
        return self._state

    @property
    def failure_count(self) -> int:
        """Current consecutive failure count."""
        return self._failure_count

    @property
    def is_closed(self) -> bool:
        """True if circuit is closed (normal operation)."""
        return self._state == CircuitState.CLOSED

    @property
    def is_open(self) -> bool:
        """True if circuit is open (fast-fail mode)."""
        return self._state == CircuitState.OPEN

    def add_listener(self, listener: CircuitBreakerListener) -> None:
        """Add a listener for state change events."""
        self._listeners.append(listener)

    def remove_listener(self, listener: CircuitBreakerListener) -> None:
        """Remove a listener."""
        if listener in self._listeners:
            self._listeners.remove(listener)

    def _notify_state_change_sync(self, old_state: CircuitState, new_state: CircuitState) -> None:
        """Notify listeners of state change (sync version for use within lock)."""
        for listener in self._listeners:
            try:
                # Listeners are notified synchronously since we hold a threading.Lock
                # Async listeners should handle this internally
                listener.on_state_change_sync(self.name, old_state, new_state)
            except Exception as e:
                logger.warning(f"Circuit breaker listener error: {e}")

    def _check_state_locked(self) -> None:
        """Check if circuit should transition from OPEN to HALF_OPEN.

        Must be called while holding self._lock.
        """
        if self._state == CircuitState.OPEN:
            elapsed = time.monotonic() - self._opened_at
            if elapsed >= self.reset_timeout:
                old_state = self._state
                self._state = CircuitState.HALF_OPEN
                logger.info(
                    f"Circuit breaker '{self.name}' -> HALF_OPEN "
                    f"(testing recovery after {elapsed:.1f}s)"
                )
                self._notify_state_change_sync(old_state, self._state)

    def _get_remaining_open_time(self) -> float:
        """Get remaining time before circuit transitions to half-open."""
        if self._state != CircuitState.OPEN:
            return 0
        elapsed = time.monotonic() - self._opened_at
        return max(0, self.reset_timeout - elapsed)

    def record_failure_sync(self, exception: Exception | None = None) -> None:
        """Record a failure (sync version). May trigger circuit open."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            old_state: CircuitState | None = None

            if self._state == CircuitState.HALF_OPEN:
                # Failure during probe - reopen circuit
                old_state = self._state
                self._state = CircuitState.OPEN
                self._opened_at = time.monotonic()
                logger.warning(f"Circuit breaker '{self.name}' -> OPEN (probe failed: {exception})")

            elif self._state == CircuitState.CLOSED:
                if self._failure_count >= self.fail_max:
                    old_state = self._state
                    self._state = CircuitState.OPEN
                    self._opened_at = time.monotonic()
                    logger.warning(
                        f"Circuit breaker '{self.name}' -> OPEN "
                        f"(failures: {self._failure_count}/{self.fail_max}, "
                        f"reset in {self.reset_timeout}s)"
                    )

            if old_state is not None:
                self._notify_state_change_sync(old_state, self._state)

    async def record_failure(self, exception: Exception | None = None) -> None:
        """Record a failure. May trigger circuit open."""
        # Use sync version since we use threading.Lock
        self.record_failure_sync(exception)

    def record_success_sync(self) -> None:
        """Record a success (sync version). May close circuit.

        Optimized: Only acquires lock if circuit is not CLOSED, since
        resetting failure_count when CLOSED is not critical.
        """
        # Fast path: if circuit is CLOSED, just reset failure count without lock
        # This is safe because:
        # 1. Reading _state is atomic in Python (GIL)
        # 2. Worst case: we miss a state change and reset count unnecessarily
        if self._state == CircuitState.CLOSED:
            self._failure_count = 0
            return

        # Slow path: circuit is OPEN or HALF_OPEN, need lock for state transition
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                # Successful probe - close circuit
                old_state: CircuitState = self._state
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                logger.info(f"Circuit breaker '{self.name}' -> CLOSED (recovered successfully)")
                self._notify_state_change_sync(old_state, self._state)
            # Note: CLOSED handled by fast path above; OPEN requires no action on success

    async def record_success(self) -> None:
        """Record a success. May close circuit."""
        # Use sync version since we use threading.Lock
        self.record_success_sync()

    def allow_request_sync(self) -> bool:
        """Check if a request should be allowed through (sync version).

        Returns:
            True if request can proceed, False if circuit is open
        """
        with self._lock:
            self._check_state_locked()
            # Allow requests when CLOSED or HALF_OPEN (probe)
            # Reject when OPEN
            return self._state in (CircuitState.CLOSED, CircuitState.HALF_OPEN)

    async def allow_request(self) -> bool:
        """Check if a request should be allowed through.

        Returns:
            True if request can proceed, False if circuit is open
        """
        # Use sync version since we use threading.Lock
        return self.allow_request_sync()

    @asynccontextmanager
    async def protect(self) -> AsyncGenerator[None, None]:
        """Context manager that protects a Redis operation.

        Raises:
            CircuitBreakerError: If circuit is open

        Example:
            async with circuit.protect():
                await redis.ping()
        """
        if not await self.allow_request():
            remaining = self._get_remaining_open_time()
            raise CircuitBreakerError(self.name, remaining)

        try:
            yield
            await self.record_success()
        except Exception as e:
            await self.record_failure(e)
            raise

    def get_status(self) -> dict[str, Any]:
        """Get current circuit breaker status for monitoring."""
        return {
            "name": self.name,
            "state": self._state.value,
            "failure_count": self._failure_count,
            "fail_max": self.fail_max,
            "reset_timeout": self.reset_timeout,
            "remaining_open_time": self._get_remaining_open_time(),
        }


class CircuitBreakerListener:
    """Base class for circuit breaker event listeners."""

    def on_state_change_sync(
        self,
        circuit_name: str,
        old_state: CircuitState,
        new_state: CircuitState,
    ) -> None:
        """Called when circuit state changes (sync version)."""


class LoggingCircuitListener(CircuitBreakerListener):
    """Listener that logs state changes with appropriate severity."""

    def on_state_change_sync(
        self,
        circuit_name: str,
        old_state: CircuitState,
        new_state: CircuitState,
    ) -> None:
        if new_state == CircuitState.OPEN:
            logger.error(
                f"Redis circuit breaker OPENED - all Redis operations will "
                f"fail-fast for {_CIRCUIT_RESET_TIMEOUT}s"
            )
        elif new_state == CircuitState.CLOSED:
            logger.info("Redis circuit breaker CLOSED - normal operation resumed")
        elif new_state == CircuitState.HALF_OPEN:
            logger.info("Redis circuit breaker testing recovery...")


class DebouncedErrorLogger:
    """Debounces similar error messages to reduce log spam.

    When Redis becomes unavailable, multiple background tasks may all
    fail simultaneously, creating a flood of similar error messages.
    This class groups similar errors within a time window.

    Thread-safe: Uses threading.Lock for cross-thread safety.

    Usage:
        debouncer = DebouncedErrorLogger(window_sec=10)

        # Instead of: logger.error(f"Redis error: {e}")
        debouncer.log_error("redis_timeout", f"Redis error: {e}")

        # On cleanup:
        debouncer.flush()  # Log any suppressed counts
    """

    def __init__(self, window_sec: float | None = None):
        self.window_sec = window_sec or _ERROR_DEBOUNCE_WINDOW
        self._last_logged: dict[str, float] = defaultdict(float)
        self._suppressed_counts: dict[str, int] = defaultdict(int)
        # Use threading.Lock for cross-thread safety
        self._lock = threading.Lock()

    def log_error_sync(
        self,
        error_key: str,
        message: str,
        *,
        level: str = "warning",
    ) -> bool:
        """Log an error, potentially debouncing it (sync version).

        Args:
            error_key: Key to group similar errors (e.g., "redis_timeout")
            message: Full error message to log
            level: Log level ("warning", "error", "info")

        Returns:
            True if message was logged, False if suppressed
        """
        with self._lock:
            now = time.monotonic()
            last_time = self._last_logged[error_key]

            if now - last_time < self.window_sec:
                # Within debounce window - suppress
                self._suppressed_counts[error_key] += 1
                return False

            # Outside window - log with suppression count
            suppressed = self._suppressed_counts[error_key]
            self._suppressed_counts[error_key] = 0
            self._last_logged[error_key] = now

            if suppressed > 0:
                message = f"{message} (suppressed {suppressed} similar in last {self.window_sec}s)"

            log_func = getattr(logger, level, logger.warning)
            log_func(message)
            return True

    async def log_error(
        self,
        error_key: str,
        message: str,
        *,
        level: str = "warning",
    ) -> bool:
        """Log an error, potentially debouncing it.

        Args:
            error_key: Key to group similar errors (e.g., "redis_timeout")
            message: Full error message to log
            level: Log level ("warning", "error", "info")

        Returns:
            True if message was logged, False if suppressed
        """
        return self.log_error_sync(error_key, message, level=level)

    def flush_sync(self) -> None:
        """Flush any pending suppressed error counts (sync version)."""
        with self._lock:
            for error_key, count in self._suppressed_counts.items():
                if count > 0:
                    logger.info(f"Suppressed {count} '{error_key}' errors in final window")
            self._suppressed_counts.clear()

    async def flush(self) -> None:
        """Flush any pending suppressed error counts."""
        self.flush_sync()

    def get_stats(self) -> dict[str, int]:
        """Get current suppression stats."""
        with self._lock:
            return dict(self._suppressed_counts)


class RedisHealthMonitor:
    """Coordinates Redis health checks across multiple background tasks.

    Instead of each task independently discovering Redis is down (thundering
    herd), this monitor provides a shared health status. Tasks check
    `is_healthy` before attempting Redis operations.

    Usage:
        monitor = RedisHealthMonitor(circuit_breaker)

        # Background tasks check before Redis ops:
        if not monitor.is_healthy:
            await monitor.wait_for_healthy(timeout=30)

        # Single health check loop updates status:
        async def health_loop():
            while running:
                try:
                    await redis.ping()
                    monitor.mark_healthy()
                except Exception:
                    monitor.mark_unhealthy()
                await asyncio.sleep(5)
    """

    def __init__(self, circuit_breaker: RedisCircuitBreaker | None = None):
        self._circuit = circuit_breaker
        self._healthy = asyncio.Event()
        self._healthy.set()  # Start healthy
        self._last_check_time: float = 0
        self._consecutive_failures: int = 0

    @property
    def is_healthy(self) -> bool:
        """True if Redis is believed to be healthy."""
        # If circuit is open, we know Redis is unhealthy
        if self._circuit and self._circuit.is_open:
            return False
        return self._healthy.is_set()

    def mark_healthy(self) -> None:
        """Mark Redis as healthy (call after successful ping)."""
        self._consecutive_failures = 0
        self._last_check_time = time.monotonic()
        if not self._healthy.is_set():
            logger.info("Redis health restored")
            self._healthy.set()

    def mark_unhealthy(self) -> None:
        """Mark Redis as unhealthy (call after failed ping)."""
        self._consecutive_failures += 1
        self._last_check_time = time.monotonic()
        if self._healthy.is_set():
            logger.warning(f"Redis health check failed ({self._consecutive_failures} consecutive)")
            self._healthy.clear()

    async def wait_for_healthy(self, timeout: float = 30) -> bool:
        """Wait for Redis to become healthy.

        Args:
            timeout: Max seconds to wait

        Returns:
            True if Redis is healthy, False if timeout
        """
        try:
            await asyncio.wait_for(self._healthy.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    def get_status(self) -> dict[str, Any]:
        """Get current health status for monitoring."""
        return {
            "is_healthy": self.is_healthy,
            "consecutive_failures": self._consecutive_failures,
            "circuit_state": self._circuit.state.value if self._circuit else None,
        }


# Global instances for shared use across background tasks
_redis_circuit: RedisCircuitBreaker | None = None
_error_debouncer: DebouncedErrorLogger | None = None
_health_monitor: RedisHealthMonitor | None = None


def get_redis_circuit() -> RedisCircuitBreaker:
    """Get the shared Redis circuit breaker instance."""
    global _redis_circuit
    if _redis_circuit is None:
        _redis_circuit = RedisCircuitBreaker("redis")
        _redis_circuit.add_listener(LoggingCircuitListener())
    return _redis_circuit


def get_error_debouncer() -> DebouncedErrorLogger:
    """Get the shared error debouncer instance."""
    global _error_debouncer
    if _error_debouncer is None:
        _error_debouncer = DebouncedErrorLogger()
    return _error_debouncer


def get_health_monitor() -> RedisHealthMonitor:
    """Get the shared Redis health monitor instance."""
    global _health_monitor
    if _health_monitor is None:
        _health_monitor = RedisHealthMonitor(get_redis_circuit())
    return _health_monitor


def reset_circuit_breaker_state() -> None:
    """Reset circuit breaker state (for testing)."""
    global _redis_circuit, _error_debouncer, _health_monitor
    _redis_circuit = None
    _error_debouncer = None
    _health_monitor = None


__all__ = [
    "CircuitBreakerError",
    "CircuitBreakerListener",
    "CircuitState",
    "DebouncedErrorLogger",
    "LoggingCircuitListener",
    "RedisCircuitBreaker",
    "RedisHealthMonitor",
    "get_error_debouncer",
    "get_health_monitor",
    "get_redis_circuit",
    "reset_circuit_breaker_state",
]
