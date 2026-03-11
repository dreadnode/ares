"""Unit tests for circuit breaker and error debouncing.

Tests the Redis circuit breaker pattern that prevents thundering herd
during Redis outages.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from ares.core.circuit_breaker import (
    CircuitBreakerError,
    CircuitBreakerListener,
    CircuitState,
    DebouncedErrorLogger,
    LoggingCircuitListener,
    RedisCircuitBreaker,
    RedisHealthMonitor,
    reset_circuit_breaker_state,
)

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture(autouse=True)
def reset_globals():
    """Reset global circuit breaker state between tests."""
    reset_circuit_breaker_state()
    yield
    reset_circuit_breaker_state()


# ============================================================================
# RedisCircuitBreaker Tests
# ============================================================================


class TestRedisCircuitBreaker:
    """Tests for RedisCircuitBreaker."""

    async def test_initial_state_is_closed(self):
        """Circuit starts in closed state."""
        circuit = RedisCircuitBreaker("test")
        assert circuit.state == CircuitState.CLOSED
        assert circuit.is_closed
        assert not circuit.is_open
        assert circuit.failure_count == 0

    async def test_allows_request_when_closed(self):
        """Closed circuit allows requests."""
        circuit = RedisCircuitBreaker("test")
        assert await circuit.allow_request()

    async def test_opens_after_fail_max_failures(self):
        """Circuit opens after reaching failure threshold."""
        circuit = RedisCircuitBreaker("test", fail_max=3)

        # Record failures up to threshold
        for i in range(3):
            await circuit.record_failure(Exception(f"error {i}"))

        assert circuit.state == CircuitState.OPEN
        assert circuit.is_open
        assert not circuit.is_closed

    async def test_rejects_request_when_open(self):
        """Open circuit rejects requests."""
        circuit = RedisCircuitBreaker("test", fail_max=1)
        await circuit.record_failure(Exception("error"))

        assert circuit.is_open
        assert not await circuit.allow_request()

    async def test_transitions_to_half_open_after_timeout(self):
        """Circuit transitions to half-open after reset timeout."""
        circuit = RedisCircuitBreaker("test", fail_max=1, reset_timeout=0.1)
        await circuit.record_failure(Exception("error"))

        assert circuit.is_open

        # Wait for timeout
        await asyncio.sleep(0.15)

        # Check state transitions to half-open
        assert await circuit.allow_request()
        assert circuit.state == CircuitState.HALF_OPEN

    async def test_closes_on_success_in_half_open(self):
        """Successful request in half-open closes circuit."""
        circuit = RedisCircuitBreaker("test", fail_max=1, reset_timeout=0.1)
        await circuit.record_failure(Exception("error"))

        await asyncio.sleep(0.15)
        await circuit.allow_request()  # Transition to half-open

        # Record success
        await circuit.record_success()

        assert circuit.state == CircuitState.CLOSED
        assert circuit.failure_count == 0

    async def test_reopens_on_failure_in_half_open(self):
        """Failure in half-open reopens circuit."""
        circuit = RedisCircuitBreaker("test", fail_max=1, reset_timeout=0.1)
        await circuit.record_failure(Exception("error"))

        await asyncio.sleep(0.15)
        await circuit.allow_request()  # Transition to half-open

        # Record another failure
        await circuit.record_failure(Exception("still broken"))

        assert circuit.state == CircuitState.OPEN

    async def test_success_resets_failure_count_when_closed(self):
        """Success resets failure count in closed state."""
        circuit = RedisCircuitBreaker("test", fail_max=5)

        # Record some failures
        await circuit.record_failure(Exception("error 1"))
        await circuit.record_failure(Exception("error 2"))
        assert circuit.failure_count == 2

        # Record success
        await circuit.record_success()
        assert circuit.failure_count == 0
        assert circuit.is_closed

    async def test_protect_context_manager_success(self):
        """Protect context manager records success on normal exit."""
        circuit = RedisCircuitBreaker("test")

        async with circuit.protect():
            pass  # Successful operation

        assert circuit.failure_count == 0

    async def test_protect_context_manager_failure(self):
        """Protect context manager records failure on exception."""
        circuit = RedisCircuitBreaker("test", fail_max=1)

        with pytest.raises(ValueError, match="test error"):
            async with circuit.protect():
                raise ValueError("test error")

        assert circuit.is_open

    async def test_protect_raises_when_open(self):
        """Protect raises CircuitBreakerError when circuit is open."""
        circuit = RedisCircuitBreaker("test", fail_max=1, reset_timeout=30)
        await circuit.record_failure(Exception("error"))

        with pytest.raises(CircuitBreakerError) as exc_info:
            async with circuit.protect():
                pass

        assert exc_info.value.circuit_name == "test"
        assert exc_info.value.remaining_time > 0

    async def test_get_status(self):
        """Get status returns current circuit state."""
        circuit = RedisCircuitBreaker("test", fail_max=5, reset_timeout=30)

        status = circuit.get_status()
        assert status["name"] == "test"
        assert status["state"] == "closed"
        assert status["failure_count"] == 0
        assert status["fail_max"] == 5
        assert status["reset_timeout"] == 30

    async def test_listener_notified_on_state_change(self):
        """Listeners are notified on state changes."""

        class TestListener(CircuitBreakerListener):
            def __init__(self):
                self.changes = []

            def on_state_change_sync(self, circuit_name, old_state, new_state):
                self.changes.append((circuit_name, old_state, new_state))

        circuit = RedisCircuitBreaker("test", fail_max=1, reset_timeout=0.1)
        listener = TestListener()
        circuit.add_listener(listener)

        # Trigger CLOSED -> OPEN
        await circuit.record_failure(Exception("error"))
        assert len(listener.changes) == 1
        assert listener.changes[0] == ("test", CircuitState.CLOSED, CircuitState.OPEN)

        # Wait for OPEN -> HALF_OPEN
        await asyncio.sleep(0.15)
        await circuit.allow_request()
        assert len(listener.changes) == 2
        assert listener.changes[1] == ("test", CircuitState.OPEN, CircuitState.HALF_OPEN)

        # Trigger HALF_OPEN -> CLOSED
        await circuit.record_success()
        assert len(listener.changes) == 3
        assert listener.changes[2] == ("test", CircuitState.HALF_OPEN, CircuitState.CLOSED)


# ============================================================================
# DebouncedErrorLogger Tests
# ============================================================================


class TestDebouncedErrorLogger:
    """Tests for DebouncedErrorLogger."""

    async def test_logs_first_error(self):
        """First error is always logged."""
        debouncer = DebouncedErrorLogger(window_sec=10)

        with patch("ares.core.circuit_breaker.logger") as mock_logger:
            logged = await debouncer.log_error("test_key", "Test error message")

        assert logged
        mock_logger.warning.assert_called_once()

    async def test_suppresses_duplicate_within_window(self):
        """Duplicate errors within window are suppressed."""
        debouncer = DebouncedErrorLogger(window_sec=10)

        with patch("ares.core.circuit_breaker.logger") as mock_logger:
            # First error logs
            await debouncer.log_error("test_key", "Error 1")
            # Second error suppressed
            logged = await debouncer.log_error("test_key", "Error 2")

        assert not logged
        mock_logger.warning.assert_called_once()

    async def test_logs_after_window_expires(self):
        """Error is logged after window expires."""
        debouncer = DebouncedErrorLogger(window_sec=0.1)

        with patch("ares.core.circuit_breaker.logger") as mock_logger:
            await debouncer.log_error("test_key", "Error 1")
            await asyncio.sleep(0.15)
            logged = await debouncer.log_error("test_key", "Error 2")

        assert logged
        assert mock_logger.warning.call_count == 2

    async def test_includes_suppression_count(self):
        """Logged message includes count of suppressed errors."""
        debouncer = DebouncedErrorLogger(window_sec=0.1)

        with patch("ares.core.circuit_breaker.logger") as mock_logger:
            await debouncer.log_error("test_key", "Error 1")
            await debouncer.log_error("test_key", "Error 2")
            await debouncer.log_error("test_key", "Error 3")
            await asyncio.sleep(0.15)
            await debouncer.log_error("test_key", "Error 4")

        # Last call should include suppression count
        last_call = mock_logger.warning.call_args[0][0]
        assert "suppressed 2 similar" in last_call

    async def test_different_keys_logged_independently(self):
        """Different error keys are logged independently."""
        debouncer = DebouncedErrorLogger(window_sec=10)

        with patch("ares.core.circuit_breaker.logger") as mock_logger:
            await debouncer.log_error("key1", "Error type 1")
            await debouncer.log_error("key2", "Error type 2")

        assert mock_logger.warning.call_count == 2

    async def test_flush_logs_pending_counts(self):
        """Flush logs any pending suppression counts."""
        debouncer = DebouncedErrorLogger(window_sec=10)

        with patch("ares.core.circuit_breaker.logger") as mock_logger:
            await debouncer.log_error("test_key", "Error 1")
            await debouncer.log_error("test_key", "Error 2")
            await debouncer.log_error("test_key", "Error 3")
            await debouncer.flush()

        # Should log info about suppressed errors
        mock_logger.info.assert_called()
        info_call = mock_logger.info.call_args[0][0]
        assert "Suppressed 2" in info_call

    async def test_respects_log_level(self):
        """Uses specified log level."""
        debouncer = DebouncedErrorLogger(window_sec=10)

        with patch("ares.core.circuit_breaker.logger") as mock_logger:
            await debouncer.log_error("test_key", "Error", level="error")

        mock_logger.error.assert_called_once()


# ============================================================================
# RedisHealthMonitor Tests
# ============================================================================


class TestRedisHealthMonitor:
    """Tests for RedisHealthMonitor."""

    async def test_starts_healthy(self):
        """Monitor starts in healthy state."""
        monitor = RedisHealthMonitor()
        assert monitor.is_healthy

    async def test_mark_unhealthy(self):
        """Marking unhealthy clears healthy flag."""
        monitor = RedisHealthMonitor()
        monitor.mark_unhealthy()
        assert not monitor.is_healthy

    async def test_mark_healthy_after_unhealthy(self):
        """Marking healthy sets healthy flag."""
        monitor = RedisHealthMonitor()
        monitor.mark_unhealthy()
        monitor.mark_healthy()
        assert monitor.is_healthy

    async def test_wait_for_healthy_immediate(self):
        """Wait returns immediately when healthy."""
        monitor = RedisHealthMonitor()
        result = await monitor.wait_for_healthy(timeout=0.1)
        assert result

    async def test_wait_for_healthy_timeout(self):
        """Wait times out when unhealthy."""
        monitor = RedisHealthMonitor()
        monitor.mark_unhealthy()
        result = await monitor.wait_for_healthy(timeout=0.1)
        assert not result

    async def test_wait_for_healthy_becomes_healthy(self):
        """Wait returns when health is restored."""
        monitor = RedisHealthMonitor()
        monitor.mark_unhealthy()

        async def restore_health():
            await asyncio.sleep(0.05)
            monitor.mark_healthy()

        task = asyncio.create_task(restore_health())
        result = await monitor.wait_for_healthy(timeout=1.0)
        await task  # Ensure task completes
        assert result

    async def test_circuit_breaker_affects_health(self):
        """Open circuit breaker makes monitor report unhealthy."""
        circuit = RedisCircuitBreaker("test", fail_max=1)
        monitor = RedisHealthMonitor(circuit)

        assert monitor.is_healthy

        await circuit.record_failure(Exception("error"))
        assert not monitor.is_healthy

    async def test_get_status(self):
        """Get status returns current health state."""
        circuit = RedisCircuitBreaker("test")
        monitor = RedisHealthMonitor(circuit)

        status = monitor.get_status()
        assert status["is_healthy"]
        assert status["consecutive_failures"] == 0
        assert status["circuit_state"] == "closed"


# ============================================================================
# LoggingCircuitListener Tests
# ============================================================================


class TestLoggingCircuitListener:
    """Tests for LoggingCircuitListener."""

    async def test_logs_open_state(self):
        """Logs error when circuit opens."""
        listener = LoggingCircuitListener()

        with patch("ares.core.circuit_breaker.logger") as mock_logger:
            listener.on_state_change_sync("test", CircuitState.CLOSED, CircuitState.OPEN)

        mock_logger.error.assert_called_once()
        assert "OPENED" in mock_logger.error.call_args[0][0]

    async def test_logs_closed_state(self):
        """Logs info when circuit closes."""
        listener = LoggingCircuitListener()

        with patch("ares.core.circuit_breaker.logger") as mock_logger:
            listener.on_state_change_sync("test", CircuitState.HALF_OPEN, CircuitState.CLOSED)

        mock_logger.info.assert_called_once()
        assert "CLOSED" in mock_logger.info.call_args[0][0]

    async def test_logs_half_open_state(self):
        """Logs info when circuit enters half-open."""
        listener = LoggingCircuitListener()

        with patch("ares.core.circuit_breaker.logger") as mock_logger:
            listener.on_state_change_sync("test", CircuitState.OPEN, CircuitState.HALF_OPEN)

        mock_logger.info.assert_called_once()
        assert "recovery" in mock_logger.info.call_args[0][0].lower()


# ============================================================================
# Integration Tests
# ============================================================================


class TestCircuitBreakerIntegration:
    """Integration tests for circuit breaker with Redis operations."""

    async def test_multiple_concurrent_failures_open_circuit_once(self):
        """Multiple concurrent failures only open circuit once."""
        circuit = RedisCircuitBreaker("test", fail_max=3)

        # Simulate multiple concurrent failures (thundering herd)
        failures = [circuit.record_failure(Exception(f"error {i}")) for i in range(5)]
        await asyncio.gather(*failures)

        # Circuit should be open
        assert circuit.is_open
        # Failure count should be 5 (all recorded)
        assert circuit.failure_count == 5

    async def test_circuit_prevents_further_requests(self):
        """Open circuit prevents further request attempts."""
        circuit = RedisCircuitBreaker("test", fail_max=1, reset_timeout=30)

        # Open circuit
        await circuit.record_failure(Exception("error"))

        # Try multiple requests - all should be rejected
        results = await asyncio.gather(*[circuit.allow_request() for _ in range(10)])

        assert all(not r for r in results)

    async def test_shared_circuit_across_tasks(self):
        """Multiple tasks share the same circuit state."""
        circuit = RedisCircuitBreaker("test", fail_max=2)

        async def task_that_fails():
            try:
                async with circuit.protect():
                    raise ConnectionError("Redis down")
            except ConnectionError:
                pass

        # Two tasks fail
        await asyncio.gather(task_that_fails(), task_that_fails())

        # Circuit should now be open
        assert circuit.is_open

        # Third task should be rejected immediately
        with pytest.raises(CircuitBreakerError):
            async with circuit.protect():
                pass
