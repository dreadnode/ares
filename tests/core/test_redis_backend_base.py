"""Tests for BaseRedisBackend shared functionality."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from ares.core.circuit_breaker import CircuitBreakerError
from ares.core.redis_backend_base import REDIS_RETRY_EXCEPTIONS, BaseRedisBackend


class ConcreteRedisBackend(BaseRedisBackend):
    """Concrete implementation for testing the abstract base class."""

    KEY_PREFIX = "ares:test"

    def _build_key_prefix(self, entity_id: str) -> str:
        return f"{self.KEY_PREFIX}:{entity_id}"

    @property
    def _log_prefix(self) -> str:
        return "test_backend"


class TestRedisRetryExceptions:
    """Tests for REDIS_RETRY_EXCEPTIONS constant."""

    def test_contains_connection_error(self):
        """ConnectionError should be in retry exceptions."""
        assert ConnectionError in REDIS_RETRY_EXCEPTIONS

    def test_contains_timeout_error(self):
        """TimeoutError should be in retry exceptions."""
        assert TimeoutError in REDIS_RETRY_EXCEPTIONS

    def test_contains_os_error(self):
        """OSError should be in retry exceptions."""
        assert OSError in REDIS_RETRY_EXCEPTIONS


class TestBaseRedisBackendInit:
    """Tests for BaseRedisBackend initialization."""

    def test_init_with_circuit_breaker(self):
        """Test initialization with circuit breaker enabled."""
        mock_redis = MagicMock()
        backend = ConcreteRedisBackend(mock_redis, "test-op-123", use_circuit_breaker=True)

        assert backend._redis is mock_redis
        assert backend._entity_id == "test-op-123"
        assert backend._key_prefix == "ares:test:test-op-123"
        assert backend._use_circuit_breaker is True
        assert backend._circuit is not None
        assert backend._debouncer is not None

    def test_init_without_circuit_breaker(self):
        """Test initialization with circuit breaker disabled."""
        mock_redis = MagicMock()
        backend = ConcreteRedisBackend(mock_redis, "test-op-456", use_circuit_breaker=False)

        assert backend._use_circuit_breaker is False
        assert backend._circuit is None
        assert backend._debouncer is None


class TestKeyBuilding:
    """Tests for key building methods."""

    def test_key_method(self):
        """Test _key builds correct full Redis key."""
        mock_redis = MagicMock()
        backend = ConcreteRedisBackend(mock_redis, "op-789", use_circuit_breaker=False)

        assert backend._key("credentials") == "ares:test:op-789:credentials"
        assert backend._key("meta") == "ares:test:op-789:meta"
        assert backend._key("hashes") == "ares:test:op-789:hashes"

    def test_key_prefix_property(self):
        """Test _key_prefix is set correctly."""
        mock_redis = MagicMock()
        backend = ConcreteRedisBackend(mock_redis, "my-operation", use_circuit_breaker=False)

        assert backend._key_prefix == "ares:test:my-operation"


class TestSetTtl:
    """Tests for _set_ttl method."""

    @pytest.mark.asyncio
    async def test_set_ttl_calls_expire(self):
        """Test _set_ttl calls Redis expire with correct TTL."""
        mock_redis = AsyncMock()
        backend = ConcreteRedisBackend(mock_redis, "op-123", use_circuit_breaker=False)

        await backend._set_ttl("ares:test:op-123:credentials")

        mock_redis.expire.assert_called_once_with(
            "ares:test:op-123:credentials", backend.DEFAULT_TTL
        )

    def test_default_ttl_is_24_hours(self):
        """Test DEFAULT_TTL is 24 hours (86400 seconds)."""
        assert BaseRedisBackend.DEFAULT_TTL == 86400


class TestWithRetry:
    """Tests for _with_retry method."""

    @pytest.mark.asyncio
    async def test_with_retry_no_circuit_breaker_calls_directly(self):
        """Test _with_retry calls operation directly when circuit breaker disabled."""
        mock_redis = AsyncMock()
        backend = ConcreteRedisBackend(mock_redis, "op-123", use_circuit_breaker=False)

        operation = AsyncMock(return_value="success")
        result = await backend._with_retry("test_op", operation)

        assert result == "success"
        operation.assert_called_once()

    @pytest.mark.asyncio
    async def test_with_retry_success_records_success(self):
        """Test _with_retry records success on circuit breaker."""
        mock_redis = AsyncMock()
        backend = ConcreteRedisBackend(mock_redis, "op-123", use_circuit_breaker=True)

        # Mock circuit breaker
        backend._circuit = MagicMock()
        backend._circuit.allow_request_sync.return_value = True
        backend._circuit.record_success_sync = MagicMock()

        operation = AsyncMock(return_value="result")
        result = await backend._with_retry("test_op", operation)

        assert result == "result"
        backend._circuit.record_success_sync.assert_called_once()

    @pytest.mark.asyncio
    async def test_with_retry_circuit_open_raises_error(self):
        """Test _with_retry raises CircuitBreakerError when circuit is open."""
        mock_redis = AsyncMock()
        backend = ConcreteRedisBackend(mock_redis, "op-123", use_circuit_breaker=True)

        # Mock circuit breaker in open state
        backend._circuit = MagicMock()
        backend._circuit.allow_request_sync.return_value = False
        backend._circuit._get_remaining_open_time.return_value = 30.0
        backend._circuit.name = "redis_circuit"

        operation = AsyncMock()

        with pytest.raises(CircuitBreakerError):
            await backend._with_retry("test_op", operation)

        # Operation should not be called when circuit is open
        operation.assert_not_called()

    @pytest.mark.asyncio
    async def test_with_retry_connection_error_records_failure(self):
        """Test _with_retry records failure on connection error."""
        mock_redis = AsyncMock()
        backend = ConcreteRedisBackend(mock_redis, "op-123", use_circuit_breaker=True)

        # Mock circuit breaker
        backend._circuit = MagicMock()
        backend._circuit.allow_request_sync.return_value = True
        backend._circuit.record_failure_sync = MagicMock()

        # Mock debouncer
        backend._debouncer = MagicMock()
        backend._debouncer.log_error_sync = MagicMock()

        # Operation that fails with connection error
        operation = AsyncMock(side_effect=ConnectionError("Connection refused"))

        with pytest.raises(ConnectionError):
            await backend._with_retry("test_op", operation)

        backend._circuit.record_failure_sync.assert_called()


class TestLogPrefix:
    """Tests for _log_prefix property."""

    def test_log_prefix_returns_correct_value(self):
        """Test _log_prefix returns the expected value."""
        mock_redis = MagicMock()
        backend = ConcreteRedisBackend(mock_redis, "op-123", use_circuit_breaker=False)

        assert backend._log_prefix == "test_backend"


class TestRetryConfiguration:
    """Tests for retry configuration constants."""

    def test_retry_max_attempts(self):
        """Test RETRY_MAX_ATTEMPTS is set correctly."""
        assert BaseRedisBackend.RETRY_MAX_ATTEMPTS == 3

    def test_retry_multiplier(self):
        """Test RETRY_MULTIPLIER is set correctly."""
        assert BaseRedisBackend.RETRY_MULTIPLIER == 1.0

    def test_retry_max_delay(self):
        """Test RETRY_MAX_DELAY is set correctly."""
        assert BaseRedisBackend.RETRY_MAX_DELAY == 10.0
