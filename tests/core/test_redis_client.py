"""Tests for Redis client helpers."""

from __future__ import annotations

import asyncio
import sys
import types
from typing import Any
from unittest.mock import MagicMock

import pytest

from ares.core.redis_client import (
    _resolve_sentinel_hosts,
    _verify_redis_role,
    create_redis_client,
    create_verified_redis_client,
    get_redis_sentinel_config,
    get_retry_delay,
    is_connection_error,
    timed_redis_write,
)


class DummySentinel:
    def __init__(
        self,
        hosts: list[tuple[str, int]],
        **kwargs: Any,
    ) -> None:
        self.hosts = hosts
        self.kwargs = kwargs
        self.master = None
        self.master_kwargs: dict[str, Any] | None = None
        self.slave = None
        self.slave_kwargs: dict[str, Any] | None = None

    def master_for(self, master: str, **kwargs: Any):
        self.master = master
        self.master_kwargs = kwargs
        return "sentinel-client"

    def slave_for(self, master: str, **kwargs: Any):
        self.slave = master
        self.slave_kwargs = kwargs
        return "replica-client"

    async def discover_master(self, master: str) -> tuple[str, int]:
        """Mock discover_master - returns a dummy master address."""
        return ("redis-master", 6379)


def install_dummy_redis(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    redis_module = types.ModuleType("redis")
    asyncio_module = types.ModuleType("redis.asyncio")
    redis_module.asyncio = asyncio_module
    monkeypatch.setitem(sys.modules, "redis", redis_module)
    monkeypatch.setitem(sys.modules, "redis.asyncio", asyncio_module)
    return asyncio_module


def test_get_redis_sentinel_config_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REDIS_SENTINEL_HOST", raising=False)
    monkeypatch.delenv("REDIS_SENTINEL_MASTER", raising=False)

    assert get_redis_sentinel_config() is None


def test_get_redis_sentinel_config_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDIS_SENTINEL_HOST", "sentinel")
    monkeypatch.setenv("REDIS_SENTINEL_MASTER", "mymaster")
    monkeypatch.setenv("REDIS_PASSWORD", "redis-pass")  # pragma: allowlist secret

    config = get_redis_sentinel_config()

    assert config == {
        "sentinels": [("sentinel", 26379)],
        "master": "mymaster",
        "sentinel_password": "redis-pass",  # pragma: allowlist secret
        "redis_password": "redis-pass",  # pragma: allowlist secret
        "db": 0,
    }


def test_get_redis_sentinel_config_passwords(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDIS_SENTINEL_HOST", "sentinel")
    monkeypatch.setenv("REDIS_SENTINEL_MASTER", "mymaster")
    monkeypatch.setenv("REDIS_SENTINEL_PASSWORD", "sentinel-pass")  # pragma: allowlist secret
    monkeypatch.setenv("REDIS_PASSWORD", "redis-pass")  # pragma: allowlist secret
    monkeypatch.setenv("REDIS_DB", "2")
    monkeypatch.setenv("REDIS_SENTINEL_PORT", "6380")

    config = get_redis_sentinel_config()

    assert config == {
        "sentinels": [("sentinel", 6380)],
        "master": "mymaster",
        "sentinel_password": "sentinel-pass",  # pragma: allowlist secret
        "redis_password": "redis-pass",  # pragma: allowlist secret
        "db": 2,
    }


def test_get_redis_sentinel_config_multiple_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that comma-separated sentinel hosts are parsed correctly."""
    monkeypatch.setenv("REDIS_SENTINEL_HOST", "sentinel-0:26379,sentinel-1:26379,sentinel-2:26379")
    monkeypatch.setenv("REDIS_SENTINEL_MASTER", "mymaster")
    monkeypatch.setenv("REDIS_PASSWORD", "redis-pass")  # pragma: allowlist secret

    config = get_redis_sentinel_config()

    assert config["sentinels"] == [
        ("sentinel-0", 26379),
        ("sentinel-1", 26379),
        ("sentinel-2", 26379),
    ]
    assert config["master"] == "mymaster"


def test_resolve_sentinel_hosts_comma_separated() -> None:
    """Test comma-separated host parsing."""
    result = _resolve_sentinel_hosts("host1:26379,host2:26380,host3", 26379)
    assert result == [("host1", 26379), ("host2", 26380), ("host3", 26379)]


def test_resolve_sentinel_hosts_single_with_port() -> None:
    """Test single host with port."""
    result = _resolve_sentinel_hosts("sentinel:26380", 26379)
    assert result == [("sentinel", 26380)]


def test_resolve_sentinel_hosts_single_without_port() -> None:
    """Test single host without port uses default."""
    result = _resolve_sentinel_hosts("sentinel", 26379)
    assert result == [("sentinel", 26379)]


@pytest.mark.asyncio
async def test_create_redis_client_uses_sentinel(monkeypatch: pytest.MonkeyPatch) -> None:
    asyncio_module = install_dummy_redis(monkeypatch)
    sentinel_instances: list[DummySentinel] = []

    class TrackingSentinel(DummySentinel):
        def __init__(self, hosts: list[tuple[str, int]], **kwargs: Any) -> None:
            super().__init__(hosts, **kwargs)
            sentinel_instances.append(self)

    asyncio_module.Sentinel = TrackingSentinel
    asyncio_module.from_url = MagicMock(return_value="url-client")

    monkeypatch.setenv("REDIS_SENTINEL_HOST", "sentinel")
    monkeypatch.setenv("REDIS_SENTINEL_MASTER", "mymaster")
    monkeypatch.setenv("REDIS_SENTINEL_PORT", "26379")
    monkeypatch.setenv("REDIS_SENTINEL_PASSWORD", "sentinel-pass")
    monkeypatch.setenv("REDIS_PASSWORD", "redis-pass")
    monkeypatch.setenv("REDIS_DB", "1")

    client = await create_redis_client("redis://localhost", decode_responses=True)

    assert client == "sentinel-client"
    assert asyncio_module.from_url.call_count == 0

    assert len(sentinel_instances) == 1
    sentinel_instance = sentinel_instances[0]
    assert sentinel_instance.hosts == [("sentinel", 26379)]
    assert sentinel_instance.master == "mymaster"
    assert sentinel_instance.master_kwargs == {
        "password": "redis-pass",  # pragma: allowlist secret
        "db": 1,
        "decode_responses": True,
        "socket_timeout": 10.0,  # Lowered from 30s for faster detection of stale connections
        "socket_connect_timeout": 5.0,
        "health_check_interval": 10.0,
    }


@pytest.mark.asyncio
async def test_create_redis_client_explicit_socket_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that explicit socket_timeout parameter overrides default."""
    asyncio_module = install_dummy_redis(monkeypatch)

    from_url_mock = MagicMock(return_value="url-client")
    asyncio_module.from_url = from_url_mock

    monkeypatch.delenv("REDIS_SENTINEL_HOST", raising=False)
    monkeypatch.delenv("REDIS_SENTINEL_MASTER", raising=False)

    # Test with explicit socket_timeout=None (for blocking operations like BRPOP)
    await create_redis_client("redis://localhost", socket_timeout=None)

    call_kwargs = from_url_mock.call_args[1]
    assert call_kwargs["socket_timeout"] is None


@pytest.mark.asyncio
async def test_create_redis_client_socket_timeout_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that socket_timeout=... uses default from environment."""
    asyncio_module = install_dummy_redis(monkeypatch)

    from_url_mock = MagicMock(return_value="url-client")
    asyncio_module.from_url = from_url_mock

    monkeypatch.delenv("REDIS_SENTINEL_HOST", raising=False)
    monkeypatch.delenv("REDIS_SENTINEL_MASTER", raising=False)
    monkeypatch.setenv("REDIS_SOCKET_TIMEOUT", "15")

    # Default behavior (socket_timeout=...) should use env var
    await create_redis_client("redis://localhost")

    call_kwargs = from_url_mock.call_args[1]
    assert call_kwargs["socket_timeout"] == 15.0


@pytest.mark.asyncio
async def test_create_redis_client_explicit_socket_timeout_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that explicit numeric socket_timeout is used."""
    asyncio_module = install_dummy_redis(monkeypatch)

    from_url_mock = MagicMock(return_value="url-client")
    asyncio_module.from_url = from_url_mock

    monkeypatch.delenv("REDIS_SENTINEL_HOST", raising=False)
    monkeypatch.delenv("REDIS_SENTINEL_MASTER", raising=False)

    # Test with explicit numeric socket_timeout
    await create_redis_client("redis://localhost", socket_timeout=30.0)

    call_kwargs = from_url_mock.call_args[1]
    assert call_kwargs["socket_timeout"] == 30.0


@pytest.mark.asyncio
async def test_create_redis_client_uses_url(monkeypatch: pytest.MonkeyPatch) -> None:
    asyncio_module = install_dummy_redis(monkeypatch)
    asyncio_module.Sentinel = DummySentinel
    asyncio_module.from_url = MagicMock(return_value="url-client")

    monkeypatch.delenv("REDIS_SENTINEL_HOST", raising=False)
    monkeypatch.delenv("REDIS_SENTINEL_MASTER", raising=False)

    client = await create_redis_client("redis://localhost", decode_responses=True)

    assert client == "url-client"
    asyncio_module.from_url.assert_called_once()


class MockRedisClient:
    """Mock Redis client for testing ROLE verification."""

    def __init__(self, role_response: list[Any] | Exception):
        self.role_response = role_response
        self.closed = False

    async def execute_command(self, cmd: str) -> list[Any]:
        if isinstance(self.role_response, Exception):
            raise self.role_response
        return self.role_response

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_verify_redis_role_master() -> None:
    """Test ROLE verification passes for master."""
    client = MockRedisClient(["master", 12345, []])
    assert await _verify_redis_role(client, expected_role="master") is True


@pytest.mark.asyncio
async def test_verify_redis_role_slave() -> None:
    """Test ROLE verification fails when connected to slave instead of master."""
    client = MockRedisClient(["slave", "192.168.58.10", 6379, "connected", 12345])
    assert await _verify_redis_role(client, expected_role="master") is False


@pytest.mark.asyncio
async def test_verify_redis_role_bytes_response() -> None:
    """Test ROLE verification handles bytes response."""
    client = MockRedisClient([b"master", 12345, []])
    assert await _verify_redis_role(client, expected_role="master") is True


@pytest.mark.asyncio
async def test_verify_redis_role_slave_expected() -> None:
    """Test ROLE verification for slave role."""
    client = MockRedisClient(["slave", "192.168.58.10", 6379, "connected", 12345])
    assert await _verify_redis_role(client, expected_role="slave") is True


@pytest.mark.asyncio
async def test_verify_redis_role_error() -> None:
    """Test ROLE verification handles errors gracefully."""
    client = MockRedisClient(Exception("Connection error"))
    assert await _verify_redis_role(client, expected_role="master") is False


@pytest.mark.asyncio
async def test_create_verified_redis_client_no_sentinel(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test verified client falls back to regular client when no Sentinel."""
    asyncio_module = install_dummy_redis(monkeypatch)
    asyncio_module.Sentinel = DummySentinel
    asyncio_module.from_url = MagicMock(return_value="url-client")

    monkeypatch.delenv("REDIS_SENTINEL_HOST", raising=False)
    monkeypatch.delenv("REDIS_SENTINEL_MASTER", raising=False)

    client = await create_verified_redis_client("redis://localhost", decode_responses=True)

    assert client == "url-client"


class TestIsConnectionError:
    """Tests for is_connection_error() helper function."""

    @pytest.mark.parametrize(
        "error_message",
        [
            "Connection closed unexpectedly",
            "connection reset by peer",
            "Connection refused",
            "Cannot connect to host",
            "Socket timeout",
            "Broken pipe",
            "Network unreachable",
            "No route to host",
            "EOF occurred",
            "errno 111",
            "SOCKET_ERROR",
            # DNS resolution failures
            "Name or service not known",
            "Error -2 connecting to redis-0.redis-headless: Name or service not known",
            "getaddrinfo failed: Name does not resolve",
            "Temporary failure in name resolution",
            "No address associated with hostname",
        ],
    )
    def test_detects_connection_errors(self, error_message: str) -> None:
        """Test that various connection error messages are detected."""
        error = Exception(error_message)
        assert is_connection_error(error) is True

    @pytest.mark.parametrize(
        "error_message",
        [
            "Key not found",
            "Invalid argument",
            "Permission denied",
            "Out of memory",
            "Syntax error in command",
            "WRONGTYPE Operation against a key holding the wrong kind of value",
        ],
    )
    def test_returns_false_for_non_connection_errors(self, error_message: str) -> None:
        """Test that non-connection errors are not detected."""
        error = Exception(error_message)
        assert is_connection_error(error) is False

    def test_case_insensitive_matching(self) -> None:
        """Test that matching is case-insensitive."""
        assert is_connection_error(Exception("CONNECTION RESET")) is True
        assert is_connection_error(Exception("TimeOut occurred")) is True
        assert is_connection_error(Exception("BROKEN PIPE")) is True

    def test_handles_empty_error_message(self) -> None:
        """Test handling of empty error message."""
        assert is_connection_error(Exception("")) is False

    def test_handles_base_exception(self) -> None:
        """Test that it works with BaseException types."""
        assert is_connection_error(TimeoutError("Connection timeout")) is True
        assert is_connection_error(OSError("Connection refused")) is True


class TestTimedRedisWrite:
    """Tests for timed_redis_write() helper function."""

    @pytest.mark.asyncio
    async def test_success_returns_result(self) -> None:
        """Test that successful operations return their result."""

        async def mock_redis_op():
            return "OK"

        result = await timed_redis_write(mock_redis_op(), timeout=5.0)
        assert result == "OK"

    @pytest.mark.asyncio
    async def test_timeout_raises_timeout_error(self) -> None:
        """Test that operations exceeding timeout raise TimeoutError."""

        async def slow_redis_op():
            await asyncio.sleep(10)
            return "OK"

        with pytest.raises(asyncio.TimeoutError):
            await timed_redis_write(slow_redis_op(), timeout=0.1, operation_name="slow_op")

    @pytest.mark.asyncio
    async def test_uses_custom_timeout(self) -> None:
        """Test that custom timeout is respected."""

        async def fast_redis_op():
            await asyncio.sleep(0.05)
            return "OK"

        # Should succeed with adequate timeout
        result = await timed_redis_write(fast_redis_op(), timeout=1.0)
        assert result == "OK"

        # Should fail with too-short timeout
        with pytest.raises(asyncio.TimeoutError):
            await timed_redis_write(fast_redis_op(), timeout=0.01)

    @pytest.mark.asyncio
    async def test_uses_default_timeout_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that default timeout is read from environment."""

        # Reload module to pick up new env var (or just test the behavior)
        async def fast_op():
            return "OK"

        # Default timeout (10s) should be plenty for this fast operation
        result = await timed_redis_write(fast_op())
        assert result == "OK"

    @pytest.mark.asyncio
    async def test_propagates_redis_exceptions(self) -> None:
        """Test that Redis exceptions are propagated."""

        async def failing_redis_op():
            raise ValueError("WRONGTYPE Operation")

        with pytest.raises(ValueError, match="WRONGTYPE"):
            await timed_redis_write(failing_redis_op(), timeout=5.0)

    @pytest.mark.asyncio
    async def test_returns_none_when_operation_returns_none(self) -> None:
        """Test that None results are properly returned."""

        async def none_returning_op():
            return None

        result = await timed_redis_write(none_returning_op(), timeout=5.0)
        assert result is None


class TestGetRetryDelay:
    """Tests for get_retry_delay() exponential backoff helper."""

    def test_exponential_backoff_sequence(self) -> None:
        """Test that delays follow exponential backoff pattern."""
        delays = [get_retry_delay(i) for i in range(6)]
        assert delays == [1.0, 2.0, 4.0, 8.0, 10.0, 10.0]

    def test_respects_max_delay_cap(self) -> None:
        """Test that delay is capped at max_delay."""
        # With default max_delay=10, attempt 4+ should be capped
        assert get_retry_delay(4) == 10.0
        assert get_retry_delay(10) == 10.0
        assert get_retry_delay(100) == 10.0

    def test_custom_base_delay(self) -> None:
        """Test that custom base_delay is used."""
        delays = [get_retry_delay(i, base_delay=0.5) for i in range(4)]
        assert delays == [0.5, 1.0, 2.0, 4.0]

    def test_custom_max_delay(self) -> None:
        """Test that custom max_delay is respected."""
        delays = [get_retry_delay(i, base_delay=1.0, max_delay=5.0) for i in range(6)]
        assert delays == [1.0, 2.0, 4.0, 5.0, 5.0, 5.0]

    def test_both_custom_params(self) -> None:
        """Test with both custom base_delay and max_delay."""
        delays = [get_retry_delay(i, base_delay=0.5, max_delay=3.0) for i in range(6)]
        assert delays == [0.5, 1.0, 2.0, 3.0, 3.0, 3.0]

    def test_first_attempt_equals_base_delay(self) -> None:
        """Test that attempt 0 returns base_delay (2^0 = 1)."""
        assert get_retry_delay(0, base_delay=2.0) == 2.0
        assert get_retry_delay(0, base_delay=0.1) == 0.1
