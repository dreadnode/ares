"""Tests for Redis client helpers."""

from __future__ import annotations

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
