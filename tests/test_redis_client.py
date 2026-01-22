"""Tests for Redis client helpers."""

from __future__ import annotations

import sys
import types
from typing import Any
from unittest.mock import MagicMock

import pytest

from ares.core.redis_client import create_redis_client, get_redis_sentinel_config


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

    def master_for(self, master: str, **kwargs: Any):
        self.master = master
        self.master_kwargs = kwargs
        return "sentinel-client"


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
        "host": "sentinel",
        "port": 26379,
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
        "host": "sentinel",
        "port": 6380,
        "master": "mymaster",
        "sentinel_password": "sentinel-pass",  # pragma: allowlist secret
        "redis_password": "redis-pass",  # pragma: allowlist secret
        "db": 2,
    }


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
        "socket_timeout": None,
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
