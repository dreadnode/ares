"""Tests for KubernetesPodExecutor utilities."""

from __future__ import annotations

import base64
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ares.core.k8s_executor import KubernetesPodExecutor, PodNotAvailableError


async def _noop() -> None:
    return None


@pytest.mark.asyncio
async def test_get_pod_for_role_uses_cache_when_running():
    executor = KubernetesPodExecutor()
    executor._pod_cache = {"recon": "pod-1"}
    executor._v1 = MagicMock()
    executor._v1.read_namespaced_pod.return_value = SimpleNamespace(
        status=SimpleNamespace(phase="Running")
    )
    executor._ensure_initialized = _noop

    pod_name = await executor.get_pod_for_role("recon")

    assert pod_name == "pod-1"
    executor._v1.list_namespaced_pod.assert_not_called()


@pytest.mark.asyncio
async def test_get_pod_for_role_recovers_from_stale_cache():
    executor = KubernetesPodExecutor()
    executor._pod_cache = {"recon": "pod-stale"}
    executor._v1 = MagicMock()
    executor._v1.read_namespaced_pod.side_effect = Exception("gone")
    executor._v1.list_namespaced_pod.return_value = SimpleNamespace(
        items=[SimpleNamespace(metadata=SimpleNamespace(name="pod-2"))]
    )
    executor._ensure_initialized = _noop

    pod_name = await executor.get_pod_for_role("recon")

    assert pod_name == "pod-2"
    assert executor._pod_cache["recon"] == "pod-2"


@pytest.mark.asyncio
async def test_execute_converts_string_and_retries_on_failure():
    executor = KubernetesPodExecutor()
    executor._ensure_initialized = _noop
    executor._pod_cache = {"recon": "pod-1"}

    calls = {"pod": 0, "exec": []}

    async def fake_get_pod_for_role(_role: str) -> str | None:
        calls["pod"] += 1
        return "pod-1" if calls["pod"] == 1 else "pod-2"

    async def fake_execute_in_pod(**kwargs):
        calls["exec"].append(kwargs)
        if len(calls["exec"]) == 1:
            raise RuntimeError("boom")
        return ("ok", "", 0)

    executor.get_pod_for_role = fake_get_pod_for_role
    executor._execute_in_pod = fake_execute_in_pod

    stdout, stderr, code = await executor.execute("recon", "echo hi")

    assert (stdout, stderr, code) == ("ok", "", 0)
    assert calls["exec"][0]["command"] == ["/bin/bash", "-c", "echo hi"]
    assert len(calls["exec"]) == 2


@pytest.mark.asyncio
async def test_execute_raises_when_no_pod():
    executor = KubernetesPodExecutor()
    executor._ensure_initialized = _noop

    async def fake_get_pod_for_role(_role: str) -> str | None:
        return None

    executor.get_pod_for_role = fake_get_pod_for_role

    with pytest.raises(PodNotAvailableError):
        await executor.execute("recon", ["echo", "hi"])


@pytest.mark.asyncio
async def test_copy_to_pod_success(tmp_path):
    executor = KubernetesPodExecutor()
    executor._ensure_initialized = _noop

    local_path = tmp_path / "payload.bin"
    local_path.write_bytes(b"hello")

    captured = {}

    async def fake_execute(_role, command, *_args, **_kwargs):
        captured["command"] = command
        return ("", "", 0)

    executor.execute = fake_execute

    async def fake_get_pod_for_role(_role: str) -> str:
        return "pod-1"

    executor.get_pod_for_role = fake_get_pod_for_role

    result = await executor.copy_to_pod("recon", str(local_path), "/tmp/payload.bin")

    assert result is True
    encoded = base64.b64encode(b"hello").decode()
    assert encoded in captured["command"][-1]
    assert "/tmp/payload.bin" in captured["command"][-1]


@pytest.mark.asyncio
async def test_copy_to_pod_failure_on_nonzero(tmp_path):
    executor = KubernetesPodExecutor()
    executor._ensure_initialized = _noop

    local_path = tmp_path / "payload.bin"
    local_path.write_bytes(b"hello")

    async def fake_execute(_role, _command, *_args, **_kwargs):
        return ("", "bad", 1)

    executor.execute = fake_execute

    async def fake_get_pod_for_role(_role: str) -> str:
        return "pod-1"

    executor.get_pod_for_role = fake_get_pod_for_role

    result = await executor.copy_to_pod("recon", str(local_path), "/tmp/payload.bin")

    assert result is False


@pytest.mark.asyncio
async def test_copy_from_pod_success(tmp_path):
    executor = KubernetesPodExecutor()
    executor._ensure_initialized = _noop

    local_path = tmp_path / "out.bin"
    payload = b"payload"
    encoded = base64.b64encode(payload).decode()

    async def fake_execute(_role, _command, *_args, **_kwargs):
        return (encoded, "", 0)

    executor.execute = fake_execute

    result = await executor.copy_from_pod("recon", "/tmp/remote.bin", str(local_path))

    assert result is True
    assert local_path.read_bytes() == payload


@pytest.mark.asyncio
async def test_copy_from_pod_failure_on_nonzero(tmp_path):
    executor = KubernetesPodExecutor()
    executor._ensure_initialized = _noop

    local_path = tmp_path / "out.bin"

    async def fake_execute(_role, _command, *_args, **_kwargs):
        return ("", "bad", 1)

    executor.execute = fake_execute

    result = await executor.copy_from_pod("recon", "/tmp/remote.bin", str(local_path))

    assert result is False


@pytest.mark.asyncio
async def test_list_pods_by_role_groups_by_label():
    executor = KubernetesPodExecutor()
    executor._v1 = MagicMock()
    executor._ensure_initialized = _noop

    executor._v1.list_namespaced_pod.return_value = SimpleNamespace(
        items=[
            SimpleNamespace(
                metadata=SimpleNamespace(
                    name="pod-1",
                    labels={"ares.dreadnode.io/role": "recon"},
                )
            ),
            SimpleNamespace(
                metadata=SimpleNamespace(
                    name="pod-2",
                    labels={"ares.dreadnode.io/role": "recon"},
                )
            ),
            SimpleNamespace(
                metadata=SimpleNamespace(
                    name="pod-3",
                    labels={"ares.dreadnode.io/role": "acl"},
                )
            ),
        ]
    )

    result = await executor.list_pods_by_role()

    assert result == {"recon": ["pod-1", "pod-2"], "acl": ["pod-3"]}
