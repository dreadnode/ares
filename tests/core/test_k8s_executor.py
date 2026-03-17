"""Tests for KubernetesPodExecutor utilities."""

from __future__ import annotations

import base64
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ares.core.k8s_executor import (
    KubernetesPodExecutor,
    PodExecutionError,
    PodNotAvailableError,
)


async def _noop() -> None:
    return None


@pytest.mark.asyncio
async def test_get_pod_for_role_uses_cache_when_running():
    """Test cached running pod is returned without listing pods."""
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
    """Test stale cached pods are cleared and rediscovered."""
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
async def test_get_pod_for_role_returns_none_when_no_pods_found():
    """Test pod lookup returns None when Kubernetes reports no running pods."""
    executor = KubernetesPodExecutor()
    executor._v1 = MagicMock()
    executor._v1.list_namespaced_pod.return_value = SimpleNamespace(items=[])
    executor._ensure_initialized = _noop

    pod_name = await executor.get_pod_for_role("acl")

    assert pod_name is None


@pytest.mark.asyncio
async def test_execute_converts_string_and_retries_on_failure():
    """Test string commands are shell wrapped and retried after a failed exec."""
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
    """Test execute raises PodNotAvailableError when discovery fails."""
    executor = KubernetesPodExecutor()
    executor._ensure_initialized = _noop

    async def fake_get_pod_for_role(_role: str) -> str | None:
        return None

    executor.get_pod_for_role = fake_get_pod_for_role

    with pytest.raises(PodNotAvailableError):
        await executor.execute("recon", ["echo", "hi"])


@pytest.mark.asyncio
async def test_execute_wraps_retry_failure_as_pod_execution_error():
    """Test execute raises PodExecutionError when retry also fails."""
    executor = KubernetesPodExecutor()
    executor._ensure_initialized = _noop
    executor._pod_cache = {"recon": "pod-1"}

    async def fake_get_pod_for_role(_role: str) -> str | None:
        return "pod-1"

    async def fake_execute_in_pod(**_kwargs):
        raise RuntimeError("still broken")

    executor.get_pod_for_role = fake_get_pod_for_role
    executor._execute_in_pod = fake_execute_in_pod

    with pytest.raises(PodExecutionError, match="still broken"):
        await executor.execute("recon", ["echo", "hi"])


@pytest.mark.asyncio
async def test_wait_for_pod_returns_true_when_pod_becomes_available(monkeypatch):
    """Test wait_for_pod returns True as soon as a pod is discovered."""
    executor = KubernetesPodExecutor()
    executor._ensure_initialized = _noop

    pod_results = iter([None, "pod-1"])

    async def fake_get_pod_for_role(_role: str) -> str | None:
        return next(pod_results)

    sleep_mock = AsyncMock()
    executor.get_pod_for_role = fake_get_pod_for_role
    monkeypatch.setattr("ares.core.k8s_executor.asyncio.sleep", sleep_mock)

    result = await executor.wait_for_pod("recon", timeout=5)

    assert result is True
    sleep_mock.assert_awaited_once_with(2)


@pytest.mark.asyncio
async def test_wait_for_all_pods_marks_failed_role_when_wait_raises():
    """Test wait_for_all_pods records False for roles whose wait raises."""
    executor = KubernetesPodExecutor()

    async def fake_wait_for_pod(role: str, timeout: int) -> bool:
        if role == "acl":
            raise RuntimeError("unavailable")
        return True

    executor.wait_for_pod = fake_wait_for_pod

    results = await executor.wait_for_all_pods(["recon", "acl"], timeout=1)

    assert results == {"recon": True, "acl": False}


@pytest.mark.asyncio
async def test_copy_to_pod_success(tmp_path):
    """Test local files are base64 encoded and copied into a pod."""
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
    """Test copy_to_pod returns False when the pod command fails."""
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
async def test_copy_to_pod_returns_false_when_file_read_fails(tmp_path):
    """Test copy_to_pod handles missing local files gracefully."""
    executor = KubernetesPodExecutor()
    executor._ensure_initialized = _noop

    async def fake_get_pod_for_role(_role: str) -> str:
        return "pod-1"

    executor.get_pod_for_role = fake_get_pod_for_role

    result = await executor.copy_to_pod("recon", str(tmp_path / "missing.bin"), "/tmp/x")

    assert result is False


@pytest.mark.asyncio
async def test_copy_from_pod_success(tmp_path):
    """Test copy_from_pod decodes base64 content to a local file."""
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
    """Test copy_from_pod returns False when remote read fails."""
    executor = KubernetesPodExecutor()
    executor._ensure_initialized = _noop

    local_path = tmp_path / "out.bin"

    async def fake_execute(_role, _command, *_args, **_kwargs):
        return ("", "bad", 1)

    executor.execute = fake_execute

    result = await executor.copy_from_pod("recon", "/tmp/remote.bin", str(local_path))

    assert result is False


@pytest.mark.asyncio
async def test_copy_from_pod_returns_false_on_invalid_base64(tmp_path):
    """Test copy_from_pod handles invalid base64 payloads gracefully."""
    executor = KubernetesPodExecutor()
    executor._ensure_initialized = _noop

    local_path = tmp_path / "out.bin"

    async def fake_execute(_role, _command, *_args, **_kwargs):
        return ("not-base64", "", 0)

    executor.execute = fake_execute

    result = await executor.copy_from_pod("recon", "/tmp/remote.bin", str(local_path))

    assert result is False


@pytest.mark.asyncio
async def test_get_pod_logs_reads_logs_for_discovered_pod():
    """Test get_pod_logs proxies log retrieval parameters to Kubernetes."""
    executor = KubernetesPodExecutor()
    executor._ensure_initialized = _noop
    executor._v1 = MagicMock()
    executor._v1.read_namespaced_pod_log.return_value = "log line"

    async def fake_get_pod_for_role(_role: str) -> str:
        return "pod-logs"

    executor.get_pod_for_role = fake_get_pod_for_role

    result = await executor.get_pod_logs("recon", tail_lines=5, since_seconds=60)

    assert result == "log line"
    executor._v1.read_namespaced_pod_log.assert_called_once_with(
        name="pod-logs",
        namespace=executor.namespace,
        tail_lines=5,
        since_seconds=60,
    )


@pytest.mark.asyncio
async def test_list_pods_by_role_groups_by_label():
    """Test list_pods_by_role groups Kubernetes pods by role label."""
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


def test_clear_cache_removes_all_cached_pods():
    """Test clear_cache empties the in-memory pod cache."""
    executor = KubernetesPodExecutor()
    executor._pod_cache = {"recon": "pod-1", "acl": "pod-2"}

    executor.clear_cache()

    assert executor._pod_cache == {}
