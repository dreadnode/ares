"""Tests for worker module.

Tests the discover_active_operation function and related worker utilities.
"""

# ruff: noqa: SIM117

from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.exceptions import (
    AuthenticationError,
    ConfigurationError,
    CriticalWorkerError,
)
from ares.core.models import AgentRole

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_redis_setup():
    """Create a complete mock redis setup for testing discover_active_operation.

    Returns a tuple of (mock_client, patch_context_manager) where:
    - mock_client: The mock Redis client to configure
    - patch_context_manager: A context manager that patches sys.modules
    """
    mock_client = AsyncMock()
    mock_client.ping = AsyncMock(return_value=True)
    mock_client.get = AsyncMock(return_value=None)
    mock_client.aclose = AsyncMock()

    mock_redis_async = MagicMock()
    mock_redis_async.from_url = MagicMock(return_value=mock_client)

    mock_redis = MagicMock()
    mock_redis.asyncio = mock_redis_async

    return mock_client, patch.dict(
        sys.modules, {"redis": mock_redis, "redis.asyncio": mock_redis_async}
    )


@pytest.fixture
def recent_checkpoint_time() -> str:
    """Return a recent checkpoint time (within max_operation_age)."""
    recent = datetime.now(timezone.utc) - timedelta(seconds=60)
    return recent.isoformat()


@pytest.fixture
def stale_checkpoint_time() -> str:
    """Return a stale checkpoint time (older than max_operation_age)."""
    stale = datetime.now(timezone.utc) - timedelta(seconds=600)
    return stale.isoformat()


# ============================================================================
# discover_active_operation Tests
# ============================================================================


class TestDiscoverActiveOperationFindsOperation:
    """Tests for successfully discovering operations."""

    @pytest.mark.asyncio
    async def test_finds_operation_immediately(self, mock_redis_setup, recent_checkpoint_time):
        """Test discovering an operation on first scan."""
        from ares.core.worker import discover_active_operation

        mock_client, redis_patch = mock_redis_setup

        # Mock get to return None for pointer key, checkpoint time for checkpoint keys
        async def mock_get(key):
            if key == "ares:operation:active":
                return None
            if ":checkpoint_time" in key:
                return recent_checkpoint_time
            return None

        mock_client.get = mock_get
        mock_client.exists = AsyncMock(return_value=True)

        async def mock_scan_iter(pattern):
            yield "ares:operation:test-op-001:state"

        mock_client.scan_iter = mock_scan_iter

        with redis_patch:
            result = await discover_active_operation("redis://localhost:6379", max_wait=5)

        assert result == "test-op-001"

    @pytest.mark.asyncio
    async def test_finds_most_recent_operation(self, mock_redis_setup):
        """Test returning the most recently checkpointed operation."""
        from ares.core.worker import discover_active_operation

        mock_client, redis_patch = mock_redis_setup

        now = datetime.now(timezone.utc)
        older_time = (now - timedelta(seconds=120)).isoformat()
        newer_time = (now - timedelta(seconds=30)).isoformat()

        async def mock_scan_iter(pattern):
            yield "ares:operation:old-op:state"
            yield "ares:operation:new-op:state"

        mock_client.scan_iter = mock_scan_iter

        async def mock_get(key):
            if key == "ares:operation:active":
                return None
            if "old-op" in key:
                return older_time
            if "new-op" in key:
                return newer_time
            return None

        mock_client.get = mock_get
        mock_client.exists = AsyncMock(return_value=True)

        with redis_patch:
            result = await discover_active_operation("redis://localhost:6379", max_wait=5)

        assert result == "new-op"

    @pytest.mark.asyncio
    async def test_ignores_stale_operations(self, mock_redis_setup, stale_checkpoint_time):
        """Test that stale operations are ignored."""
        from ares.core.worker import discover_active_operation

        mock_client, redis_patch = mock_redis_setup

        async def mock_get(key):
            if key == "ares:operation:active":
                return None
            if ":checkpoint_time" in key:
                return stale_checkpoint_time
            return None

        mock_client.get = mock_get
        mock_client.exists = AsyncMock(return_value=True)

        async def mock_scan_iter(pattern):
            yield "ares:operation:stale-op:state"

        mock_client.scan_iter = mock_scan_iter

        with redis_patch:
            result = await discover_active_operation(
                "redis://localhost:6379",
                max_wait=1,
                max_operation_age=300,
            )

        assert result is None


class TestDiscoverActiveOperationTimeout:
    """Tests for timeout behavior."""

    @pytest.mark.asyncio
    async def test_returns_none_after_timeout(self, mock_redis_setup):
        """Test that function returns None after max_wait is exceeded."""
        from ares.core.worker import discover_active_operation

        mock_client, redis_patch = mock_redis_setup

        async def mock_scan_iter(pattern):
            return
            yield  # Make it a generator that yields nothing

        mock_client.scan_iter = mock_scan_iter

        with redis_patch, patch("asyncio.sleep", new_callable=AsyncMock):
            start_time = 1000.0
            call_count = 0

            def mock_monotonic():
                nonlocal call_count
                result = start_time + (call_count * 5)
                call_count += 1
                return result

            with patch("time.monotonic", side_effect=mock_monotonic):
                result = await discover_active_operation("redis://localhost:6379", max_wait=2)

        assert result is None


class TestRunWorkerModelResolution:
    """Tests for model resolution in run_worker."""

    @pytest.mark.asyncio
    async def test_run_worker_requires_model(self, monkeypatch):
        """Test that run_worker returns early when no model is configured."""
        from ares.core.worker import run_worker

        monkeypatch.delenv("ARES_AGENT_RECON_MODEL", raising=False)
        monkeypatch.delenv("ARES_WORKER_MODEL", raising=False)
        monkeypatch.delenv("ARES_MODEL", raising=False)

        with (
            patch(
                "ares.core.worker._worker.get_operation_model_overrides",
                new=AsyncMock(return_value=None),
            ),
            patch("ares.core.worker._worker.get_operation_model", new=AsyncMock(return_value=None)),
            patch("ares.core.worker._worker.logger") as mock_logger,
        ):
            result = await run_worker(
                role=AgentRole.RECON,
                operation_id="op-1",
                discover_operation=False,
            )

        assert result is None
        mock_logger.error.assert_called_once()

    @pytest.mark.asyncio
    async def test_timeout_respects_max_wait_value(self, mock_redis_setup):
        """Test that different max_wait values are respected."""
        from ares.core.worker import discover_active_operation

        mock_client, redis_patch = mock_redis_setup

        async def mock_scan_iter(pattern):
            return
            yield

        mock_client.scan_iter = mock_scan_iter

        with redis_patch, patch("asyncio.sleep", new_callable=AsyncMock):
            call_count = 0
            start_time = 1000.0

            def mock_monotonic():
                nonlocal call_count
                result = start_time + (call_count * 15)
                call_count += 1
                return result

            with patch("time.monotonic", side_effect=mock_monotonic):
                result = await discover_active_operation("redis://localhost:6379", max_wait=10)

        assert result is None


class TestRunWorkerCallbacks:
    """Tests for role-specific callback tools in run_worker."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("role", "callback_attr"),
        [
            (AgentRole.CRACKER, "CrackerCallbackTools"),
            (AgentRole.LATERAL, "LateralCallbackTools"),
        ],
    )
    async def test_run_worker_adds_role_callback_tools(self, monkeypatch, role, callback_attr):
        from ares.core.worker import _worker as worker_module
        from ares.core.worker import run_worker

        created: dict[str, MagicMock] = {}

        class DummyCallback:
            def __init__(self) -> None:
                self.set_dispatcher = MagicMock()
                created["instance"] = self

        monkeypatch.setenv("ARES_MODEL", "test-model")

        shared_state = MagicMock()
        dispatcher = MagicMock(shared_state=shared_state)
        dispatcher.start = AsyncMock()
        dispatcher.recover_state = AsyncMock(return_value=None)
        dispatcher.register = AsyncMock()
        dispatcher.stop = AsyncMock()

        agent_info = MagicMock()
        agent_info.name = "agent-name"

        monkeypatch.setattr(worker_module, "RedTeamDispatcher", lambda **_kwargs: dispatcher)
        monkeypatch.setattr(
            worker_module, "create_agent_info", lambda *_args, **_kwargs: agent_info
        )
        monkeypatch.setattr(worker_module, callback_attr, DummyCallback)
        monkeypatch.setattr(
            worker_module, "get_operation_model_overrides", AsyncMock(return_value=None)
        )
        monkeypatch.setattr(worker_module, "get_operation_model", AsyncMock(return_value=None))

        create_agent_mock = MagicMock()
        monkeypatch.setattr(worker_module, "create_specialized_agent", create_agent_mock)

        worker_instance = MagicMock()
        worker_instance.start = AsyncMock()
        monkeypatch.setattr(worker_module, "WorkerAgent", MagicMock(return_value=worker_instance))

        await run_worker(
            role=role,
            operation_id="op-1",
            discover_operation=False,
            use_redis_queue=False,
        )

        created["instance"].set_dispatcher.assert_called_once_with(dispatcher)
        _, kwargs = create_agent_mock.call_args
        assert created["instance"] in kwargs["additional_tools"]


class TestDiscoverActiveOperationIndefiniteWait:
    """Tests for indefinite wait behavior when max_wait is None."""

    @pytest.mark.asyncio
    async def test_waits_indefinitely_until_operation_found(self, mock_redis_setup):
        """Test that function waits indefinitely until an operation is found."""
        from ares.core.worker import discover_active_operation

        mock_client, redis_patch = mock_redis_setup

        now = datetime.now(timezone.utc)
        recent_time = (now - timedelta(seconds=30)).isoformat()

        async def mock_get(key):
            if key == "ares:operation:active":
                return None
            if ":checkpoint_time" in key:
                return recent_time
            return None

        mock_client.get = mock_get
        mock_client.exists = AsyncMock(return_value=True)

        iteration_count = 0

        async def mock_scan_iter(pattern):
            nonlocal iteration_count
            iteration_count += 1
            if iteration_count >= 3:
                yield "ares:operation:found-op:state"

        mock_client.scan_iter = mock_scan_iter

        with redis_patch, patch("asyncio.sleep", new_callable=AsyncMock):
            with patch("time.monotonic", return_value=1000.0):
                result = await discover_active_operation("redis://localhost:6379", max_wait=None)

        assert result == "found-op"
        assert iteration_count >= 3

    @pytest.mark.asyncio
    async def test_max_wait_none_does_not_timeout(self, mock_redis_setup):
        """Test that max_wait=None never triggers timeout logic."""
        from ares.core.worker import discover_active_operation

        mock_client, redis_patch = mock_redis_setup

        now = datetime.now(timezone.utc)
        recent_time = (now - timedelta(seconds=30)).isoformat()

        async def mock_get(key):
            if key == "ares:operation:active":
                return None
            if ":checkpoint_time" in key:
                return recent_time
            return None

        mock_client.get = mock_get
        mock_client.exists = AsyncMock(return_value=True)

        iteration_count = 0
        max_iterations = 5

        async def mock_scan_iter(pattern):
            nonlocal iteration_count
            iteration_count += 1
            if iteration_count >= max_iterations:
                yield "ares:operation:test-op:state"

        mock_client.scan_iter = mock_scan_iter

        with redis_patch, patch("asyncio.sleep", new_callable=AsyncMock):
            call_count = 0

            def mock_monotonic():
                nonlocal call_count
                call_count += 1
                # Simulate hours passing - should not matter with max_wait=None
                return 1000.0 + (call_count * 3600)

            with patch("time.monotonic", side_effect=mock_monotonic):
                result = await discover_active_operation("redis://localhost:6379", max_wait=None)

        assert result == "test-op"


class TestDiscoverActiveOperationErrorHandling:
    """Tests for error handling in discover_active_operation."""

    @pytest.mark.asyncio
    async def test_handles_redis_connection_error(self, mock_redis_setup):
        """Test graceful handling of Redis connection errors."""
        from ares.core.worker import discover_active_operation

        mock_client, redis_patch = mock_redis_setup

        now = datetime.now(timezone.utc)
        recent_time = (now - timedelta(seconds=30)).isoformat()

        async def mock_get(key):
            if key == "ares:operation:active":
                return None
            if ":checkpoint_time" in key:
                return recent_time
            return None

        mock_client.get = mock_get
        mock_client.exists = AsyncMock(return_value=True)

        error_count = 0

        async def mock_scan_iter(pattern):
            nonlocal error_count
            error_count += 1
            if error_count < 3:
                raise ConnectionError("Redis connection failed")
            yield "ares:operation:recovered-op:state"

        mock_client.scan_iter = mock_scan_iter

        with redis_patch, patch("asyncio.sleep", new_callable=AsyncMock):
            with patch("time.monotonic", return_value=1000.0):
                result = await discover_active_operation("redis://localhost:6379", max_wait=None)

        assert result == "recovered-op"

    @pytest.mark.asyncio
    async def test_returns_none_when_redis_import_fails(self):
        """Test returns None when redis package import fails."""
        from ares.core.worker import discover_active_operation

        with patch.dict(sys.modules, {"redis": None, "redis.asyncio": None}):
            result = await discover_active_operation("redis://localhost:6379", max_wait=1)

        assert result is None


class TestDiscoverActiveOperationTimezoneHandling:
    """Tests for timezone handling in checkpoint times."""

    @pytest.mark.asyncio
    async def test_handles_naive_datetime_checkpoint(self, mock_redis_setup):
        """Test handling of naive (no timezone) checkpoint times."""
        from ares.core.worker import discover_active_operation

        mock_client, redis_patch = mock_redis_setup

        # Create a naive datetime that will be treated as UTC by the code
        # The code does: checkpoint_time.replace(tzinfo=timezone.utc)
        # So we need to create a naive time that's recent in UTC terms
        now_utc = datetime.now(timezone.utc)
        naive_time = now_utc.replace(tzinfo=None).isoformat()

        async def mock_get(key):
            if key == "ares:operation:active":
                return None
            if ":checkpoint_time" in key:
                return naive_time
            return None

        mock_client.get = mock_get
        mock_client.exists = AsyncMock(return_value=True)

        async def mock_scan_iter(pattern):
            yield "ares:operation:naive-tz-op:state"

        mock_client.scan_iter = mock_scan_iter

        with redis_patch:
            result = await discover_active_operation("redis://localhost:6379", max_wait=5)

        assert result == "naive-tz-op"

    @pytest.mark.asyncio
    async def test_handles_aware_datetime_checkpoint(self, mock_redis_setup):
        """Test handling of timezone-aware checkpoint times."""
        from ares.core.worker import discover_active_operation

        mock_client, redis_patch = mock_redis_setup

        # Create an aware datetime with explicit UTC timezone
        aware_time = datetime.now(timezone.utc).isoformat()

        async def mock_get(key):
            if key == "ares:operation:active":
                return None
            if ":checkpoint_time" in key:
                return aware_time
            return None

        mock_client.get = mock_get
        mock_client.exists = AsyncMock(return_value=True)

        async def mock_scan_iter(pattern):
            yield "ares:operation:aware-tz-op:state"

        mock_client.scan_iter = mock_scan_iter

        with redis_patch:
            result = await discover_active_operation("redis://localhost:6379", max_wait=5)

        assert result == "aware-tz-op"


class TestDiscoverActiveOperationCancellation:
    """Tests for graceful cancellation handling."""

    @pytest.mark.asyncio
    async def test_cancellation_cleans_up_resources(self, mock_redis_setup):
        """Test that CancelledError triggers proper cleanup."""
        from ares.core.worker import discover_active_operation

        mock_client, redis_patch = mock_redis_setup

        async def mock_scan_iter(pattern):
            return
            yield

        mock_client.scan_iter = mock_scan_iter

        sleep_called = asyncio.Event()
        real_sleep = asyncio.sleep

        async def mock_sleep(delay):
            sleep_called.set()
            await real_sleep(delay)

        with redis_patch, patch("time.monotonic", return_value=1000.0):
            with patch("asyncio.sleep", side_effect=mock_sleep):
                task = asyncio.create_task(
                    discover_active_operation("redis://localhost:6379", max_wait=None)
                )

                # Wait until we're in the sleep call
                await asyncio.wait_for(sleep_called.wait(), timeout=1.0)

                # Cancel it
                task.cancel()

                with pytest.raises(asyncio.CancelledError):
                    await task

                # Verify cleanup was called (in finally block)
                mock_client.aclose.assert_called()

    @pytest.mark.asyncio
    async def test_cancellation_during_sleep_propagates(self, mock_redis_setup):
        """Test that cancellation during sleep is handled properly."""
        from ares.core.worker import discover_active_operation

        mock_client, redis_patch = mock_redis_setup

        async def mock_scan_iter(pattern):
            return
            yield

        mock_client.scan_iter = mock_scan_iter

        sleep_called = asyncio.Event()
        real_sleep = asyncio.sleep

        async def mock_sleep(delay):
            sleep_called.set()
            # Actually wait so we can be cancelled
            await real_sleep(delay)

        with redis_patch, patch("time.monotonic", return_value=1000.0):
            with patch("asyncio.sleep", side_effect=mock_sleep):
                task = asyncio.create_task(
                    discover_active_operation("redis://localhost:6379", max_wait=None)
                )

                # Wait until we're actually in the sleep
                await asyncio.wait_for(sleep_called.wait(), timeout=1.0)

                # Cancel
                task.cancel()

                # Should raise CancelledError
                with pytest.raises(asyncio.CancelledError):
                    await task


class TestDiscoverActiveOperationExponentialBackoff:
    """Tests for exponential backoff on errors."""

    @pytest.mark.asyncio
    async def test_backoff_increases_on_consecutive_errors(self, mock_redis_setup):
        """Test that backoff delay increases with consecutive errors."""
        from ares.core.worker import discover_active_operation

        mock_client, redis_patch = mock_redis_setup

        now = datetime.now(timezone.utc)
        recent_time = (now - timedelta(seconds=30)).isoformat()

        async def mock_get(key):
            if key == "ares:operation:active":
                return None
            if ":checkpoint_time" in key:
                return recent_time
            return None

        mock_client.get = mock_get
        mock_client.exists = AsyncMock(return_value=True)

        error_count = 0
        sleep_delays = []

        async def mock_scan_iter(pattern):
            nonlocal error_count
            error_count += 1
            if error_count < 4:
                raise ConnectionError("Redis connection failed")
            yield "ares:operation:recovered-op:state"

        mock_client.scan_iter = mock_scan_iter

        async def capture_sleep(delay):
            sleep_delays.append(delay)
            # Don't actually sleep in tests

        with redis_patch, patch("asyncio.sleep", side_effect=capture_sleep):
            with patch("time.monotonic", return_value=1000.0):
                with patch("ares.core.worker._worker.random.uniform", return_value=0.5):
                    result = await discover_active_operation(
                        "redis://localhost:6379", max_wait=None
                    )

        assert result == "recovered-op"
        # Should have 3 error sleeps with exponential backoff
        # First error: 5 * 2^0 + 0.5 = 5.5
        # Second error: 5 * 2^1 + 0.5 = 10.5
        # Third error: 5 * 2^2 + 0.5 = 20.5
        assert len(sleep_delays) >= 3
        assert sleep_delays[0] == pytest.approx(5.5, rel=0.1)
        assert sleep_delays[1] == pytest.approx(10.5, rel=0.1)
        assert sleep_delays[2] == pytest.approx(20.5, rel=0.1)

    @pytest.mark.asyncio
    async def test_backoff_caps_at_60_seconds(self, mock_redis_setup):
        """Test that backoff is capped at 60 seconds."""
        from ares.core.worker import discover_active_operation

        mock_client, redis_patch = mock_redis_setup

        now = datetime.now(timezone.utc)
        recent_time = (now - timedelta(seconds=30)).isoformat()

        async def mock_get(key):
            if key == "ares:operation:active":
                return None
            if ":checkpoint_time" in key:
                return recent_time
            return None

        mock_client.get = mock_get
        mock_client.exists = AsyncMock(return_value=True)

        error_count = 0
        sleep_delays = []

        async def mock_scan_iter(pattern):
            nonlocal error_count
            error_count += 1
            if error_count < 10:
                raise ConnectionError("Redis connection failed")
            yield "ares:operation:recovered-op:state"

        mock_client.scan_iter = mock_scan_iter

        async def capture_sleep(delay):
            sleep_delays.append(delay)

        with redis_patch, patch("asyncio.sleep", side_effect=capture_sleep):
            with patch("time.monotonic", return_value=1000.0):
                with patch("ares.core.worker._worker.random.uniform", return_value=0.5):
                    result = await discover_active_operation(
                        "redis://localhost:6379", max_wait=None
                    )

        assert result == "recovered-op"
        # Later delays should be capped at 60 + jitter (0.5)
        for delay in sleep_delays[4:]:  # After 4th error, should be capped
            assert delay <= 60.5

    @pytest.mark.asyncio
    async def test_backoff_resets_after_success(self, mock_redis_setup):
        """Test that error count resets after successful connection."""
        from ares.core.worker import discover_active_operation

        mock_client, redis_patch = mock_redis_setup

        now = datetime.now(timezone.utc)
        recent_time = (now - timedelta(seconds=30)).isoformat()

        async def mock_get(key):
            if key == "ares:operation:active":
                return None
            if ":checkpoint_time" in key:
                return recent_time
            return None

        mock_client.get = mock_get
        mock_client.exists = AsyncMock(return_value=True)

        call_count = 0
        sleep_delays = []

        async def mock_scan_iter(pattern):
            nonlocal call_count
            call_count += 1
            # First call errors, second succeeds but no ops, third errors, fourth finds op
            if call_count == 1:
                raise ConnectionError("Error 1")
            elif call_count == 2:
                return  # Success but no operations
                yield
            elif call_count == 3:
                raise ConnectionError("Error 2")
            else:
                yield "ares:operation:test-op:state"

        mock_client.scan_iter = mock_scan_iter

        async def capture_sleep(delay):
            sleep_delays.append(delay)

        with redis_patch, patch("asyncio.sleep", side_effect=capture_sleep):
            with patch("time.monotonic", return_value=1000.0):
                with patch("ares.core.worker._worker.random.uniform", return_value=0.5):
                    result = await discover_active_operation(
                        "redis://localhost:6379", max_wait=None
                    )

        assert result == "test-op"
        # First error: 5 + 0.5 = 5.5 (consecutive_errors=1)
        # Second iteration succeeds (no ops found), resets count, normal sleep of 10
        # Third error: 5 + 0.5 = 5.5 (consecutive_errors reset to 1)
        # Error backoff sleeps have jitter (5.5), normal polling is 10
        error_sleeps = [d for d in sleep_delays if d == pytest.approx(5.5, rel=0.1)]
        assert len(error_sleeps) == 2  # Two separate errors, each reset to backoff=1


class TestDiscoverActiveOperationConnectionReuse:
    """Tests for Redis connection reuse."""

    @pytest.mark.asyncio
    async def test_reuses_connection_on_success(self, mock_redis_setup):
        """Test that connection is reused across iterations when healthy."""
        from ares.core.worker import discover_active_operation

        mock_client, _redis_patch = mock_redis_setup

        now = datetime.now(timezone.utc)
        recent_time = (now - timedelta(seconds=30)).isoformat()

        async def mock_get(key):
            if key == "ares:operation:active":
                return None
            if ":checkpoint_time" in key:
                return recent_time
            return None

        mock_client.get = mock_get
        mock_client.exists = AsyncMock(return_value=True)

        iteration_count = 0

        async def mock_scan_iter(pattern):
            nonlocal iteration_count
            iteration_count += 1
            if iteration_count >= 3:
                yield "ares:operation:test-op:state"

        mock_client.scan_iter = mock_scan_iter

        mock_redis_async = MagicMock()
        mock_redis_async.from_url = MagicMock(return_value=mock_client)
        mock_redis = MagicMock()
        mock_redis.asyncio = mock_redis_async

        with (
            patch.dict(sys.modules, {"redis": mock_redis, "redis.asyncio": mock_redis_async}),
            patch("asyncio.sleep", new_callable=AsyncMock),
        ):
            with patch("time.monotonic", return_value=1000.0):
                result = await discover_active_operation("redis://localhost:6379", max_wait=None)

        assert result == "test-op"
        # Connection should only be created once (reused across iterations)
        assert mock_redis_async.from_url.call_count == 1

    @pytest.mark.asyncio
    async def test_reconnects_after_error(self, mock_redis_setup):
        """Test that connection is recreated after an error."""
        from ares.core.worker import discover_active_operation

        mock_client, _redis_patch = mock_redis_setup

        now = datetime.now(timezone.utc)
        recent_time = (now - timedelta(seconds=30)).isoformat()

        async def mock_get(key):
            if key == "ares:operation:active":
                return None
            if ":checkpoint_time" in key:
                return recent_time
            return None

        mock_client.get = mock_get
        mock_client.exists = AsyncMock(return_value=True)

        error_count = 0

        async def mock_scan_iter(pattern):
            nonlocal error_count
            error_count += 1
            if error_count == 1:
                raise ConnectionError("Connection lost")
            yield "ares:operation:test-op:state"

        mock_client.scan_iter = mock_scan_iter

        mock_redis_async = MagicMock()
        mock_redis_async.from_url = MagicMock(return_value=mock_client)
        mock_redis = MagicMock()
        mock_redis.asyncio = mock_redis_async

        with (
            patch.dict(sys.modules, {"redis": mock_redis, "redis.asyncio": mock_redis_async}),
            patch("asyncio.sleep", new_callable=AsyncMock),
        ):
            with patch("time.monotonic", return_value=1000.0):
                with patch("ares.core.worker._worker.random.uniform", return_value=0.0):
                    result = await discover_active_operation(
                        "redis://localhost:6379", max_wait=None
                    )

        assert result == "test-op"
        # Connection created initially, then recreated after error
        assert mock_redis_async.from_url.call_count == 2
        # Client should have been closed after error
        assert mock_client.aclose.call_count >= 1


class TestWorkerFatalErrorHandling:
    """Tests for fatal error handling in RedisWorkerAgent.

    Note: These tests verify error handling behavior conceptually.
    Full integration testing requires actual worker loop execution.
    """

    def test_authentication_error_hierarchy(self):
        """Test that AuthenticationError is properly defined."""
        # Verify the exception can be created and caught
        try:
            raise AuthenticationError("test", service="grafana", status_code=401)
        except AuthenticationError as e:
            assert e.service == "grafana"
            assert e.status_code == 401
            assert "grafana" in str(e)

    def test_configuration_error_hierarchy(self):
        """Test that ConfigurationError is properly defined."""
        try:
            raise ConfigurationError("Missing config")
        except ConfigurationError as e:
            assert str(e) == "Missing config"

    def test_critical_worker_error_hierarchy(self):
        """Test that CriticalWorkerError is properly defined."""
        try:
            raise CriticalWorkerError("Fatal error")
        except CriticalWorkerError as e:
            assert str(e) == "Fatal error"

    def test_fatal_exceptions_caught_by_ares_exception(self):
        """Test that all fatal errors can be caught as AresError."""
        from ares.core.exceptions import AresError

        fatal_errors = [
            AuthenticationError("test"),
            ConfigurationError("test"),
            CriticalWorkerError("test"),
        ]

        for error in fatal_errors:
            try:
                raise error
            except AresError:
                pass  # Successfully caught as base error


class TestGeneratePromptFromTaskTechniqueEnforcement:
    """Tests for technique enforcement in generate_prompt_from_task."""

    def test_generate_prompt_enforces_techniques_with_creds(self):
        """Test that techniques are enforced when credentials are provided."""
        from ares.core.models import Host, SharedRedTeamState, Target
        from ares.core.task_queue import TaskMessage
        from ares.core.worker import generate_prompt_from_task

        state = SharedRedTeamState(
            operation_id="op-enforce",
            target=Target(ip="192.168.58.100", domain="contoso.local"),
        )
        # Add a DC host
        dc = Host(ip="192.168.58.101", hostname="DC01", roles=["DC"])
        state.all_hosts.append(dc)

        task = TaskMessage(
            task_id="task-001",
            task_type="credential_access",
            source_agent="orchestrator",
            target_agent="credential_access",
            payload={
                "domain": "contoso.local",
                "username": "testuser",
                "password": "TestPass123",  # pragma: allowlist secret
                "techniques": ["sysvol_script_search", "gpp_password_finder"],
            },
        )

        prompt = generate_prompt_from_task(task, state)

        # Should contain technique instructions
        assert "sysvol_script_search" in prompt
        assert "gpp_password_finder" in prompt
        assert "credential" in prompt.lower()

    def test_generate_prompt_enforces_techniques_no_creds(self):
        """Test that no-cred techniques are enforced properly."""
        from ares.core.models import Host, SharedRedTeamState, Target
        from ares.core.task_queue import TaskMessage
        from ares.core.worker import generate_prompt_from_task

        state = SharedRedTeamState(
            operation_id="op-nocred",
            target=Target(ip="192.168.58.102", domain="contoso.local"),
        )
        dc = Host(ip="192.168.58.103", hostname="DC02", roles=["DC"])
        state.all_hosts.append(dc)

        task = TaskMessage(
            task_id="task-002",
            task_type="credential_access",
            source_agent="orchestrator",
            target_agent="credential_access",
            payload={
                "domain": "contoso.local",
                "techniques": ["asrep_roast", "username_as_password"],
            },
        )

        prompt = generate_prompt_from_task(task, state)

        # Should contain no-cred technique enforcement
        assert "MANDATORY TECHNIQUE EXECUTION (NO CREDENTIALS)" in prompt
        assert "asrep_roast" in prompt
        assert "username_as_password" in prompt

    def test_generate_prompt_technique_map_completeness(self):
        """Test that all common techniques have proper instructions."""
        from ares.core.models import Host, SharedRedTeamState, Target
        from ares.core.task_queue import TaskMessage
        from ares.core.worker import generate_prompt_from_task

        state = SharedRedTeamState(
            operation_id="op-complete",
            target=Target(ip="192.168.58.104", domain="contoso.local"),
        )
        dc = Host(ip="192.168.58.105", hostname="DC03", roles=["DC"])
        state.all_hosts.append(dc)

        # Test with-creds techniques
        with_cred_techniques = [
            "sysvol_script_search",
            "gpp_password_finder",
            "ldap_search_descriptions",
            "kerberoast",
            "secretsdump",
            "lsassy",
            "laps_dump",
        ]

        for technique in with_cred_techniques:
            task = TaskMessage(
                task_id=f"task-{technique}",
                task_type="credential_access",
                source_agent="orchestrator",
                target_agent="credential_access",
                payload={
                    "domain": "contoso.local",
                    "username": "user",
                    "password": "pass",  # pragma: allowlist secret
                    "techniques": [technique],
                },
            )

            prompt = generate_prompt_from_task(task, state)

            # Each technique should appear in the prompt with instructions
            assert technique in prompt.lower(), f"Technique {technique} not in prompt"
            assert "credential" in prompt.lower()

    def test_generate_prompt_preserves_task_id(self):
        """Test that task ID is included in enforced technique prompts."""
        from ares.core.models import Host, SharedRedTeamState, Target
        from ares.core.task_queue import TaskMessage
        from ares.core.worker import generate_prompt_from_task

        state = SharedRedTeamState(
            operation_id="op-taskid",
            target=Target(ip="192.168.58.106", domain="contoso.local"),
        )
        dc = Host(ip="192.168.58.107", hostname="DC04", roles=["DC"])
        state.all_hosts.append(dc)

        task = TaskMessage(
            task_id="task-special-123",
            task_type="credential_access",
            source_agent="orchestrator",
            target_agent="credential_access",
            payload={
                "domain": "contoso.local",
                "username": "user",
                "password": "pass",  # pragma: allowlist secret
                "techniques": ["kerberoast"],
            },
        )

        prompt = generate_prompt_from_task(task, state)

        # Task ID should be in the prompt
        assert "task-special-123" in prompt

    def test_generate_prompt_fallback_without_techniques(self):
        """Test that prompt generation works when no explicit techniques are provided."""
        from ares.core.models import Host, SharedRedTeamState, Target
        from ares.core.task_queue import TaskMessage
        from ares.core.worker import generate_prompt_from_task

        state = SharedRedTeamState(
            operation_id="op-fallback",
            target=Target(ip="192.168.58.108", domain="contoso.local"),
        )
        dc = Host(ip="192.168.58.109", hostname="DC05", roles=["DC"])
        state.all_hosts.append(dc)

        task = TaskMessage(
            task_id="task-no-tech",
            task_type="credential_access",
            source_agent="orchestrator",
            target_agent="credential_access",
            payload={
                "domain": "contoso.local",
                "username": "user",
                "password": "pass",  # pragma: allowlist secret
                # No techniques specified
            },
        )

        prompt = generate_prompt_from_task(task, state)

        # Should generate a valid prompt even without techniques
        assert len(prompt) > 0
        assert "credential access" in prompt.lower()

    def test_generate_prompt_handles_hash_credentials(self):
        """Test that technique enforcement works with hash credentials (PTH)."""
        from ares.core.models import Host, SharedRedTeamState, Target
        from ares.core.task_queue import TaskMessage
        from ares.core.worker import generate_prompt_from_task

        state = SharedRedTeamState(
            operation_id="op-hash",
            target=Target(ip="192.168.58.110", domain="contoso.local"),
        )
        dc = Host(ip="192.168.58.111", hostname="DC06", roles=["DC"])
        state.all_hosts.append(dc)

        task = TaskMessage(
            task_id="task-hash",
            task_type="credential_access",
            source_agent="orchestrator",
            target_agent="credential_access",
            payload={
                "domain": "contoso.local",
                "username": "admin",
                "hash_value": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                "hash_type": "ntlm",
                "techniques": ["secretsdump"],
            },
        )

        prompt = generate_prompt_from_task(task, state)

        # Should enforce techniques with hash credential
        assert "MANDATORY TECHNIQUE EXECUTION" in prompt
        assert "secretsdump" in prompt
        assert "hashes=" in prompt  # Should use hash parameter

    def test_generate_prompt_handles_privesc_enumeration(self):
        """Test that privesc_enumeration task type generates correct prompt."""
        from ares.core.models import Host, SharedRedTeamState, Target
        from ares.core.task_queue import TaskMessage
        from ares.core.worker import generate_prompt_from_task

        state = SharedRedTeamState(
            operation_id="op-privesc-enum",
            target=Target(ip="192.168.58.10", domain="contoso.local"),
        )
        # Add DC to state
        dc = Host(
            ip="192.168.58.240",
            hostname="dc01.contoso.local",
            roles=["DC"],
            services=["389/tcp ldap", "88/tcp kerberos"],
        )
        state.all_hosts.append(dc)

        task = TaskMessage(
            task_id="task-privesc-enum-001",
            task_type="privesc_enumeration",
            source_agent="orchestrator",
            target_agent="privesc",
            payload={
                "domain": "contoso.local",
                "dc_ip": "192.168.58.240",
                "username": "testuser",
                "password": "P@ssw0rd!",  # pragma: allowlist secret
                "techniques": ["find_delegation"],
            },
        )

        prompt = generate_prompt_from_task(task, state)

        # Verify prompt structure
        assert "Run privilege escalation enumeration:" in prompt
        assert "Domain: contoso.local" in prompt
        assert "DC IP: 192.168.58.240" in prompt
        assert "Username: testuser" in prompt
        assert "Password: P@ssw0rd!" in prompt  # pragma: allowlist secret
        assert "Task ID: task-privesc-enum-001" in prompt

        # Verify technique instructions
        assert "EXECUTE THESE ENUMERATION TECHNIQUES:" in prompt
        assert "find_delegation" in prompt
        assert "Find accounts with Kerberos delegation" in prompt

        # Verify workflow instructions
        assert "WORKFLOW:" in prompt
        assert "Execute each enumeration technique" in prompt
        assert "CONSTRAINED DELEGATION" in prompt

    def test_generate_prompt_handles_multiple_privesc_techniques(self):
        """Test that privesc_enumeration supports multiple techniques."""
        from ares.core.models import Host, SharedRedTeamState, Target
        from ares.core.task_queue import TaskMessage
        from ares.core.worker import generate_prompt_from_task

        state = SharedRedTeamState(
            operation_id="op-privesc-multi",
            target=Target(ip="192.168.58.10", domain="contoso.local"),
        )
        dc = Host(
            ip="192.168.58.240",
            hostname="dc01.contoso.local",
            roles=["DC"],
        )
        state.all_hosts.append(dc)

        task = TaskMessage(
            task_id="task-privesc-enum-002",
            task_type="privesc_enumeration",
            source_agent="orchestrator",
            target_agent="privesc",
            payload={
                "domain": "contoso.local",
                "dc_ip": "192.168.58.240",
                "username": "admin",
                "password": "AdminP@ss!",  # pragma: allowlist secret
                "techniques": ["find_delegation", "find_trusts"],
            },
        )

        prompt = generate_prompt_from_task(task, state)

        # Verify both techniques are included
        assert "1. find_delegation" in prompt
        assert "2. find_trusts" in prompt or "find_trusts(...)" in prompt


class TestUpdateEtcHosts:
    """Tests for _update_etc_hosts function."""

    def test_update_etc_hosts_adds_fqdn_and_short_name(self, tmp_path):
        """Test that /etc/hosts entries include both FQDN and short hostname."""
        from ares.core.models import Host
        from ares.core.worker._worker import _update_etc_hosts

        # Create a temp hosts file
        hosts_file = tmp_path / "hosts"
        hosts_file.write_text("127.0.0.1 localhost\n")

        hosts_list = [
            Host(ip="192.168.58.50", hostname="web01.contoso.local"),
        ]

        with patch("builtins.open", create=True) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file

            result = _update_etc_hosts(hosts_list, set(), "test-agent")

        # Should have written the entry
        assert "192.168.58.50" in result
        calls = mock_file.write.call_args_list
        written = "".join(call[0][0] for call in calls)
        # Non-DC: just FQDN and short name
        assert "192.168.58.50  web01.contoso.local web01\n" in written

    def test_update_etc_hosts_adds_domain_for_dc(self, tmp_path):
        """Test that domain controllers get domain alias on the same line."""
        from ares.core.models import Host
        from ares.core.worker._worker import _update_etc_hosts

        hosts_list = [
            Host(
                ip="192.168.58.10",
                hostname="dc01.contoso.local",
                is_dc=True,
            ),
        ]

        with patch("builtins.open", create=True) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file

            result = _update_etc_hosts(hosts_list, set(), "test-agent")

        assert "192.168.58.10" in result
        calls = mock_file.write.call_args_list
        written = "".join(call[0][0] for call in calls)
        # DC: FQDN, short name, and domain all on one line
        assert "192.168.58.10  dc01.contoso.local dc01 contoso.local\n" in written

    def test_update_etc_hosts_skips_already_written(self):
        """Test that already-written IPs are skipped."""
        from ares.core.models import Host
        from ares.core.worker._worker import _update_etc_hosts

        hosts_list = [
            Host(ip="192.168.58.10", hostname="dc01.contoso.local"),
        ]

        # IP already in written set
        written_ips = {"192.168.58.10"}

        with patch("builtins.open", create=True) as mock_open:
            result = _update_etc_hosts(hosts_list, written_ips, "test-agent")

        # open should not be called since all hosts are already written
        mock_open.assert_not_called()
        assert result == {"192.168.58.10"}

    def test_update_etc_hosts_skips_hosts_without_hostname(self):
        """Test that hosts without hostnames are skipped."""
        from ares.core.models import Host
        from ares.core.worker._worker import _update_etc_hosts

        hosts_list = [
            Host(ip="192.168.58.10", hostname=""),  # No hostname
            Host(ip="192.168.58.20", hostname="sql01.contoso.local"),
        ]

        with patch("builtins.open", create=True) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file

            result = _update_etc_hosts(hosts_list, set(), "test-agent")

        # Only the host with a hostname should be written
        assert "192.168.58.10" not in result
        assert "192.168.58.20" in result
        calls = mock_file.write.call_args_list
        written = "".join(call[0][0] for call in calls)
        assert "192.168.58.10" not in written
        assert "192.168.58.20  sql01.contoso.local sql01\n" in written

    def test_update_etc_hosts_multiple_dcs_each_get_domain(self):
        """Test that each DC gets its own domain alias on its line."""
        from ares.core.models import Host
        from ares.core.worker._worker import _update_etc_hosts

        hosts_list = [
            Host(
                ip="192.168.58.10",
                hostname="dc01.contoso.local",
                is_dc=True,
            ),
            Host(
                ip="192.168.58.11",
                hostname="dc02.contoso.local",
                is_dc=True,
            ),
        ]

        with patch("builtins.open", create=True) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file

            result = _update_etc_hosts(hosts_list, set(), "test-agent")

        assert "192.168.58.10" in result
        assert "192.168.58.11" in result
        calls = mock_file.write.call_args_list
        written = "".join(call[0][0] for call in calls)
        # Each DC line has the domain alias
        assert "192.168.58.10  dc01.contoso.local dc01 contoso.local\n" in written
        assert "192.168.58.11  dc02.contoso.local dc02 contoso.local\n" in written

    def test_update_etc_hosts_handles_permission_error(self):
        """Test graceful handling of permission errors."""
        from ares.core.models import Host
        from ares.core.worker._worker import _update_etc_hosts

        hosts_list = [
            Host(ip="192.168.58.30", hostname="web01.contoso.local"),
        ]

        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            # Should not raise, just log warning
            result = _update_etc_hosts(hosts_list, set(), "test-agent")

        # IP should still be marked as "written" to avoid repeated attempts
        assert "192.168.58.30" in result

    def test_update_etc_hosts_handles_child_domain(self):
        """Test proper handling of child domains (multi-level FQDNs)."""
        from ares.core.models import Host
        from ares.core.worker._worker import _update_etc_hosts

        hosts_list = [
            Host(
                ip="192.168.58.100",
                hostname="dc01.child.contoso.local",
                is_dc=True,
            ),
        ]

        with patch("builtins.open", create=True) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file

            _update_etc_hosts(hosts_list, set(), "test-agent")

        calls = mock_file.write.call_args_list
        written = "".join(call[0][0] for call in calls)
        # DC with child domain: FQDN, short name, child domain all on one line
        assert "192.168.58.100  dc01.child.contoso.local dc01 child.contoso.local\n" in written


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
