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
        mock_client.get = AsyncMock(return_value=recent_checkpoint_time)

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
            if "old-op" in key:
                return older_time
            if "new-op" in key:
                return newer_time
            return None

        mock_client.get = mock_get

        with redis_patch:
            result = await discover_active_operation("redis://localhost:6379", max_wait=5)

        assert result == "new-op"

    @pytest.mark.asyncio
    async def test_ignores_stale_operations(self, mock_redis_setup, stale_checkpoint_time):
        """Test that stale operations are ignored."""
        from ares.core.worker import discover_active_operation

        mock_client, redis_patch = mock_redis_setup
        mock_client.get = AsyncMock(return_value=stale_checkpoint_time)

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

        monkeypatch.delenv("ARES_AGENT_ENUM_MODEL", raising=False)
        monkeypatch.delenv("ARES_WORKER_MODEL", raising=False)
        monkeypatch.delenv("ARES_MODEL", raising=False)

        with (
            patch(
                "ares.core.worker.get_operation_model_overrides", new=AsyncMock(return_value=None)
            ),
            patch("ares.core.worker.get_operation_model", new=AsyncMock(return_value=None)),
            patch("ares.core.worker.logger") as mock_logger,
        ):
            result = await run_worker(
                role=AgentRole.ENUM,
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
        from ares.core import worker as worker_module

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

        await worker_module.run_worker(
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
        mock_client.get = AsyncMock(return_value=recent_time)

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
        mock_client.get = AsyncMock(return_value=recent_time)

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
        mock_client.get = AsyncMock(return_value=recent_time)

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
        mock_client.get = AsyncMock(return_value=naive_time)

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
        mock_client.get = AsyncMock(return_value=aware_time)

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
        mock_client.get = AsyncMock(return_value=recent_time)

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
                with patch("ares.core.worker.random.uniform", return_value=0.5):
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
        mock_client.get = AsyncMock(return_value=recent_time)

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
                with patch("ares.core.worker.random.uniform", return_value=0.5):
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
        mock_client.get = AsyncMock(return_value=recent_time)

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
                with patch("ares.core.worker.random.uniform", return_value=0.5):
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
        mock_client.get = AsyncMock(return_value=recent_time)

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
        mock_client.get = AsyncMock(return_value=recent_time)

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
                with patch("ares.core.worker.random.uniform", return_value=0.0):
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
