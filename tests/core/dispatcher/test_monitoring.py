"""Tests for dispatcher monitoring module.

Tests for Redis connection health checking and reconnection logic.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestPingOrReconnectDispatcherRedis:
    """Tests for _ping_or_reconnect_dispatcher_redis method."""

    @pytest.fixture
    def mock_dispatcher(self):
        """Create a mock dispatcher with monitoring mixin attributes."""
        from ares.core.dispatcher.monitoring import MonitoringMixin

        # Create a class that includes the mixin
        class MockDispatcher(MonitoringMixin):
            def __init__(self):
                self._redis_client = None
                self._redis_url = "redis://localhost:6379"
                self._shared_state = None
                self._context_offloader = None

        return MockDispatcher()

    @pytest.mark.asyncio
    async def test_returns_true_when_no_client(self, mock_dispatcher):
        """Test that True is returned when no Redis client is configured."""
        mock_dispatcher._redis_client = None

        result = await mock_dispatcher._ping_or_reconnect_dispatcher_redis()

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_true_on_successful_ping(self, mock_dispatcher):
        """Test that True is returned when ping succeeds."""
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(return_value=True)
        mock_dispatcher._redis_client = mock_client

        result = await mock_dispatcher._ping_or_reconnect_dispatcher_redis()

        assert result is True
        mock_client.ping.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_false_after_reconnection(self, mock_dispatcher):
        """Test that False is returned after successful reconnection."""
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(side_effect=ConnectionError("Connection lost"))
        mock_client.aclose = AsyncMock()
        mock_dispatcher._redis_client = mock_client

        new_client = AsyncMock()
        new_client.ping = AsyncMock(return_value=True)

        with patch(
            "ares.core.redis_client.create_redis_client",
            new=AsyncMock(return_value=new_client),
        ):
            result = await mock_dispatcher._ping_or_reconnect_dispatcher_redis()

        assert result is False
        mock_client.aclose.assert_awaited_once()
        assert mock_dispatcher._redis_client is new_client

    @pytest.mark.asyncio
    async def test_updates_state_backend_on_reconnect(self, mock_dispatcher):
        """Test that state backend is updated with new client on reconnect."""
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(side_effect=ConnectionError("Connection lost"))
        mock_client.aclose = AsyncMock()
        mock_dispatcher._redis_client = mock_client

        # Set up shared state with a backend
        mock_backend = MagicMock()
        mock_shared_state = MagicMock()
        mock_shared_state.operation_id = "op-123"
        mock_shared_state._backend = mock_backend
        mock_shared_state.set_backend = MagicMock()
        mock_dispatcher._shared_state = mock_shared_state

        new_client = AsyncMock()
        new_client.ping = AsyncMock(return_value=True)

        with (
            patch(
                "ares.core.redis_client.create_redis_client",
                new=AsyncMock(return_value=new_client),
            ),
            patch("ares.core.state_backend.RedisStateBackend") as mock_backend_class,
        ):
            mock_new_backend = MagicMock()
            mock_backend_class.return_value = mock_new_backend

            await mock_dispatcher._ping_or_reconnect_dispatcher_redis()

        mock_backend_class.assert_called_once_with(new_client, "op-123")
        mock_shared_state.set_backend.assert_called_once_with(mock_new_backend)

    @pytest.mark.asyncio
    async def test_updates_context_offloader_on_reconnect(self, mock_dispatcher):
        """Test that context offloader is updated with new client on reconnect."""
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(side_effect=ConnectionError("Connection lost"))
        mock_client.aclose = AsyncMock()
        mock_dispatcher._redis_client = mock_client

        # Set up context offloader
        mock_offloader = MagicMock()
        mock_offloader._redis = mock_client
        mock_dispatcher._context_offloader = mock_offloader

        new_client = AsyncMock()
        new_client.ping = AsyncMock(return_value=True)

        with (
            patch(
                "ares.core.redis_client.create_redis_client",
                new=AsyncMock(return_value=new_client),
            ),
        ):
            await mock_dispatcher._ping_or_reconnect_dispatcher_redis()

        assert mock_offloader._redis is new_client

    @pytest.mark.asyncio
    async def test_raises_on_reconnection_failure(self, mock_dispatcher):
        """Test that exception is raised when reconnection fails."""
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(side_effect=ConnectionError("Connection lost"))
        mock_client.aclose = AsyncMock()
        mock_dispatcher._redis_client = mock_client

        with (
            patch(
                "ares.core.redis_client.create_redis_client",
                new=AsyncMock(side_effect=ConnectionError("Failed to reconnect")),
            ),
            pytest.raises(ConnectionError, match="Failed to reconnect"),
        ):
            await mock_dispatcher._ping_or_reconnect_dispatcher_redis()

    @pytest.mark.asyncio
    async def test_handles_timeout_on_ping(self, mock_dispatcher):
        """Test that ping timeout triggers reconnection."""
        mock_client = AsyncMock()

        async def slow_ping():
            await asyncio.sleep(10)  # Would timeout
            return True

        mock_client.ping = slow_ping
        mock_client.aclose = AsyncMock()
        mock_dispatcher._redis_client = mock_client

        new_client = AsyncMock()
        new_client.ping = AsyncMock(return_value=True)

        with (
            patch(
                "ares.core.redis_client.create_redis_client",
                new=AsyncMock(return_value=new_client),
            ),
        ):
            # Use a short timeout to trigger the timeout path
            result = await mock_dispatcher._ping_or_reconnect_dispatcher_redis(timeout=0.01)

        assert result is False
        assert mock_dispatcher._redis_client is new_client

    @pytest.mark.asyncio
    async def test_handles_aclose_failure_gracefully(self, mock_dispatcher):
        """Test that aclose failure doesn't prevent reconnection."""
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(side_effect=ConnectionError("Connection lost"))
        mock_client.aclose = AsyncMock(side_effect=Exception("Close failed"))
        mock_dispatcher._redis_client = mock_client

        new_client = AsyncMock()
        new_client.ping = AsyncMock(return_value=True)

        with (
            patch(
                "ares.core.redis_client.create_redis_client",
                new=AsyncMock(return_value=new_client),
            ),
        ):
            # Should not raise despite aclose failure
            result = await mock_dispatcher._ping_or_reconnect_dispatcher_redis()

        assert result is False
        assert mock_dispatcher._redis_client is new_client


class TestMaintenanceLoopRedisHealthCheck:
    """Tests for Redis health checking in maintenance loop."""

    @pytest.fixture
    def mock_dispatcher(self):
        """Create a mock dispatcher for maintenance loop testing."""
        from ares.core.dispatcher.monitoring import MonitoringMixin

        class MockDispatcher(MonitoringMixin):
            def __init__(self):
                self._running = True
                self._redis_client = AsyncMock()
                self._redis_url = "redis://localhost:6379"
                self._shared_state = MagicMock()
                self._shared_state.pending_tasks = {}
                self._task_queue = AsyncMock()
                self._context_offloader = None
                self._checkpoint_requested = MagicMock()
                self._checkpoint_requested.is_set = MagicMock(return_value=False)
                self._credential_access_requested = MagicMock()
                self._credential_access_requested.is_set = MagicMock(return_value=False)
                self._deferred_task_requested = MagicMock()
                self._deferred_task_requested.is_set = MagicMock(return_value=False)
                self._dispatch_requested = MagicMock()
                self._dispatch_requested.is_set = MagicMock(return_value=False)
                self._agents = {}

            async def _cleanup_stale_tasks(self):
                pass

            async def _reconcile_tasks_with_workers(self):
                pass

            async def _log_throttle_health(self):
                pass

            async def _checkpoint(self):
                pass

            def signal_credential_access(self):
                pass

            async def _process_pending_deferred_tasks(self):
                pass

            async def _process_pending_dispatches(self):
                pass

        return MockDispatcher()

    @pytest.mark.asyncio
    async def test_maintenance_loop_checks_both_redis_clients(self, mock_dispatcher):
        """Test that maintenance loop checks both task queue and dispatcher Redis clients."""
        mock_dispatcher._task_queue.ping_or_reconnect = AsyncMock(return_value=True)

        ping_calls = []

        async def track_ping(timeout=5.0):
            ping_calls.append("dispatcher")
            return True

        mock_dispatcher._ping_or_reconnect_dispatcher_redis = track_ping

        # Run one iteration of the maintenance loop
        iteration_count = 0

        async def limited_sleep(duration):
            nonlocal iteration_count
            iteration_count += 1
            if iteration_count >= 1:
                mock_dispatcher._running = False

        with (
            patch("asyncio.sleep", side_effect=limited_sleep),
            patch("time.monotonic", return_value=1000.0),
        ):
            await mock_dispatcher._maintenance_loop()

        # Both should have been checked
        mock_dispatcher._task_queue.ping_or_reconnect.assert_awaited()
        assert "dispatcher" in ping_calls


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
