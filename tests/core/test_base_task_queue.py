"""Tests for BaseTaskQueue shared functionality."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.base_task_queue import BaseTaskQueue


class ConcreteTaskQueue(BaseTaskQueue):
    """Concrete implementation for testing the abstract base class."""

    def _result_queue_key(self, task_id: str) -> str:
        return f"test:results:{task_id}"

    def _heartbeat_key(self, agent_name: str) -> str:
        return f"test:heartbeat:{agent_name}"


class TestBaseTaskQueueInit:
    """Tests for BaseTaskQueue initialization."""

    def test_init_with_redis_url(self):
        """Test initialization with explicit Redis URL."""
        queue = ConcreteTaskQueue(redis_url="redis://custom:6379")

        assert queue.redis_url == "redis://custom:6379"
        assert queue._client is None
        assert queue._connected is False

    def test_init_without_redis_url_uses_config(self):
        """Test initialization uses config when URL not provided."""
        with patch("ares.core.base_task_queue.get_redis_url") as mock_get_url:
            mock_get_url.return_value = "redis://config:6379"
            queue = ConcreteTaskQueue()

            assert queue.redis_url == "redis://config:6379"

    def test_heartbeat_ttl_minimum(self):
        """Test heartbeat TTL is at least HEARTBEAT_TTL."""
        with patch("ares.core.base_task_queue.get_agent_heartbeat_timeout") as mock_timeout:
            mock_timeout.return_value = 10  # Would give 20s, but minimum is 60s
            queue = ConcreteTaskQueue()

            assert queue._heartbeat_ttl >= BaseTaskQueue.HEARTBEAT_TTL

    def test_heartbeat_ttl_scales_with_timeout(self):
        """Test heartbeat TTL scales with agent heartbeat timeout."""
        with patch("ares.core.base_task_queue.get_agent_heartbeat_timeout") as mock_timeout:
            mock_timeout.return_value = 60  # Would give 120s
            queue = ConcreteTaskQueue()

            assert queue._heartbeat_ttl == 120


class TestRedisProperty:
    """Tests for the redis property."""

    def test_redis_property_returns_client(self):
        """Test redis property returns the client when connected."""
        queue = ConcreteTaskQueue()
        mock_client = MagicMock()
        queue._client = mock_client

        assert queue.redis is mock_client

    def test_redis_property_raises_when_not_connected(self):
        """Test redis property raises when not connected."""
        queue = ConcreteTaskQueue()

        with pytest.raises(RuntimeError, match="Not connected to Redis"):
            _ = queue.redis


class TestConnect:
    """Tests for connect method."""

    @pytest.mark.asyncio
    async def test_connect_success(self):
        """Test successful connection."""
        queue = ConcreteTaskQueue(redis_url="redis://localhost:6379")

        mock_client = AsyncMock()
        mock_client.ping = AsyncMock()

        with patch("ares.core.base_task_queue.create_redis_client") as mock_create:
            mock_create.return_value = mock_client
            await queue.connect()

        assert queue._connected is True
        assert queue._client is mock_client
        mock_client.ping.assert_called_once()

    @pytest.mark.asyncio
    async def test_connect_already_connected_skips(self):
        """Test connect does nothing when already connected."""
        queue = ConcreteTaskQueue()
        queue._connected = True
        queue._client = MagicMock()

        with patch("ares.core.base_task_queue.create_redis_client") as mock_create:
            await queue.connect()

        mock_create.assert_not_called()

    @pytest.mark.asyncio
    async def test_connect_uses_direct_connection_in_non_main_thread(self):
        """Test connect uses direct connection when not in main thread."""
        queue = ConcreteTaskQueue(redis_url="redis://localhost:6379")

        mock_client = AsyncMock()
        mock_client.ping = AsyncMock()

        with (
            patch("ares.core.base_task_queue.create_redis_client") as mock_create,
            patch("ares.core.base_task_queue.threading") as mock_threading,
        ):
            # Simulate being in a non-main thread
            mock_threading.current_thread.return_value = MagicMock()
            mock_threading.main_thread.return_value = MagicMock()  # Different object
            mock_create.return_value = mock_client

            await queue.connect()

        # Should pass direct_connection=True
        mock_create.assert_called_once()
        call_kwargs = mock_create.call_args[1]
        assert call_kwargs["direct_connection"] is True

    @pytest.mark.asyncio
    async def test_connect_failure_raises_runtime_error(self):
        """Test connect raises RuntimeError on failure."""
        queue = ConcreteTaskQueue(redis_url="redis://localhost:6379")

        with patch("ares.core.base_task_queue.create_redis_client") as mock_create:
            mock_create.side_effect = Exception("Connection failed")

            with pytest.raises(RuntimeError, match="Failed to connect to Redis"):
                await queue.connect()


class TestDisconnect:
    """Tests for disconnect method."""

    @pytest.mark.asyncio
    async def test_disconnect_closes_client(self):
        """Test disconnect closes the Redis client."""
        queue = ConcreteTaskQueue()
        mock_client = AsyncMock()
        queue._client = mock_client
        queue._connected = True

        await queue.disconnect()

        mock_client.aclose.assert_called_once()
        assert queue._connected is False

    @pytest.mark.asyncio
    async def test_disconnect_with_no_client(self):
        """Test disconnect does nothing when client is None."""
        queue = ConcreteTaskQueue()
        queue._client = None

        # Should not raise
        await queue.disconnect()


class TestPingOrReconnect:
    """Tests for ping_or_reconnect method."""

    @pytest.mark.asyncio
    async def test_ping_success_returns_true(self):
        """Test ping_or_reconnect returns True on successful ping."""
        queue = ConcreteTaskQueue()
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock()
        queue._client = mock_client
        queue._connected = True

        result = await queue.ping_or_reconnect()

        assert result is True
        mock_client.ping.assert_called_once()

    @pytest.mark.asyncio
    async def test_ping_failure_triggers_reconnect(self):
        """Test ping_or_reconnect reconnects on ping failure."""
        queue = ConcreteTaskQueue(redis_url="redis://localhost:6379")
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(side_effect=ConnectionError("Lost connection"))
        mock_client.aclose = AsyncMock()
        queue._client = mock_client
        queue._connected = True

        new_client = AsyncMock()
        new_client.ping = AsyncMock()

        with (
            patch("ares.core.base_task_queue.invalidate_sentinel_client") as mock_invalidate,
            patch("ares.core.base_task_queue.create_redis_client") as mock_create,
        ):
            mock_create.return_value = new_client

            result = await queue.ping_or_reconnect()

        assert result is False  # Returns False when reconnection was needed
        mock_invalidate.assert_called_once()
        mock_client.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_ping_without_client_connects(self):
        """Test ping_or_reconnect connects when no client exists."""
        queue = ConcreteTaskQueue(redis_url="redis://localhost:6379")
        queue._client = None

        mock_client = AsyncMock()
        mock_client.ping = AsyncMock()

        with patch("ares.core.base_task_queue.create_redis_client") as mock_create:
            mock_create.return_value = mock_client

            result = await queue.ping_or_reconnect()

        assert result is False  # Connection was established, not ping success
        assert queue._connected is True


class TestHandleConnectionError:
    """Tests for _handle_connection_error method."""

    def test_handle_connection_error_resets_state(self):
        """Test _handle_connection_error resets connection state."""
        queue = ConcreteTaskQueue()
        mock_client = MagicMock()
        queue._client = mock_client
        queue._connected = True

        queue._handle_connection_error(ConnectionError("Lost connection"))

        assert queue._connected is False
        assert queue._client is None

    def test_handle_connection_error_logs_warning(self):
        """Test _handle_connection_error logs a warning."""
        queue = ConcreteTaskQueue()
        queue._connected = True

        with patch("ares.core.base_task_queue.logger") as mock_logger:
            queue._handle_connection_error(ConnectionError("Connection reset"))

            mock_logger.warning.assert_called_once()
            call_args = mock_logger.warning.call_args[0][0]
            assert "Redis connection error" in call_args


class TestAbstractMethods:
    """Tests for abstract method implementations."""

    def test_result_queue_key(self):
        """Test _result_queue_key returns correct key."""
        queue = ConcreteTaskQueue()

        assert queue._result_queue_key("task-123") == "test:results:task-123"
        assert queue._result_queue_key("task-456") == "test:results:task-456"

    def test_heartbeat_key(self):
        """Test _heartbeat_key returns correct key."""
        queue = ConcreteTaskQueue()

        assert queue._heartbeat_key("agent-1") == "test:heartbeat:agent-1"
        assert queue._heartbeat_key("worker-pod") == "test:heartbeat:worker-pod"


class TestConstants:
    """Tests for class constants."""

    def test_result_ttl(self):
        """Test RESULT_TTL is 24 hours."""
        assert BaseTaskQueue.RESULT_TTL == 86400

    def test_heartbeat_ttl(self):
        """Test HEARTBEAT_TTL is 60 seconds."""
        assert BaseTaskQueue.HEARTBEAT_TTL == 60
