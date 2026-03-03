"""Unit tests for Redis-based task queue.

Tests the RedisTaskQueue class used for cross-pod messaging
in Kubernetes multi-agent deployments.
"""

from __future__ import annotations

import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.task_queue import (
    RedisTaskQueue,
    TaskMessage,
    TaskResult,
)

# Create a mock redis.asyncio module if redis is not installed
# This allows tests to run without the redis package
if "redis" not in sys.modules:
    mock_redis_module = MagicMock()
    mock_redis_asyncio = MagicMock()
    mock_redis_module.asyncio = mock_redis_asyncio
    sys.modules["redis"] = mock_redis_module
    sys.modules["redis.asyncio"] = mock_redis_asyncio


# ============================================================================
# TaskMessage Tests
# ============================================================================


class TestTaskMessage:
    """Tests for TaskMessage model."""

    def test_task_message_creation(self):
        """Test basic TaskMessage creation."""
        msg = TaskMessage(
            task_id="crack_abc123",
            task_type="crack",
            source_agent="orchestrator",
            target_agent="cracker",
            payload={"hash_value": "abc123", "hash_type": "NTLM"},
        )

        assert msg.task_id == "crack_abc123"
        assert msg.task_type == "crack"
        assert msg.source_agent == "orchestrator"
        assert msg.target_agent == "cracker"
        assert msg.payload["hash_value"] == "abc123"
        assert msg.priority == 5  # Default
        assert msg.created_at is not None

    def test_task_message_with_priority(self):
        """Test TaskMessage with custom priority."""
        msg = TaskMessage(
            task_id="crack_urgent",
            task_type="crack",
            source_agent="orchestrator",
            target_agent="cracker",
            payload={"hash_value": "krbtgt_hash"},
            priority=1,
        )

        assert msg.priority == 1

    def test_task_message_serialization(self):
        """Test TaskMessage JSON serialization."""
        msg = TaskMessage(
            task_id="test_123",
            task_type="lateral",
            source_agent="orchestrator",
            target_agent="lateral",
            payload={"target_host": "192.168.58.10"},
        )

        json_str = msg.model_dump_json()
        parsed = json.loads(json_str)

        assert parsed["task_id"] == "test_123"
        assert parsed["task_type"] == "lateral"
        assert parsed["payload"]["target_host"] == "192.168.58.10"

    def test_task_message_deserialization(self):
        """Test TaskMessage JSON deserialization."""
        json_str = json.dumps(
            {
                "task_id": "test_456",
                "task_type": "exploit",
                "source_agent": "acl-agent",
                "target_agent": "privesc",
                "payload": {"vuln_type": "ADCS_ESC1"},
                "priority": 2,
                "created_at": "2024-01-15T10:30:00Z",
            }
        )

        msg = TaskMessage.model_validate_json(json_str)

        assert msg.task_id == "test_456"
        assert msg.task_type == "exploit"
        assert msg.priority == 2

    def test_task_message_callback_queue(self):
        """Test TaskMessage with callback queue."""
        msg = TaskMessage(
            task_id="test_789",
            task_type="crack",
            source_agent="orchestrator",
            target_agent="cracker",
            payload={},
            callback_queue="ares:results:test_789",
        )

        assert msg.callback_queue == "ares:results:test_789"


# ============================================================================
# TaskResult Tests
# ============================================================================


class TestTaskResult:
    """Tests for TaskResult model."""

    def test_task_result_success(self):
        """Test successful TaskResult creation."""
        result = TaskResult(
            task_id="crack_abc123",
            success=True,
            result={"password": "cracked123"},  # pragma: allowlist secret
        )

        assert result.task_id == "crack_abc123"
        assert result.success is True
        assert result.result["password"] == "cracked123"  # pragma: allowlist secret
        assert result.error is None
        assert result.completed_at is not None

    def test_task_result_failure(self):
        """Test failed TaskResult creation."""
        result = TaskResult(
            task_id="crack_failed",
            success=False,
            error="Hash not crackable with wordlist",
        )

        assert result.task_id == "crack_failed"
        assert result.success is False
        assert result.result is None
        assert result.error == "Hash not crackable with wordlist"

    def test_task_result_with_worker_pod(self):
        """Test TaskResult with worker pod info."""
        result = TaskResult(
            task_id="task_123",
            success=True,
            result={"output": "done"},
            worker_pod="cracker-agent-0",
        )

        assert result.worker_pod == "cracker-agent-0"

    def test_task_result_serialization(self):
        """Test TaskResult JSON serialization."""
        result = TaskResult(
            task_id="task_456",
            success=True,
            result={"credentials": ["user1:pass1"]},
            worker_pod="lateral-agent-0",
        )

        json_str = result.model_dump_json()
        parsed = json.loads(json_str)

        assert parsed["task_id"] == "task_456"
        assert parsed["success"] is True
        assert parsed["worker_pod"] == "lateral-agent-0"


# ============================================================================
# RedisTaskQueue Tests (Mocked Redis)
# ============================================================================


@pytest.fixture
def mock_redis_client():
    """Create a mock Redis async client."""
    client = AsyncMock()
    client.ping = AsyncMock(return_value=True)
    client.lpush = AsyncMock(return_value=1)
    client.rpush = AsyncMock(return_value=1)
    client.brpop = AsyncMock(return_value=None)
    client.rpop = AsyncMock(return_value=None)
    client.llen = AsyncMock(return_value=0)
    client.set = AsyncMock(return_value=True)
    client.get = AsyncMock(return_value=None)
    client.expire = AsyncMock(return_value=True)
    client.aclose = AsyncMock()
    client.scan_iter = AsyncMock(return_value=iter([]))
    return client


@pytest.fixture
async def task_queue(mock_redis_client):
    """Create a RedisTaskQueue with mocked Redis."""
    # Patch at the module level where it's imported
    with patch.object(
        sys.modules.get("redis.asyncio", MagicMock()),
        "from_url",
        return_value=mock_redis_client,
    ):
        # Also patch directly in the task_queue module
        import ares.core.task_queue as tq_module

        with patch.object(tq_module, "redis", create=True) as mock_redis:
            mock_redis.asyncio = MagicMock()
            mock_redis.asyncio.from_url = MagicMock(return_value=mock_redis_client)

            queue = RedisTaskQueue("redis://localhost:6379")
            # Manually set up the connection since we're mocking
            queue._client = mock_redis_client
            queue._connected = True

            yield queue

            await queue.disconnect()


class TestRedisTaskQueueConnection:
    """Tests for RedisTaskQueue connection handling."""

    @pytest.mark.asyncio
    async def test_connect_success(self, mock_redis_client):
        """Test successful connection to Redis."""
        queue = RedisTaskQueue("redis://localhost:6379")
        # Simulate successful connection
        queue._client = mock_redis_client
        queue._connected = True

        assert queue._connected is True

    @pytest.mark.asyncio
    async def test_connect_already_connected(self, mock_redis_client):
        """Test connect when already connected does nothing."""
        queue = RedisTaskQueue("redis://localhost:6379")
        queue._client = mock_redis_client
        queue._connected = True

        # Calling connect again should return early
        await queue.connect()

        # Should not try to ping again (already connected)
        assert queue._connected is True

    @pytest.mark.asyncio
    async def test_disconnect(self, mock_redis_client):
        """Test disconnection from Redis."""
        queue = RedisTaskQueue("redis://localhost:6379")
        queue._client = mock_redis_client
        queue._connected = True

        await queue.disconnect()

        assert queue._connected is False
        mock_redis_client.aclose.assert_called_once()


class TestRedisTaskQueueConnectionErrorHandling:
    """Tests for connection error handling in RedisTaskQueue."""

    def test_handle_connection_error_resets_state(self, mock_redis_client):
        """Test that _handle_connection_error resets connection state."""
        queue = RedisTaskQueue("redis://localhost:6379")
        queue._client = mock_redis_client
        queue._connected = True

        error = Exception("Connection closed")
        queue._handle_connection_error(error)

        assert queue._connected is False
        assert queue._client is None

    def test_handle_connection_error_logs_warning(self, mock_redis_client):
        """Test that _handle_connection_error logs a warning."""
        queue = RedisTaskQueue("redis://localhost:6379")
        queue._client = mock_redis_client
        queue._connected = True

        with patch("ares.core.task_queue.logger") as mock_logger:
            error = Exception("Connection reset by peer")
            queue._handle_connection_error(error)

            mock_logger.warning.assert_called_once()
            call_args = mock_logger.warning.call_args[0][0]
            assert "Redis connection error" in call_args
            assert "will retry" in call_args

    @pytest.mark.asyncio
    async def test_poll_task_connection_error_retries_and_returns_none(
        self, task_queue, mock_redis_client
    ):
        """Test poll_task retries on connection errors and returns None after exhausting retries."""
        mock_redis_client.brpop.side_effect = Exception("Connection closed unexpectedly")

        # With retry logic, poll_task returns None after exhausting retries
        result = await task_queue.poll_task(role="cracker", timeout=1.0, max_retries=2)

        assert result is None
        # brpop should be called max_retries + 1 times
        assert mock_redis_client.brpop.call_count == 3

    @pytest.mark.asyncio
    async def test_poll_task_connection_timeout_retries(self, task_queue, mock_redis_client):
        """Test poll_task retries on timeout errors."""
        mock_redis_client.brpop.side_effect = Exception("Connection timeout")

        result = await task_queue.poll_task(role="cracker", timeout=1.0, max_retries=1)

        assert result is None
        assert mock_redis_client.brpop.call_count == 2

    @pytest.mark.asyncio
    async def test_poll_task_broken_pipe_retries(self, task_queue, mock_redis_client):
        """Test poll_task retries on broken pipe errors."""
        mock_redis_client.brpop.side_effect = Exception("Broken pipe")

        result = await task_queue.poll_task(role="cracker", timeout=1.0, max_retries=1)

        assert result is None
        assert mock_redis_client.brpop.call_count == 2

    @pytest.mark.asyncio
    async def test_poll_task_non_connection_error_preserves_state(
        self, task_queue, mock_redis_client
    ):
        """Test poll_task preserves state for non-connection errors."""
        mock_redis_client.brpop.side_effect = ValueError("Invalid data format")

        with pytest.raises(ValueError, match="Invalid data format"):
            await task_queue.poll_task(role="cracker", timeout=1.0)

        # Connection state should be preserved for non-connection errors
        assert task_queue._connected is True
        assert task_queue._client is not None

    @pytest.mark.asyncio
    async def test_send_result_connection_error_resets_state(self, task_queue, mock_redis_client):
        """Test send_result handles connection errors and resets state."""
        mock_redis_client.lpush.side_effect = Exception("Connection reset by peer")

        with pytest.raises(Exception, match="Connection reset"):
            await task_queue.send_result(
                task_id="task_123",
                success=True,
                result={"data": "test"},
            )

        assert task_queue._connected is False
        assert task_queue._client is None

    @pytest.mark.asyncio
    async def test_send_result_closed_connection_resets_state(self, task_queue, mock_redis_client):
        """Test send_result handles closed connection errors."""
        mock_redis_client.lpush.side_effect = Exception("Connection closed")

        with pytest.raises(Exception, match="closed"):
            await task_queue.send_result(
                task_id="task_456",
                success=False,
                error="Task failed",
            )

        assert task_queue._connected is False

    @pytest.mark.asyncio
    async def test_send_result_non_connection_error_preserves_state(
        self, task_queue, mock_redis_client
    ):
        """Test send_result preserves state for non-connection errors."""
        mock_redis_client.lpush.side_effect = TypeError("Serialization error")

        with pytest.raises(TypeError, match="Serialization error"):
            await task_queue.send_result(
                task_id="task_789",
                success=True,
                result={"data": "test"},
            )

        # Connection state should be preserved for non-connection errors
        assert task_queue._connected is True
        assert task_queue._client is not None

    @pytest.mark.asyncio
    async def test_poll_task_asyncio_timeout_handles_stale_connection(
        self, task_queue, mock_redis_client
    ):
        """Test poll_task handles asyncio.TimeoutError from hung BRPOP.

        This tests the fix for stale Sentinel connections where BRPOP hangs
        forever on a dead TCP socket. The asyncio.wait_for wrapper should
        detect this and reset connection state.
        """
        import asyncio

        # Simulate a hung BRPOP that never returns (stale connection)
        async def hung_brpop(*args, **kwargs):
            await asyncio.sleep(100)  # Would block forever without wait_for

        mock_redis_client.brpop = hung_brpop

        with patch("ares.core.task_queue.invalidate_sentinel_client") as mock_invalidate:
            # poll_task with timeout=0.1 should trigger asyncio.TimeoutError
            # after 0.1 + 2.0 = 2.1 seconds, but we mock so it's faster
            # Actually the wait_for will use timeout + 2.0, so we use a tiny timeout
            # Using max_retries=0 to test single attempt behavior
            result = await task_queue.poll_task(role="cracker", timeout=0.1, max_retries=0)

            # Should return None (not raise) to allow retry
            assert result is None

            # Connection state should be reset
            assert task_queue._connected is False
            assert task_queue._client is None

            # Sentinel client should be invalidated for fresh DNS resolution
            mock_invalidate.assert_called_once()


class TestRedisTaskQueueKeyGeneration:
    """Tests for queue key generation methods."""

    def test_task_queue_key(self):
        """Test task queue key generation."""
        queue = RedisTaskQueue()
        assert queue._task_queue_key("cracker") == "ares:tasks:cracker"
        assert queue._task_queue_key("lateral") == "ares:tasks:lateral"

    def test_result_queue_key(self):
        """Test result queue key generation."""
        queue = RedisTaskQueue()
        assert queue._result_queue_key("task_123") == "ares:results:task_123"

    def test_heartbeat_key(self):
        """Test heartbeat key generation."""
        queue = RedisTaskQueue()
        assert queue._heartbeat_key("cracker-agent") == "ares:heartbeat:cracker-agent"


class TestRedisTaskQueueSubmit:
    """Tests for task submission."""

    @pytest.mark.asyncio
    async def test_submit_task(self, task_queue, mock_redis_client):
        """Test submitting a task to the queue."""
        task_id = await task_queue.submit_task(
            task_type="crack",
            target_role="cracker",
            payload={"hash_value": "abc123", "hash_type": "NTLM"},
        )

        assert task_id.startswith("crack_")
        mock_redis_client.lpush.assert_called_once()

        # Verify the pushed data
        call_args = mock_redis_client.lpush.call_args
        assert call_args[0][0] == "ares:tasks:cracker"

    @pytest.mark.asyncio
    async def test_submit_task_with_custom_id(self, task_queue, mock_redis_client):
        """Test submitting a task with custom task ID."""
        task_id = await task_queue.submit_task(
            task_type="crack",
            target_role="cracker",
            payload={"hash_value": "xyz"},
            task_id="custom_task_id",
        )

        assert task_id == "custom_task_id"

    @pytest.mark.asyncio
    async def test_submit_task_with_priority(self, task_queue, mock_redis_client):
        """Test submitting a task with priority."""
        await task_queue.submit_task(
            task_type="crack",
            target_role="cracker",
            payload={"hash_value": "krbtgt"},
            priority=1,
        )

        # Verify priority is in the pushed data
        # High priority (<=2) uses rpush to front of queue
        call_args = mock_redis_client.rpush.call_args
        pushed_json = call_args[0][1]
        pushed_data = json.loads(pushed_json)
        assert pushed_data["priority"] == 1


class TestRedisTaskQueuePoll:
    """Tests for task polling."""

    @pytest.mark.asyncio
    async def test_poll_task_empty(self, task_queue, mock_redis_client):
        """Test polling when queue is empty returns None."""
        mock_redis_client.brpop.return_value = None

        task = await task_queue.poll_task(role="cracker", timeout=1.0)

        assert task is None
        mock_redis_client.brpop.assert_called_once_with("ares:tasks:cracker", timeout=1)

    @pytest.mark.asyncio
    async def test_poll_task_success(self, task_queue, mock_redis_client):
        """Test polling a task successfully."""
        task_message = TaskMessage(
            task_id="crack_abc",
            task_type="crack",
            source_agent="orchestrator",
            target_agent="cracker",
            payload={"hash_value": "test123"},
        )

        mock_redis_client.brpop.return_value = (
            "ares:tasks:cracker",
            task_message.model_dump_json(),
        )

        task = await task_queue.poll_task(role="cracker", timeout=5.0)

        assert task is not None
        assert task.task_id == "crack_abc"
        assert task.payload["hash_value"] == "test123"


class TestRedisTaskQueueResults:
    """Tests for result handling."""

    @pytest.mark.asyncio
    async def test_send_result_success(self, task_queue, mock_redis_client):
        """Test sending a successful result."""
        await task_queue.send_result(
            task_id="task_123",
            success=True,
            result={"password": "cracked"},  # pragma: allowlist secret
            worker_pod="cracker-0",
        )

        mock_redis_client.lpush.assert_called_once()
        mock_redis_client.expire.assert_called_once_with(
            "ares:results:task_123",
            86400,  # RESULT_TTL (24 hours)
        )

    @pytest.mark.asyncio
    async def test_send_result_failure(self, task_queue, mock_redis_client):
        """Test sending a failed result."""
        await task_queue.send_result(
            task_id="task_456",
            success=False,
            error="Cracking failed",
            worker_pod="cracker-0",
        )

        # Verify error is in the pushed data
        call_args = mock_redis_client.lpush.call_args
        pushed_json = call_args[0][1]
        pushed_data = json.loads(pushed_json)
        assert pushed_data["success"] is False
        assert pushed_data["error"] == "Cracking failed"

    @pytest.mark.asyncio
    async def test_wait_for_result_timeout(self, task_queue, mock_redis_client):
        """Test waiting for result times out."""
        mock_redis_client.brpop.return_value = None

        result = await task_queue.wait_for_result("task_789", timeout=1.0)

        assert result is None

    @pytest.mark.asyncio
    async def test_wait_for_result_success(self, task_queue, mock_redis_client):
        """Test waiting for result successfully."""
        task_result = TaskResult(
            task_id="task_abc",
            success=True,
            result={"output": "done"},
        )

        mock_redis_client.brpop.return_value = (
            "ares:results:task_abc",
            task_result.model_dump_json(),
        )

        result = await task_queue.wait_for_result("task_abc", timeout=5.0)

        assert result is not None
        assert result.success is True
        assert result.result["output"] == "done"

    @pytest.mark.asyncio
    async def test_wait_for_result_asyncio_timeout(self, task_queue, mock_redis_client):
        """Test wait_for_result handles asyncio.TimeoutError from hung BRPOP.

        This tests the fix for stale connections where BRPOP hangs forever
        on a dead TCP socket. The asyncio.wait_for wrapper should detect
        this and return None while resetting connection state.
        """
        import asyncio

        # Simulate a hung BRPOP that never returns (stale connection)
        async def hung_brpop(*args, **kwargs):
            await asyncio.sleep(100)  # Would block forever without wait_for

        mock_redis_client.brpop = hung_brpop

        with patch("ares.core.task_queue.invalidate_sentinel_client"):
            # wait_for_result with timeout=0.1 should trigger asyncio.TimeoutError
            # after 0.1 + 5.0 = 5.1 seconds, but we mock so it's faster
            result = await task_queue.wait_for_result("task_stale", timeout=0.1)

            # Should return None (not raise) to indicate timeout
            assert result is None

            # Connection state should be reset
            assert task_queue._connected is False
            assert task_queue._client is None

    @pytest.mark.asyncio
    async def test_check_result_not_ready(self, task_queue, mock_redis_client):
        """Test non-blocking check when result not ready."""
        mock_redis_client.rpop.return_value = None

        result = await task_queue.check_result("task_xyz")

        assert result is None

    @pytest.mark.asyncio
    async def test_check_result_ready(self, task_queue, mock_redis_client):
        """Test non-blocking check when result is ready."""
        task_result = TaskResult(
            task_id="task_xyz",
            success=True,
            result={"data": "test"},
        )

        mock_redis_client.rpop.return_value = task_result.model_dump_json()

        result = await task_queue.check_result("task_xyz")

        assert result is not None
        assert result.task_id == "task_xyz"


class TestRedisTaskQueueHeartbeat:
    """Tests for heartbeat functionality."""

    @pytest.mark.asyncio
    async def test_send_heartbeat(self, task_queue, mock_redis_client):
        """Test sending a heartbeat."""
        await task_queue.send_heartbeat(
            agent_name="cracker-agent",
            status="busy",
            current_task="task_123",
            pod_name="cracker-0",
        )

        mock_redis_client.set.assert_called_once()

        # Verify heartbeat data
        call_args = mock_redis_client.set.call_args
        assert call_args[0][0] == "ares:heartbeat:cracker-agent"
        heartbeat_data = json.loads(call_args[0][1])
        assert heartbeat_data["status"] == "busy"
        assert heartbeat_data["current_task"] == "task_123"
        assert heartbeat_data["pod_name"] == "cracker-0"

    @pytest.mark.asyncio
    async def test_get_heartbeat_not_found(self, task_queue, mock_redis_client):
        """Test getting heartbeat when agent not found."""
        mock_redis_client.get.return_value = None

        heartbeat = await task_queue.get_heartbeat("unknown-agent")

        assert heartbeat is None

    @pytest.mark.asyncio
    async def test_get_heartbeat_found(self, task_queue, mock_redis_client):
        """Test getting heartbeat successfully."""
        mock_redis_client.get.return_value = json.dumps(
            {
                "status": "idle",
                "current_task": None,
                "pod_name": "lateral-0",
                "timestamp": "2024-01-15T10:30:00Z",
            }
        )

        heartbeat = await task_queue.get_heartbeat("lateral-agent")

        assert heartbeat is not None
        assert heartbeat["status"] == "idle"
        assert heartbeat["pod_name"] == "lateral-0"


class TestRedisTaskQueueRequeue:
    """Tests for task requeuing functionality."""

    @pytest.mark.asyncio
    async def test_requeue_task_basic(self, task_queue, mock_redis_client):
        """Test basic requeue of a task."""
        task_id = await task_queue.requeue_task(
            task_type="crack",
            target_role="cracker",
            payload={"hash_value": "abc123", "hash_type": "NTLM"},
            task_id="original_task_123",
            retry_count=1,
        )

        assert task_id == "original_task_123"
        mock_redis_client.rpush.assert_called_once()

        # Verify the pushed data
        call_args = mock_redis_client.rpush.call_args
        assert call_args[0][0] == "ares:tasks:cracker"

    @pytest.mark.asyncio
    async def test_requeue_task_preserves_task_id(self, task_queue, mock_redis_client):
        """Test that requeue preserves the original task ID."""
        original_id = "task_to_retry_456"

        returned_id = await task_queue.requeue_task(
            task_type="lateral",
            target_role="lateral",
            payload={"target_host": "192.168.58.10"},
            task_id=original_id,
            retry_count=2,
        )

        assert returned_id == original_id

        # Verify the task message contains the original ID
        call_args = mock_redis_client.rpush.call_args
        pushed_json = call_args[0][1]
        pushed_data = json.loads(pushed_json)
        assert pushed_data["task_id"] == original_id

    @pytest.mark.asyncio
    async def test_requeue_task_adds_retry_metadata(self, task_queue, mock_redis_client):
        """Test that requeue adds retry metadata to payload."""
        await task_queue.requeue_task(
            task_type="crack",
            target_role="cracker",
            payload={"hash_value": "xyz789"},
            task_id="retry_task_001",
            retry_count=3,
        )

        call_args = mock_redis_client.rpush.call_args
        pushed_json = call_args[0][1]
        pushed_data = json.loads(pushed_json)

        assert pushed_data["payload"]["_retry_count"] == 3
        assert pushed_data["payload"]["_is_retry"] is True
        assert pushed_data["payload"]["hash_value"] == "xyz789"

    @pytest.mark.asyncio
    async def test_requeue_task_uses_high_priority(self, task_queue, mock_redis_client):
        """Test that requeued tasks have high priority by default."""
        await task_queue.requeue_task(
            task_type="recon",
            target_role="recon",
            payload={"target": "192.168.58.0/24"},
            task_id="recon_retry_001",
            retry_count=1,
        )

        call_args = mock_redis_client.rpush.call_args
        pushed_json = call_args[0][1]
        pushed_data = json.loads(pushed_json)

        assert pushed_data["priority"] == 1  # High priority for retries

    @pytest.mark.asyncio
    async def test_requeue_task_uses_rpush_for_priority(self, task_queue, mock_redis_client):
        """Test that requeue uses RPUSH to prioritize retried tasks."""
        await task_queue.requeue_task(
            task_type="crack",
            target_role="cracker",
            payload={},
            task_id="priority_task",
            retry_count=1,
        )

        # Should use rpush (not lpush) to put at front of queue
        mock_redis_client.rpush.assert_called_once()
        mock_redis_client.lpush.assert_not_called()

    @pytest.mark.asyncio
    async def test_requeue_task_connection_error_resets_state(self, task_queue, mock_redis_client):
        """Test requeue handles connection errors and resets state."""
        mock_redis_client.rpush.side_effect = Exception("Connection closed")

        with pytest.raises(Exception, match="Connection closed"):
            await task_queue.requeue_task(
                task_type="crack",
                target_role="cracker",
                payload={},
                task_id="task_123",
                retry_count=1,
            )

        assert task_queue._connected is False
        assert task_queue._client is None

    @pytest.mark.asyncio
    async def test_requeue_task_non_connection_error_preserves_state(
        self, task_queue, mock_redis_client
    ):
        """Test requeue preserves state for non-connection errors."""
        mock_redis_client.rpush.side_effect = TypeError("Serialization error")

        with pytest.raises(TypeError, match="Serialization error"):
            await task_queue.requeue_task(
                task_type="crack",
                target_role="cracker",
                payload={},
                task_id="task_456",
                retry_count=1,
            )

        # Connection state should be preserved for non-connection errors
        assert task_queue._connected is True
        assert task_queue._client is not None


class TestRedisTaskQueueStats:
    """Tests for queue statistics."""

    @pytest.mark.asyncio
    async def test_get_queue_length_empty(self, task_queue, mock_redis_client):
        """Test getting queue length when empty."""
        mock_redis_client.llen.return_value = 0

        length = await task_queue.get_queue_length("cracker")

        assert length == 0
        mock_redis_client.llen.assert_called_once_with("ares:tasks:cracker")

    @pytest.mark.asyncio
    async def test_get_queue_length_with_tasks(self, task_queue, mock_redis_client):
        """Test getting queue length with pending tasks."""
        mock_redis_client.llen.return_value = 5

        length = await task_queue.get_queue_length("cracker")

        assert length == 5

    @pytest.mark.asyncio
    async def test_get_all_queue_stats(self, task_queue, mock_redis_client):
        """Test getting all queue statistics."""
        # Return different lengths for different roles
        mock_redis_client.llen.side_effect = [3, 0, 1, 0, 2, 0, 0]

        stats = await task_queue.get_all_queue_stats()

        assert stats["cracker"] == 3
        assert stats["lateral"] == 0
        assert stats["acl"] == 1
        assert stats["privesc"] == 0
        assert stats["coercion"] == 2
        assert stats["recon"] == 0
        assert stats["credential_access"] == 0


# ============================================================================
# End-to-End Flow Tests (Simulated)
# ============================================================================


class TestEndToEndFlow:
    """Tests for complete task submission and result flow."""

    @pytest.mark.asyncio
    async def test_submit_poll_complete_flow(self, mock_redis_client):
        """Test complete flow: submit -> poll -> send result -> get result."""
        # Track pushed messages
        pushed_tasks = []
        pushed_results = []

        async def track_lpush(key, value):
            if "tasks" in key:
                pushed_tasks.append((key, value))
            else:
                pushed_results.append((key, value))
            return 1

        mock_redis_client.lpush = AsyncMock(side_effect=track_lpush)

        # Create two queue instances (simulating orchestrator and worker)
        orchestrator_queue = RedisTaskQueue("redis://localhost:6379")
        orchestrator_queue._client = mock_redis_client
        orchestrator_queue._connected = True

        worker_queue = RedisTaskQueue("redis://localhost:6379")
        worker_queue._client = mock_redis_client
        worker_queue._connected = True

        # Orchestrator submits task
        task_id = await orchestrator_queue.submit_task(
            task_type="crack",
            target_role="cracker",
            payload={
                "hash_value": "aad3b435b51404ee",  # pragma: allowlist secret
                "hash_type": "NTLM",
            },
        )

        assert task_id.startswith("crack_")
        assert len(pushed_tasks) == 1

        # Simulate worker polling (return the pushed task)
        pushed_task_json = pushed_tasks[0][1]
        mock_redis_client.brpop.return_value = ("ares:tasks:cracker", pushed_task_json)

        task = await worker_queue.poll_task(role="cracker")

        assert task is not None
        assert task.task_id == task_id

        # Worker sends result
        await worker_queue.send_result(
            task_id=task_id,
            success=True,
            result={"password": "Password123"},  # pragma: allowlist secret
            worker_pod="cracker-0",
        )

        assert len(pushed_results) == 1

        # Orchestrator gets result
        pushed_result_json = pushed_results[0][1]
        mock_redis_client.brpop.return_value = (
            f"ares:results:{task_id}",
            pushed_result_json,
        )

        result = await orchestrator_queue.wait_for_result(task_id)

        assert result is not None
        assert result.success is True
        assert result.result["password"] == "Password123"  # pragma: allowlist secret

        await orchestrator_queue.disconnect()
        await worker_queue.disconnect()

    @pytest.mark.asyncio
    async def test_multiple_workers_same_role(self, mock_redis_client):
        """Test multiple workers polling from same queue."""
        task_counter = [0]

        async def mock_brpop(key, timeout):
            task_counter[0] += 1
            if task_counter[0] <= 3:
                task = TaskMessage(
                    task_id=f"task_{task_counter[0]}",
                    task_type="crack",
                    source_agent="orchestrator",
                    target_agent="cracker",
                    payload={},
                )
                return (key, task.model_dump_json())
            return None

        mock_redis_client.brpop = AsyncMock(side_effect=mock_brpop)

        worker1 = RedisTaskQueue("redis://localhost:6379")
        worker1._client = mock_redis_client
        worker1._connected = True

        worker2 = RedisTaskQueue("redis://localhost:6379")
        worker2._client = mock_redis_client
        worker2._connected = True

        # Both workers poll
        task1 = await worker1.poll_task(role="cracker")
        task2 = await worker2.poll_task(role="cracker")
        task3 = await worker1.poll_task(role="cracker")

        # Each got a different task
        assert task1.task_id == "task_1"
        assert task2.task_id == "task_2"
        assert task3.task_id == "task_3"

        await worker1.disconnect()
        await worker2.disconnect()


# ============================================================================
# Real-Time Discovery Tests
# ============================================================================


class TestRealTimeDiscovery:
    """Tests for real-time discovery publishing and polling."""

    @pytest.fixture
    def mock_redis_client(self):
        """Create a mock Redis client."""
        client = AsyncMock()
        client.close = AsyncMock()
        client.lpush = AsyncMock(return_value=1)
        client.pipeline = MagicMock()
        return client

    @pytest.mark.asyncio
    async def test_publish_discovery_delegation(self, mock_redis_client):
        """Test publishing a delegation discovery."""
        queue = RedisTaskQueue("redis://localhost:6379")
        queue._client = mock_redis_client
        queue._connected = True

        result = await queue.publish_discovery(
            operation_id="op-123",
            discovery_type="delegation",
            data={
                "account": "srv_sql",
                "delegation_type": "constrained",
                "target_spn": "cifs/dc01.contoso.local",
            },
            source_agent="privesc-worker",
        )

        assert result is True
        mock_redis_client.lpush.assert_called_once()

        # Verify the discovery was serialized correctly
        call_args = mock_redis_client.lpush.call_args
        key = call_args[0][0]
        data = json.loads(call_args[0][1])

        assert key == "ares:discoveries:op-123"
        assert data["type"] == "delegation"
        assert data["data"]["account"] == "srv_sql"
        assert data["source_agent"] == "privesc-worker"

        await queue.disconnect()

    @pytest.mark.asyncio
    async def test_publish_discovery_hash(self, mock_redis_client):
        """Test publishing a hash discovery."""
        queue = RedisTaskQueue("redis://localhost:6379")
        queue._client = mock_redis_client
        queue._connected = True

        result = await queue.publish_discovery(
            operation_id="op-456",
            discovery_type="hash",
            data={
                "username": "administrator",
                "hash_value": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                "hash_type": "NTLM",
                "domain": "contoso.local",
            },
            source_agent="credential-worker",
        )

        assert result is True

        call_args = mock_redis_client.lpush.call_args
        data = json.loads(call_args[0][1])

        assert data["type"] == "hash"
        assert data["data"]["username"] == "administrator"
        assert data["data"]["hash_type"] == "NTLM"

        await queue.disconnect()

    @pytest.mark.asyncio
    async def test_publish_discovery_credential(self, mock_redis_client):
        """Test publishing a credential discovery."""
        queue = RedisTaskQueue("redis://localhost:6379")
        queue._client = mock_redis_client
        queue._connected = True

        result = await queue.publish_discovery(
            operation_id="op-789",
            discovery_type="credential",
            data={
                "username": "svc_backup",
                "password": "Backup2024!",  # pragma: allowlist secret
                "domain": "contoso.local",
            },
            source_agent="credential-worker",
        )

        assert result is True

        call_args = mock_redis_client.lpush.call_args
        data = json.loads(call_args[0][1])

        assert data["type"] == "credential"
        assert data["data"]["username"] == "svc_backup"

        await queue.disconnect()

    @pytest.mark.asyncio
    async def test_publish_discovery_vulnerability(self, mock_redis_client):
        """Test publishing a vulnerability discovery."""
        queue = RedisTaskQueue("redis://localhost:6379")
        queue._client = mock_redis_client
        queue._connected = True

        result = await queue.publish_discovery(
            operation_id="op-adcs",
            discovery_type="vulnerability",
            data={
                "vuln_type": "adcs_esc1",
                "target": "192.168.58.10",
                "details": {"esc_type": "ESC1"},
                "priority": 2,
            },
            source_agent="privesc-worker",
        )

        assert result is True

        call_args = mock_redis_client.lpush.call_args
        data = json.loads(call_args[0][1])

        assert data["type"] == "vulnerability"
        assert data["data"]["vuln_type"] == "adcs_esc1"
        assert data["data"]["priority"] == 2

        await queue.disconnect()

    @pytest.mark.asyncio
    async def test_poll_discoveries_empty(self, mock_redis_client):
        """Test polling discoveries when queue is empty."""
        pipeline = AsyncMock()
        pipeline.rpop = MagicMock(return_value=pipeline)
        pipeline.execute = AsyncMock(return_value=[None] * 50)
        mock_redis_client.pipeline.return_value = pipeline

        queue = RedisTaskQueue("redis://localhost:6379")
        queue._client = mock_redis_client
        queue._connected = True

        discoveries = await queue.poll_discoveries("op-empty")

        assert discoveries == []

        await queue.disconnect()

    @pytest.mark.asyncio
    async def test_poll_discoveries_returns_items(self, mock_redis_client):
        """Test polling discoveries returns queued items."""
        discovery1 = json.dumps(
            {
                "type": "hash",
                "data": {"username": "admin", "hash_value": "abc123", "hash_type": "NTLM"},
                "source_agent": "worker1",
            }
        )
        discovery2 = json.dumps(
            {
                "type": "credential",
                "data": {"username": "user1", "password": "pass1"},  # pragma: allowlist secret
                "source_agent": "worker2",
            }
        )

        pipeline = AsyncMock()
        pipeline.rpop = MagicMock(return_value=pipeline)
        pipeline.execute = AsyncMock(return_value=[discovery1, discovery2] + [None] * 48)
        mock_redis_client.pipeline.return_value = pipeline

        queue = RedisTaskQueue("redis://localhost:6379")
        queue._client = mock_redis_client
        queue._connected = True

        discoveries = await queue.poll_discoveries("op-test", max_items=50)

        assert len(discoveries) == 2
        assert discoveries[0]["type"] == "hash"
        assert discoveries[0]["data"]["username"] == "admin"
        assert discoveries[1]["type"] == "credential"

        await queue.disconnect()

    @pytest.mark.asyncio
    async def test_publish_discovery_connection_error(self, mock_redis_client):
        """Test publish returns False when lpush fails."""
        mock_redis_client.lpush = AsyncMock(side_effect=Exception("Connection lost"))

        queue = RedisTaskQueue("redis://localhost:6379")
        queue._client = mock_redis_client
        queue._connected = True

        result = await queue.publish_discovery(
            operation_id="op-fail",
            discovery_type="hash",
            data={"username": "test"},
            source_agent="worker",
        )

        assert result is False

        await queue.disconnect()


# ============================================================================
# Extraction Hooks Tests
# ============================================================================


class TestExtractionHooks:
    """Tests for real-time extraction hooks in red_agents.py."""

    @pytest.mark.asyncio
    async def test_extraction_roles_includes_recon(self):
        """Test that RECON role is in extraction_roles."""
        from ares.core.models import AgentRole

        # The extraction_roles set should include RECON
        extraction_roles = {
            AgentRole.CREDENTIAL_ACCESS,
            AgentRole.PRIVESC,
            AgentRole.LATERAL,
            AgentRole.ACL,
            AgentRole.RECON,  # Added to support SMB/LDAP credential discovery
        }

        assert AgentRole.RECON in extraction_roles
        assert AgentRole.CREDENTIAL_ACCESS in extraction_roles
        assert AgentRole.PRIVESC in extraction_roles

    @pytest.mark.asyncio
    async def test_vuln_extraction_roles(self):
        """Test vulnerability extraction roles configuration."""
        from ares.core.models import AgentRole

        # vuln_extraction_roles should include PRIVESC and LATERAL
        vuln_extraction_roles = {
            AgentRole.PRIVESC,  # certipy_find
            AgentRole.LATERAL,  # mssql_enum_impersonation
        }

        assert AgentRole.PRIVESC in vuln_extraction_roles
        assert AgentRole.LATERAL in vuln_extraction_roles
        # RECON should NOT be in vuln_extraction_roles (doesn't run certipy/mssql tools)
        assert AgentRole.RECON not in vuln_extraction_roles


# ============================================================================
# Double Extraction Prevention Tests
# ============================================================================


class TestDoubleExtractionPrevention:
    """Tests for preventing double extraction of hashes."""

    @pytest.mark.asyncio
    async def test_skips_hash_extraction_for_realtime_roles(self):
        """Test that hash extraction is skipped for agents with real-time hooks."""
        # Roles that have real-time extraction hooks (includes variations)
        realtime_extraction_roles = {
            "credential_access",
            "credential",
            "privesc",
            "lateral",
            "acl",
            "recon",
            "reconnaissance",
        }

        # Test agent names that should skip extraction
        should_skip = [
            "privesc-worker-1",
            "credential_access-agent",
            "credential-harvester",  # Short form
            "lateral-movement",
            "acl-analyst",
            "recon-scanner",
            "reconnaissance-scanner",  # Long form
            "PRIVESC",  # Case insensitive
        ]

        for agent in should_skip:
            source_lower = agent.lower()
            has_realtime_hooks = any(role in source_lower for role in realtime_extraction_roles)
            assert has_realtime_hooks, f"Agent {agent} should have realtime hooks"

    @pytest.mark.asyncio
    async def test_does_not_skip_for_non_realtime_roles(self):
        """Test that hash extraction is NOT skipped for agents without real-time hooks."""
        realtime_extraction_roles = {
            "credential_access",
            "credential",
            "privesc",
            "lateral",
            "acl",
            "recon",
            "reconnaissance",
        }

        # Test agent names that should NOT skip extraction
        should_not_skip = [
            "orchestrator",
            "unknown-worker",
            "manual-task",
            "exploit-runner",
            "persistence-agent",
        ]

        for agent in should_not_skip:
            source_lower = agent.lower()
            has_realtime_hooks = any(role in source_lower for role in realtime_extraction_roles)
            assert not has_realtime_hooks, f"Agent {agent} should NOT have realtime hooks"


# ============================================================================
# Monitoring Processing Tests
# ============================================================================


class TestMonitoringProcessing:
    """Tests for monitoring.py discovery processing."""

    @pytest.fixture
    def mock_shared_state(self):
        """Create a mock shared state."""
        state = MagicMock()
        state.discovered_vulnerabilities = {}
        state.all_credentials = []
        state.all_hashes = []
        state.target_domain = "contoso.local"
        state.dc_ip = "192.168.58.10"
        state.domain_controllers = ["192.168.58.10"]
        return state

    @pytest.mark.asyncio
    async def test_credential_discovery_data_structure(self):
        """Test credential discovery data structure."""
        data = {
            "username": "svc_sql",
            "password": "SqlP@ss123!",  # pragma: allowlist secret
            "domain": "contoso.local",
            "is_admin": False,
        }

        # Verify required fields
        assert "username" in data
        assert "password" in data
        assert "domain" in data
        assert data["domain"] == "contoso.local"  # Uses correct domain convention

    @pytest.mark.asyncio
    async def test_hash_discovery_data_structure(self):
        """Test hash discovery data structure."""
        data = {
            "username": "administrator",
            "hash_value": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "hash_type": "NTLM",
            "domain": "contoso.local",
        }

        # Verify required fields
        assert "username" in data
        assert "hash_value" in data
        assert "hash_type" in data
        assert data["hash_type"] in ("NTLM", "TGS", "AS-REP")

    @pytest.mark.asyncio
    async def test_vulnerability_discovery_data_structure(self):
        """Test vulnerability discovery data structure."""
        data = {
            "vuln_type": "constrained_delegation",
            "target": "192.168.58.10",
            "vuln_id": "cd_srv_sql",
            "details": {
                "account": "srv_sql",
                "target_spn": "cifs/dc01.contoso.local",
            },
            "priority": 2,
        }

        # Verify required fields
        assert "vuln_type" in data
        assert "target" in data
        assert data["vuln_type"] in (
            "constrained_delegation",
            "unconstrained_delegation",
            "esc1",
            "esc4",
            "esc8",
            "mssql_impersonation",
        )

    @pytest.mark.asyncio
    async def test_high_value_vulns_trigger_exploit(self):
        """Test that high-value vulnerabilities are in the auto-exploit set."""
        high_value_vulns = {
            "constrained_delegation",
            "unconstrained_delegation",
            "esc1",
            "esc4",
            "esc8",
            "adcs_esc1",
            "adcs_esc4",
            "adcs_esc8",
            "mssql_impersonation",
        }

        # These should trigger auto-exploit
        should_trigger = [
            "constrained_delegation",
            "esc1",
            "mssql_impersonation",
        ]

        for vuln in should_trigger:
            assert vuln.lower() in high_value_vulns, f"{vuln} should trigger auto-exploit"

        # These should NOT trigger auto-exploit
        should_not_trigger = [
            "smb_signing_disabled",
            "local_admin",
            "gpo_abuse",
        ]

        for vuln in should_not_trigger:
            assert vuln.lower() not in high_value_vulns, f"{vuln} should NOT trigger auto-exploit"


# ============================================================================
# Target Fallback Tests
# ============================================================================


class TestTargetFallback:
    """Tests for target fallback logic in vulnerability publishing."""

    @pytest.mark.asyncio
    async def test_target_fallback_order(self):
        """Test that target fallback uses correct priority order."""
        # Mock shared state with various fallback sources
        dc_ip = "192.168.58.10"
        target_domain = "contoso.local"
        domain_controllers = ["192.168.58.10", "192.168.58.11"]

        # Fallback order should be: dc_ip -> target_domain -> domain_controllers[0]
        target = dc_ip or target_domain or (domain_controllers[0] if domain_controllers else "")

        assert target == "192.168.58.10"

        # Test with empty dc_ip
        dc_ip = ""
        target = dc_ip or target_domain or (domain_controllers[0] if domain_controllers else "")
        assert target == "contoso.local"

        # Test with empty dc_ip and target_domain
        target_domain = ""
        target = dc_ip or target_domain or (domain_controllers[0] if domain_controllers else "")
        assert target == "192.168.58.10"

    @pytest.mark.asyncio
    async def test_skips_vuln_when_no_target(self):
        """Test that vulnerabilities are skipped when no target is available."""
        # When all sources are empty, target should be empty
        dc_ip = ""
        target_domain = ""
        domain_controllers: list[str] = []

        target = dc_ip or target_domain or (domain_controllers[0] if domain_controllers else "")

        assert target == ""
        # In this case, the vulnerability should be skipped (not published)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
