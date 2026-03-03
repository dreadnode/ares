"""Tests for BlueTaskQueue Redis-based task queue."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from ares.core.blue_task_queue import (
    BlueTaskMessage,
    BlueTaskQueue,
    BlueTaskResult,
)


class TestBlueTaskMessage:
    """Tests for BlueTaskMessage model."""

    def test_creates_with_required_fields(self):
        msg = BlueTaskMessage(
            task_id="task-123",
            task_type="triage_alert",
            investigation_id="inv-abc",
            assigned_role="triage",
            params={"alert_name": "HighCPU"},
        )
        assert msg.task_id == "task-123"
        assert msg.task_type == "triage_alert"
        assert msg.investigation_id == "inv-abc"
        assert msg.assigned_role == "triage"
        assert msg.params == {"alert_name": "HighCPU"}
        assert msg.created_at is not None

    def test_auto_sets_created_at(self):
        before = datetime.now(timezone.utc)
        msg = BlueTaskMessage(
            task_id="task-123",
            task_type="threat_hunt",
            investigation_id="inv-abc",
            assigned_role="threat_hunter",
            params={},
        )
        after = datetime.now(timezone.utc)
        assert before <= msg.created_at <= after

    def test_preserves_explicit_created_at(self):
        explicit_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        msg = BlueTaskMessage(
            task_id="task-123",
            task_type="lateral_analysis",
            investigation_id="inv-abc",
            assigned_role="lateral_analyst",
            params={},
            created_at=explicit_time,
        )
        assert msg.created_at == explicit_time

    def test_serializes_to_json(self):
        msg = BlueTaskMessage(
            task_id="task-123",
            task_type="triage_alert",
            investigation_id="inv-abc",
            assigned_role="triage",
            params={"key": "value"},
        )
        json_str = msg.model_dump_json()
        data = json.loads(json_str)
        assert data["task_id"] == "task-123"
        assert data["task_type"] == "triage_alert"
        assert data["params"]["key"] == "value"

    def test_deserializes_from_json(self):
        json_str = json.dumps(
            {
                "task_id": "task-456",
                "task_type": "threat_hunt",
                "investigation_id": "inv-xyz",
                "assigned_role": "threat_hunter",
                "params": {"technique_id": "T1558"},
                "created_at": "2026-02-25T10:00:00Z",
            }
        )
        msg = BlueTaskMessage.model_validate_json(json_str)
        assert msg.task_id == "task-456"
        assert msg.task_type == "threat_hunt"
        assert msg.params["technique_id"] == "T1558"


class TestBlueTaskResult:
    """Tests for BlueTaskResult model."""

    def test_creates_success_result(self):
        result = BlueTaskResult(
            task_id="task-123",
            success=True,
            result={"findings": ["suspicious_login"]},
        )
        assert result.task_id == "task-123"
        assert result.success is True
        assert result.result == {"findings": ["suspicious_login"]}
        assert result.error is None
        assert result.completed_at is not None

    def test_creates_failure_result(self):
        result = BlueTaskResult(
            task_id="task-123",
            success=False,
            error="Connection timeout",
        )
        assert result.success is False
        assert result.error == "Connection timeout"
        assert result.result is None

    def test_auto_sets_completed_at(self):
        before = datetime.now(timezone.utc)
        result = BlueTaskResult(task_id="task-123", success=True)
        after = datetime.now(timezone.utc)
        assert before <= result.completed_at <= after

    def test_includes_worker_metadata(self):
        result = BlueTaskResult(
            task_id="task-123",
            success=True,
            worker_pod="blue-worker-abc123",
            agent_name="blue-triage-worker",
        )
        assert result.worker_pod == "blue-worker-abc123"
        assert result.agent_name == "blue-triage-worker"

    def test_serializes_to_json(self):
        result = BlueTaskResult(
            task_id="task-123",
            success=True,
            result={"evidence": ["log_entry"]},
            worker_pod="pod-1",
        )
        json_str = result.model_dump_json()
        data = json.loads(json_str)
        assert data["task_id"] == "task-123"
        assert data["success"] is True
        assert data["worker_pod"] == "pod-1"

    def test_deserializes_from_json(self):
        json_str = json.dumps(
            {
                "task_id": "task-789",
                "success": False,
                "error": "Task failed",
                "completed_at": "2026-02-25T12:00:00Z",
            }
        )
        result = BlueTaskResult.model_validate_json(json_str)
        assert result.task_id == "task-789"
        assert result.success is False
        assert result.error == "Task failed"


class TestBlueTaskQueueKeyGeneration:
    """Tests for Redis key generation methods."""

    def test_task_queue_key_per_investigation(self):
        queue = BlueTaskQueue(redis_url="redis://localhost")
        key = queue._task_queue_key("inv-123", "triage")
        assert key == "ares:blue:tasks:inv-123:triage"

    def test_global_task_queue_key(self):
        queue = BlueTaskQueue(redis_url="redis://localhost")
        key = queue._global_task_queue_key("threat_hunter")
        assert key == "ares:blue:tasks:global:threat_hunter"

    def test_result_queue_key(self):
        queue = BlueTaskQueue(redis_url="redis://localhost")
        key = queue._result_queue_key("task-abc")
        assert key == "ares:blue:results:task-abc"

    def test_heartbeat_key(self):
        queue = BlueTaskQueue(redis_url="redis://localhost")
        key = queue._heartbeat_key("blue-triage-pod1")
        assert key == "ares:blue:heartbeat:blue-triage-pod1"

    def test_investigation_meta_key(self):
        queue = BlueTaskQueue(redis_url="redis://localhost")
        key = queue._investigation_meta_key("inv-xyz")
        assert key == "ares:blue:investigation:inv-xyz:meta"


class TestBlueTaskQueueConnection:
    """Tests for connection management."""

    @pytest.mark.asyncio
    async def test_connect_sets_connected_flag(self):
        queue = BlueTaskQueue(redis_url="redis://localhost")
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(return_value=True)

        with patch(
            "ares.core.blue_task_queue.create_redis_client",
            return_value=mock_client,
        ):
            await queue.connect()
            assert queue._connected is True
            assert queue._client is mock_client

    @pytest.mark.asyncio
    async def test_connect_skips_if_already_connected(self):
        queue = BlueTaskQueue(redis_url="redis://localhost")
        queue._connected = True

        with patch("ares.core.blue_task_queue.create_redis_client") as mock_create:
            await queue.connect()
            mock_create.assert_not_called()

    @pytest.mark.asyncio
    async def test_disconnect_closes_client(self):
        queue = BlueTaskQueue(redis_url="redis://localhost")
        mock_client = AsyncMock()
        mock_client.aclose = AsyncMock()
        queue._client = mock_client
        queue._connected = True

        await queue.disconnect()

        mock_client.aclose.assert_awaited_once()
        assert queue._connected is False

    @pytest.mark.asyncio
    async def test_ping_or_reconnect_success(self):
        queue = BlueTaskQueue(redis_url="redis://localhost")
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(return_value=True)
        queue._client = mock_client
        queue._connected = True

        result = await queue.ping_or_reconnect()

        assert result is True
        mock_client.ping.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_ping_or_reconnect_failure_triggers_reconnect(self):
        queue = BlueTaskQueue(redis_url="redis://localhost")
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(side_effect=ConnectionError("Connection lost"))
        mock_client.aclose = AsyncMock()
        queue._client = mock_client
        queue._connected = True

        new_mock_client = AsyncMock()
        new_mock_client.ping = AsyncMock(return_value=True)

        with (
            patch(
                "ares.core.blue_task_queue.create_redis_client",
                return_value=new_mock_client,
            ),
            patch("ares.core.blue_task_queue.invalidate_sentinel_client"),
        ):
            result = await queue.ping_or_reconnect()

        assert result is False
        assert queue._connected is True

    @pytest.mark.asyncio
    async def test_redis_property_raises_when_not_connected(self):
        queue = BlueTaskQueue(redis_url="redis://localhost")

        with pytest.raises(RuntimeError, match="Not connected"):
            _ = queue.redis


class TestBlueTaskQueueInvestigationManagement:
    """Tests for investigation registration and discovery."""

    @pytest.fixture
    def connected_queue(self):
        queue = BlueTaskQueue(redis_url="redis://localhost")
        mock_client = AsyncMock()
        mock_client.sadd = AsyncMock()
        mock_client.hset = AsyncMock()
        mock_client.expire = AsyncMock()
        mock_client.srem = AsyncMock()
        mock_client.delete = AsyncMock()
        mock_client.smembers = AsyncMock(return_value=set())
        mock_client.hget = AsyncMock(return_value=None)
        queue._client = mock_client
        queue._connected = True
        return queue

    @pytest.mark.asyncio
    async def test_register_investigation(self, connected_queue):
        alert = {"labels": {"alertname": "HighCPU", "severity": "critical"}}

        await connected_queue.register_investigation(
            investigation_id="inv-123",
            alert=alert,
            model="gpt-4.1",
            credentials={"OPENAI_API_KEY": "test-key"},  # pragma: allowlist secret
        )

        connected_queue._client.sadd.assert_awaited_with(
            "ares:blue:active_investigations", "inv-123"
        )
        connected_queue._client.hset.assert_awaited()
        # Verify TTL is set
        assert connected_queue._client.expire.await_count >= 2

    @pytest.mark.asyncio
    async def test_unregister_investigation(self, connected_queue):
        await connected_queue.unregister_investigation("inv-123")

        connected_queue._client.srem.assert_awaited_with(
            "ares:blue:active_investigations", "inv-123"
        )
        connected_queue._client.delete.assert_awaited_with("ares:blue:investigation:inv-123:meta")

    @pytest.mark.asyncio
    async def test_discover_active_investigation_finds_one(self, connected_queue):
        connected_queue._client.smembers = AsyncMock(return_value={"inv-abc", "inv-xyz"})

        result = await connected_queue.discover_active_investigation(max_wait=1)

        assert result in {"inv-abc", "inv-xyz"}

    @pytest.mark.asyncio
    async def test_discover_active_investigation_timeout(self, connected_queue):
        connected_queue._client.smembers = AsyncMock(return_value=set())

        result = await connected_queue.discover_active_investigation(
            max_wait=0.1, poll_interval=0.05
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_get_investigation_model(self, connected_queue):
        connected_queue._client.hget = AsyncMock(return_value="gpt-4.1")

        result = await connected_queue.get_investigation_model("inv-123")

        assert result == "gpt-4.1"
        connected_queue._client.hget.assert_awaited_with(
            "ares:blue:investigation:inv-123:meta", "model"
        )

    @pytest.mark.asyncio
    async def test_get_investigation_credentials(self, connected_queue):
        creds = {"OPENAI_API_KEY": "test-key"}  # pragma: allowlist secret
        connected_queue._client.hget = AsyncMock(return_value=json.dumps(creds))

        result = await connected_queue.get_investigation_credentials("inv-123")

        assert result == creds

    @pytest.mark.asyncio
    async def test_get_investigation_credentials_returns_empty_on_none(self, connected_queue):
        connected_queue._client.hget = AsyncMock(return_value=None)

        result = await connected_queue.get_investigation_credentials("inv-123")

        assert result == {}

    @pytest.mark.asyncio
    async def test_get_investigation_alert(self, connected_queue):
        alert = {"labels": {"alertname": "Test"}}
        connected_queue._client.hget = AsyncMock(return_value=json.dumps(alert))

        result = await connected_queue.get_investigation_alert("inv-123")

        assert result == alert


class TestBlueTaskQueueTaskSubmission:
    """Tests for task submission and polling."""

    @pytest.fixture
    def connected_queue(self):
        queue = BlueTaskQueue(redis_url="redis://localhost", use_global_queue=False)
        mock_client = AsyncMock()
        mock_client.lpush = AsyncMock()
        mock_client.expire = AsyncMock()
        mock_client.brpop = AsyncMock(return_value=None)
        queue._client = mock_client
        queue._connected = True
        return queue

    @pytest.fixture
    def global_queue(self):
        queue = BlueTaskQueue(redis_url="redis://localhost", use_global_queue=True)
        mock_client = AsyncMock()
        mock_client.lpush = AsyncMock()
        mock_client.expire = AsyncMock()
        mock_client.brpop = AsyncMock(return_value=None)
        queue._client = mock_client
        queue._connected = True
        return queue

    @pytest.mark.asyncio
    async def test_submit_task_to_per_investigation_queue(self, connected_queue):
        task_id = await connected_queue.submit_task(
            investigation_id="inv-123",
            task_type="triage_alert",
            target_role="triage",
            params={"alert_name": "HighCPU"},
        )

        assert task_id.startswith("triage_alert_")
        connected_queue._client.lpush.assert_awaited_once()
        call_args = connected_queue._client.lpush.call_args
        assert call_args[0][0] == "ares:blue:tasks:inv-123:triage"

    @pytest.mark.asyncio
    async def test_submit_task_to_global_queue(self, global_queue):
        task_id = await global_queue.submit_task(
            investigation_id="inv-123",
            task_type="threat_hunt",
            target_role="threat_hunter",
            params={"technique_id": "T1558"},
        )

        assert task_id.startswith("threat_hunt_")
        global_queue._client.lpush.assert_awaited_once()
        call_args = global_queue._client.lpush.call_args
        assert call_args[0][0] == "ares:blue:tasks:global:threat_hunter"

    @pytest.mark.asyncio
    async def test_submit_task_with_custom_task_id(self, connected_queue):
        task_id = await connected_queue.submit_task(
            investigation_id="inv-123",
            task_type="triage_alert",
            target_role="triage",
            params={},
            task_id="custom-task-id",
        )

        assert task_id == "custom-task-id"

    @pytest.mark.asyncio
    async def test_poll_task_returns_message(self, connected_queue):
        task_msg = BlueTaskMessage(
            task_id="task-123",
            task_type="triage_alert",
            investigation_id="inv-abc",
            assigned_role="triage",
            params={"key": "value"},
        )
        connected_queue._client.brpop = AsyncMock(
            return_value=("queue_key", task_msg.model_dump_json())
        )

        result = await connected_queue.poll_task(
            investigation_id="inv-abc",
            role="triage",
            timeout=5.0,
        )

        assert result is not None
        assert result.task_id == "task-123"
        assert result.task_type == "triage_alert"

    @pytest.mark.asyncio
    async def test_poll_task_returns_none_on_timeout(self, connected_queue):
        connected_queue._client.brpop = AsyncMock(return_value=None)

        result = await connected_queue.poll_task(
            investigation_id="inv-abc",
            role="triage",
            timeout=0.1,
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_poll_global_task_returns_message(self, global_queue):
        task_msg = BlueTaskMessage(
            task_id="task-456",
            task_type="threat_hunt",
            investigation_id="inv-xyz",
            assigned_role="threat_hunter",
            params={},
        )
        global_queue._client.brpop = AsyncMock(
            return_value=("queue_key", task_msg.model_dump_json())
        )

        result = await global_queue.poll_global_task(role="threat_hunter", timeout=5.0)

        assert result is not None
        assert result.task_id == "task-456"
        assert result.investigation_id == "inv-xyz"


class TestBlueTaskQueueResults:
    """Tests for result sending and waiting."""

    @pytest.fixture
    def connected_queue(self):
        queue = BlueTaskQueue(redis_url="redis://localhost")
        mock_client = AsyncMock()
        mock_client.lpush = AsyncMock()
        mock_client.expire = AsyncMock()
        mock_client.brpop = AsyncMock(return_value=None)
        queue._client = mock_client
        queue._connected = True
        return queue

    @pytest.mark.asyncio
    async def test_send_result_success(self, connected_queue):
        await connected_queue.send_result(
            task_id="task-123",
            success=True,
            result={"findings": ["suspicious_activity"]},
            worker_pod="pod-1",
            agent_name="blue-triage",
        )

        connected_queue._client.lpush.assert_awaited_once()
        call_args = connected_queue._client.lpush.call_args
        assert call_args[0][0] == "ares:blue:results:task-123"

        # Verify result data
        result_json = call_args[0][1]
        result_data = json.loads(result_json)
        assert result_data["task_id"] == "task-123"
        assert result_data["success"] is True
        assert result_data["result"]["findings"] == ["suspicious_activity"]

    @pytest.mark.asyncio
    async def test_send_result_failure(self, connected_queue):
        await connected_queue.send_result(
            task_id="task-456",
            success=False,
            error="Task processing failed",
        )

        call_args = connected_queue._client.lpush.call_args
        result_json = call_args[0][1]
        result_data = json.loads(result_json)
        assert result_data["success"] is False
        assert result_data["error"] == "Task processing failed"

    @pytest.mark.asyncio
    async def test_wait_for_result_returns_result(self, connected_queue):
        task_result = BlueTaskResult(
            task_id="task-123",
            success=True,
            result={"data": "test"},
        )
        connected_queue._client.brpop = AsyncMock(
            return_value=("result_key", task_result.model_dump_json())
        )

        result = await connected_queue.wait_for_result("task-123", timeout=5.0)

        assert result is not None
        assert result.task_id == "task-123"
        assert result.success is True

    @pytest.mark.asyncio
    async def test_wait_for_result_timeout(self, connected_queue):
        connected_queue._client.brpop = AsyncMock(return_value=None)

        result = await connected_queue.wait_for_result("task-123", timeout=0.1)

        assert result is None


class TestBlueTaskQueueHeartbeat:
    """Tests for heartbeat functionality."""

    @pytest.fixture
    def connected_queue(self):
        queue = BlueTaskQueue(redis_url="redis://localhost")
        mock_client = AsyncMock()
        mock_client.setex = AsyncMock()
        mock_client.get = AsyncMock(return_value=None)
        queue._client = mock_client
        queue._connected = True
        return queue

    @pytest.mark.asyncio
    async def test_heartbeat_sends_status(self, connected_queue):
        with patch.dict("os.environ", {"HOSTNAME": "pod-abc123"}):
            await connected_queue.heartbeat(
                agent_name="blue-triage-1",
                status="busy",
                current_task="task-123",
            )

        connected_queue._client.setex.assert_awaited_once()
        call_args = connected_queue._client.setex.call_args
        assert call_args[0][0] == "ares:blue:heartbeat:blue-triage-1"

        heartbeat_data = json.loads(call_args[0][2])
        assert heartbeat_data["agent_name"] == "blue-triage-1"
        assert heartbeat_data["status"] == "busy"
        assert heartbeat_data["current_task"] == "task-123"
        assert heartbeat_data["pod"] == "pod-abc123"

    @pytest.mark.asyncio
    async def test_get_worker_status_returns_data(self, connected_queue):
        status_data = {
            "agent_name": "blue-hunter-1",
            "status": "idle",
            "current_task": None,
            "timestamp": "2026-02-25T12:00:00Z",
            "pod": "pod-xyz",
        }
        connected_queue._client.get = AsyncMock(return_value=json.dumps(status_data))

        result = await connected_queue.get_worker_status("blue-hunter-1")

        assert result is not None
        assert result["agent_name"] == "blue-hunter-1"
        assert result["status"] == "idle"

    @pytest.mark.asyncio
    async def test_get_worker_status_returns_none_when_missing(self, connected_queue):
        connected_queue._client.get = AsyncMock(return_value=None)

        result = await connected_queue.get_worker_status("nonexistent-agent")

        assert result is None


class TestBlueTaskQueueErrorHandling:
    """Tests for connection error handling."""

    @pytest.fixture
    def connected_queue(self):
        queue = BlueTaskQueue(redis_url="redis://localhost")
        mock_client = AsyncMock()
        queue._client = mock_client
        queue._connected = True
        return queue

    @pytest.mark.asyncio
    async def test_submit_task_handles_connection_error(self, connected_queue):
        connected_queue._client.lpush = AsyncMock(side_effect=ConnectionError("Connection reset"))
        connected_queue._client.aclose = AsyncMock()

        with (
            patch(
                "ares.core.blue_task_queue.create_redis_client",
                return_value=connected_queue._client,
            ),
            pytest.raises(ConnectionError),
        ):
            await connected_queue.submit_task(
                investigation_id="inv-123",
                task_type="triage",
                target_role="triage",
                params={},
                max_retries=0,  # Test single attempt behavior
            )

        assert connected_queue._connected is False

    @pytest.mark.asyncio
    async def test_poll_task_handles_timeout_error(self, connected_queue):
        # Simulate BRPOP hanging beyond the asyncio.wait_for timeout
        async def slow_brpop(*args, **kwargs):
            await asyncio.sleep(10)

        connected_queue._client.brpop = slow_brpop

        with (
            patch("ares.core.blue_task_queue.invalidate_sentinel_client"),
            patch(
                "ares.core.blue_task_queue.create_redis_client",
                return_value=connected_queue._client,
            ),
        ):
            # Use max_retries=0 to test single attempt behavior
            result = await connected_queue.poll_task(
                investigation_id="inv-123",
                role="triage",
                timeout=0.1,
                max_retries=0,
            )

        assert result is None
        assert connected_queue._connected is False

    @pytest.mark.asyncio
    async def test_handle_connection_error_resets_state(self, connected_queue):
        connected_queue._client.aclose = AsyncMock()

        await connected_queue._handle_connection_error(ConnectionError("Test error"))

        assert connected_queue._connected is False
        assert connected_queue._client is None


class TestBlueTaskQueueRetryLogic:
    """Tests for poll_task and poll_global_task retry behavior."""

    @pytest.fixture
    def queue_with_reconnect(self):
        """Queue that tracks reconnection attempts."""
        queue = BlueTaskQueue(redis_url="redis://localhost")
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(return_value=True)
        queue._client = mock_client
        queue._connected = True
        return queue

    @pytest.mark.asyncio
    async def test_poll_task_retries_on_connection_error(self, queue_with_reconnect):
        """Test poll_task retries on connection errors."""
        call_count = 0

        async def failing_then_success(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("Connection closed unexpectedly")

        queue_with_reconnect._client.brpop = failing_then_success

        with patch(
            "ares.core.blue_task_queue.create_redis_client",
            return_value=queue_with_reconnect._client,
        ):
            result = await queue_with_reconnect.poll_task(
                investigation_id="inv-123",
                role="triage",
                timeout=0.1,
                max_retries=2,
            )

        assert result is None
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_poll_task_returns_none_after_exhausting_retries(self, queue_with_reconnect):
        """Test poll_task returns None after all retries fail."""
        brpop_call_count = [0]

        async def failing_brpop(*args, **kwargs):
            brpop_call_count[0] += 1
            raise ConnectionError("Connection reset by peer")

        # Set up initial client
        queue_with_reconnect._client.brpop = failing_brpop

        # Create fresh mock client for each reconnection that also fails
        async def mock_create_client(*args, **kwargs):
            mock = AsyncMock()
            mock.ping = AsyncMock(return_value=True)
            mock.brpop = failing_brpop
            return mock

        with patch(
            "ares.core.blue_task_queue.create_redis_client",
            side_effect=mock_create_client,
        ):
            result = await queue_with_reconnect.poll_task(
                investigation_id="inv-123",
                role="triage",
                timeout=0.1,
                max_retries=2,
            )

        assert result is None
        # max_retries=2 means 3 total attempts (initial + 2 retries)
        assert brpop_call_count[0] == 3

    @pytest.mark.asyncio
    async def test_poll_task_succeeds_on_retry_after_initial_failure(self, queue_with_reconnect):
        """Test poll_task returns message on successful retry."""
        task_msg = BlueTaskMessage(
            task_id="task-123",
            task_type="triage_alert",
            investigation_id="inv-abc",
            assigned_role="triage",
            params={},
        )
        call_count = 0

        async def fail_then_succeed(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise TimeoutError("Connection timeout")
            return ("queue_key", task_msg.model_dump_json())

        queue_with_reconnect._client.brpop = fail_then_succeed

        with patch(
            "ares.core.blue_task_queue.create_redis_client",
            return_value=queue_with_reconnect._client,
        ):
            result = await queue_with_reconnect.poll_task(
                investigation_id="inv-abc",
                role="triage",
                timeout=1.0,
                max_retries=2,
            )

        assert result is not None
        assert result.task_id == "task-123"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_poll_global_task_retries_on_timeout(self, queue_with_reconnect):
        """Test poll_global_task retries on stale connection timeout."""
        call_count = 0

        async def slow_then_normal(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Simulate hung connection (will trigger asyncio.TimeoutError)
                await asyncio.sleep(10)

        queue_with_reconnect._client.brpop = slow_then_normal

        with (
            patch("ares.core.blue_task_queue.invalidate_sentinel_client"),
            patch(
                "ares.core.blue_task_queue.create_redis_client",
                return_value=queue_with_reconnect._client,
            ),
        ):
            result = await queue_with_reconnect.poll_global_task(
                role="threat_hunter",
                timeout=0.1,
                max_retries=2,
            )

        assert result is None
        # First call times out, second succeeds with None
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_poll_global_task_returns_none_after_exhausting_retries(
        self, queue_with_reconnect
    ):
        """Test poll_global_task returns None after all retries fail."""
        brpop_call_count = [0]

        async def failing_brpop(*args, **kwargs):
            brpop_call_count[0] += 1
            raise OSError("Network unreachable")

        # Set up initial client
        queue_with_reconnect._client.brpop = failing_brpop

        # Create fresh mock client for each reconnection that also fails
        async def mock_create_client(*args, **kwargs):
            mock = AsyncMock()
            mock.ping = AsyncMock(return_value=True)
            mock.brpop = failing_brpop
            return mock

        with patch(
            "ares.core.blue_task_queue.create_redis_client",
            side_effect=mock_create_client,
        ):
            result = await queue_with_reconnect.poll_global_task(
                role="lateral_analyst",
                timeout=0.1,
                max_retries=1,
            )

        assert result is None
        # max_retries=1 means 2 total attempts
        assert brpop_call_count[0] == 2

    @pytest.mark.asyncio
    async def test_poll_task_raises_non_connection_errors(self, queue_with_reconnect):
        """Test poll_task raises non-connection errors immediately."""
        queue_with_reconnect._client.brpop = AsyncMock(
            side_effect=ValueError("Invalid data format")
        )

        with pytest.raises(ValueError, match="Invalid data format"):
            await queue_with_reconnect.poll_task(
                investigation_id="inv-123",
                role="triage",
                timeout=0.1,
                max_retries=2,
            )

        # Should not retry for non-connection errors
        assert queue_with_reconnect._client.brpop.call_count == 1


class TestBlueTaskQueueAutoConnect:
    """Tests for auto-connect behavior in methods."""

    @pytest.mark.asyncio
    async def test_submit_task_auto_connects(self):
        queue = BlueTaskQueue(redis_url="redis://localhost")
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(return_value=True)
        mock_client.lpush = AsyncMock()
        mock_client.expire = AsyncMock()

        with patch(
            "ares.core.blue_task_queue.create_redis_client",
            return_value=mock_client,
        ):
            await queue.submit_task(
                investigation_id="inv-123",
                task_type="triage",
                target_role="triage",
                params={},
            )

        assert queue._connected is True

    @pytest.mark.asyncio
    async def test_register_investigation_auto_connects(self):
        queue = BlueTaskQueue(redis_url="redis://localhost")
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(return_value=True)
        mock_client.sadd = AsyncMock()
        mock_client.hset = AsyncMock()
        mock_client.expire = AsyncMock()

        with patch(
            "ares.core.blue_task_queue.create_redis_client",
            return_value=mock_client,
        ):
            await queue.register_investigation(
                investigation_id="inv-123",
                alert={"labels": {}},
            )

        assert queue._connected is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
