"""Integration tests for Redis-based orchestrator→worker flow.

Tests the complete multi-agent communication flow using Redis task queues
for cross-pod messaging in Kubernetes deployments.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.integration

if os.getenv("ARES_RUN_INTEGRATION_TESTS") != "1":
    pytest.skip(
        "Set ARES_RUN_INTEGRATION_TESTS=1 to run integration tests.",
        allow_module_level=True,
    )

# Create mock redis module if not installed
if "redis" not in sys.modules:
    mock_redis_module = MagicMock()
    mock_redis_asyncio = MagicMock()
    mock_redis_module.asyncio = mock_redis_asyncio
    sys.modules["redis"] = mock_redis_module
    sys.modules["redis.asyncio"] = mock_redis_asyncio

from ares.core.dispatcher import RedTeamDispatcher  # noqa: E402
from ares.core.models import AgentInfo, AgentRole  # noqa: E402
from ares.core.task_queue import RedisTaskQueue, TaskMessage, TaskResult  # noqa: E402
from ares.core.worker import (  # noqa: E402
    RedisWorkerAgent,
    generate_prompt_from_task,
)

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_redis_client():
    """Create a comprehensive mock Redis async client."""
    client = AsyncMock()
    client.ping = AsyncMock(return_value=True)
    client.lpush = AsyncMock(return_value=1)
    client.brpop = AsyncMock(return_value=None)
    client.rpop = AsyncMock(return_value=None)
    client.llen = AsyncMock(return_value=0)
    client.set = AsyncMock(return_value=True)
    client.get = AsyncMock(return_value=None)
    client.expire = AsyncMock(return_value=True)
    client.exists = AsyncMock(return_value=0)
    client.delete = AsyncMock(return_value=1)
    client.aclose = AsyncMock()
    client.close = AsyncMock()

    # Create async generator for scan_iter
    async def async_scan_iter(pattern):
        return
        yield  # Make this an async generator

    client.scan_iter = async_scan_iter
    return client


@pytest.fixture
async def dispatcher_with_redis(mock_redis_client):
    """Create a dispatcher with mocked Redis and task queue."""
    dispatcher = RedTeamDispatcher(redis_url="redis://localhost:6379")

    # Manually setup the mocked connections
    dispatcher._redis_client = mock_redis_client
    if dispatcher._task_queue:
        dispatcher._task_queue._client = mock_redis_client
        dispatcher._task_queue._connected = True

    # Initialize shared state
    from ares.core.models import SharedRedTeamState

    dispatcher._shared_state = SharedRedTeamState(operation_id="test-operation-redis")
    dispatcher._running = True

    yield dispatcher

    dispatcher._running = False
    if dispatcher._task_queue:
        dispatcher._task_queue._connected = False


@pytest.fixture
async def task_queue(mock_redis_client):
    """Create a RedisTaskQueue with mocked Redis."""
    queue = RedisTaskQueue("redis://localhost:6379")
    queue._client = mock_redis_client
    queue._connected = True

    yield queue

    queue._connected = False


@pytest.fixture
def mock_agent():
    """Create a mock Dreadnode Agent."""
    agent = MagicMock()
    agent.run = AsyncMock(return_value=MagicMock(output="Task completed successfully"))
    return agent


# ============================================================================
# Prompt Generation Tests
# ============================================================================


class TestPromptGeneration:
    """Tests for generate_prompt_from_task function."""

    def test_crack_prompt(self):
        """Test prompt generation for crack tasks."""
        task = TaskMessage(
            task_id="crack_abc",
            task_type="crack",
            source_agent="orchestrator",
            target_agent="cracker",
            payload={
                "hash_value": "aad3b435b51404ee:500",
                "hash_type": "NTLM",
                "username": "admin",
                "domain": "contoso.local",
                "wordlist": "rockyou.txt",
            },
        )

        prompt = generate_prompt_from_task(task)

        assert "admin" in prompt
        assert "NTLM" in prompt
        assert "aad3b435b51404ee:500" in prompt
        assert "rockyou.txt" in prompt
        assert "crack_abc" in prompt

    def test_lateral_prompt(self):
        """Test prompt generation for lateral movement tasks."""
        task = TaskMessage(
            task_id="lateral_xyz",
            task_type="lateral",
            source_agent="orchestrator",
            target_agent="lateral",
            payload={
                "target_host": "192.168.56.10",
                "username": "admin",
                "domain": "contoso.local",
                "password": "Password123",  # pragma: allowlist secret
                "method": "psexec",
            },
        )

        prompt = generate_prompt_from_task(task)

        assert "192.168.56.10" in prompt
        assert "contoso.local\\admin" in prompt
        assert "password" in prompt.lower()
        assert "lateral_xyz" in prompt

    def test_acl_analysis_prompt(self):
        """Test prompt generation for ACL analysis tasks."""
        task = TaskMessage(
            task_id="acl_123",
            task_type="acl_analysis",
            source_agent="orchestrator",
            target_agent="acl",
            payload={
                "target_user": "danj",
                "domain": "contoso.local",
                "find_path_to": "Domain Admins",
            },
        )

        prompt = generate_prompt_from_task(task)

        assert "danj" in prompt
        assert "contoso.local" in prompt
        assert "Domain Admins" in prompt
        assert "BloodHound" in prompt

    def test_exploit_prompt(self):
        """Test prompt generation for exploit tasks."""
        task = TaskMessage(
            task_id="exploit_adcs",
            task_type="exploit",
            source_agent="orchestrator",
            target_agent="privesc",
            payload={
                "vuln_type": "ADCS_ESC1",
                "target": "dc01.contoso.local",
                "vuln_id": "vuln_001",
            },
        )

        prompt = generate_prompt_from_task(task)

        assert "ADCS_ESC1" in prompt
        assert "dc01.contoso.local" in prompt
        assert "exploit_adcs" in prompt

    def test_coercion_prompt(self):
        """Test prompt generation for coercion tasks."""
        task = TaskMessage(
            task_id="coercion_001",
            task_type="coercion",
            source_agent="orchestrator",
            target_agent="coercion",
            payload={
                "interface": "eth0",
                "techniques": ["LLMNR", "NBT-NS", "mDNS"],
                "duration": 600,
            },
        )

        prompt = generate_prompt_from_task(task)

        assert "eth0" in prompt
        assert "LLMNR" in prompt
        assert "600" in prompt

    def test_command_task_returns_none(self):
        """Test that command tasks return None for direct execution."""
        task = TaskMessage(
            task_id="cmd_001",
            task_type="command",
            source_agent="orchestrator",
            target_agent="worker",
            payload={"command": "whoami"},
        )

        prompt = generate_prompt_from_task(task)

        assert prompt is None

    def test_unknown_task_fallback(self):
        """Test fallback prompt for unknown task types."""
        task = TaskMessage(
            task_id="unknown_001",
            task_type="custom_task",
            source_agent="orchestrator",
            target_agent="worker",
            payload={"custom_key": "custom_value"},
        )

        prompt = generate_prompt_from_task(task)

        assert "custom_task" in prompt
        assert "custom_key" in prompt


# ============================================================================
# Dispatcher Redis Integration Tests
# ============================================================================


class TestDispatcherRedisIntegration:
    """Tests for dispatcher with Redis task queue."""

    @pytest.mark.asyncio
    async def test_dispatcher_creates_task_queue(self):
        """Test dispatcher creates task queue when redis_url provided."""
        dispatcher = RedTeamDispatcher(redis_url="redis://localhost:6379")

        assert dispatcher._task_queue is not None
        assert dispatcher._redis_url == "redis://localhost:6379"

    @pytest.mark.asyncio
    async def test_request_crack_uses_redis_queue(self, dispatcher_with_redis, mock_redis_client):
        """Test crack request goes through Redis queue."""
        task_id = await dispatcher_with_redis.request_crack(
            hash_value="aad3b435b51404ee:test",
            hash_type="NTLM",
            source_agent="orchestrator",
            username="admin",
            domain="contoso.local",
        )

        assert task_id.startswith("crack_")
        assert task_id in dispatcher_with_redis.shared_state.pending_tasks

        # Verify Redis lpush was called
        mock_redis_client.lpush.assert_called()

    @pytest.mark.asyncio
    async def test_request_lateral_uses_redis_queue(self, dispatcher_with_redis, mock_redis_client):
        """Test lateral movement request goes through Redis queue."""
        task_id = await dispatcher_with_redis.request_lateral_movement(
            target_host="192.168.56.10",
            username="admin",
            source_agent="orchestrator",
            password="Password123",  # pragma: allowlist secret
            domain="contoso.local",
        )

        assert task_id.startswith("lateral_")
        mock_redis_client.lpush.assert_called()

    @pytest.mark.asyncio
    async def test_request_acl_analysis_uses_redis_queue(
        self, dispatcher_with_redis, mock_redis_client
    ):
        """Test ACL analysis request goes through Redis queue."""
        task_id = await dispatcher_with_redis.request_acl_analysis(
            target_user="compromised",
            domain="contoso.local",
            source_agent="orchestrator",
        )

        assert task_id.startswith("acl_analysis_")
        mock_redis_client.lpush.assert_called()

    @pytest.mark.asyncio
    async def test_request_exploit_uses_redis_queue(self, dispatcher_with_redis, mock_redis_client):
        """Test exploit request goes through Redis queue."""
        task_id = await dispatcher_with_redis.request_exploit(
            vuln_type="ADCS_ESC1",
            vuln_id="vuln_001",
            target="dc01",
            source_agent="orchestrator",
        )

        assert task_id.startswith("exploit_")
        mock_redis_client.lpush.assert_called()

    @pytest.mark.asyncio
    async def test_request_coercion_uses_redis_queue(
        self, dispatcher_with_redis, mock_redis_client
    ):
        """Test coercion request goes through Redis queue."""
        task_id = await dispatcher_with_redis.request_coercion(
            source_agent="orchestrator",
            interface="eth0",
        )

        assert task_id.startswith("coercion_")
        mock_redis_client.lpush.assert_called()

    @pytest.mark.asyncio
    async def test_dispatch_and_wait(self, dispatcher_with_redis, mock_redis_client):
        """Test dispatch_and_wait convenience method."""
        # Setup mock to return result
        task_result = TaskResult(
            task_id="test_task",
            success=True,
            result={"output": "done"},
        )
        mock_redis_client.brpop.return_value = (
            "ares:results:test_task",
            task_result.model_dump_json(),
        )

        result = await dispatcher_with_redis.dispatch_and_wait(
            task_type="crack",
            target_role="cracker",
            payload={"hash_value": "test"},
            timeout=5.0,
        )

        assert result is not None
        assert result.success is True

    @pytest.mark.asyncio
    async def test_result_consumer_completes_task(self, dispatcher_with_redis):
        """Test result consumer updates dispatcher state from Redis results."""
        task_id = await dispatcher_with_redis.request_crack(
            hash_value="aad3b435b51404ee:test",
            hash_type="NTLM",
            source_agent="orchestrator",
            username="admin",
            domain="contoso.local",
        )

        task_result = TaskResult(
            task_id=task_id,
            success=True,
            result={"output": "done"},
            worker_pod="cracker-0",
        )
        dispatcher_with_redis._task_queue.check_result = AsyncMock(return_value=task_result)

        await dispatcher_with_redis._consume_pending_results()

        assert task_id not in dispatcher_with_redis._redis_task_ids
        assert task_id not in dispatcher_with_redis.shared_state.pending_tasks
        assert task_id in dispatcher_with_redis.shared_state.completed_tasks
        assert dispatcher_with_redis.shared_state.completed_tasks[task_id].success is True


# ============================================================================
# RedisWorkerAgent Tests
# ============================================================================


class TestRedisWorkerAgent:
    """Tests for RedisWorkerAgent class."""

    @pytest.mark.asyncio
    async def test_worker_agent_init(self, task_queue, mock_agent):
        """Test RedisWorkerAgent initialization."""
        worker = RedisWorkerAgent(
            role=AgentRole.CRACKER,
            task_queue=task_queue,
            agent=mock_agent,
            agent_name="cracker-agent",
            pod_name="cracker-0",
        )

        assert worker.role == AgentRole.CRACKER
        assert worker.agent_name == "cracker-agent"
        assert worker.pod_name == "cracker-0"
        assert worker._running is False
        assert worker._tasks_completed == 0

    @pytest.mark.asyncio
    async def test_worker_processes_task(self, task_queue, mock_agent, mock_redis_client):
        """Test worker processes a task successfully."""
        worker = RedisWorkerAgent(
            role=AgentRole.CRACKER,
            task_queue=task_queue,
            agent=mock_agent,
            agent_name="cracker-agent",
            pod_name="cracker-0",
        )

        task = TaskMessage(
            task_id="crack_test",
            task_type="crack",
            source_agent="orchestrator",
            target_agent="cracker",
            payload={"hash_value": "abc", "hash_type": "NTLM"},
        )

        # Process task directly
        await worker._process_task(task)

        # Verify agent was run
        mock_agent.run.assert_called_once()

        # Verify result was sent
        mock_redis_client.lpush.assert_called()
        mock_redis_client.expire.assert_called()

    @pytest.mark.asyncio
    async def test_worker_handles_task_failure(self, task_queue, mock_agent, mock_redis_client):
        """Test worker handles task failure gracefully."""
        mock_agent.run.side_effect = Exception("Agent crashed")

        worker = RedisWorkerAgent(
            role=AgentRole.CRACKER,
            task_queue=task_queue,
            agent=mock_agent,
            agent_name="cracker-agent",
            pod_name="cracker-0",
        )

        # Provide valid payload so prompt generation succeeds
        task = TaskMessage(
            task_id="crash_test",
            task_type="crack",
            source_agent="orchestrator",
            target_agent="cracker",
            payload={"hash_value": "abc123", "hash_type": "NTLM"},
        )

        await worker._process_task(task)

        # Verify error result was sent
        call_args = mock_redis_client.lpush.call_args
        result_json = call_args[0][1]
        result_data = json.loads(result_json)
        assert result_data["success"] is False
        assert "Agent crashed" in result_data["error"]

    @pytest.mark.asyncio
    async def test_worker_heartbeat(self, task_queue, mock_agent, mock_redis_client):
        """Test worker sends heartbeats."""
        worker = RedisWorkerAgent(
            role=AgentRole.CRACKER,
            task_queue=task_queue,
            agent=mock_agent,
            agent_name="cracker-agent",
            pod_name="cracker-0",
        )

        worker._running = True

        # Run one heartbeat iteration
        await task_queue.send_heartbeat(
            agent_name="cracker-agent",
            status="idle",
            current_task=None,
            pod_name="cracker-0",
        )

        mock_redis_client.set.assert_called()
        call_args = mock_redis_client.set.call_args
        assert call_args[0][0] == "ares:heartbeat:cracker-agent"

    @pytest.mark.asyncio
    async def test_worker_extracts_result(self, task_queue, mock_agent):
        """Test worker extracts result from agent output."""
        worker = RedisWorkerAgent(
            role=AgentRole.CRACKER,
            task_queue=task_queue,
            agent=mock_agent,
            agent_name="cracker-agent",
        )

        # Test with output attribute
        result_obj = MagicMock()
        result_obj.output = "Result from output"
        assert worker._extract_result(result_obj) == "Result from output"

        # Test with content attribute
        result_obj2 = MagicMock(spec=[])
        result_obj2.content = "Result from content"
        del result_obj2.output  # Remove output attr
        assert worker._extract_result(result_obj2) == "Result from content"

        # Test with string
        assert worker._extract_result("Plain string") == "Plain string"


# ============================================================================
# Orchestrator → Worker Flow Tests
# ============================================================================


class TestOrchestratorWorkerFlow:
    """Integration tests for complete orchestrator to worker flow."""

    @pytest.mark.asyncio
    async def test_complete_crack_flow(self, mock_redis_client):
        """Test complete flow: orchestrator submits crack → worker processes → result returned."""
        # Track all Redis operations
        task_queue_items = []
        result_queue_items = []

        async def track_lpush(key, value):
            if "tasks" in key:
                task_queue_items.append((key, value))
            elif "results" in key:
                result_queue_items.append((key, value))
            return 1

        mock_redis_client.lpush = AsyncMock(side_effect=track_lpush)

        # Create dispatcher (orchestrator side) with manual mocking
        from ares.core.models import SharedRedTeamState

        dispatcher = RedTeamDispatcher(redis_url="redis://localhost:6379")
        dispatcher._redis_client = mock_redis_client
        dispatcher._shared_state = SharedRedTeamState(operation_id="flow-test-001")
        dispatcher._running = True
        if dispatcher._task_queue:
            dispatcher._task_queue._client = mock_redis_client
            dispatcher._task_queue._connected = True

        # Submit crack task
        task_id = await dispatcher.request_crack(
            hash_value="aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM",
            source_agent="orchestrator",
            username="admin",
            domain="contoso.local",
        )

        assert len(task_queue_items) == 1
        assert "cracker" in task_queue_items[0][0]

        # Simulate worker polling and processing
        task_json = task_queue_items[0][1]
        task = TaskMessage.model_validate_json(task_json)

        assert task.task_id == task_id
        assert task.payload["hash_value"] == "aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"

        # Worker sends result back
        worker_queue = RedisTaskQueue("redis://localhost:6379")
        worker_queue._client = mock_redis_client
        worker_queue._connected = True

        await worker_queue.send_result(
            task_id=task_id,
            success=True,
            result={"password": "CrackedPassword123"},  # pragma: allowlist secret
            worker_pod="cracker-0",
        )

        assert len(result_queue_items) == 1

        # Orchestrator gets result
        result_json = result_queue_items[0][1]
        mock_redis_client.brpop.return_value = (
            f"ares:results:{task_id}",
            result_json,
        )

        result = await dispatcher.wait_for_redis_result(task_id, timeout=5.0)

        assert result is not None
        assert result.success is True
        assert result.result["password"] == "CrackedPassword123"  # pragma: allowlist secret

        worker_queue._connected = False
        dispatcher._running = False

    @pytest.mark.asyncio
    async def test_multi_role_parallel_tasks(self, mock_redis_client):
        """Test submitting tasks to multiple workers in parallel."""
        submitted_tasks = {}

        async def track_lpush(key, value):
            role = key.split(":")[-1]
            if role not in submitted_tasks:
                submitted_tasks[role] = []
            submitted_tasks[role].append(json.loads(value))
            return 1

        mock_redis_client.lpush = AsyncMock(side_effect=track_lpush)

        # Create dispatcher with manual mocking
        from ares.core.models import SharedRedTeamState

        dispatcher = RedTeamDispatcher(redis_url="redis://localhost:6379")
        dispatcher._redis_client = mock_redis_client
        dispatcher._shared_state = SharedRedTeamState(operation_id="multi-role-test")
        dispatcher._running = True
        if dispatcher._task_queue:
            dispatcher._task_queue._client = mock_redis_client
            dispatcher._task_queue._connected = True

        # Submit tasks to different workers concurrently
        tasks = await asyncio.gather(
            dispatcher.request_crack(
                hash_value="hash1",
                hash_type="NTLM",
                source_agent="orchestrator",
            ),
            dispatcher.request_lateral_movement(
                target_host="192.168.56.10",
                username="admin",
                password="TestPass123!",  # pragma: allowlist secret
                source_agent="orchestrator",
            ),
            dispatcher.request_acl_analysis(
                target_user="user1",
                domain="contoso.local",
                source_agent="orchestrator",
            ),
        )

        # Verify tasks went to different queues
        assert "cracker" in submitted_tasks
        assert "lateral" in submitted_tasks
        assert "acl" in submitted_tasks

        # All task IDs should be unique
        assert len(set(tasks)) == 3

        dispatcher._running = False

    @pytest.mark.asyncio
    async def test_worker_fallback_to_inmemory(self, mock_redis_client):
        """Test dispatcher falls back to in-memory queue without Redis URL."""
        dispatcher = RedTeamDispatcher()  # No redis_url
        await dispatcher.start("fallback-test")

        # Register a cracker agent for in-memory routing
        agent_info = AgentInfo(
            name="cracker-agent",
            pod_name="cracker-0",
            role=AgentRole.CRACKER,
            capabilities={"hashcat"},
        )
        await dispatcher.register(agent_info)

        # Submit task - should use in-memory queue
        task_id = await dispatcher.request_crack(
            hash_value="test_hash",
            hash_type="NTLM",
            source_agent="orchestrator",
        )

        assert task_id != ""

        # Message should be in in-memory queue
        messages = await dispatcher.get_messages("cracker-agent")
        assert len(messages) == 1
        assert messages[0].type.value == "crack_request"

        await dispatcher.stop()


# ============================================================================
# Error Handling Tests
# ============================================================================


class TestErrorHandling:
    """Tests for error handling in Redis task queue flow."""

    @pytest.mark.asyncio
    async def test_redis_connection_failure_graceful(self, mock_redis_client):
        """Test graceful handling of Redis connection failure."""
        # Test that dispatcher can be created and initialized
        # even if Redis connection would fail at runtime
        dispatcher = RedTeamDispatcher(redis_url="redis://localhost:6379")

        # Task queue should be created
        assert dispatcher._task_queue is not None

    @pytest.mark.asyncio
    async def test_task_timeout(self, mock_redis_client):
        """Test handling of task timeout."""
        mock_redis_client.brpop.return_value = None  # Simulate timeout

        queue = RedisTaskQueue("redis://localhost:6379")
        queue._client = mock_redis_client
        queue._connected = True

        result = await queue.wait_for_result("nonexistent_task", timeout=1.0)

        assert result is None

        queue._connected = False

    @pytest.mark.asyncio
    async def test_worker_unsupported_task_type(self, task_queue, mock_agent, mock_redis_client):
        """Test worker handles unsupported task type."""
        worker = RedisWorkerAgent(
            role=AgentRole.CRACKER,
            task_queue=task_queue,
            agent=mock_agent,
            agent_name="cracker-agent",
        )

        # Create task that generates None prompt (like command type)
        task = TaskMessage(
            task_id="unsupported_001",
            task_type="command",
            source_agent="orchestrator",
            target_agent="cracker",
            payload={"command": "whoami"},
        )

        # This should be handled by _execute_command_task, not agent
        with patch.object(worker, "_execute_command_task", new_callable=AsyncMock) as mock_exec:
            await worker._process_task(task)
            mock_exec.assert_called_once_with(task)


# ============================================================================
# State Persistence Tests
# ============================================================================


class TestStatePersistence:
    """Tests for state persistence with Redis."""

    @pytest.mark.asyncio
    async def test_heartbeat_expiry(self, task_queue, mock_redis_client):
        """Test heartbeat has correct TTL."""
        await task_queue.send_heartbeat(
            agent_name="test-agent",
            status="idle",
        )

        # Verify set was called with expiry
        call_args = mock_redis_client.set.call_args
        assert call_args.kwargs.get("ex") == 60  # HEARTBEAT_TTL

    @pytest.mark.asyncio
    async def test_result_expiry(self, task_queue, mock_redis_client):
        """Test result has correct TTL."""
        await task_queue.send_result(
            task_id="test_task",
            success=True,
            result={},
        )

        # Verify expire was called with correct TTL (24 hours)
        mock_redis_client.expire.assert_called_with("ares:results:test_task", 86400)


# ============================================================================
# Command Task Execution Tests
# ============================================================================


class TestExecuteCommandTask:
    """Tests for _execute_command_task local execution."""

    @pytest.mark.asyncio
    async def test_execute_command_success(self, task_queue, mock_agent, mock_redis_client):
        """Test successful command execution locally."""
        worker = RedisWorkerAgent(
            role=AgentRole.CRACKER,
            task_queue=task_queue,
            agent=mock_agent,
            agent_name="cracker-agent",
            pod_name="cracker-0",
        )

        task = TaskMessage(
            task_id="cmd_001",
            task_type="command",
            source_agent="orchestrator",
            target_agent="worker",
            payload={
                "command": "whoami",
                "working_directory": "/tmp",
                "timeout_seconds": 60,
            },
        )

        mock_result = MagicMock()
        mock_result.stdout = "root\n"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            await worker._execute_command_task(task)
            mock_run.assert_called_once()

        call_args = mock_redis_client.lpush.call_args
        result_json = call_args[0][1]
        result_data = json.loads(result_json)
        assert result_data["success"] is True
        assert result_data["result"]["stdout"] == "root\n"
        assert result_data["result"]["return_code"] == 0

    @pytest.mark.asyncio
    async def test_execute_command_uses_working_directory(
        self, task_queue, mock_agent, mock_redis_client
    ):
        """Test command execution respects working directory."""
        worker = RedisWorkerAgent(
            role=AgentRole.CRACKER,
            task_queue=task_queue,
            agent=mock_agent,
            agent_name="cracker-agent",
            pod_name="cracker-0",
        )

        task = TaskMessage(
            task_id="cmd_002",
            task_type="command",
            source_agent="orchestrator",
            target_agent="worker",
            payload={
                "command": "pwd",
                "working_directory": "/tmp",
                "timeout_seconds": 10,
            },
        )

        mock_result = MagicMock()
        mock_result.stdout = "/tmp\n"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            await worker._execute_command_task(task)

        _, kwargs = mock_run.call_args
        assert kwargs["cwd"] == "/tmp"
        assert kwargs["shell"] is True

    @pytest.mark.asyncio
    async def test_execute_command_timeout(self, task_queue, mock_agent, mock_redis_client):
        """Test handling of command timeout."""
        import subprocess

        worker = RedisWorkerAgent(
            role=AgentRole.CRACKER,
            task_queue=task_queue,
            agent=mock_agent,
            agent_name="cracker-agent",
            pod_name="cracker-0",
        )

        task = TaskMessage(
            task_id="cmd_004",
            task_type="command",
            source_agent="orchestrator",
            target_agent="worker",
            payload={
                "command": "sleep 1000",
                "timeout_seconds": 5,
            },
        )

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("command", 5)):
            await worker._execute_command_task(task)

        call_args = mock_redis_client.lpush.call_args
        result_json = call_args[0][1]
        result_data = json.loads(result_json)
        assert result_data["success"] is False
        assert "timed out" in result_data["error"]

    @pytest.mark.asyncio
    async def test_execute_command_general_exception(
        self, task_queue, mock_agent, mock_redis_client
    ):
        """Test handling of general execution exception."""
        worker = RedisWorkerAgent(
            role=AgentRole.CRACKER,
            task_queue=task_queue,
            agent=mock_agent,
            agent_name="cracker-agent",
            pod_name="cracker-0",
        )

        task = TaskMessage(
            task_id="cmd_005",
            task_type="command",
            source_agent="orchestrator",
            target_agent="worker",
            payload={"command": "whoami"},
        )

        with patch("subprocess.run", side_effect=Exception("Unexpected error")):
            await worker._execute_command_task(task)

        call_args = mock_redis_client.lpush.call_args
        result_json = call_args[0][1]
        result_data = json.loads(result_json)
        assert result_data["success"] is False
        assert "Unexpected error" in result_data["error"]

    @pytest.mark.asyncio
    async def test_execute_command_with_nonzero_exit(
        self, task_queue, mock_agent, mock_redis_client
    ):
        """Test command that returns non-zero exit code."""
        worker = RedisWorkerAgent(
            role=AgentRole.CRACKER,
            task_queue=task_queue,
            agent=mock_agent,
            agent_name="cracker-agent",
            pod_name="cracker-0",
        )

        task = TaskMessage(
            task_id="cmd_007",
            task_type="command",
            source_agent="orchestrator",
            target_agent="worker",
            payload={"command": "ls /nonexistent"},
        )

        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = "ls: cannot access '/nonexistent': No such file or directory"
        mock_result.returncode = 2

        with patch("subprocess.run", return_value=mock_result):
            await worker._execute_command_task(task)

        call_args = mock_redis_client.lpush.call_args
        result_json = call_args[0][1]
        result_data = json.loads(result_json)
        assert result_data["success"] is True
        assert result_data["result"]["return_code"] == 2
        assert "No such file or directory" in result_data["result"]["stderr"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
