"""Worker agent loop for multi-agent red team operations.

This module provides the worker loop that specialized agents use to:
- Poll the Redis task queue for assigned tasks (Kubernetes multi-pod mode)
- Poll the dispatcher for assigned tasks (single-process fallback mode)
- Process tasks using their specialized toolsets
- Report results back to the orchestrator via Redis
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.dispatcher import RedTeamDispatcher
from ares.core.factories.red_agents import create_agent_info, create_specialized_agent
from ares.core.messages import (
    AgentMessage,
    DomainAdminAchieved,
    GoldenTicketForged,
    MessageType,
    OperationComplete,
)
from ares.core.models import AgentRole  # noqa: TC001 - used at runtime
from ares.core.task_queue import RedisTaskQueue, TaskMessage

if TYPE_CHECKING:
    from dreadnode.agent import Agent


async def discover_active_operation(redis_url: str, max_wait: int = 300) -> str | None:
    """
    Discover an active operation from Redis by scanning for operation keys.

    Waits up to max_wait seconds for an operation to appear.
    Returns the most recently checkpointed operation ID.

    Args:
        redis_url: Redis connection URL
        max_wait: Maximum seconds to wait for an operation (default: 300 = 5 minutes)

    Returns:
        Operation ID if found, None otherwise
    """
    try:
        import redis.asyncio as redis_async
    except ImportError:
        logger.error("redis package not installed, cannot discover operations")
        return None

    start_time = asyncio.get_event_loop().time()

    while True:
        client = None
        try:
            client = redis_async.from_url(redis_url)
            await client.ping()

            # Scan for operation state keys
            operations: list[tuple[str, datetime]] = []
            async for key in client.scan_iter("ares:operation:*:state"):
                # Extract operation ID from key: ares:operation:<op_id>:state
                parts = key.decode().split(":")
                if len(parts) >= 3:
                    op_id = parts[2]

                    # Get checkpoint time to find most recent operation
                    time_key = f"ares:operation:{op_id}:checkpoint_time"
                    checkpoint_data = await client.get(time_key)

                    if checkpoint_data:
                        checkpoint_time = datetime.fromisoformat(checkpoint_data.decode())
                        operations.append((op_id, checkpoint_time))

            await client.aclose()

            if operations:
                # Return the most recently checkpointed operation
                operations.sort(key=lambda x: x[1], reverse=True)
                operation_id = operations[0][0]
                logger.info(f"Discovered active operation: {operation_id}")
                return operation_id

            # Check if we've exceeded max wait time
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed >= max_wait:
                logger.warning(f"No active operations found after {max_wait}s")
                return None

            # Wait before retrying
            logger.debug("No operations found, waiting 10s before retry...")
            await asyncio.sleep(10)

        except Exception as e:
            logger.warning(f"Failed to scan for operations: {e}")
            if client:
                try:
                    await client.aclose()
                except Exception:
                    pass
            await asyncio.sleep(5)


# Mapping of message types to task prompt generators (for dispatcher-based messaging)
TASK_PROMPTS: dict[MessageType, callable] = {
    MessageType.CRACK_REQUEST: lambda msg: (
        f"Crack this hash for user {msg.username}@{msg.domain}:\n"
        f"Hash: {msg.hash_value}\n"
        f"Type: {msg.hash_type}\n"
        f"Wordlist: {msg.wordlist}\n"
        f"Task ID: {msg.task_id}\n\n"
        "Use hashcat or john to crack this hash. Report the result using task_complete."
    ),
    MessageType.LATERAL_REQUEST: lambda msg: (
        f"Perform lateral movement to {msg.target_host}:\n"
        f"Username: {msg.domain}\\{msg.username}\n"
        f"Credential: {'password' if msg.password else 'hash'}\n"
        f"Method: {msg.method or 'auto-select'}\n"
        f"Task ID: {msg.task_id}\n\n"
        "Try to establish access using psexec, evil-winrm, or wmi. "
        "If successful, run secretsdump to harvest credentials. "
        "Report the result using task_complete."
    ),
    MessageType.ACL_ANALYSIS_REQUEST: lambda msg: (
        f"Analyze ACLs and find attack paths:\n"
        f"Target User: {msg.target_user}\n"
        f"Domain: {msg.domain}\n"
        f"Find Path To: {msg.find_path_to}\n"
        f"Task ID: {msg.task_id}\n\n"
        "Run BloodHound collection if needed, then find shortest paths. "
        "Execute any viable ACL abuse attacks. Report the result using task_complete."
    ),
    MessageType.EXPLOIT_REQUEST: lambda msg: (
        f"Exploit vulnerability:\n"
        f"Type: {msg.vuln_type}\n"
        f"Target: {msg.target}\n"
        f"Vuln ID: {msg.vuln_id}\n"
        f"Params: {msg.params}\n"
        f"Task ID: {msg.task_id}\n\n"
        "Execute the appropriate exploitation technique. "
        "Report any credentials or access obtained using task_complete."
    ),
    MessageType.POISON_REQUEST: lambda msg: (
        f"Start network poisoning:\n"
        f"Interface: {msg.interface}\n"
        f"Techniques: {', '.join(msg.techniques)}\n"
        f"Duration: {msg.duration}s\n"
        f"Task ID: {msg.task_id}\n\n"
        "Start responder/mitm6 and capture any hashes. "
        "Report captured credentials using task_complete."
    ),
    MessageType.ATOMIC_TEST_REQUEST: lambda msg: (
        f"Execute Atomic Red Team test:\n"
        f"Technique: {msg.technique_id}\n"
        f"Test Number: {msg.test_number}\n"
        f"Input Args: {msg.input_args}\n"
        f"Task ID: {msg.task_id}\n\n"
        "Execute the atomic test and report results using task_complete."
    ),
}


def generate_prompt_from_task(task: TaskMessage) -> str | None:
    """
    Generate agent prompt from Redis TaskMessage.

    This is used when polling tasks from Redis queue instead of dispatcher.

    Args:
        task: TaskMessage from Redis queue

    Returns:
        Prompt string for the agent
    """
    payload = task.payload

    if task.task_type == "crack":
        return (
            f"Crack this hash for user {payload.get('username', 'unknown')}"
            f"@{payload.get('domain', '')}:\n"
            f"Hash: {payload['hash_value']}\n"
            f"Type: {payload['hash_type']}\n"
            f"Wordlist: {payload.get('wordlist', 'rockyou.txt')}\n"
            f"Task ID: {task.task_id}\n\n"
            "Use hashcat or john to crack. Report when done."
        )

    if task.task_type == "lateral":
        cred_type = "password" if payload.get("password") else "hash"
        return (
            f"Perform lateral movement to {payload['target_host']}:\n"
            f"Username: {payload.get('domain', '')}\\{payload['username']}\n"
            f"Credential: {cred_type}\n"
            f"Method: {payload.get('method') or 'auto-select'}\n"
            f"Task ID: {task.task_id}\n\n"
            "Establish access and run secretsdump if successful."
        )

    if task.task_type == "acl_analysis":
        return (
            f"Analyze ACLs and find attack paths:\n"
            f"Target User: {payload['target_user']}\n"
            f"Domain: {payload['domain']}\n"
            f"Find Path To: {payload.get('find_path_to', 'Domain Admins')}\n"
            f"Task ID: {task.task_id}\n\n"
            "Run BloodHound collection if needed. Execute viable ACL abuse attacks."
        )

    if task.task_type == "exploit":
        return (
            f"Exploit vulnerability:\n"
            f"Type: {payload['vuln_type']}\n"
            f"Target: {payload['target']}\n"
            f"Vuln ID: {payload.get('vuln_id', 'unknown')}\n"
            f"Params: {payload}\n"
            f"Task ID: {task.task_id}\n\n"
            "Execute the exploitation technique. Report credentials obtained."
        )

    if task.task_type == "poison":
        techniques = payload.get("techniques", ["LLMNR", "NBT-NS"])
        return (
            f"Start network poisoning:\n"
            f"Interface: {payload.get('interface', 'eth0')}\n"
            f"Techniques: {', '.join(techniques)}\n"
            f"Duration: {payload.get('duration', 300)}s\n"
            f"Task ID: {task.task_id}\n\n"
            "Start responder/mitm6 and capture hashes."
        )

    if task.task_type == "atomic":
        return (
            f"Execute Atomic Red Team test:\n"
            f"Technique: {payload.get('technique_id', 'unknown')}\n"
            f"Test Number: {payload.get('test_number', 1)}\n"
            f"Input Args: {payload.get('input_args', {})}\n"
            f"Task ID: {task.task_id}\n\n"
            "Execute the atomic test and report results."
        )

    # "command" tasks are handled specially - executed directly, not via agent
    if task.task_type == "command":
        # Return None to signal direct execution
        return None

    # Generic fallback
    return f"Execute task: {task.task_type}\nPayload: {payload}\nTask ID: {task.task_id}"


class RedisWorkerAgent:
    """
    Worker agent that polls Redis task queue for work.

    This is the preferred worker mode for Kubernetes multi-pod deployments
    where in-memory queues cannot be shared across pods.
    """

    def __init__(
        self,
        role: AgentRole,
        task_queue: RedisTaskQueue,
        agent: Agent,
        agent_name: str,
        pod_name: str | None = None,
    ):
        self.role = role
        self.task_queue = task_queue
        self.agent = agent
        self.agent_name = agent_name
        self.pod_name = pod_name or os.environ.get("HOSTNAME", "unknown")
        self._running = False
        self._current_task: str | None = None
        self._tasks_completed = 0

    async def start(self) -> None:
        """Start the Redis worker loop."""
        self._running = True
        logger.info(f"Redis worker {self.agent_name} starting...")

        # Start heartbeat task
        heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        try:
            await self._worker_loop()
        finally:
            self._running = False
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass

    async def stop(self) -> None:
        """Stop the worker loop."""
        self._running = False
        logger.info(f"Redis worker {self.agent_name} stopping...")

    async def _worker_loop(self) -> None:
        """Main worker loop - poll Redis for tasks."""
        logger.info(f"Worker {self.agent_name} polling Redis for {self.role.value} tasks")

        while self._running:
            try:
                # Poll Redis queue (blocks up to 5 seconds)
                task = await self.task_queue.poll_task(
                    role=self.role.value,
                    timeout=5.0,
                )

                if task:
                    await self._process_task(task)

            except asyncio.CancelledError:  # noqa: PERF203
                break
            except Exception as e:
                logger.error(f"Worker loop error: {e}")
                await asyncio.sleep(5)

    async def _process_task(self, task: TaskMessage) -> None:
        """Process a task from the Redis queue."""
        self._current_task = task.task_id
        logger.info(f"[{self.agent_name}] Processing task {task.task_id}")

        try:
            # Handle "command" tasks directly via subprocess (no agent needed)
            if task.task_type == "command":
                await self._execute_command_task(task)
                return

            # Generate prompt from task
            prompt = generate_prompt_from_task(task)

            if prompt is None:
                # Task type not supported for agent execution
                await self.task_queue.send_result(
                    task_id=task.task_id,
                    success=False,
                    error=f"Unsupported task type: {task.task_type}",
                    worker_pod=self.pod_name,
                )
                return

            # Run agent
            logger.info(f"[{self.agent_name}] Running agent for task {task.task_id}")
            result = await self.agent.run(prompt)
            result_text = self._extract_result(result)

            # Send success result via Redis
            await self.task_queue.send_result(
                task_id=task.task_id,
                success=True,
                result={"output": result_text, "task_type": task.task_type},
                worker_pod=self.pod_name,
            )
            self._tasks_completed += 1
            logger.success(f"[{self.agent_name}] Task {task.task_id} completed")

        except Exception as e:
            logger.error(f"[{self.agent_name}] Task {task.task_id} failed: {e}")
            await self.task_queue.send_result(
                task_id=task.task_id,
                success=False,
                error=str(e),
                worker_pod=self.pod_name,
            )
        finally:
            self._current_task = None

    async def _execute_command_task(self, task: TaskMessage) -> None:
        """Execute a command task directly via subprocess."""
        import subprocess

        payload = task.payload
        command = payload.get("command", "")
        working_dir = payload.get("working_directory", "/tmp")  # noqa: S108  # nosec B108
        timeout = payload.get("timeout_seconds", 300)

        logger.info(f"[{self.agent_name}] Executing command: {command[:100]}...")

        try:
            result = subprocess.run(  # noqa: S602, ASYNC221  # nosec B602
                command,
                shell=True,  # nosec B602
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=working_dir,
                check=False,
            )

            await self.task_queue.send_result(
                task_id=task.task_id,
                success=True,
                result={
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "return_code": result.returncode,
                },
                worker_pod=self.pod_name,
            )
            self._tasks_completed += 1
            logger.success(f"[{self.agent_name}] Command completed: exit code {result.returncode}")

        except subprocess.TimeoutExpired:
            await self.task_queue.send_result(
                task_id=task.task_id,
                success=False,
                error=f"Command timed out after {timeout}s",
                worker_pod=self.pod_name,
            )
        except Exception as e:
            await self.task_queue.send_result(
                task_id=task.task_id,
                success=False,
                error=str(e),
                worker_pod=self.pod_name,
            )

    def _extract_result(self, result: Any) -> str:
        """Extract text result from agent output."""
        if hasattr(result, "output"):
            return str(result.output)
        if hasattr(result, "content"):
            return str(result.content)
        return str(result)

    async def _heartbeat_loop(self) -> None:
        """Send heartbeats to Redis."""
        while self._running:
            try:
                status = "busy" if self._current_task else "idle"
                await self.task_queue.send_heartbeat(
                    agent_name=self.agent_name,
                    status=status,
                    current_task=self._current_task,
                    pod_name=self.pod_name,
                )
            except Exception as e:
                logger.warning(f"Heartbeat failed: {e}")

            await asyncio.sleep(15)


class WorkerAgent:
    """
    Worker agent that processes tasks from the dispatcher.

    This class wraps a specialized Dreadnode Agent and adds:
    - Dispatcher integration for receiving tasks
    - Heartbeat monitoring
    - Task completion reporting
    """

    def __init__(
        self,
        role: AgentRole,
        dispatcher: RedTeamDispatcher,
        agent: Agent,
        agent_name: str,
    ):
        self.role = role
        self.dispatcher = dispatcher
        self.agent = agent
        self.agent_name = agent_name
        self._running = False
        self._current_task: str | None = None
        self._tasks_completed = 0

    async def start(self) -> None:
        """Start the worker loop."""
        self._running = True
        logger.info(f"Worker {self.agent_name} starting...")

        # Start heartbeat task
        heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        try:
            await self._worker_loop()
        finally:
            self._running = False
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass

    async def stop(self) -> None:
        """Stop the worker loop."""
        self._running = False
        logger.info(f"Worker {self.agent_name} stopping...")

    async def _worker_loop(self) -> None:
        """Main worker loop - poll for messages and process tasks."""
        logger.info(f"Worker {self.agent_name} entering main loop")

        while self._running:
            try:
                # Poll for messages
                messages = await self.dispatcher.get_messages(self.agent_name, timeout=1.0)

                for msg in messages:
                    await self._handle_message(msg)

                # Small sleep to prevent busy-waiting
                await asyncio.sleep(0.5)

            except asyncio.CancelledError:  # noqa: PERF203
                break
            except Exception as e:
                logger.error(f"Worker loop error: {e}")
                await asyncio.sleep(5)  # Back off on error

    async def _handle_message(self, msg: AgentMessage) -> None:
        """Handle an incoming message."""
        logger.info(f"[{self.agent_name}] Received message: {msg.type}")

        # Check for operation-level messages
        if isinstance(msg, DomainAdminAchieved):
            logger.success(
                f"🎯 Domain Admin achieved by {msg.source_agent}: {msg.domain}\\{msg.username}"
            )
            return

        if isinstance(msg, GoldenTicketForged):
            logger.success(f"🎫 Golden Ticket forged for {msg.domain}")
            return

        if isinstance(msg, OperationComplete):
            logger.info(f"Operation complete: {msg.summary}")
            self._running = False
            return

        # Route task requests to agent
        await self._process_task(msg)

    async def _process_task(self, msg: AgentMessage) -> None:
        """Process a task request message."""
        task_id = getattr(msg, "task_id", None)
        if not task_id:
            logger.warning(f"Message {msg.type} has no task_id, skipping")
            return

        self._current_task = task_id
        logger.info(f"[{self.agent_name}] Processing task {task_id}")

        try:
            # Generate prompt based on message type
            prompt = self._generate_task_prompt(msg)
            if not prompt:
                logger.warning(f"No prompt generator for message type {msg.type}")
                await self.dispatcher.complete_task(
                    task_id=task_id,
                    success=False,
                    error=f"Unsupported message type: {msg.type}",
                    source_agent=self.agent_name,
                )
                return

            # Run the agent
            logger.info(f"[{self.agent_name}] Running agent for task {task_id}")
            result = await self.agent.run(prompt)

            # Extract result from agent output
            result_text = self._extract_result(result)

            # Report completion
            await self.dispatcher.complete_task(
                task_id=task_id,
                success=True,
                result={"output": result_text, "task_type": msg.type.value},
                source_agent=self.agent_name,
            )
            self._tasks_completed += 1
            logger.success(f"[{self.agent_name}] Task {task_id} completed")

        except Exception as e:
            logger.error(f"[{self.agent_name}] Task {task_id} failed: {e}")
            await self.dispatcher.complete_task(
                task_id=task_id,
                success=False,
                error=str(e),
                source_agent=self.agent_name,
            )

        finally:
            self._current_task = None

    def _generate_task_prompt(self, msg: AgentMessage) -> str | None:
        """Generate a prompt for the agent based on message type."""
        prompt_generator = TASK_PROMPTS.get(msg.type)
        if prompt_generator:
            return prompt_generator(msg)
        return None

    def _extract_result(self, result: Any) -> str:
        """Extract text result from agent output."""
        if hasattr(result, "output"):
            return str(result.output)
        if hasattr(result, "content"):
            return str(result.content)
        return str(result)

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats to dispatcher."""
        while self._running:
            try:
                status = "busy" if self._current_task else "idle"
                await self.dispatcher.heartbeat(
                    agent_name=self.agent_name,
                    status=status,
                    current_task=self._current_task,
                )
            except Exception as e:
                logger.warning(f"Heartbeat failed: {e}")

            await asyncio.sleep(15)


async def run_worker(
    role: AgentRole,
    operation_id: str | None = None,
    redis_url: str = "redis://localhost:6379",
    model: str = "claude-sonnet-4-20250514",
    max_steps: int | None = None,
    discover_operation: bool = True,
    discovery_timeout: int = 300,
    use_redis_queue: bool = True,
) -> None:
    """
    Run a specialized worker agent.

    In Kubernetes multi-pod mode (use_redis_queue=True), uses Redis task queues
    for cross-pod communication. In single-process mode (use_redis_queue=False),
    uses in-memory dispatcher queues.

    Args:
        role: The agent role (cracker, acl, privesc, lateral, poisoning, atomic).
        operation_id: The operation ID to join (optional - will discover if not provided).
        redis_url: Redis URL for task queue and state.
        model: LLM model to use.
        max_steps: Override default max steps for role.
        discover_operation: If True and operation_id is None/empty, discover from Redis.
        discovery_timeout: Max seconds to wait for operation discovery.
        use_redis_queue: If True, poll Redis queue for tasks (Kubernetes mode).
    """
    pod_name = os.environ.get("HOSTNAME", f"local-{role.value}")

    # Handle empty string operation IDs from k8s configmaps
    if operation_id == "":
        operation_id = None

    # Discover operation if not provided
    if operation_id is None and discover_operation:
        logger.info("No operation ID provided, scanning Redis for active operations...")
        operation_id = await discover_active_operation(redis_url, max_wait=discovery_timeout)

        if operation_id is None:
            logger.error("No active operation found and none specified")
            return

    if operation_id is None:
        logger.error("Operation ID required but not provided and discovery disabled")
        return

    logger.info(f"Starting {role.value} worker for operation {operation_id}")
    logger.info(f"Pod: {pod_name}, Redis: {redis_url}, Redis Queue: {use_redis_queue}")

    # Create Redis task queue for direct polling (Kubernetes mode)
    task_queue: RedisTaskQueue | None = None
    if use_redis_queue:
        task_queue = RedisTaskQueue(redis_url)
        await task_queue.connect()
        logger.info("Worker connected to Redis task queue")

    # Create dispatcher for state management and fallback messaging
    dispatcher = RedTeamDispatcher(redis_url=redis_url)
    await dispatcher.start(operation_id)

    # Try to recover existing state
    recovered = await dispatcher.recover_state(operation_id)
    if recovered:
        logger.info(f"Recovered state: {len(recovered.all_credentials)} credentials")

    shared_state = dispatcher.shared_state

    # Create agent info and register (even in Redis mode for state tracking)
    agent_info = create_agent_info(role, pod_name=pod_name)
    await dispatcher.register(agent_info)

    # Create the specialized agent
    agent = create_specialized_agent(
        role=role,
        model=model,
        shared_state=shared_state,
        dispatcher=dispatcher,
        pod_name=pod_name,
        max_steps=max_steps,
    )

    try:
        worker: RedisWorkerAgent | WorkerAgent
        if use_redis_queue and task_queue:
            # Kubernetes multi-pod mode: poll Redis queue directly
            worker = RedisWorkerAgent(
                role=role,
                task_queue=task_queue,
                agent=agent,
                agent_name=agent_info.name,
                pod_name=pod_name,
            )
            logger.info(f"Starting Redis worker for role {role.value}")
        else:
            # Single-process mode: use dispatcher in-memory queues
            worker = WorkerAgent(
                role=role,
                dispatcher=dispatcher,
                agent=agent,
                agent_name=agent_info.name,
            )
            logger.info(f"Starting dispatcher worker for role {role.value}")

        await worker.start()
    finally:
        if task_queue:
            await task_queue.disconnect()
        await dispatcher.stop()
        logger.info(f"Worker {agent_info.name} shutdown complete")


__all__ = [
    "RedisWorkerAgent",
    "WorkerAgent",
    "discover_active_operation",
    "generate_prompt_from_task",
    "run_worker",
]
