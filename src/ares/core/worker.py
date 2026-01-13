"""Worker agent loop for multi-agent red team operations.

This module provides the worker loop that specialized agents use to:
- Poll the dispatcher for assigned tasks
- Process tasks using their specialized toolsets
- Report results back to the orchestrator
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


# Mapping of message types to task prompt generators
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
) -> None:
    """
    Run a specialized worker agent.

    Args:
        role: The agent role (cracker, acl, privesc, lateral, poisoning, atomic).
        operation_id: The operation ID to join (optional - will discover if not provided).
        redis_url: Redis URL for dispatcher connection.
        model: LLM model to use.
        max_steps: Override default max steps for role.
        discover_operation: If True and operation_id is None/empty, discover from Redis.
        discovery_timeout: Max seconds to wait for operation discovery.
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
    logger.info(f"Pod: {pod_name}, Redis: {redis_url}")

    # Create dispatcher and connect to Redis
    dispatcher = RedTeamDispatcher(redis_url=redis_url)
    await dispatcher.start(operation_id)

    # Try to recover existing state
    recovered = await dispatcher.recover_state(operation_id)
    if recovered:
        logger.info(f"Recovered state: {len(recovered.all_credentials)} credentials")

    shared_state = dispatcher.shared_state

    # Create agent info and register
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

    # Create and run worker
    worker = WorkerAgent(
        role=role,
        dispatcher=dispatcher,
        agent=agent,
        agent_name=agent_info.name,
    )

    try:
        await worker.start()
    finally:
        await dispatcher.stop()
        logger.info(f"Worker {agent_info.name} shutdown complete")


__all__ = [
    "WorkerAgent",
    "discover_active_operation",
    "run_worker",
]
