"""Worker agent loop for multi-agent red team operations.

This module provides the worker loop that specialized agents use to:
- Poll the dispatcher for assigned tasks
- Process tasks using their specialized toolsets
- Report results back to the orchestrator
"""

from __future__ import annotations

import asyncio
import os
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
    operation_id: str,
    redis_url: str = "redis://localhost:6379",
    model: str = "claude-sonnet-4-20250514",
    max_steps: int | None = None,
) -> None:
    """
    Run a specialized worker agent.

    Args:
        role: The agent role (cracker, acl, privesc, lateral, poisoning, atomic).
        operation_id: The operation ID to join.
        redis_url: Redis URL for dispatcher connection.
        model: LLM model to use.
        max_steps: Override default max steps for role.
    """
    pod_name = os.environ.get("HOSTNAME", f"local-{role.value}")

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
    "run_worker",
]
