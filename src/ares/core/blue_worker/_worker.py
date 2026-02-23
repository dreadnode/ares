"""Blue team worker agent for multi-agent investigations.

Each worker runs in-process via asyncio.create_task(). It receives
a pre-configured dreadnode Agent and processes tasks dispatched by
the BlueTeamDispatcher.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.blue_worker.prompts import generate_blue_task_prompt
from ares.core.models import BlueRole, BlueTaskInfo, BlueTaskType, TaskStatus

if TYPE_CHECKING:
    from dreadnode.agent import Agent

    from ares.core.blue_dispatcher import BlueTeamDispatcher
    from ares.tools.blue.callbacks import BlueWorkerCallbackTools


class BlueWorkerAgent:
    """In-process worker that processes blue team investigation tasks.

    Each worker:
    1. Receives a task from the dispatcher
    2. Generates a task prompt
    3. Runs the dreadnode agent with that prompt
    4. Reports results back to the dispatcher

    Workers are started via start() which creates an asyncio task.
    They process a single task at a time (synchronous from the
    orchestrator's perspective when using wait_for_result=True).

    Attributes:
        role: The worker's specialized role.
        agent: Pre-configured dreadnode Agent with role-specific tools.
        agent_name: Human-readable agent name for logging.
        investigation_id: Current investigation ID.
        dispatcher: Reference to the dispatcher for result reporting.
        callback_tools: Worker callback tools (for completion event).
    """

    def __init__(
        self,
        role: BlueRole,
        agent: Agent,
        agent_name: str,
        investigation_id: str,
        dispatcher: BlueTeamDispatcher,
        callback_tools: BlueWorkerCallbackTools,
    ) -> None:
        self.role = role
        self.agent = agent
        self.agent_name = agent_name
        self.investigation_id = investigation_id
        self.dispatcher = dispatcher
        self.callback_tools = callback_tools
        self._task: asyncio.Task | None = None
        self._should_stop = False

    async def process_task(self, task: BlueTaskInfo) -> dict[str, Any]:
        """Process a single task.

        Generates the task prompt, runs the agent, and returns the
        result from the callback tools.

        Args:
            task: The task to process.

        Returns:
            Result dict from the worker's completion callback.
        """
        logger.info(
            f"[{self.agent_name}] Processing task {task.task_id}: "
            f"{task.task_type.value}"
        )

        # Get current state summary for context
        state_summary = None
        try:
            state_summary = await self.dispatcher.get_investigation_summary()
        except Exception as e:
            logger.warning(f"[{self.agent_name}] Failed to get state summary: {e}")

        # Generate task prompt
        prompt = generate_blue_task_prompt(
            task_type=task.task_type,
            params=task.params,
            shared_state_summary=state_summary,
        )

        # Set up completion event
        completion_event = asyncio.Event()
        self.callback_tools.set_completion_event(completion_event)

        # Run the agent
        try:
            logger.info(f"[{self.agent_name}] Starting agent.run() for task {task.task_id}")
            await self.agent.run(prompt)

            # Check if the agent called a completion callback
            if completion_event.is_set():
                result = self.callback_tools.result_data
                logger.info(
                    f"[{self.agent_name}] Task {task.task_id} completed via callback"
                )
                return result
            else:
                # Agent finished without calling callback (hit max_steps or stop condition)
                logger.warning(
                    f"[{self.agent_name}] Task {task.task_id} ended without completion callback"
                )
                return {
                    "type": self.role.value,
                    "summary": "Agent completed without explicit completion signal",
                    "partial": True,
                }

        except asyncio.CancelledError:
            logger.info(f"[{self.agent_name}] Task {task.task_id} cancelled")
            return {
                "type": self.role.value,
                "error": "Task cancelled",
                "partial": True,
            }
        except Exception as e:
            logger.error(f"[{self.agent_name}] Task {task.task_id} failed: {e}")
            return {
                "type": self.role.value,
                "error": str(e),
                "partial": True,
            }

    async def execute_and_report(self, task: BlueTaskInfo) -> None:
        """Execute a task and report results to the dispatcher.

        This is the method called by the orchestrator's dispatch tools.
        It processes the task and notifies the dispatcher of the result.

        Args:
            task: The task to process.
        """
        try:
            result = await self.process_task(task)
            await self.dispatcher.notify_task_result(
                task_id=task.task_id,
                success=not result.get("error"),
                result=result,
                error=result.get("error"),
            )
        except Exception as e:
            logger.error(f"[{self.agent_name}] Failed to report task {task.task_id}: {e}")
            await self.dispatcher.notify_task_result(
                task_id=task.task_id,
                success=False,
                error=str(e),
            )

    def start_task(self, task: BlueTaskInfo) -> asyncio.Task:
        """Start processing a task in the background.

        Creates an asyncio task that processes and reports the result.

        Args:
            task: The task to process.

        Returns:
            The asyncio.Task for the running work.
        """
        self._task = asyncio.create_task(
            self.execute_and_report(task),
            name=f"{self.agent_name}:{task.task_id}",
        )
        return self._task

    async def stop(self) -> None:
        """Stop the worker and cancel any running task."""
        self._should_stop = True
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(self._task), timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass
        logger.info(f"[{self.agent_name}] Stopped")
