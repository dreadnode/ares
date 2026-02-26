"""Redis-based blue team worker agent.

This module provides the worker loop that blue team agents use to:
- Discover active investigations from Redis
- Poll the Redis task queue for assigned tasks
- Process tasks using specialized toolsets (with MCP tools from Grafana)
- Report results back to the orchestrator via Redis
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.blue_worker.prompts import generate_blue_task_prompt
from ares.core.models import BlueRole, BlueTaskType

if TYPE_CHECKING:
    from dreadnode.agent import Agent

    from ares.core.blue_state_backend import BlueStateBackend
    from ares.core.blue_task_queue import BlueTaskMessage, BlueTaskQueue
    from ares.tools.blue.callbacks import BlueWorkerCallbackTools


class BlueRedisWorkerAgent:
    """Worker agent that polls Redis task queue for blue team tasks.

    This is the preferred worker mode for Kubernetes multi-pod deployments
    where workers run in separate pods from the orchestrator.

    Attributes:
        role: The worker's specialized role.
        task_queue: BlueTaskQueue for Redis task polling.
        agent: Pre-configured dreadnode Agent with role-specific tools.
        agent_name: Human-readable agent name for logging.
        investigation_id: Current investigation ID.
        pod_name: Kubernetes pod name.
        callback_tools: Callback tools for signaling completion.
        backend: BlueStateBackend for direct Redis persistence.
    """

    def __init__(
        self,
        role: BlueRole,
        task_queue: BlueTaskQueue,
        agent: Agent,
        agent_name: str,
        callback_tools: BlueWorkerCallbackTools,
        backend: BlueStateBackend,
        investigation_id: str,
        pod_name: str | None = None,
        redis_url: str | None = None,
    ):
        self.role = role
        self.task_queue = task_queue
        self.agent = agent
        self.agent_name = agent_name
        self.callback_tools = callback_tools
        self.backend = backend
        self.investigation_id = investigation_id
        self.pod_name = pod_name or os.environ.get("HOSTNAME", "unknown")
        self.redis_url = redis_url

        self._running = False
        self._current_task: str | None = None
        self._tasks_completed = 0

        # Threaded heartbeat to avoid blocking by sync tool execution
        self._heartbeat_thread: threading.Thread | None = None
        self._heartbeat_stop_event = threading.Event()

    async def start(self) -> None:
        """Start the Redis worker loop."""
        self._running = True
        self._heartbeat_stop_event.clear()
        logger.info(f"Blue Redis worker {self.agent_name} starting...")

        # Start heartbeat thread
        self._heartbeat_thread = threading.Thread(
            target=self._threaded_heartbeat_loop,
            name=f"{self.agent_name}-heartbeat",
            daemon=True,
        )
        self._heartbeat_thread.start()
        logger.debug(f"Heartbeat thread started for {self.agent_name}")

        try:
            await self._worker_loop()
        finally:
            self._running = False
            self._heartbeat_stop_event.set()
            if self._heartbeat_thread and self._heartbeat_thread.is_alive():
                self._heartbeat_thread.join(timeout=5.0)
                if self._heartbeat_thread.is_alive():
                    logger.warning(
                        f"Heartbeat thread for {self.agent_name} did not stop gracefully"
                    )

    async def stop(self) -> None:
        """Stop the worker loop."""
        self._running = False
        logger.info(f"Blue Redis worker {self.agent_name} stopping...")

    async def _worker_loop(self) -> None:
        """Main worker loop - poll Redis for tasks."""
        logger.info(
            f"Worker {self.agent_name} polling Redis for {self.role.value} tasks "
            f"(investigation={self.investigation_id})"
        )

        retry_delay = 1.0
        max_retry_delay = 60.0
        last_maintenance = time.monotonic()
        maintenance_interval = 15.0  # Ping Redis every 15s

        while self._running:
            try:
                # Periodic maintenance: ping/reconnect to detect stale connections
                if (time.monotonic() - last_maintenance) >= maintenance_interval:
                    last_maintenance = time.monotonic()
                    await self.task_queue.ping_or_reconnect()

                # Check if investigation is still active
                inv_alert = await self.task_queue.get_investigation_alert(self.investigation_id)
                if not inv_alert:
                    logger.info(
                        f"Investigation {self.investigation_id} no longer active, stopping worker"
                    )
                    break

                # Poll Redis queue (blocks up to 5 seconds)
                task = await self.task_queue.poll_task(
                    investigation_id=self.investigation_id,
                    role=self.role.value,
                    timeout=5.0,
                )

                if task:
                    await self._process_task(task)

                retry_delay = 1.0

            except asyncio.CancelledError:
                break
            except Exception as e:
                error_str = str(e).lower()
                is_connection_error = any(
                    keyword in error_str
                    for keyword in ["connection", "closed", "timeout", "broken pipe", "reset"]
                )

                if is_connection_error:
                    logger.warning(
                        f"Worker loop connection error, retrying in {retry_delay:.1f}s: {e}"
                    )
                    await asyncio.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, max_retry_delay)
                else:
                    logger.error(f"Worker loop error: {e}", exc_info=True)
                    await asyncio.sleep(5)
                    retry_delay = 1.0

    async def _process_task(self, task: BlueTaskMessage) -> None:
        """Process a task from the Redis queue."""
        self._current_task = task.task_id
        logger.info(f"[{self.agent_name}] Processing task {task.task_id} (type={task.task_type})")

        try:
            # Get task type enum
            try:
                task_type = BlueTaskType(task.task_type)
            except ValueError:
                logger.warning(f"Unknown task type: {task.task_type}")
                await self._send_error_result(task.task_id, f"Unknown task type: {task.task_type}")
                return

            # Get current state summary for context
            state_summary = await self._get_state_summary()

            # Generate task prompt
            prompt = generate_blue_task_prompt(
                task_type=task_type,
                params=task.params,
                shared_state_summary=state_summary,
            )

            # Set up completion event for callback tools
            completion_event = asyncio.Event()
            self.callback_tools.set_completion_event(completion_event)

            # Run the agent
            logger.info(f"[{self.agent_name}] Running agent for task {task.task_id}")
            await self.agent.run(prompt)

            # Check if agent completed via callback
            if completion_event.is_set():
                result = self.callback_tools.result_data
                logger.info(f"[{self.agent_name}] Task {task.task_id} completed via callback")
                await self._send_success_result(task.task_id, result)
            else:
                # Agent finished without callback (hit max_steps)
                logger.warning(
                    f"[{self.agent_name}] Task {task.task_id} ended without completion callback"
                )
                await self._send_success_result(
                    task.task_id,
                    {
                        "type": self.role.value,
                        "summary": "Agent completed without explicit completion signal",
                        "partial": True,
                    },
                )

            self._tasks_completed += 1

        except Exception as e:
            logger.error(f"[{self.agent_name}] Task {task.task_id} failed: {e}", exc_info=True)
            await self._send_error_result(task.task_id, str(e))

        finally:
            self._current_task = None

    async def _get_state_summary(self) -> dict[str, Any]:
        """Get current investigation state summary from Redis."""
        try:
            snapshot = await self.backend.snapshot()
            return {
                "investigation_id": self.investigation_id,
                "evidence_count": len(snapshot.get("evidence", [])),
                "techniques_identified": list(snapshot.get("techniques", set())),
                "hosts_investigated": list(snapshot.get("hosts", set())),
                "users_investigated": list(snapshot.get("users", set())),
                "stage": snapshot.get("meta", {}).get("stage", "triage"),
            }
        except Exception as e:
            logger.warning(f"Failed to get state summary: {e}")
            return {}

    async def _send_success_result(self, task_id: str, result: dict[str, Any]) -> None:
        """Send successful task result to Redis."""
        await self.task_queue.send_result(
            task_id=task_id,
            success=True,
            result=result,
            worker_pod=self.pod_name,
            agent_name=self.agent_name,
        )

    async def _send_error_result(self, task_id: str, error: str) -> None:
        """Send failed task result to Redis."""
        await self.task_queue.send_result(
            task_id=task_id,
            success=False,
            error=error,
            worker_pod=self.pod_name,
            agent_name=self.agent_name,
        )

    def _threaded_heartbeat_loop(self) -> None:
        """Send heartbeats from a dedicated thread to avoid blocking.

        Creates its own Redis client to avoid event loop conflicts with the
        main thread's client.
        """
        import json
        from datetime import datetime, timezone

        from ares.core.redis_client import create_redis_client

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        redis_client = None
        retry_delay = 1.0
        max_retry_delay = 60.0
        heartbeat_key = f"ares:blue:heartbeat:{self.agent_name}"
        heartbeat_ttl = 60

        async def connect_redis():
            """Create a Redis client for this thread's event loop."""
            return await create_redis_client(self.redis_url, decode_responses=True)

        async def send_heartbeat(client, status: str, current_task: str | None):
            """Send a heartbeat to Redis."""
            data = json.dumps(
                {
                    "agent_name": self.agent_name,
                    "status": status,
                    "current_task": current_task,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "pod": self.pod_name,
                }
            )
            await client.setex(heartbeat_key, heartbeat_ttl, data)

        async def close_redis(client):
            """Close the Redis client."""
            if client:
                await client.aclose()

        try:
            # Create Redis client for this thread
            redis_client = loop.run_until_complete(connect_redis())

            while not self._heartbeat_stop_event.is_set() and self._running:
                try:
                    status = "busy" if self._current_task else "idle"
                    loop.run_until_complete(
                        send_heartbeat(redis_client, status, self._current_task)
                    )
                    retry_delay = 1.0

                except Exception as e:
                    error_str = str(e).lower()
                    is_connection_error = any(
                        keyword in error_str
                        for keyword in ["connection", "closed", "timeout", "broken pipe", "reset"]
                    )

                    if is_connection_error:
                        logger.warning(f"Heartbeat connection error, will retry: {e}")
                        # Try to reconnect
                        try:
                            loop.run_until_complete(close_redis(redis_client))
                            redis_client = loop.run_until_complete(connect_redis())
                        except Exception as reconnect_error:
                            logger.warning(f"Heartbeat reconnect failed: {reconnect_error}")
                        self._heartbeat_stop_event.wait(retry_delay)
                        retry_delay = min(retry_delay * 2, max_retry_delay)
                        continue
                    logger.warning(f"Heartbeat failed: {e}")

                self._heartbeat_stop_event.wait(15)

        finally:
            if redis_client:
                try:
                    loop.run_until_complete(close_redis(redis_client))
                except Exception:
                    pass
            loop.close()
            logger.debug(f"Heartbeat thread stopped for {self.agent_name}")


async def run_blue_worker(
    role: BlueRole,
    investigation_id: str | None = None,
    redis_url: str | None = None,
    model: str | None = None,
    max_steps: int | None = None,
    discover_investigation: bool = True,
    discovery_timeout: int | None = None,
    grafana_url: str | None = None,
) -> None:
    """Run a specialized blue team worker agent.

    Args:
        role: The agent role (triage, threat_hunter, lateral_analyst).
        investigation_id: Investigation ID to join (optional - will discover if not provided).
        redis_url: Redis URL for task queue and state.
        model: LLM model to use.
        max_steps: Override default max steps for role.
        discover_investigation: If True and investigation_id is None, discover from Redis.
        discovery_timeout: Max seconds to wait for investigation discovery.
        grafana_url: Grafana URL for MCP tools.
    """
    from ares.core.blue_state_backend import BlueStateBackend
    from ares.core.blue_task_queue import BlueTaskQueue
    from ares.core.config import get_redis_url
    from ares.core.factories.blue_agents import create_blue_agent
    from ares.core.litellm_env import configure_litellm_env
    from ares.core.redis_client import create_redis_client
    from ares.core.rigging_patches import apply as apply_rigging_patches
    from ares.integrations.mitre import MITREAttackClient

    apply_rigging_patches()
    configure_litellm_env()

    redis_url = redis_url or get_redis_url()
    pod_name = os.environ.get("HOSTNAME", f"local-{role.value}")

    if not os.environ.get("ARES_ROLE"):
        os.environ["ARES_ROLE"] = role.value

    # Handle empty string investigation IDs
    if investigation_id == "":
        investigation_id = None

    # Create task queue and connect
    task_queue = BlueTaskQueue(redis_url)
    await task_queue.connect()

    # Track original investigation_id to know if we should loop
    original_investigation_id = investigation_id
    should_loop = discover_investigation and original_investigation_id is None

    try:
        while True:
            # Discover investigation if not provided (or re-discover after completion)
            current_investigation_id = investigation_id
            if current_investigation_id is None and discover_investigation:
                if discovery_timeout is None:
                    logger.info(
                        "No investigation ID provided, waiting indefinitely for an active investigation..."
                    )
                else:
                    logger.info(
                        f"No investigation ID provided, waiting up to {discovery_timeout}s..."
                    )
                current_investigation_id = await task_queue.discover_active_investigation(
                    max_wait=discovery_timeout
                )

                if current_investigation_id is None:
                    logger.error("No active investigation found within timeout")
                    return

            if current_investigation_id is None:
                logger.error("Investigation ID required but not provided and discovery disabled")
                return

            # Get model from investigation config if not provided
            current_model = model
            if not current_model:
                current_model = await task_queue.get_investigation_model(current_investigation_id)
            if not current_model:
                current_model = os.getenv("ARES_MODEL") or os.getenv("ARES_WORKER_MODEL")
            if not current_model:
                logger.error("No model specified for worker")
                return

            # Get credentials from investigation
            credentials = await task_queue.get_investigation_credentials(current_investigation_id)
            if credentials:
                for key, value in credentials.items():
                    if value and not os.environ.get(key):
                        os.environ[key] = value
                        logger.debug(f"Set credential from Redis: {key}")
                logger.info(f"Loaded {len(credentials)} credentials from investigation config")

            # Get alert for agent context
            alert = await task_queue.get_investigation_alert(current_investigation_id)

            logger.info(
                f"Starting {role.value} worker for investigation {current_investigation_id}"
            )
            logger.info(f"Pod: {pod_name}, Model: {current_model}")

            # Create Redis client for state backend
            redis_client = await create_redis_client(redis_url, decode_responses=True)
            backend = BlueStateBackend(redis_client, current_investigation_id)

            # Create MITRE client
            mitre_client = MITREAttackClient()

            # Attempt to load MCP tools from mcp-grafana
            mcp_tools = await _load_mcp_tools(grafana_url)

            # Create blue team dispatcher for shared state access
            from ares.core.blue_dispatcher import BlueTeamDispatcher

            dispatcher = BlueTeamDispatcher(redis_client)
            await dispatcher.start(current_investigation_id, alert)

            # Create the specialized agent
            agent, callback_tools = create_blue_agent(
                role=role,
                model=current_model,
                backend=backend,
                dispatcher=dispatcher,
                mitre_client=mitre_client,
                mcp_tools=mcp_tools,
                max_steps=max_steps or 30,
                grafana_url=grafana_url or os.environ.get("GRAFANA_URL", ""),
                alert=alert,
            )

            # Create and start worker
            worker = BlueRedisWorkerAgent(
                role=role,
                task_queue=task_queue,
                agent=agent,
                agent_name=f"blue-{role.value}-{pod_name}",
                callback_tools=callback_tools,
                backend=backend,
                investigation_id=current_investigation_id,
                pod_name=pod_name,
                redis_url=redis_url,
            )

            await worker.start()

            # Worker finished - investigation completed or no longer active
            logger.info(f"Worker finished for investigation {current_investigation_id}")

            # Clean up dispatcher
            await dispatcher.stop()
            await redis_client.aclose()

            # If we were given a specific investigation ID, don't loop
            if not should_loop:
                logger.info("Worker bound to specific investigation, exiting")
                break

            # Loop back to discover next investigation
            logger.info("Investigation completed, waiting for next investigation...")
            investigation_id = None  # Reset to trigger re-discovery

    finally:
        await task_queue.disconnect()


async def _load_mcp_tools(grafana_url: str | None = None) -> list:
    """Attempt to load MCP tools from mcp-grafana.

    Returns empty list if MCP not available.
    """
    mcp_tools: list = []

    try:
        from dreadnode.mcp import connect_stdio

        # Check if mcp-grafana is available
        mcp_grafana_path = os.environ.get("MCP_GRAFANA_PATH", "mcp-grafana")

        # Try to connect
        logger.info(f"Attempting to load MCP tools from {mcp_grafana_path}")
        mcp_client = await connect_stdio(mcp_grafana_path)

        if mcp_client:
            # Get tools from MCP
            tools = await mcp_client.list_tools()
            if tools:
                mcp_tools = list(tools)
                logger.info(f"Loaded {len(mcp_tools)} MCP tools from mcp-grafana")
            else:
                logger.warning("MCP connected but no tools available")

    except ImportError:
        logger.debug("dreadnode MCP not available")
    except FileNotFoundError:
        logger.warning("mcp-grafana binary not found")
    except Exception as e:
        logger.warning(f"Failed to load MCP tools: {e}")

    return mcp_tools


__all__ = [
    "BlueRedisWorkerAgent",
    "run_blue_worker",
]
