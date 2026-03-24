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
from opentelemetry import trace
from opentelemetry.trace import SpanKind

from ares.core.blue_worker.prompts import generate_blue_task_prompt
from ares.core.models import BlueRole, BlueTaskType
from ares.core.redis_client import is_connection_error
from ares.core.tracing import create_agent_span_attributes

_tracer = trace.get_tracer("ares.blue_worker")

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
        operation_id: str | None = None,
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
        self.operation_id = operation_id  # Red team operation ID for trace correlation

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
                if is_connection_error(e):
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

        # Create CONSUMER span for Tempo service graph (explicit span management)
        # This pairs with the PRODUCER span from submit_task
        span_attrs = create_agent_span_attributes(self.role.value, "blue")
        span_attrs.update(
            {
                "task.id": task.task_id,
                "task.type": task.task_type,
                "investigation.id": self.investigation_id,
                "worker.pod": self.pod_name,
                "worker.agent": self.agent_name,
            }
        )
        # Add red team operation ID for trace correlation if available
        if self.operation_id:
            span_attrs["attack_operation_id"] = self.operation_id
        _task_span = _tracer.start_span(
            "process_task", kind=SpanKind.CONSUMER, attributes=span_attrs
        )

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
            agent_result = await self.agent.run(prompt)

            # Extract token usage for metrics and tracing
            usage = getattr(agent_result, "usage", None)
            usage_dict: dict[str, int] | None = None
            if usage:
                usage_dict = {
                    "input_tokens": getattr(usage, "input_tokens", 0),
                    "output_tokens": getattr(usage, "output_tokens", 0),
                    "total_tokens": getattr(usage, "total_tokens", 0),
                }
                # Add to span for Tempo/OTel (follows OpenTelemetry GenAI semantic conventions)
                _task_span.set_attribute("gen_ai.usage.input_tokens", usage_dict["input_tokens"])
                _task_span.set_attribute("gen_ai.usage.output_tokens", usage_dict["output_tokens"])
                _task_span.set_attribute("gen_ai.usage.total_tokens", usage_dict["total_tokens"])

            # Check if agent completed via callback
            if completion_event.is_set():
                result = self.callback_tools.result_data
                if usage_dict:
                    result["usage"] = usage_dict
                logger.info(f"[{self.agent_name}] Task {task.task_id} completed via callback")
                await self._send_success_result(task.task_id, result)
            else:
                # Agent finished without callback (hit max_steps)
                logger.warning(
                    f"[{self.agent_name}] Task {task.task_id} ended without completion callback"
                )
                partial_result: dict[str, Any] = {
                    "type": self.role.value,
                    "summary": "Agent completed without explicit completion signal",
                    "partial": True,
                }
                if usage_dict:
                    partial_result["usage"] = usage_dict
                await self._send_success_result(task.task_id, partial_result)

            self._tasks_completed += 1

        except Exception as e:
            logger.error(f"[{self.agent_name}] Task {task.task_id} failed: {e}", exc_info=True)
            await self._send_error_result(task.task_id, str(e))

        finally:
            self._current_task = None
            # End the CONSUMER span for Tempo service graph
            _task_span.end()

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

    # Configure OTEL tracing to export to OTLP endpoint (e.g., Alloy/Tempo)
    # This is required because the dreadnode SDK doesn't auto-configure from OTEL env vars
    from ares.core.tracing import setup_otel_tracing

    setup_otel_tracing()

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
                    logger.info("No investigation ID, waiting indefinitely for active one")
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

            # Get operation ID for trace correlation
            operation_id = await task_queue.get_investigation_operation_id(current_investigation_id)
            if operation_id:
                logger.info(f"Investigation correlated to red team operation: {operation_id}")

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
                max_steps=max_steps or 10,
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
                operation_id=operation_id,
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


async def run_blue_global_worker(
    role: BlueRole,
    redis_url: str | None = None,
    model: str | None = None,
    max_steps: int | None = None,
    grafana_url: str | None = None,
) -> None:
    """Run a global pool worker that handles tasks from any investigation.

    Unlike run_blue_worker which binds to a specific investigation, this worker
    polls from the global role queue and handles tasks from any active investigation.
    This enables N workers per role across all investigations for better throughput.

    Args:
        role: The agent role (triage, threat_hunter, lateral_analyst).
        redis_url: Redis URL for task queue and state.
        model: LLM model to use (falls back to ARES_MODEL env var).
        max_steps: Override default max steps for role.
        grafana_url: Grafana URL for MCP tools.
    """
    from ares.core.blue_state_backend import BlueStateBackend
    from ares.core.blue_task_queue import BlueTaskQueue
    from ares.core.blue_worker.prompts import generate_blue_task_prompt
    from ares.core.config import get_redis_url
    from ares.core.factories.blue_agents import create_blue_agent
    from ares.core.litellm_env import configure_litellm_env
    from ares.core.models import BlueTaskType
    from ares.core.redis_client import create_redis_client
    from ares.core.rigging_patches import apply as apply_rigging_patches
    from ares.integrations.mitre import MITREAttackClient

    apply_rigging_patches()
    configure_litellm_env()

    # Configure OTEL tracing to export to OTLP endpoint (e.g., Alloy/Tempo)
    # This is required because the dreadnode SDK doesn't auto-configure from OTEL env vars
    from ares.core.tracing import setup_otel_tracing

    setup_otel_tracing()

    redis_url = redis_url or get_redis_url()
    pod_name = os.environ.get("HOSTNAME", f"local-{role.value}")

    if not os.environ.get("ARES_ROLE"):
        os.environ["ARES_ROLE"] = role.value

    # Get model from env if not provided
    current_model = model or os.getenv("ARES_MODEL") or os.getenv("ARES_WORKER_MODEL")
    if not current_model:
        logger.error("No model specified for global worker (set ARES_MODEL)")
        return

    # Create task queue with global queue enabled
    task_queue = BlueTaskQueue(redis_url, use_global_queue=True)
    await task_queue.connect()

    # MCP tools are loaded per-investigation when credentials are available
    # (see get_investigation_context)
    mitre_client = MITREAttackClient()

    agent_name = f"blue-{role.value}-{pod_name}"
    logger.info(f"Starting global pool worker {agent_name} for role {role.value}")
    logger.info(f"Model: {current_model}, polling from global queue")

    # Cache for investigation-specific resources
    _investigation_cache: dict[str, dict] = {}

    async def get_investigation_context(investigation_id: str) -> dict:
        """Get or create context for an investigation."""
        if investigation_id in _investigation_cache:
            return _investigation_cache[investigation_id]

        # Load credentials from investigation config (stored by orchestrator)
        credentials = await task_queue.get_investigation_credentials(investigation_id)
        if credentials:
            for key, value in credentials.items():
                if value:
                    os.environ[key] = value
                    logger.debug(f"Set credential from investigation: {key}")
            logger.info(
                f"Loaded {len(credentials)} credentials for investigation {investigation_id}"
            )

        # Get operation ID for trace correlation
        operation_id = await task_queue.get_investigation_operation_id(investigation_id)
        if operation_id:
            logger.info(f"Investigation correlated to red team operation: {operation_id}")

        # Load MCP tools now that credentials are available
        # (credentials may include GRAFANA_SERVICE_ACCOUNT_TOKEN)
        inv_mcp_tools = await _load_mcp_tools(grafana_url)

        # Create new context for this investigation
        redis_client = await create_redis_client(redis_url, decode_responses=True)
        backend = BlueStateBackend(redis_client, investigation_id)
        alert = await task_queue.get_investigation_alert(investigation_id)

        from ares.core.blue_dispatcher import BlueTeamDispatcher

        dispatcher = BlueTeamDispatcher(redis_client)
        await dispatcher.start(investigation_id, alert)

        agent, callback_tools = create_blue_agent(
            role=role,
            model=current_model,
            backend=backend,
            dispatcher=dispatcher,
            mitre_client=mitre_client,
            mcp_tools=inv_mcp_tools,
            max_steps=max_steps or 10,
            grafana_url=grafana_url or os.environ.get("GRAFANA_URL", ""),
            alert=alert,
        )

        ctx = {
            "redis_client": redis_client,
            "backend": backend,
            "dispatcher": dispatcher,
            "agent": agent,
            "callback_tools": callback_tools,
            "operation_id": operation_id,
        }
        _investigation_cache[investigation_id] = ctx
        return ctx

    async def cleanup_context(investigation_id: str) -> None:
        """Clean up cached context for an investigation."""
        if investigation_id not in _investigation_cache:
            return

        ctx = _investigation_cache.pop(investigation_id)
        try:
            await ctx["dispatcher"].stop()
            await ctx["redis_client"].aclose()
        except Exception as e:
            logger.warning(f"Error cleaning up context for {investigation_id}: {e}")

    retry_delay = 1.0
    max_retry_delay = 60.0
    last_maintenance = time.monotonic()
    maintenance_interval = 15.0

    poll_count = 0
    try:
        while True:
            try:
                poll_count += 1
                if poll_count <= 3 or poll_count % 60 == 0:
                    logger.debug(f"[{agent_name}] Poll iteration {poll_count}")

                # Periodic maintenance
                if (time.monotonic() - last_maintenance) >= maintenance_interval:
                    last_maintenance = time.monotonic()
                    await task_queue.ping_or_reconnect()

                    # Clean up contexts for completed investigations
                    for inv_id in list(_investigation_cache.keys()):
                        alert = await task_queue.get_investigation_alert(inv_id)
                        if not alert:
                            logger.info(f"Investigation {inv_id} no longer active, cleaning up")
                            await cleanup_context(inv_id)

                # Poll global queue for tasks
                task = await task_queue.poll_global_task(role=role.value, timeout=5.0)

                if task is None:
                    if poll_count <= 3:
                        logger.debug(f"[{agent_name}] No task available, continuing to poll")
                    retry_delay = 1.0
                    continue

                logger.info(
                    f"[{agent_name}] Received task {task.task_id} "
                    f"(type={task.task_type}, inv={task.investigation_id})"
                )

                # Get context for this task's investigation
                ctx = await get_investigation_context(task.investigation_id)
                agent = ctx["agent"]
                callback_tools = ctx["callback_tools"]
                backend = ctx["backend"]
                operation_id = ctx.get("operation_id")

                # Create CONSUMER span for Tempo service graph (for trace correlation)
                span_attrs = create_agent_span_attributes(role.value, "blue")
                span_attrs.update(
                    {
                        "task.id": task.task_id,
                        "task.type": task.task_type,
                        "investigation.id": task.investigation_id,
                        "worker.pod": pod_name,
                        "worker.agent": agent_name,
                    }
                )
                if operation_id:
                    span_attrs["attack_operation_id"] = operation_id
                _task_span = _tracer.start_span(
                    "process_task", kind=SpanKind.CONSUMER, attributes=span_attrs
                )

                # Process the task
                try:
                    task_type = BlueTaskType(task.task_type)
                except ValueError:
                    logger.warning(f"Unknown task type: {task.task_type}")
                    await task_queue.send_result(
                        task_id=task.task_id,
                        success=False,
                        error=f"Unknown task type: {task.task_type}",
                        worker_pod=pod_name,
                        agent_name=agent_name,
                    )
                    continue

                # Get state summary
                try:
                    snapshot = await backend.snapshot()
                    state_summary = {
                        "investigation_id": task.investigation_id,
                        "evidence_count": len(snapshot.get("evidence", [])),
                        "techniques_identified": list(snapshot.get("techniques", set())),
                        "hosts_investigated": list(snapshot.get("hosts", set())),
                        "users_investigated": list(snapshot.get("users", set())),
                        "stage": snapshot.get("meta", {}).get("stage", "triage"),
                    }
                except Exception:
                    state_summary = {}

                # Generate prompt and run agent
                prompt = generate_blue_task_prompt(
                    task_type=task_type,
                    params=task.params,
                    shared_state_summary=state_summary,
                )

                completion_event = asyncio.Event()
                callback_tools.set_completion_event(completion_event)

                logger.info(f"[{agent_name}] Running agent for task {task.task_id}")
                agent_result = await agent.run(prompt)

                # Extract token usage for metrics
                usage = getattr(agent_result, "usage", None)
                usage_dict: dict[str, int] | None = None
                if usage:
                    usage_dict = {
                        "input_tokens": getattr(usage, "input_tokens", 0),
                        "output_tokens": getattr(usage, "output_tokens", 0),
                        "total_tokens": getattr(usage, "total_tokens", 0),
                    }

                # Send result
                if completion_event.is_set():
                    result_data = callback_tools.result_data
                    if usage_dict:
                        result_data["usage"] = usage_dict
                    logger.info(f"[{agent_name}] Task {task.task_id} completed")
                    await task_queue.send_result(
                        task_id=task.task_id,
                        success=True,
                        result=result_data,
                        worker_pod=pod_name,
                        agent_name=agent_name,
                    )
                else:
                    logger.warning(f"[{agent_name}] Task {task.task_id} ended without callback")
                    partial_result: dict[str, Any] = {
                        "type": role.value,
                        "summary": "Agent completed without explicit completion signal",
                        "partial": True,
                    }
                    if usage_dict:
                        partial_result["usage"] = usage_dict
                    await task_queue.send_result(
                        task_id=task.task_id,
                        success=True,
                        result=partial_result,
                        worker_pod=pod_name,
                        agent_name=agent_name,
                    )

                # End the task span
                _task_span.end()
                retry_delay = 1.0

            except asyncio.CancelledError:
                # End span if it was created
                if "_task_span" in dir() and _task_span:
                    _task_span.end()
                break
            except Exception as e:
                # End span if it was created
                if "_task_span" in dir() and _task_span:
                    _task_span.end()
                if is_connection_error(e):
                    logger.warning(
                        f"Global worker connection error, retrying in {retry_delay:.1f}s: {e}"
                    )
                    await asyncio.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, max_retry_delay)
                else:
                    logger.error(f"Global worker error: {e}", exc_info=True)
                    # Send error result if we have a task
                    if "task" in dir() and task:
                        try:
                            await task_queue.send_result(
                                task_id=task.task_id,
                                success=False,
                                error=str(e),
                                worker_pod=pod_name,
                                agent_name=agent_name,
                            )
                        except Exception:
                            pass
                    await asyncio.sleep(5)
                    retry_delay = 1.0

    finally:
        # Clean up all cached contexts
        for inv_id in list(_investigation_cache.keys()):
            await cleanup_context(inv_id)
        await task_queue.disconnect()
        logger.info(f"Global worker {agent_name} stopped")


async def _load_mcp_tools(grafana_url: str | None = None) -> list:
    """Load MCP tools from mcp-grafana using the pooled connection.

    Uses the same MCP connection approach as the orchestrator (rigging.mcp) to ensure:
    - Proper credentials are passed (GRAFANA_URL, GRAFANA_SERVICE_ACCOUNT_TOKEN)
    - Tools are returned in the correct format (callable tool objects, not descriptors)
    - Connection pooling is used for efficiency

    Returns empty list if MCP not available or credentials missing.
    """
    try:
        from ares.tools.blue.grafana import connect_grafana_mcp

        # Get credentials from env (may have been loaded from investigation config)
        grafana_url = grafana_url or os.environ.get("GRAFANA_URL", "")
        grafana_api_key = os.environ.get("GRAFANA_SERVICE_ACCOUNT_TOKEN", "") or os.environ.get(
            "GRAFANA_API_KEY", ""
        )

        if not grafana_url:
            logger.warning("GRAFANA_URL not set - MCP tools not available")
            return []

        if not grafana_api_key:
            logger.warning("GRAFANA_SERVICE_ACCOUNT_TOKEN not set - MCP tools not available")
            return []

        logger.info(f"Loading MCP tools from mcp-grafana (grafana_url={grafana_url[:50]}...)")

        # Use the same pooled connection as the orchestrator
        # This returns a rigging MCP client with callable tool objects
        mcp_client = await connect_grafana_mcp(
            grafana_url=grafana_url,
            grafana_api_key=grafana_api_key,
        )

        if mcp_client and mcp_client.tools:
            logger.success(f"Loaded {len(mcp_client.tools)} MCP tools from mcp-grafana")
            return mcp_client.tools

        logger.warning("MCP connected but no tools available")
        return []

    except FileNotFoundError:
        install_cmd = "go install github.com/grafana/mcp-grafana/cmd/mcp-grafana@latest"
        logger.warning(f"mcp-grafana binary not found - install with: {install_cmd}")
    except Exception as e:
        logger.warning(f"Failed to load MCP tools: {e}")

    return []


__all__ = [
    "BlueRedisWorkerAgent",
    "run_blue_global_worker",
    "run_blue_worker",
]
