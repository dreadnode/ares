"""Persistent blue team orchestrator service for Kubernetes deployment.

This service runs as a persistent pod in Kubernetes, listening for investigation
requests on Redis and coordinating blue team investigations.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger

from ares.core.blue_task_queue import BlueTaskQueue
from ares.core.config import get_namespace, get_redis_url
from ares.core.litellm_env import configure_litellm_env
from ares.core.redis_client import (
    get_retry_delay,
    invalidate_sentinel_client,
    is_connection_error,
)
from ares.core.task_queue import RedisTaskQueue


def _configure_dreadnode():
    """Configure runtime integrations before returning the Dreadnode SDK."""
    configure_litellm_env()

    # Configure OTEL tracing to export to OTLP endpoint (e.g., Alloy/Tempo)
    # This is required because the dreadnode SDK doesn't auto-configure from OTEL env vars
    from ares.core.tracing import setup_otel_tracing

    setup_otel_tracing()

    import dreadnode as dn

    return dn


# Severity levels that trigger multi-agent routing
HIGH_SEVERITY_LEVELS = frozenset({"critical", "high"})

# Stale investigation threshold - investigations running longer than this are orphaned
STALE_INVESTIGATION_THRESHOLD_SECONDS = 3600  # 1 hour


@dataclass
class InvestigationRequest:
    """Investigation request from client."""

    investigation_id: str
    alert: dict[str, Any]
    correlation_context: dict[str, Any] | None = None
    model: str | None = None
    max_steps: int = 25
    multi_agent: bool = False
    auto_route: bool = True
    report_dir: str | None = None
    grafana_url: str | None = None
    grafana_api_key: str | None = None
    # API keys passed from client (set as env vars before running)
    env_vars: dict[str, str] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InvestigationRequest:
        """Create investigation request from dictionary."""
        env_vars = data.get("env_vars") or {}
        model = (
            data.get("model")
            or env_vars.get("ARES_ORCHESTRATOR_MODEL")
            or env_vars.get("ARES_MODEL")
            or os.environ.get("ARES_ORCHESTRATOR_MODEL")
            or os.environ.get("ARES_MODEL")
        )

        return cls(
            investigation_id=data["investigation_id"],
            alert=data["alert"],
            correlation_context=data.get("correlation_context"),
            model=model,
            max_steps=data.get("max_steps", 25),
            multi_agent=data.get("multi_agent", False),
            auto_route=data.get("auto_route", True),
            report_dir=data.get("report_dir")
            or env_vars.get("ARES_REPORT_DIR")
            or os.environ.get("ARES_REPORT_DIR"),
            grafana_url=data.get("grafana_url")
            or env_vars.get("GRAFANA_URL")
            or os.environ.get("GRAFANA_URL"),
            grafana_api_key=data.get("grafana_api_key")
            or env_vars.get("GRAFANA_SERVICE_ACCOUNT_TOKEN")
            or env_vars.get("GRAFANA_API_KEY")
            or os.environ.get("GRAFANA_SERVICE_ACCOUNT_TOKEN")
            or os.environ.get("GRAFANA_API_KEY"),
            env_vars=env_vars or None,
        )


class BlueOrchestratorService:
    """Persistent blue team orchestrator service."""

    def __init__(
        self,
        redis_url: str | None = None,
        namespace: str | None = None,
        investigations_queue: str = "ares:blue:investigations",
    ):
        """Initialize blue orchestrator service.

        Args:
            redis_url: Redis connection URL (default: from config)
            namespace: Kubernetes namespace (default: from config)
            investigations_queue: Redis queue for investigation requests
        """
        self.redis_url = redis_url or get_redis_url()
        self.namespace = namespace or get_namespace()
        self.investigations_queue = investigations_queue
        self.task_queue: RedisTaskQueue | None = None
        self.blue_task_queue: BlueTaskQueue | None = None
        self.running = False
        self._shutdown_event = asyncio.Event()
        self._report_dir = Path(os.environ.get("ARES_REPORT_DIR", "./reports"))
        # Concurrent investigation processing (default 10 for better throughput)
        self._max_concurrent = int(os.environ.get("ARES_BLUE_MAX_CONCURRENT", "10"))
        self._active_investigations: set[asyncio.Task] = set()
        self._grafana_url = os.environ.get("GRAFANA_URL", "")
        self._grafana_api_key = os.environ.get("GRAFANA_SERVICE_ACCOUNT_TOKEN") or os.environ.get(
            "GRAFANA_API_KEY", ""
        )
        # Distributed workers mode - if True, register investigations for remote workers
        # Supports both ARES_BLUE_DISTRIBUTED_WORKERS and COORDINATION_MODE env vars
        distributed_env = os.environ.get("ARES_BLUE_DISTRIBUTED_WORKERS", "").lower()
        coordination_mode = os.environ.get("COORDINATION_MODE", "").lower()
        self._use_distributed_workers = (
            distributed_env in ("1", "true", "yes") or coordination_mode == "distributed"
        )

    @staticmethod
    def _decode_redis_value(value: str | bytes) -> str:
        """Return a Redis value as a decoded string."""
        return value.decode() if isinstance(value, bytes) else str(value)

    async def start(self) -> None:
        """Start the blue orchestrator service."""
        logger.info("Starting blue team orchestrator service")
        logger.info(f"Redis URL: {self.redis_url}")
        logger.info(f"Namespace: {self.namespace}")
        logger.info(f"Investigations queue: {self.investigations_queue}")

        # Connect to Redis
        self.task_queue = RedisTaskQueue(self.redis_url)
        await self.task_queue.connect()
        logger.success("Connected to Redis")

        # Initialize BlueTaskQueue for investigation registration (distributed workers)
        if self._use_distributed_workers:
            self.blue_task_queue = BlueTaskQueue(self.redis_url)
            await self.blue_task_queue.connect()
            logger.info(
                "Distributed workers mode enabled - will register investigations for remote workers"
            )

        self.running = True

        # Cleanup stale investigations from previous orchestrator instance
        await self._cleanup_stale_investigations()

        # Setup signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))

        logger.info("Blue team orchestrator service started, waiting for investigation requests...")

        # Main service loop
        try:
            await self._run_service_loop()
        except Exception as e:
            logger.error(f"Service loop error: {e}")
            raise
        finally:
            await self.shutdown()

    async def _cleanup_stale_investigations(self) -> None:
        """Clean up investigations orphaned by previous orchestrator instance.

        When the orchestrator restarts, in-flight investigations are left in "running"
        status forever. This method detects and marks them as failed on startup.
        """
        if not self.task_queue or not self.task_queue._client:
            logger.warning("Cannot cleanup stale investigations - no Redis connection")
            return

        try:
            client = self.task_queue._client
            now = datetime.now(timezone.utc)
            cleaned = 0

            # Find all investigation status keys
            status_keys = await asyncio.wait_for(
                client.keys("ares:blue:inv:*:status"),
                timeout=30.0,
            )

            for key in status_keys:
                try:
                    key_str = key.decode() if isinstance(key, bytes) else key
                    status_json = await asyncio.wait_for(client.get(key_str), timeout=5.0)

                    if not status_json:
                        continue

                    status = json.loads(status_json)
                    if status.get("status") != "running":
                        continue

                    started_at = status.get("started_at")
                    if not started_at:
                        continue

                    # Parse start time and check if stale
                    start_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
                    elapsed = (now - start_dt).total_seconds()

                    if elapsed > STALE_INVESTIGATION_THRESHOLD_SECONDS:
                        # Extract investigation ID from key
                        parts = key_str.split(":")
                        inv_id = parts[3] if len(parts) >= 4 else "unknown"

                        # Mark as failed
                        status["status"] = "failed"
                        status["failed_at"] = now.isoformat()
                        status["error"] = (
                            f"Investigation orphaned after orchestrator restart "
                            f"(was running {elapsed / 3600:.1f}h)"
                        )

                        await asyncio.wait_for(
                            client.set(key_str, json.dumps(status)),
                            timeout=5.0,
                        )

                        logger.warning(
                            f"Marked stale investigation {inv_id} as failed "
                            f"(running {elapsed / 3600:.1f}h)"
                        )
                        cleaned += 1

                except Exception as e:
                    logger.debug(f"Error processing investigation key {key}: {e}")
                    continue

            if cleaned > 0:
                logger.info(f"Cleaned up {cleaned} stale investigations from previous instance")

        except asyncio.TimeoutError:
            logger.warning("Timeout scanning for stale investigations")
        except Exception as e:
            logger.warning(f"Error cleaning up stale investigations: {e}")

    async def _run_service_loop(self) -> None:
        """Main service loop - poll for investigations and process concurrently."""
        import time

        last_successful_poll = time.monotonic()
        last_health_check = time.monotonic()
        last_stale_check = time.monotonic()
        health_check_interval = 15.0  # Periodic health check every 15s
        stale_check_interval = 300.0  # Check for stale investigations every 5 min
        # Base threshold when idle; extended when investigations are active
        stale_connection_threshold_idle = 30.0
        stale_connection_threshold_busy = 300.0  # 5 min when busy (LLM calls starve event loop)

        logger.info(f"Concurrent investigation limit: {self._max_concurrent}")

        while self.running:
            try:
                now = time.monotonic()

                # Clean up completed tasks
                done_tasks = {t for t in self._active_investigations if t.done()}
                for task in done_tasks:
                    self._active_investigations.discard(task)
                    # Log any exceptions from completed tasks
                    if task.exception():
                        logger.error(f"Investigation task failed: {task.exception()}")

                # Periodic health check to detect stale Redis connections early
                if now - last_health_check >= health_check_interval:
                    last_health_check = now
                    if self.task_queue:
                        try:
                            ping_ok = await self.task_queue.ping_or_reconnect(timeout=5.0)
                            if not ping_ok:
                                logger.info("Redis connection was stale, reconnected proactively")
                        except Exception as e:
                            logger.warning(f"Health check failed: {e}")

                # Periodic check for stale investigations (stuck mid-operation)
                if now - last_stale_check >= stale_check_interval:
                    last_stale_check = now
                    try:
                        await self._cleanup_stale_investigations()
                    except Exception as e:
                        logger.warning(f"Stale investigation cleanup failed: {e}")

                # Check if we can accept more investigations
                if len(self._active_investigations) >= self._max_concurrent:
                    # At capacity - wait briefly for a slot to free up
                    await asyncio.sleep(1)
                    continue

                result = await asyncio.wait_for(self._pop_investigation_request(), timeout=5.0)
                last_successful_poll = now

                if result:
                    # Spawn investigation as background task
                    inv_id = result.get("investigation_id", "unknown")
                    task = asyncio.create_task(
                        self._process_investigation_request(result),
                        name=f"investigation-{inv_id}",
                    )
                    self._active_investigations.add(task)
                    logger.info(
                        f"Spawned investigation {inv_id} "
                        f"({len(self._active_investigations)}/{self._max_concurrent} active)"
                    )

            except asyncio.TimeoutError:
                elapsed = time.monotonic() - last_successful_poll
                # Use longer threshold when investigations are active - LLM calls can starve
                # the event loop, causing poll timeouts that aren't actual Redis failures
                has_active = len(self._active_investigations) > 0
                threshold = (
                    stale_connection_threshold_busy
                    if has_active
                    else stale_connection_threshold_idle
                )

                if elapsed > threshold:
                    # Before forcing reconnect, verify connection is actually dead with a ping
                    if await self._is_connection_alive():
                        # Connection is fine, just event loop starvation from LLM calls
                        logger.debug(
                            f"Poll timeout after {elapsed:.1f}s but Redis ping succeeded "
                            f"({len(self._active_investigations)} active investigations)"
                        )
                        last_successful_poll = time.monotonic()
                    else:
                        logger.warning(
                            f"No successful Redis poll for {elapsed:.1f}s and ping failed, "
                            f"forcing reconnection (possible Sentinel pod restart)"
                        )
                        await self._force_reconnect()
                        last_successful_poll = time.monotonic()
                continue
            except Exception as e:
                logger.error(f"Error in service loop: {e}")
                if "ConnectionError" in str(type(e).__name__) or "Redis" in str(type(e).__name__):
                    logger.warning("Redis connection error, forcing reconnection")
                    await self._force_reconnect()
                    last_successful_poll = time.monotonic()
                await asyncio.sleep(5)

    async def _force_reconnect(self) -> None:
        """Force reconnection to Redis by invalidating cached clients."""
        invalidate_sentinel_client()

        if self.task_queue:
            try:
                await self.task_queue.disconnect()
            except Exception as e:
                logger.debug(f"Error disconnecting task queue: {e}")
            try:
                await self.task_queue.connect()
                logger.info("Reconnected task_queue to Redis")
            except Exception as e:
                logger.error(f"Failed to reconnect task_queue to Redis: {e}")

        if self.blue_task_queue:
            try:
                await self.blue_task_queue.disconnect()
            except Exception as e:
                logger.debug(f"Error disconnecting blue_task_queue: {e}")
            try:
                await self.blue_task_queue.connect()
                logger.info("Reconnected blue_task_queue to Redis")
            except Exception as e:
                logger.error(f"Failed to reconnect blue_task_queue to Redis: {e}")

    async def _is_connection_alive(self) -> bool:
        """Check if Redis connection is alive with a quick ping.

        Used to distinguish between actual connection failures and event loop
        starvation (e.g., from concurrent LLM calls blocking the loop).
        """
        if not self.task_queue or not self.task_queue._client:
            return False

        try:
            # Use a short timeout - if ping doesn't respond quickly, connection is likely dead
            result = await asyncio.wait_for(
                self.task_queue._client.ping(),
                timeout=2.0,
            )
            return result is True
        except Exception:
            return False

    async def _pop_investigation_request(self, max_retries: int = 2) -> dict[str, Any] | None:
        """Pop an investigation request from Redis queue.

        Includes timeout protection and retry logic for stale connections.
        """
        if not self.task_queue or not self.task_queue._client:
            return None

        timeout = 5.0
        for attempt in range(max_retries + 1):
            try:
                # Wrap blpop with asyncio.wait_for to detect stale connections
                result = await asyncio.wait_for(
                    self.task_queue._client.blpop(self.investigations_queue, timeout=int(timeout)),
                    timeout=timeout + 2.0,
                )
                if result:
                    _, value = result
                    return json.loads(value)
                return None

            except asyncio.TimeoutError:
                attempt_info = f"attempt {attempt + 1}/{max_retries + 1}"
                logger.warning(
                    f"BLPOP hung on {self.investigations_queue} - "
                    f"stale connection detected ({attempt_info})"
                )
                await self._force_reconnect()
                continue

            except Exception as e:
                if is_connection_error(e):
                    attempt_info = f"attempt {attempt + 1}/{max_retries + 1}"
                    logger.warning(f"Connection error during poll ({attempt_info}): {e}")
                    await self._force_reconnect()
                    continue
                raise

        logger.error(f"_pop_investigation_request failed after {max_retries + 1} attempts")
        return None

    def _should_use_multi_agent(self, request: InvestigationRequest) -> bool:
        """Return whether an investigation should use the multi-agent path."""
        if request.multi_agent:
            return True
        if not request.auto_route:
            return False

        severity = request.alert.get("labels", {}).get("severity", "").lower()
        return severity in HIGH_SEVERITY_LEVELS

    async def _process_investigation_request(self, request_data: dict[str, Any]) -> None:
        """Process an investigation request."""
        started_at = datetime.now(timezone.utc)
        investigation_id = request_data.get("investigation_id", "unknown")

        try:
            # Fetch env_vars from separate key if not in request
            if not request_data.get("env_vars") and investigation_id != "unknown":
                env_vars_key = f"ares:blue:inv:{investigation_id}:env_vars"
                if self.task_queue and self.task_queue._client:
                    try:
                        env_vars_data = await asyncio.wait_for(
                            self.task_queue._client.get(env_vars_key),
                            timeout=10.0,
                        )
                        if env_vars_data:
                            env_vars_str = self._decode_redis_value(env_vars_data)
                            request_data["env_vars"] = json.loads(env_vars_str)
                            await asyncio.wait_for(
                                self.task_queue._client.delete(env_vars_key),
                                timeout=10.0,
                            )
                            logger.debug(f"Loaded and deleted env_vars from {env_vars_key}")
                    except asyncio.TimeoutError:
                        logger.warning(f"Timeout fetching env_vars for {investigation_id}")
                    except Exception as e:
                        logger.warning(f"Error fetching env_vars: {e}")

            request = InvestigationRequest.from_dict(request_data)
            alert_name = request.alert.get("labels", {}).get("alertname", "unknown")
            logger.info(f"Processing investigation request: {request.investigation_id}")
            logger.info(f"Alert: {alert_name}")

            # Set environment variables from request
            if request.env_vars:
                for key, value in request.env_vars.items():
                    if value:
                        os.environ[key] = value
                        logger.debug(f"Set environment variable: {key}")

            try:
                dn = _configure_dreadnode()
                dn.configure()
            except Exception as e:
                logger.warning(f"Dreadnode configure failed, continuing without telemetry: {e}")

            # Publish investigation status: started
            await self._publish_investigation_status(
                request.investigation_id,
                "running",
                {"started_at": started_at.isoformat()},
            )

            # Track investigation to operation if operation_context is present
            # or if there's an active red operation running
            operation_context = request.alert.get("operation_context", {})
            operation_id = operation_context.get("operation_id")

            # If no explicit operation_context, try to find active red operation
            if not operation_id and self.task_queue and self.task_queue._client:
                try:
                    # Look for running red operations (ares:op:*:meta with completed_at=None)
                    op_keys = await asyncio.wait_for(
                        self.task_queue._client.keys("ares:op:*:meta"),
                        timeout=5.0,
                    )
                    for key in op_keys:
                        key_str = key.decode() if isinstance(key, bytes) else key
                        meta = await asyncio.wait_for(
                            self.task_queue._client.hgetall(key_str),
                            timeout=5.0,
                        )
                        # Check if operation is still running (no completed_at)
                        completed = meta.get(b"completed_at") or meta.get("completed_at")
                        if not completed:
                            # Extract operation ID from key: ares:op:{op_id}:meta
                            parts = key_str.split(":")
                            if len(parts) >= 3:
                                operation_id = parts[2]
                                logger.debug(
                                    f"Auto-tracking to active red operation: {operation_id}"
                                )
                                break
                except Exception as e:
                    logger.debug(f"Could not find active red operation: {e}")

            if operation_id and self.task_queue and self.task_queue._client:
                try:
                    op_inv_key = f"ares:blue:op:{operation_id}:investigations"
                    await asyncio.wait_for(
                        self.task_queue._client.sadd(op_inv_key, request.investigation_id),
                        timeout=5.0,
                    )
                    # Set TTL of 7 days
                    await asyncio.wait_for(
                        self.task_queue._client.expire(op_inv_key, 7 * 24 * 3600),
                        timeout=5.0,
                    )
                    logger.info(
                        f"Tracked investigation {request.investigation_id} "
                        f"to operation {operation_id}"
                    )
                    # Update investigation status with operation_id for trace correlation
                    await self._publish_investigation_status(
                        request.investigation_id,
                        "running",
                        {"operation_id": operation_id},
                    )
                except Exception as e:
                    logger.warning(f"Failed to track investigation to operation: {e}")

            if not request.model:
                raise ValueError(
                    "No model specified for investigation. Provide --model at submit time or set "
                    "ARES_ORCHESTRATOR_MODEL/ARES_MODEL in the orchestrator environment."
                )

            # Create orchestrator based on routing decision
            use_multi_agent = self._should_use_multi_agent(request)
            logger.info(
                f"Using {'multi-agent' if use_multi_agent else 'single-agent'} orchestrator"
            )

            from ares.integrations.mitre import MITREAttackClient

            mitre_client = MITREAttackClient()
            report_dir = Path(request.report_dir) if request.report_dir else self._report_dir
            grafana_url = request.grafana_url or self._grafana_url
            grafana_api_key = request.grafana_api_key or self._grafana_api_key

            if not grafana_url:
                raise ValueError("GRAFANA_URL is required for blue team investigations")

            configure_litellm_env()

            if use_multi_agent:
                from ares.agents.blue import BlueTeamOrchestrator

                # Register investigation for distributed workers if enabled
                if self._use_distributed_workers and self.blue_task_queue:
                    # Collect credentials to pass to workers
                    worker_credentials = {}
                    for key in [
                        "OPENAI_API_KEY",
                        "GRAFANA_SERVICE_ACCOUNT_TOKEN",
                        "GRAFANA_API_KEY",
                    ]:
                        val = os.environ.get(key)
                        if val:
                            worker_credentials[key] = val

                    await self.blue_task_queue.register_investigation(
                        investigation_id=request.investigation_id,
                        alert=request.alert,
                        model=request.model,
                        credentials=worker_credentials,
                        operation_id=operation_id,
                    )
                    inv_id = request.investigation_id
                    logger.info(f"Registered investigation {inv_id} for distributed workers")

                orchestrator = BlueTeamOrchestrator(
                    model=request.model,
                    grafana_url=grafana_url,
                    grafana_api_key=grafana_api_key,
                    mitre_client=mitre_client,
                    report_dir=report_dir,
                    max_steps=request.max_steps,
                    redis_url=self.redis_url,
                    use_distributed_workers=self._use_distributed_workers,
                    blue_task_queue=self.blue_task_queue,
                )
            else:
                from ares.agents.blue import InvestigationOrchestrator

                orchestrator = InvestigationOrchestrator(
                    model=request.model,
                    grafana_url=grafana_url,
                    grafana_api_key=grafana_api_key,
                    mitre_client=mitre_client,
                    report_dir=report_dir,
                    max_steps=request.max_steps,
                )

            # Run the investigation with retry for transient connection errors
            # Note: Status is updated to "completed" inside investigate() after report generation
            logger.info(f"Starting investigation: {request.investigation_id}")
            max_retries = 3
            last_error: Exception | None = None
            for attempt in range(max_retries):
                try:
                    result = await orchestrator.investigate(
                        alert=request.alert,
                        correlation_context=request.correlation_context,
                        investigation_id=request.investigation_id,
                    )
                    break  # Success
                except Exception as e:
                    last_error = e
                    if is_connection_error(e) and attempt < max_retries - 1:
                        delay = get_retry_delay(attempt)
                        logger.warning(
                            f"Connection error in investigation {request.investigation_id} "
                            f"(attempt {attempt + 1}/{max_retries}): {e}. "
                            f"Retrying in {delay:.1f}s..."
                        )
                        invalidate_sentinel_client()
                        await asyncio.sleep(delay)
                    else:
                        raise
            else:
                # All retries exhausted
                raise last_error  # type: ignore[misc]

            completed_at = datetime.now(timezone.utc)
            elapsed = (completed_at - started_at).total_seconds()
            hours, remainder = divmod(int(elapsed), 3600)
            minutes, seconds = divmod(remainder, 60)
            if hours > 0:
                duration_str = f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                duration_str = f"{minutes}m {seconds}s"
            else:
                duration_str = f"{seconds}s"

            logger.success(
                f"Investigation {request.investigation_id} completed: "
                f"{result.get('evidence_count', 0)} evidence items, "
                f"{len(result.get('techniques_identified', []))} techniques "
                f"(duration {duration_str})"
            )

            # Unregister investigation from distributed workers
            if self._use_distributed_workers and self.blue_task_queue:
                await self.blue_task_queue.unregister_investigation(request.investigation_id)

        except Exception as e:
            logger.error(f"Error processing investigation: {e}")
            await self._publish_investigation_status(
                investigation_id,
                "failed",
                {
                    "failed_at": datetime.now(timezone.utc).isoformat(),
                    "error": str(e),
                },
            )

    async def _publish_investigation_status(
        self,
        investigation_id: str,
        status: str,
        data: dict[str, Any],
    ) -> None:
        """Publish investigation status update to Redis."""
        if not self.task_queue or not self.task_queue._client:
            return

        status_key = f"ares:blue:inv:{investigation_id}:status"
        status_data = {
            "status": status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            **data,
        }

        try:
            # Set status in Redis with 24h expiry, with timeout protection
            await asyncio.wait_for(
                self.task_queue._client.setex(
                    status_key,
                    86400,
                    json.dumps(status_data),
                ),
                timeout=10.0,
            )
            logger.debug(f"Published status for {investigation_id}: {status}")
        except asyncio.TimeoutError:
            logger.warning(f"Timeout publishing status for {investigation_id}")
        except Exception as e:
            if is_connection_error(e):
                logger.warning(f"Connection error publishing status: {e}")
            else:
                logger.error(f"Error publishing status: {e}")

    async def shutdown(self) -> None:
        """Shutdown the blue orchestrator service."""
        if not self.running:
            return

        logger.info("Shutting down blue team orchestrator service...")
        self.running = False
        self._shutdown_event.set()

        # Wait for active investigations to complete (with timeout)
        if self._active_investigations:
            logger.info(f"Waiting for {len(self._active_investigations)} active investigations...")
            _, pending = await asyncio.wait(
                self._active_investigations,
                timeout=60.0,
            )
            if pending:
                logger.warning(f"Cancelling {len(pending)} pending investigations")
                for task in pending:
                    task.cancel()

        if self.task_queue:
            await self.task_queue.disconnect()

        if self.blue_task_queue:
            await self.blue_task_queue.disconnect()

        logger.info("Blue team orchestrator service stopped")


async def main() -> None:
    """Main entry point for blue orchestrator service."""
    investigations_queue = os.getenv("INVESTIGATIONS_QUEUE", "ares:blue:investigations")

    # Setup logging
    logger.remove()
    log_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
        "<level>{message}</level>"
    )
    logger.add(
        sys.stderr,
        format=log_format,
        level=os.getenv("LOG_LEVEL", "INFO"),
    )

    service = BlueOrchestratorService(
        investigations_queue=investigations_queue,
    )

    try:
        await service.start()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Service error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
