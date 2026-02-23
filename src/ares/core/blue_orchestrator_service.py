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

from ares.core.config import get_namespace, get_redis_url
from ares.core.litellm_env import configure_litellm_env
from ares.core.redis_client import invalidate_sentinel_client
from ares.core.task_queue import RedisTaskQueue


def _configure_dreadnode():
    configure_litellm_env()
    import dreadnode as dn

    return dn


# Severity levels that trigger multi-agent routing
HIGH_SEVERITY_LEVELS = frozenset({"critical", "high"})


@dataclass
class InvestigationRequest:
    """Investigation request from client."""

    investigation_id: str
    alert: dict[str, Any]
    correlation_context: dict[str, Any] | None = None
    model: str | None = None
    max_steps: int = 50
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
            max_steps=data.get("max_steps", 50),
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
        self.running = False
        self._shutdown_event = asyncio.Event()
        self._report_dir = Path(os.environ.get("ARES_REPORT_DIR", "./reports"))
        self._grafana_url = os.environ.get("GRAFANA_URL", "")
        self._grafana_api_key = os.environ.get("GRAFANA_SERVICE_ACCOUNT_TOKEN") or os.environ.get(
            "GRAFANA_API_KEY", ""
        )

    @staticmethod
    def _decode_redis_value(value: str | bytes) -> str:
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

        self.running = True

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

    async def _run_service_loop(self) -> None:
        """Main service loop - poll for investigations."""
        import time

        last_successful_poll = time.monotonic()
        stale_connection_threshold = 30.0

        while self.running:
            try:
                result = await asyncio.wait_for(self._pop_investigation_request(), timeout=5.0)
                last_successful_poll = time.monotonic()

                if result:
                    await self._process_investigation_request(result)

            except asyncio.TimeoutError:
                elapsed = time.monotonic() - last_successful_poll
                if elapsed > stale_connection_threshold:
                    logger.warning(
                        f"No successful Redis poll for {elapsed:.1f}s, "
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
                logger.info("Reconnected to Redis after forced reconnection")
            except Exception as e:
                logger.error(f"Failed to reconnect to Redis: {e}")

    async def _pop_investigation_request(self) -> dict[str, Any] | None:
        """Pop an investigation request from Redis queue."""
        if not self.task_queue or not self.task_queue._client:
            return None

        result = await self.task_queue._client.blpop(self.investigations_queue, timeout=5)
        if result:
            _, value = result
            return json.loads(value)
        return None

    def _should_use_multi_agent(self, request: InvestigationRequest) -> bool:
        """Determine if multi-agent should be used for this investigation."""
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
                    env_vars_data = await self.task_queue._client.get(env_vars_key)
                    if env_vars_data:
                        env_vars_str = self._decode_redis_value(env_vars_data)
                        request_data["env_vars"] = json.loads(env_vars_str)
                        await self.task_queue._client.delete(env_vars_key)
                        logger.debug(f"Loaded and deleted env_vars from {env_vars_key}")

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

                orchestrator = BlueTeamOrchestrator(
                    model=request.model,
                    grafana_url=grafana_url,
                    grafana_api_key=grafana_api_key,
                    mitre_client=mitre_client,
                    report_dir=report_dir,
                    max_steps=request.max_steps,
                    redis_url=self.redis_url,
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

            # Run the investigation
            logger.info(f"Starting investigation: {request.investigation_id}")
            result = await orchestrator.investigate(
                alert=request.alert,
                correlation_context=request.correlation_context,
            )

            # Publish investigation status: completed
            await self._publish_investigation_status(
                request.investigation_id,
                "completed",
                {
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "result": {
                        "investigation_id": result.get("investigation_id"),
                        "status": result.get("status"),
                        "evidence_count": result.get("evidence_count"),
                        "techniques_identified": result.get("techniques_identified"),
                        "highest_pyramid_level": result.get("highest_pyramid_level"),
                    },
                },
            )

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

        # Set status in Redis with 24h expiry
        await self.task_queue._client.setex(
            status_key,
            86400,
            json.dumps(status_data),
        )

        logger.debug(f"Published status for {investigation_id}: {status}")

    async def shutdown(self) -> None:
        """Shutdown the blue orchestrator service."""
        if not self.running:
            return

        logger.info("Shutting down blue team orchestrator service...")
        self.running = False
        self._shutdown_event.set()

        if self.task_queue:
            await self.task_queue.disconnect()

        logger.info("Blue team orchestrator service stopped")


async def main() -> None:
    """Main entry point for blue orchestrator service."""
    investigations_queue = os.getenv("INVESTIGATIONS_QUEUE", "ares:blue:investigations")

    # Setup logging
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
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
