"""Persistent orchestrator service for Kubernetes deployment.

This service runs as a persistent pod in Kubernetes, listening for operation
requests on Redis and coordinating multi-agent operations.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from loguru import logger

from ares.core.models import Credential
from ares.core.orchestrator import run_multi_agent_operation
from ares.core.task_queue import RedisTaskQueue


@dataclass
class OperationRequest:
    """Operation request from client."""

    operation_id: str
    target_domain: str
    target_ips: list[str]
    initial_credential: dict[str, str] | None = None
    resume_from_checkpoint: bool = False
    model: str = "claude-sonnet-4-20250514"
    max_steps: int = 200
    checkpoint_interval: int = 60

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OperationRequest:
        """Create operation request from dictionary."""
        # Convert credential dict to Credential object if present
        initial_cred = None
        if data.get("initial_credential"):
            cred_data = data["initial_credential"]
            initial_cred = cred_data  # Keep as dict for now

        return cls(
            operation_id=data["operation_id"],
            target_domain=data["target_domain"],
            target_ips=data["target_ips"],
            initial_credential=initial_cred,
            resume_from_checkpoint=data.get("resume_from_checkpoint", False),
            model=data.get("model", "claude-sonnet-4-20250514"),
            max_steps=data.get("max_steps", 200),
            checkpoint_interval=data.get("checkpoint_interval", 60),
        )


class OrchestratorService:
    """Persistent orchestrator service."""

    def __init__(
        self,
        redis_url: str = "redis://redis.attack-simulation.svc.cluster.local:6379",
        namespace: str = "attack-simulation",
        operations_queue: str = "ares:operations",
    ):
        """Initialize orchestrator service.

        Args:
            redis_url: Redis connection URL
            namespace: Kubernetes namespace
            operations_queue: Redis queue for operation requests
        """
        self.redis_url = redis_url
        self.namespace = namespace
        self.operations_queue = operations_queue
        self.task_queue: RedisTaskQueue | None = None
        self.running = False
        self._shutdown_event = asyncio.Event()

    async def start(self) -> None:
        """Start the orchestrator service."""
        logger.info("Starting orchestrator service")
        logger.info(f"Redis URL: {self.redis_url}")
        logger.info(f"Namespace: {self.namespace}")
        logger.info(f"Operations queue: {self.operations_queue}")

        # Connect to Redis
        self.task_queue = RedisTaskQueue(self.redis_url)
        await self.task_queue.connect()
        logger.success("Connected to Redis")

        self.running = True

        # Setup signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))

        logger.info("Orchestrator service started, waiting for operation requests...")

        # Main service loop
        try:
            await self._run_service_loop()
        except Exception as e:
            logger.error(f"Service loop error: {e}")
            raise
        finally:
            await self.shutdown()

    async def _run_service_loop(self) -> None:
        """Main service loop - poll for operations."""
        while self.running:
            try:
                # Block for up to 5 seconds waiting for an operation request
                # Using BLPOP for blocking pop from list
                result = await asyncio.wait_for(self._pop_operation_request(), timeout=5.0)

                if result:
                    await self._process_operation_request(result)

            except asyncio.TimeoutError:  # noqa: PERF203
                # No operation in queue, continue polling
                continue
            except Exception as e:
                logger.error(f"Error in service loop: {e}")
                await asyncio.sleep(5)  # Back off on error

    async def _pop_operation_request(self) -> dict[str, Any] | None:
        """Pop an operation request from Redis queue.

        Returns:
            Operation request data or None if queue is empty
        """
        if not self.task_queue or not self.task_queue._client:
            return None

        # BLPOP returns (queue_name, value) or None
        result = await self.task_queue._client.blpop(self.operations_queue, timeout=5)
        if result:
            _, value = result
            return json.loads(value)
        return None

    async def _process_operation_request(self, request_data: dict[str, Any]) -> None:
        """Process an operation request.

        Args:
            request_data: Operation request data from Redis
        """
        try:
            # Parse request
            request = OperationRequest.from_dict(request_data)
            logger.info(f"Processing operation request: {request.operation_id}")
            logger.info(f"Target: {request.target_domain} ({len(request.target_ips)} IPs)")

            # Publish operation status: started
            await self._publish_operation_status(
                request.operation_id,
                "running",
                {"started_at": datetime.now(timezone.utc).isoformat()},
            )

            # Convert initial credential if present
            initial_cred = None
            if request.initial_credential:
                cred_data = request.initial_credential
                initial_cred = Credential(
                    username=cred_data.get("username", ""),
                    password=cred_data.get("password"),
                    ntlm_hash=cred_data.get("ntlm_hash"),
                    domain=cred_data.get("domain", request.target_domain),
                )

            # Run the operation
            logger.info(f"Starting multi-agent operation: {request.operation_id}")
            result = await run_multi_agent_operation(
                operation_id=request.operation_id,
                target_domain=request.target_domain,
                target_ips=request.target_ips,
                initial_credential=initial_cred,
                resume_from_checkpoint=request.resume_from_checkpoint,
                redis_url=self.redis_url,
                namespace=self.namespace,
                model=request.model,
                max_steps=request.max_steps,
                checkpoint_interval=request.checkpoint_interval,
            )

            # Publish operation status: completed
            await self._publish_operation_status(
                request.operation_id,
                "completed",
                {
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "result": result,
                },
            )

            logger.success(f"Operation {request.operation_id} completed successfully")

        except Exception as e:
            logger.error(f"Error processing operation: {e}")

            # Publish operation status: failed
            if "request" in locals():
                await self._publish_operation_status(
                    request.operation_id,
                    "failed",
                    {
                        "failed_at": datetime.now(timezone.utc).isoformat(),
                        "error": str(e),
                    },
                )

    async def _publish_operation_status(
        self,
        operation_id: str,
        status: str,
        data: dict[str, Any],
    ) -> None:
        """Publish operation status update to Redis.

        Args:
            operation_id: Operation ID
            status: Status (running, completed, failed)
            data: Additional status data
        """
        if not self.task_queue or not self.task_queue._client:
            return

        status_key = f"ares:operations:{operation_id}:status"
        status_data = {
            "status": status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            **data,
        }

        # Set status in Redis with 24h expiry
        await self.task_queue._client.setex(
            status_key,
            86400,  # 24 hours
            json.dumps(status_data),
        )

        logger.debug(f"Published status for {operation_id}: {status}")

    async def shutdown(self) -> None:
        """Shutdown the orchestrator service."""
        if not self.running:
            return

        logger.info("Shutting down orchestrator service...")
        self.running = False
        self._shutdown_event.set()

        if self.task_queue:
            await self.task_queue.disconnect()

        logger.info("Orchestrator service stopped")


async def main() -> None:
    """Main entry point for orchestrator service."""
    # Get configuration from environment
    redis_url = os.getenv("REDIS_URL", "redis://redis.attack-simulation.svc.cluster.local:6379")
    namespace = os.getenv("NAMESPACE", "attack-simulation")
    operations_queue = os.getenv("OPERATIONS_QUEUE", "ares:operations")

    # Setup logging
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=os.getenv("LOG_LEVEL", "INFO"),
    )

    # Create and start service
    service = OrchestratorService(
        redis_url=redis_url,
        namespace=namespace,
        operations_queue=operations_queue,
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
