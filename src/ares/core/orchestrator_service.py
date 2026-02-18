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

from ares.core.config import clear_config_cache, get_namespace, get_redis_url
from ares.core.litellm_env import configure_litellm_env
from ares.core.models import Credential
from ares.core.orchestrator import run_multi_agent_operation
from ares.core.recovery import OperationRecoveryManager
from ares.core.task_queue import RedisTaskQueue


def _configure_dreadnode():
    configure_litellm_env()
    import dreadnode as dn

    return dn


@dataclass
class OperationRequest:
    """Operation request from client."""

    operation_id: str
    target_domain: str
    target_ips: list[str]
    initial_credential: dict[str, str] | None = None
    resume_from_checkpoint: bool = False
    model: str | None = None
    max_steps: int = 200
    checkpoint_interval: int = 60
    report_dir: str | None = None
    # API keys passed from client (set as env vars before running)
    env_vars: dict[str, str] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OperationRequest:
        """Create operation request from dictionary."""
        # Convert credential dict to Credential object if present
        initial_cred = None
        if data.get("initial_credential"):
            cred_data = data["initial_credential"]
            initial_cred = cred_data  # Keep as dict for now

        # Resolve model - check request env_vars first (they haven't been applied to os.environ yet)
        env_vars = data.get("env_vars") or {}
        model = (
            data.get("model")
            or env_vars.get("ARES_ORCHESTRATOR_MODEL")
            or env_vars.get("ARES_MODEL")
            or os.environ.get("ARES_ORCHESTRATOR_MODEL")
            or os.environ.get("ARES_MODEL")
        )

        return cls(
            operation_id=data["operation_id"],
            target_domain=data["target_domain"],
            target_ips=data["target_ips"],
            initial_credential=initial_cred,
            resume_from_checkpoint=data.get("resume_from_checkpoint", False),
            model=model,
            max_steps=data.get("max_steps", 200),
            checkpoint_interval=data.get("checkpoint_interval", 60),
            report_dir=data.get("report_dir")
            or env_vars.get("ARES_REPORT_DIR")
            or os.environ.get("ARES_REPORT_DIR"),
            env_vars=env_vars or None,
        )


class OrchestratorService:
    """Persistent orchestrator service."""

    def __init__(
        self,
        redis_url: str | None = None,
        namespace: str | None = None,
        operations_queue: str = "ares:operations",
    ):
        """Initialize orchestrator service.

        Args:
            redis_url: Redis connection URL (default: from config)
            namespace: Kubernetes namespace (default: from config)
            operations_queue: Redis queue for operation requests
        """
        self.redis_url = redis_url or get_redis_url()
        self.namespace = namespace or get_namespace()
        self.operations_queue = operations_queue
        self.task_queue: RedisTaskQueue | None = None
        self.running = False
        self._shutdown_event = asyncio.Event()
        # Max age in seconds for an operation to be considered recoverable
        self._max_operation_age = int(os.getenv("MAX_OPERATION_AGE", "300"))  # 5 minutes default
        self._report_dir = os.environ.get("ARES_REPORT_DIR")

    @staticmethod
    def _decode_redis_value(value: str | bytes) -> str:
        return value.decode() if isinstance(value, bytes) else str(value)

    async def _get_checkpoint_time(self, op_id: str) -> datetime | None:
        if self.task_queue is None:
            return None
        # Read started_at from redis-native meta hash
        meta_key = f"ares:op:{op_id}:meta"
        started_at = await self.task_queue._client.hget(meta_key, "started_at")
        if not started_at:
            logger.debug(f"Operation {op_id} has no started_at in meta, skipping")
            return None

        checkpoint_str = self._decode_redis_value(started_at)
        # Decode JSON since set_meta uses json.dumps()
        try:
            checkpoint_str = json.loads(checkpoint_str)
        except json.JSONDecodeError:
            pass
        checkpoint_time = datetime.fromisoformat(checkpoint_str)
        if checkpoint_time.tzinfo is None:
            checkpoint_time = checkpoint_time.replace(tzinfo=timezone.utc)
        return checkpoint_time

    async def _discover_orphaned_operations(self) -> list[str]:
        """
        Discover orphaned operations in Redis that can be recovered.

        Scans Redis for operation state keys and returns operation IDs that:
        - Have a recent checkpoint (within _max_operation_age seconds)
        - Don't have an active lock held by another orchestrator

        Returns:
            List of recoverable operation IDs, sorted by most recent first.
        """
        if not self.task_queue or not self.task_queue._client:
            return []

        recoverable: list[tuple[str, datetime]] = []
        now = datetime.now(timezone.utc)

        try:
            # Scan for operation state keys (redis-native format)
            async for key in self.task_queue._client.scan_iter("ares:op:*:meta"):
                # Extract operation ID from key: ares:op:<op_id>:meta
                key_str = key.decode() if isinstance(key, bytes) else str(key)
                parts = key_str.split(":")
                if len(parts) < 3:
                    continue

                op_id = parts[2]

                # Get checkpoint time to check if operation is recent
                checkpoint_time = await self._get_checkpoint_time(op_id)
                if not checkpoint_time:
                    continue

                age_seconds = (now - checkpoint_time).total_seconds()
                if age_seconds > self._max_operation_age:
                    logger.debug(
                        f"Operation {op_id} checkpoint is stale "
                        f"({age_seconds:.0f}s > {self._max_operation_age}s)"
                    )
                    continue

                # Check if operation is already locked by another orchestrator
                lock_key = f"ares:lock:{op_id}"
                lock_held = await self.task_queue._client.exists(lock_key)
                if lock_held:
                    logger.debug(f"Operation {op_id} is locked by another orchestrator")
                    continue

                # Check operation status - don't recover completed/failed operations
                status_key = f"ares:op:{op_id}:status"
                status_data = await self.task_queue._client.get(status_key)
                if status_data:
                    status_str = self._decode_redis_value(status_data)
                    status = json.loads(status_str)
                    if status.get("status") in ("completed", "failed"):
                        logger.debug(f"Operation {op_id} is already {status.get('status')}")
                        continue

                recoverable.append((op_id, checkpoint_time))
                logger.info(
                    f"Found recoverable operation: {op_id} (checkpoint age: {age_seconds:.0f}s)"
                )

        except Exception as e:
            logger.error(f"Error scanning for orphaned operations: {e}")
            return []

        # Sort by most recent checkpoint first
        recoverable.sort(key=lambda x: x[1], reverse=True)
        return [op_id for op_id, _ in recoverable]

    async def _recover_orphaned_operation(self, operation_id: str) -> None:
        """
        Recover and resume an orphaned operation.

        Args:
            operation_id: The operation ID to recover
        """
        logger.info(f"Attempting to recover orphaned operation: {operation_id}")

        try:
            # Use recovery manager to get operation state
            recovery_manager = OperationRecoveryManager(redis_url=self.redis_url)
            await recovery_manager.start()

            try:
                state, _requeued_task_ids = await recovery_manager.recover_operation(
                    operation_id, auto_requeue=True
                )
            finally:
                await recovery_manager.stop()

            # Publish status update
            await self._publish_operation_status(
                operation_id,
                "running",
                {
                    "resumed_at": datetime.now(timezone.utc).isoformat(),
                    "recovered": True,
                },
            )

            # Resume the operation using stored state
            target_domain = state.target.domain if state.target else ""
            target_ips = [h.ip for h in state.all_hosts if h.ip]
            if not target_ips and state.target and state.target.ip:
                target_ips = [state.target.ip]

            # Load stored model from Redis (required for recovery)
            model: str | None = None
            model_key = f"ares:op:{operation_id}:model"
            if self.task_queue and self.task_queue._client:
                stored_model = await self.task_queue._client.get(model_key)
                if stored_model:
                    model = (
                        stored_model.decode()
                        if isinstance(stored_model, bytes)
                        else str(stored_model)
                    )
            if not model:
                # Fallback to environment variables if model not stored
                model = os.environ.get("ARES_ORCHESTRATOR_MODEL") or os.environ.get("ARES_MODEL")
            if not model:
                raise ValueError(
                    f"No model stored for operation {operation_id} and no "
                    "ARES_ORCHESTRATOR_MODEL/ARES_MODEL in environment"
                )

            logger.info(
                f"Resuming operation {operation_id}: "
                f"target={target_domain}, model={model}, "
                f"credentials={len(state.all_credentials)}, "
                f"hosts={len(state.all_hosts)}"
            )

            configure_litellm_env()

            result = await run_multi_agent_operation(
                operation_id=operation_id,
                target_domain=target_domain,
                target_ips=target_ips,
                initial_credential=state.all_credentials[0] if state.all_credentials else None,
                resume_from_checkpoint=True,
                report_dir=self._report_dir,
                redis_url=self.redis_url,
                namespace=self.namespace,
                model=model,
            )

            # Publish completion status
            await self._publish_operation_status(
                operation_id,
                "completed",
                {
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "result": result,
                    "recovered": True,
                },
            )
            logger.success(f"Recovered operation {operation_id} completed successfully")

        except Exception as e:
            logger.error(f"Failed to recover operation {operation_id}: {e}")
            await self._publish_operation_status(
                operation_id,
                "failed",
                {
                    "failed_at": datetime.now(timezone.utc).isoformat(),
                    "error": str(e),
                    "recovered": True,
                },
            )

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

        # Check for orphaned operations that need recovery
        orphaned_ops = await self._discover_orphaned_operations()
        if orphaned_ops:
            logger.warning(f"Found {len(orphaned_ops)} orphaned operation(s) to recover")
            for op_id in orphaned_ops:
                if not self.running:
                    break
                await self._recover_orphaned_operation(op_id)
        else:
            logger.info("No orphaned operations found")

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

            except asyncio.TimeoutError:
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

    def _log_env_vars(self, raw_env_vars: Any) -> None:
        """Log environment variables from request."""
        if raw_env_vars is None:
            logger.warning("Request missing env_vars")
        elif isinstance(raw_env_vars, dict):
            raw_keys = sorted(k for k, v in raw_env_vars.items() if v)
            if raw_keys:
                logger.info(f"Request env_vars keys (raw): {', '.join(raw_keys)}")
            else:
                logger.warning("Request env_vars present but empty")
        else:
            logger.warning(f"Request env_vars not a dict: {type(raw_env_vars)}")

    def _resolve_openai_api_key(self, request_env_vars: dict[str, str] | None) -> str | None:
        """Resolve OpenAI API key from request or environment."""
        openai_api_key = request_env_vars.get("OPENAI_API_KEY") if request_env_vars else None
        if request_env_vars:
            present_keys = sorted(k for k, v in request_env_vars.items() if v)
            if present_keys:
                logger.info(f"Request env keys present: {', '.join(present_keys)}")
        if not openai_api_key:
            openai_api_key = os.environ.get("OPENAI_API_KEY")
            if openai_api_key:
                logger.warning("OPENAI_API_KEY missing in request env vars; using process env")
        return openai_api_key

    async def _persist_operation_model(self, operation_id: str, model: str) -> None:
        """Persist per-operation model so workers can resolve it."""
        if not self.task_queue or not self.task_queue._client:
            logger.warning("Cannot persist operation model: Redis client unavailable")
            return
        key = f"ares:op:{operation_id}:model"
        try:
            await self.task_queue._client.set(key, model)
        except Exception as e:
            logger.warning(f"Failed to persist operation model for {operation_id}: {e}")

    async def _persist_operation_model_overrides(
        self, operation_id: str, request_env_vars: dict[str, str] | None
    ) -> None:
        """Persist model env overrides so workers can resolve role-specific models."""
        if not request_env_vars:
            return
        if not self.task_queue or not self.task_queue._client:
            logger.warning("Cannot persist model overrides: Redis client unavailable")
            return

        allowed_keys = {
            "ARES_MODEL",
            "ARES_ORCHESTRATOR_MODEL",
            "ARES_WORKER_MODEL",
        }
        overrides = {
            key: value
            for key, value in request_env_vars.items()
            if value
            and (key in allowed_keys or (key.startswith("ARES_AGENT_") and key.endswith("_MODEL")))
        }
        if not overrides:
            return

        key = f"ares:op:{operation_id}:model_overrides"
        try:
            await self.task_queue._client.set(key, json.dumps(overrides))
        except Exception as e:
            logger.warning(f"Failed to persist model overrides for {operation_id}: {e}")

    async def _process_operation_request(self, request_data: dict[str, Any]) -> None:
        """Process an operation request.

        Args:
            request_data: Operation request data from Redis
        """
        started_at = datetime.now(timezone.utc)
        try:
            # Fetch env_vars from separate key if not in request (security: secrets stored separately)
            if not request_data.get("env_vars") and request_data.get("operation_id"):
                env_vars_key = f"ares:op:{request_data['operation_id']}:env_vars"
                if self.task_queue and self.task_queue._client:
                    env_vars_data = await self.task_queue._client.get(env_vars_key)
                    if env_vars_data:
                        env_vars_str = self._decode_redis_value(env_vars_data)
                        request_data["env_vars"] = json.loads(env_vars_str)
                        # Delete the key immediately after reading to minimize exposure
                        await self.task_queue._client.delete(env_vars_key)
                        logger.debug(f"Loaded and deleted env_vars from {env_vars_key}")

            self._log_env_vars(request_data.get("env_vars"))

            # Parse request
            request = OperationRequest.from_dict(request_data)
            logger.info(f"Processing operation request: {request.operation_id}")
            logger.info(f"Target: {request.target_domain} ({len(request.target_ips)} IPs)")

            # Set environment variables from request (API keys, etc.)
            if request.env_vars:
                for key, value in request.env_vars.items():
                    if value:  # Only set non-empty values
                        os.environ[key] = value
                        logger.debug(f"Set environment variable: {key}")
                # Clear config cache so env overrides are applied on next load_config()
                clear_config_cache()

            if request.model:
                await self._persist_operation_model(request.operation_id, request.model)
            await self._persist_operation_model_overrides(request.operation_id, request.env_vars)

            openai_api_key = self._resolve_openai_api_key(request.env_vars)

            try:
                dn = _configure_dreadnode()
                dn.configure()
            except Exception as e:
                logger.warning(f"Dreadnode configure failed, continuing without telemetry: {e}")

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
            if not request.model:
                raise ValueError(
                    "No model specified for operation. Provide --model at submit time or set "
                    "ARES_ORCHESTRATOR_MODEL/ARES_MODEL in the orchestrator environment."
                )
            logger.info(
                f"Runtime env presence: OPENAI_API_KEY={'set' if os.environ.get('OPENAI_API_KEY') else 'missing'} DREADNODE_API_KEY={'set' if os.environ.get('DREADNODE_API_KEY') else 'missing'}"
            )
            if request.model.startswith("gpt-") and not os.environ.get("OPENAI_API_KEY"):
                raise ValueError(
                    "OPENAI_API_KEY is required for OpenAI models. Ensure it is set in the "
                    "orchestrator environment or passed via env_vars."
                )
            configure_litellm_env()

            result = await run_multi_agent_operation(
                operation_id=request.operation_id,
                target_domain=request.target_domain,
                target_ips=request.target_ips,
                initial_credential=initial_cred,
                resume_from_checkpoint=request.resume_from_checkpoint,
                report_dir=request.report_dir or self._report_dir,
                redis_url=self.redis_url,
                namespace=self.namespace,
                model=request.model,
                max_steps=request.max_steps,
                checkpoint_interval=request.checkpoint_interval,
                openai_api_key=openai_api_key,
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
            start_str = started_at.strftime("%H:%M:%S")
            end_str = completed_at.strftime("%H:%M:%S")
            logger.success(
                f"Operation {request.operation_id} completed successfully "
                f"(started {start_str}, ended {end_str}, duration {duration_str})"
            )

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

        status_key = f"ares:op:{operation_id}:status"
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
    # Get configuration from environment (operations_queue not in config system)
    operations_queue = os.getenv("OPERATIONS_QUEUE", "ares:operations")

    # Setup logging
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=os.getenv("LOG_LEVEL", "INFO"),
    )

    # Create and start service (redis_url and namespace from config system)
    service = OrchestratorService(
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
