"""Client for submitting operations to the orchestrator service."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Any

from loguru import logger

from ares.core.config import get_redis_url
from ares.core.task_queue import RedisTaskQueue


async def submit_operation(
    operation_id: str,
    target_domain: str,
    target_ips: list[str],
    initial_credential: dict[str, str] | None = None,
    resume_from_checkpoint: bool = False,
    model: str | None = None,
    max_steps: int = 200,
    checkpoint_interval: int = 60,
    report_dir: str | None = None,
    redis_url: str | None = None,
    operations_queue: str = "ares:operations",
    wait_for_completion: bool = False,
    poll_interval: float = 10.0,
    env_vars: dict[str, str] | None = None,
    target_environment: str | None = None,
) -> dict[str, Any]:
    """Submit an operation request to the orchestrator service.

    Args:
        operation_id: Unique identifier for this operation
        target_domain: Target domain (e.g., "contoso.local")
        target_ips: List of target IPs to scan
        initial_credential: Optional initial credential dict with keys:
            - username: Username
            - password: Password (optional)
            - ntlm_hash: NTLM hash (optional)
            - domain: Domain (optional, defaults to target_domain)
        resume_from_checkpoint: Resume from previous checkpoint
        model: LLM model to use
        max_steps: Maximum agent steps
        checkpoint_interval: Seconds between checkpoints
        report_dir: Directory for markdown reports (orchestrator-side)
        redis_url: Redis connection URL (default: from config)
        operations_queue: Redis queue name for operations
        wait_for_completion: If True, wait for operation to complete
        poll_interval: Seconds between status polls when waiting
        env_vars: Environment variables to pass to orchestrator (API keys, etc.)
        target_environment: Target environment (e.g., "dev", "staging", "prod")

    Returns:
        Operation status dict with keys:
        - operation_id: Operation ID
        - status: "submitted", "running", "completed", or "failed"
        - Additional status data if wait_for_completion=True
    """
    # Resolve config defaults
    redis_url = redis_url or get_redis_url()

    # Build operation request
    request = {
        "operation_id": operation_id,
        "target_domain": target_domain,
        "target_ips": target_ips,
        "target_environment": target_environment,
        "initial_credential": initial_credential,
        "resume_from_checkpoint": resume_from_checkpoint,
        "model": model or os.environ.get("ARES_ORCHESTRATOR_MODEL") or os.environ.get("ARES_MODEL"),
        "max_steps": max_steps,
        "checkpoint_interval": checkpoint_interval,
        "report_dir": report_dir,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "env_vars": env_vars,
    }
    if env_vars:
        redacted = {k: ("<set>" if v else "") for k, v in env_vars.items()}
        logger.info(f"Submitting operation with env_vars: {redacted}")

    if not request["model"]:
        raise ValueError(
            "No model specified. Provide a model or set "
            "ARES_ORCHESTRATOR_MODEL/ARES_MODEL in the environment."
        )

    # Connect to Redis
    task_queue = RedisTaskQueue(redis_url)
    await task_queue.connect()

    try:
        # Push operation request to queue
        if not task_queue._client:
            raise RuntimeError("Redis connection not established")

        # Store env_vars separately to avoid exposing secrets in the main queue
        # The orchestrator will read and delete this key when processing
        if env_vars:
            env_vars_key = f"ares:op:{operation_id}:env_vars"
            await task_queue._client.set(env_vars_key, json.dumps(env_vars))
            # Set TTL of 1 hour in case operation is never processed
            await task_queue._client.expire(env_vars_key, 3600)
            # Remove env_vars from request - orchestrator will fetch from separate key
            request = {k: v for k, v in request.items() if k != "env_vars"}

        await task_queue._client.rpush(operations_queue, json.dumps(request))
        logger.success(f"Operation {operation_id} submitted to orchestrator service")

        result = {
            "operation_id": operation_id,
            "status": "submitted",
            "submitted_at": request["submitted_at"],
        }

        # Wait for completion if requested
        if wait_for_completion:
            logger.info(f"Waiting for operation {operation_id} to complete...")
            final_status = await wait_for_operation_completion(
                operation_id=operation_id,
                redis_url=redis_url,
                poll_interval=poll_interval,
            )
            result.update(final_status)

        return result

    finally:
        await task_queue.disconnect()


async def wait_for_operation_completion(
    operation_id: str,
    redis_url: str,
    poll_interval: float = 10.0,
    timeout: float = 3600.0,
) -> dict[str, Any]:
    """Wait for an operation to complete.

    Args:
        operation_id: Operation ID to wait for
        redis_url: Redis connection URL
        poll_interval: Seconds between status polls
        timeout: Maximum time to wait in seconds

    Returns:
        Final operation status dict

    Raises:
        TimeoutError: If operation doesn't complete within timeout
    """
    task_queue = RedisTaskQueue(redis_url)
    await task_queue.connect()

    try:
        if not task_queue._client:
            raise RuntimeError("Redis connection not established")

        status_key = f"ares:op:{operation_id}:status"
        start_time = asyncio.get_event_loop().time()

        while True:
            # Check timeout
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
                raise TimeoutError(f"Operation {operation_id} did not complete within {timeout}s")

            # Get operation status
            status_json = await task_queue.redis.get(status_key)
            if status_json:
                status = json.loads(status_json)

                # Check if operation is complete
                if status["status"] in ("completed", "failed"):
                    logger.info(
                        f"Operation {operation_id} {status['status']}: "
                        f"{status.get('completed_at') or status.get('failed_at')}"
                    )
                    return status

                # Log progress
                logger.debug(
                    f"Operation {operation_id} status: {status['status']} (elapsed: {elapsed:.0f}s)"
                )

            # Wait before next poll
            await asyncio.sleep(poll_interval)

    finally:
        await task_queue.disconnect()


async def get_operation_status(
    operation_id: str,
    redis_url: str | None = None,
) -> dict[str, Any] | None:
    """Get the current status of an operation.

    Args:
        operation_id: Operation ID.
        redis_url: Redis connection URL. Defaults to the configured value.

    Returns:
        Operation status data, or None if no status has been stored yet.
    """
    redis_url = redis_url or get_redis_url()
    task_queue = RedisTaskQueue(redis_url)
    await task_queue.connect()

    try:
        if not task_queue._client:
            raise RuntimeError("Redis connection not established")

        status_key = f"ares:op:{operation_id}:status"
        status_json = await task_queue.redis.get(status_key)

        if status_json:
            return json.loads(status_json)
        return None

    finally:
        await task_queue.disconnect()
