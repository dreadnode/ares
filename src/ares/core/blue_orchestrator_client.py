"""Client for submitting investigations to the blue orchestrator service."""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from loguru import logger

from ares.core.config import get_redis_url
from ares.core.task_queue import RedisTaskQueue


async def submit_investigation(
    alert: dict[str, Any],
    investigation_id: str | None = None,
    correlation_context: dict[str, Any] | None = None,
    model: str | None = None,
    max_steps: int = 50,
    multi_agent: bool = False,
    auto_route: bool = True,
    report_dir: str | None = None,
    grafana_url: str | None = None,
    grafana_api_key: str | None = None,
    redis_url: str | None = None,
    investigations_queue: str = "ares:blue:investigations",
    wait_for_completion: bool = False,
    poll_interval: float = 10.0,
    env_vars: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Submit an investigation request to the blue orchestrator service.

    Args:
        alert: Alert dictionary to investigate
        investigation_id: Unique identifier (auto-generated if not provided)
        correlation_context: Optional context from alert correlator
        model: LLM model to use
        max_steps: Maximum agent steps
        multi_agent: Force multi-agent orchestrator
        auto_route: Enable severity-based routing (multi-agent for HIGH/CRITICAL)
        report_dir: Directory for markdown reports
        grafana_url: Grafana URL for MCP connection
        grafana_api_key: Grafana API key
        redis_url: Redis connection URL (default: from config)
        investigations_queue: Redis queue name for investigations
        wait_for_completion: If True, wait for investigation to complete
        poll_interval: Seconds between status polls when waiting
        env_vars: Environment variables to pass to orchestrator (API keys, etc.)

    Returns:
        Investigation status dict with keys:
        - investigation_id: Investigation ID
        - status: "submitted", "running", "completed", or "failed"
        - Additional status data if wait_for_completion=True
    """
    redis_url = redis_url or get_redis_url()
    investigation_id = investigation_id or f"inv-{uuid.uuid4().hex[:8]}"

    request = {
        "investigation_id": investigation_id,
        "alert": alert,
        "correlation_context": correlation_context,
        "model": model or os.environ.get("ARES_ORCHESTRATOR_MODEL") or os.environ.get("ARES_MODEL"),
        "max_steps": max_steps,
        "multi_agent": multi_agent,
        "auto_route": auto_route,
        "report_dir": report_dir,
        "grafana_url": grafana_url,
        "grafana_api_key": grafana_api_key,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "env_vars": env_vars,
    }

    if env_vars:
        redacted = {k: ("<set>" if v else "") for k, v in env_vars.items()}
        logger.info(f"Submitting investigation with env_vars: {redacted}")

    if not request["model"]:
        raise ValueError(
            "No model specified. Provide a model or set "
            "ARES_ORCHESTRATOR_MODEL/ARES_MODEL in the environment."
        )

    task_queue = RedisTaskQueue(redis_url)
    await task_queue.connect()

    try:
        if not task_queue._client:
            raise RuntimeError("Redis connection not established")

        # Store env_vars separately to avoid exposing secrets
        if env_vars:
            env_vars_key = f"ares:blue:inv:{investigation_id}:env_vars"
            await task_queue._client.set(env_vars_key, json.dumps(env_vars))
            await task_queue._client.expire(env_vars_key, 3600)
            request = {k: v for k, v in request.items() if k != "env_vars"}

        await task_queue._client.rpush(investigations_queue, json.dumps(request))
        logger.success(f"Investigation {investigation_id} submitted to blue orchestrator service")

        result = {
            "investigation_id": investigation_id,
            "status": "submitted",
            "submitted_at": request["submitted_at"],
        }

        if wait_for_completion:
            logger.info(f"Waiting for investigation {investigation_id} to complete...")
            final_status = await wait_for_investigation_completion(
                investigation_id=investigation_id,
                redis_url=redis_url,
                poll_interval=poll_interval,
            )
            result.update(final_status)

        return result

    finally:
        await task_queue.disconnect()


async def wait_for_investigation_completion(
    investigation_id: str,
    redis_url: str,
    poll_interval: float = 10.0,
    timeout: float = 3600.0,
) -> dict[str, Any]:
    """Wait for an investigation to complete.

    Args:
        investigation_id: Investigation ID to wait for
        redis_url: Redis connection URL
        poll_interval: Seconds between status polls
        timeout: Maximum time to wait in seconds

    Returns:
        Final investigation status dict

    Raises:
        TimeoutError: If investigation doesn't complete within timeout
    """
    task_queue = RedisTaskQueue(redis_url)
    await task_queue.connect()

    try:
        if not task_queue._client:
            raise RuntimeError("Redis connection not established")

        status_key = f"ares:blue:inv:{investigation_id}:status"
        start_time = asyncio.get_event_loop().time()

        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
                raise TimeoutError(
                    f"Investigation {investigation_id} did not complete within {timeout}s"
                )

            status_json = await task_queue.redis.get(status_key)
            if status_json:
                status = json.loads(status_json)

                if status["status"] in ("completed", "failed"):
                    logger.info(
                        f"Investigation {investigation_id} {status['status']}: "
                        f"{status.get('completed_at') or status.get('failed_at')}"
                    )
                    return status

                logger.debug(
                    f"Investigation {investigation_id} status: {status['status']} (elapsed: {elapsed:.0f}s)"
                )

            await asyncio.sleep(poll_interval)

    finally:
        await task_queue.disconnect()


async def get_investigation_status(
    investigation_id: str,
    redis_url: str | None = None,
) -> dict[str, Any] | None:
    """Get the current status of an investigation.

    Args:
        investigation_id: Investigation ID
        redis_url: Redis connection URL (default: from config)

    Returns:
        Investigation status dict or None if not found
    """
    redis_url = redis_url or get_redis_url()
    task_queue = RedisTaskQueue(redis_url)
    await task_queue.connect()

    try:
        if not task_queue._client:
            raise RuntimeError("Redis connection not established")

        status_key = f"ares:blue:inv:{investigation_id}:status"
        status_json = await task_queue.redis.get(status_key)

        if status_json:
            return json.loads(status_json)
        return None

    finally:
        await task_queue.disconnect()
