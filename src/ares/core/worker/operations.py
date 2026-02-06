"""Operation discovery and configuration from Redis.

This module provides utilities for discovering active operations,
fetching operation-specific model configurations, and managing
the operation lifecycle for workers.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from datetime import datetime, timezone

from loguru import logger

from ares.core.redis_client import create_redis_client


async def discover_active_operation(  # noqa: PLR0912
    redis_url: str, max_wait: int | None = None, max_operation_age: int = 300
) -> str | None:
    """
    Discover an active operation from Redis by scanning for operation keys.

    Waits indefinitely (by default) for an operation to appear.
    Returns the most recently checkpointed operation ID, only if it was
    checkpointed within max_operation_age seconds.

    This function is cancellation-safe and will clean up resources properly
    when cancelled (e.g., during graceful shutdown).

    Args:
        redis_url: Redis connection URL
        max_wait: Maximum seconds to wait for an operation (default: None = wait forever).
            Set to a positive integer to timeout after that many seconds.
        max_operation_age: Maximum age in seconds for an operation to be considered
            active (default: 300 = 5 minutes). Operations with older checkpoints
            are ignored to prevent workers from joining stale operations.

    Returns:
        Operation ID if found, None only if max_wait is set and exceeded

    Raises:
        asyncio.CancelledError: Re-raised after cleanup when the task is cancelled
    """
    start_time = time.monotonic()
    last_log_time = start_time
    consecutive_errors = 0
    client = None

    async def _cleanup_client() -> None:
        """Close Redis client if open."""
        nonlocal client
        if client:
            try:
                await client.aclose()
            except Exception:
                pass
            client = None

    try:
        while True:
            try:
                # Reuse existing connection or create new one
                if client is None:
                    client = await create_redis_client(
                        redis_url,
                        decode_responses=True,
                    )
                await client.ping()

                now = datetime.now(timezone.utc)

                # Honor explicit operation pointer before scanning checkpoints.
                active_key = await client.get("ares:operation:active")
                if active_key:
                    active_op_id = str(active_key)
                    state_key = f"ares:operation:{active_op_id}:state"
                    if await client.exists(state_key):
                        time_key = f"ares:operation:{active_op_id}:checkpoint_time"
                        checkpoint_data = await client.get(time_key)
                        if checkpoint_data:
                            checkpoint_time = datetime.fromisoformat(str(checkpoint_data))
                            if checkpoint_time.tzinfo is None:
                                checkpoint_time = checkpoint_time.replace(tzinfo=timezone.utc)
                            age_seconds = (now - checkpoint_time).total_seconds()
                            if age_seconds <= max_operation_age:
                                logger.info(
                                    f"Discovered active operation via pointer: {active_op_id}"
                                )
                                await _cleanup_client()
                                return active_op_id
                            logger.debug(
                                f"Ignoring stale pointed operation {active_op_id} "
                                f"(checkpoint age: {age_seconds:.0f}s > "
                                f"{max_operation_age}s)"
                            )
                        else:
                            logger.debug(
                                f"Active operation pointer has no checkpoint yet: {active_op_id}"
                            )
                    else:
                        logger.debug(
                            f"Active operation pointer references missing state: {active_op_id}"
                        )

                # Scan for operation state keys
                operations: list[tuple[str, datetime]] = []
                async for key in client.scan_iter("ares:operation:*:state"):
                    # Extract operation ID from key: ares:operation:<op_id>:state
                    parts = str(key).split(":")
                    if len(parts) >= 3:
                        op_id = parts[2]

                        # Get checkpoint time to find most recent operation
                        time_key = f"ares:operation:{op_id}:checkpoint_time"
                        checkpoint_data = await client.get(time_key)

                        if checkpoint_data:
                            checkpoint_time = datetime.fromisoformat(str(checkpoint_data))
                            # Ensure checkpoint_time is timezone-aware for comparison
                            if checkpoint_time.tzinfo is None:
                                checkpoint_time = checkpoint_time.replace(tzinfo=timezone.utc)

                            # Only consider operations checkpointed within max_operation_age
                            age_seconds = (now - checkpoint_time).total_seconds()
                            if age_seconds <= max_operation_age:
                                operations.append((op_id, checkpoint_time))
                            else:
                                logger.debug(
                                    f"Ignoring stale operation {op_id} "
                                    f"(checkpoint age: {age_seconds:.0f}s > "
                                    f"{max_operation_age}s)"
                                )

                if operations:
                    # Return the most recently checkpointed operation
                    operations.sort(key=lambda x: x[1], reverse=True)
                    operation_id = operations[0][0]
                    logger.info(f"Discovered active operation: {operation_id}")
                    await _cleanup_client()
                    return operation_id

                # Calculate elapsed time once for both timeout check and logging
                elapsed = time.monotonic() - start_time

                # Check if we've exceeded max wait time (only if max_wait is set)
                if max_wait is not None and elapsed >= max_wait:
                    logger.warning(f"No active operations found after {max_wait}s")
                    await _cleanup_client()
                    return None

                # Successful iteration (no errors) - reset backoff counter
                consecutive_errors = 0

                # Wait before retrying (log once per minute to reduce noise)
                if elapsed - last_log_time >= 60:
                    logger.debug(f"No operations found, waiting... ({int(elapsed)}s elapsed)")
                    last_log_time = time.monotonic()
                await asyncio.sleep(10)

            except asyncio.CancelledError:  # noqa: PERF203
                # Graceful shutdown - clean up and re-raise
                logger.info("Operation discovery cancelled, cleaning up")
                raise

            except Exception as e:
                consecutive_errors += 1
                logger.warning(f"Failed to scan for operations: {e}")

                # Close broken connection so we reconnect next iteration
                await _cleanup_client()

                # If Redis isn't available at all, don't spin forever.
                if isinstance(e, RuntimeError) and "redis package required" in str(e):
                    logger.error("redis package not installed, cannot discover operations")
                    return None

                # Respect max_wait even when errors occur.
                if max_wait is not None and (time.monotonic() - start_time) >= max_wait:
                    logger.warning(f"No active operations found after {max_wait}s")
                    return None

                # Exponential backoff with jitter, capped at 60s
                backoff = min(5 * (2 ** (consecutive_errors - 1)), 60)
                jitter = random.uniform(0, 1)  # nosec B311 # noqa: S311 - jitter for backoff
                await asyncio.sleep(backoff + jitter)

    finally:
        # Ensure cleanup on any exit path
        await _cleanup_client()


async def get_operation_model(redis_url: str, operation_id: str) -> str | None:
    """Fetch the model configured for a specific operation from Redis."""
    client = await create_redis_client(redis_url, decode_responses=True)
    try:
        return await client.get(f"ares:operation:{operation_id}:model")
    except Exception as e:
        logger.warning(f"Failed to read operation model for {operation_id}: {e}")
        return None
    finally:
        try:
            await client.aclose()
        except Exception:
            pass


async def get_operation_model_overrides(redis_url: str, operation_id: str) -> dict[str, str] | None:
    """Fetch model override env vars for a specific operation from Redis."""
    client = await create_redis_client(redis_url, decode_responses=True)
    try:
        raw = await client.get(f"ares:operation:{operation_id}:model_overrides")
        if not raw:
            return None
        data = json.loads(raw)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items() if v}
        logger.warning(f"Unexpected model overrides payload type: {type(data)}")
        return None
    except Exception as e:
        logger.warning(f"Failed to read model overrides for {operation_id}: {e}")
        return None
    finally:
        try:
            await client.aclose()
        except Exception:
            pass


async def get_active_operation_pointer(redis_url: str, max_operation_age: int = 300) -> str | None:
    """Fetch a valid active operation pointer from Redis, if present."""
    client = await create_redis_client(redis_url, decode_responses=True)
    try:
        active_key = await client.get("ares:operation:active")
        if not active_key:
            return None
        op_id = str(active_key)
        state_key = f"ares:operation:{op_id}:state"
        if not await client.exists(state_key):
            return None
        time_key = f"ares:operation:{op_id}:checkpoint_time"
        checkpoint_data = await client.get(time_key)
        if not checkpoint_data:
            return op_id
        checkpoint_time = datetime.fromisoformat(str(checkpoint_data))
        if checkpoint_time.tzinfo is None:
            checkpoint_time = checkpoint_time.replace(tzinfo=timezone.utc)
        age_seconds = (datetime.now(timezone.utc) - checkpoint_time).total_seconds()
        if age_seconds <= max_operation_age:
            return op_id
        return None
    except Exception as e:
        logger.warning(f"Failed to read active operation pointer: {e}")
        return None
    finally:
        try:
            await client.aclose()
        except Exception:
            pass


__all__ = [
    "discover_active_operation",
    "get_active_operation_pointer",
    "get_operation_model",
    "get_operation_model_overrides",
]
