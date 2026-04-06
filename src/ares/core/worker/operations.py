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


def _unwrap_json_string(value: str) -> str:
    """Unwrap a potentially double-encoded JSON string.

    Some Redis values may be double-encoded (json.dumps called twice),
    resulting in values like '"\"2026-02-22T21:32:56\""'. This function
    repeatedly decodes until we get a non-JSON-string result.
    """
    result = value
    for _ in range(3):  # Max 3 levels of encoding
        try:
            decoded = json.loads(result)
            if isinstance(decoded, str):
                result = decoded
            else:
                # Not a string, return as-is
                return result
        except (json.JSONDecodeError, TypeError):
            break
    return result


async def discover_active_operation(
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
                active_key = await client.get("ares:op:active")
                if active_key:
                    active_op_id = str(active_key)
                    # Check redis-native state format
                    native_meta_key = f"ares:op:{active_op_id}:meta"
                    has_native_state = await client.exists(native_meta_key)

                    if has_native_state:
                        # Check if operation has a lock (actively running)
                        lock_key = f"ares:lock:{active_op_id}"
                        has_lock = await client.exists(lock_key)

                        # If operation has a lock, it's actively running - accept immediately
                        if has_lock:
                            logger.info(
                                f"Discovered active operation via pointer (has lock): {active_op_id}"
                            )
                            await _cleanup_client()
                            return active_op_id

                        # No lock - check age to avoid joining abandoned operations
                        checkpoint_time = None
                        # Read started_at from meta hash
                        meta_data = await client.hgetall(native_meta_key)
                        if meta_data:
                            started_raw = meta_data.get("started_at")
                            if started_raw:
                                try:
                                    checkpoint_time = datetime.fromisoformat(str(started_raw))
                                    if checkpoint_time.tzinfo is None:
                                        checkpoint_time = checkpoint_time.replace(
                                            tzinfo=timezone.utc
                                        )
                                except Exception:
                                    pass

                        # Fall back to parsing timestamp from operation ID
                        if not checkpoint_time:
                            try:
                                parts = active_op_id.split("-")
                                if len(parts) >= 3:
                                    date_str = parts[1]
                                    time_str = parts[2]
                                    checkpoint_time = datetime.strptime(
                                        f"{date_str}{time_str}", "%Y%m%d%H%M%S"
                                    ).replace(tzinfo=timezone.utc)
                            except Exception:
                                pass
                            # Default to now if all parsing failed
                            if not checkpoint_time:
                                checkpoint_time = now

                        age_seconds = (now - checkpoint_time).total_seconds()
                        if age_seconds <= max_operation_age:
                            logger.info(f"Discovered active operation via pointer: {active_op_id}")
                            await _cleanup_client()
                            return active_op_id
                        logger.debug(
                            f"Ignoring stale pointed operation {active_op_id} "
                            f"(age: {age_seconds:.0f}s, no lock)"
                        )
                    else:
                        # Stale pointer - state was cleared but pointer wasn't.
                        # Delete the invalid pointer so we can discover new operations.
                        logger.warning(
                            f"Deleting stale operation pointer to missing state: {active_op_id}"
                        )
                        await client.delete("ares:op:active")

                # Scan for operation state keys (redis-native format)
                operations: list[tuple[str, datetime]] = []
                seen_ops: set[str] = set()

                # Scan redis-native state format: ares:op:*:meta
                async for key in client.scan_iter("ares:op:*:meta"):
                    parts = str(key).split(":")
                    if len(parts) >= 3:
                        op_id = parts[2]
                        if op_id in seen_ops:
                            continue
                        seen_ops.add(op_id)

                        # Check if operation has a lock (actively running orchestrator)
                        # If locked, accept immediately regardless of timestamps
                        lock_key = f"ares:lock:{op_id}"
                        has_lock = await client.exists(lock_key)
                        if has_lock:
                            logger.info(f"Discovered active operation via lock (scan): {op_id}")
                            operations.append((op_id, now))  # Use now for sorting
                            continue

                        # Get started_at from meta hash (JSON-encoded by set_meta)
                        checkpoint_time = None
                        meta_key = f"ares:op:{op_id}:meta"
                        started_at_raw = await client.hget(meta_key, "started_at")
                        if started_at_raw:
                            try:
                                # Decode JSON, handling potentially double-encoded strings
                                started_at = _unwrap_json_string(str(started_at_raw))
                                checkpoint_time = datetime.fromisoformat(started_at)
                                if checkpoint_time.tzinfo is None:
                                    checkpoint_time = checkpoint_time.replace(tzinfo=timezone.utc)
                            except Exception:
                                pass

                        # Parse timestamp from operation ID (op-YYYYMMDD-HHMMSS)
                        if not checkpoint_time:
                            try:
                                # Extract YYYYMMDD-HHMMSS from op_id
                                parts = op_id.split("-")
                                if len(parts) >= 3:
                                    date_str = parts[1]  # YYYYMMDD
                                    time_str = parts[2]  # HHMMSS
                                    checkpoint_time = datetime.strptime(
                                        f"{date_str}{time_str}", "%Y%m%d%H%M%S"
                                    ).replace(tzinfo=timezone.utc)
                            except Exception:
                                pass
                            # Default to now if all parsing failed
                            if not checkpoint_time:
                                checkpoint_time = now

                        age_seconds = (now - checkpoint_time).total_seconds()
                        if age_seconds <= max_operation_age:
                            operations.append((op_id, checkpoint_time))
                        else:
                            logger.debug(
                                f"Ignoring stale operation {op_id} "
                                f"(age: {age_seconds:.0f}s > {max_operation_age}s)"
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

            except asyncio.CancelledError:
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
        return await client.get(f"ares:op:{operation_id}:model")
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
        raw = await client.get(f"ares:op:{operation_id}:model_overrides")
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


async def is_operation_completed(redis_url: str, operation_id: str) -> bool:
    """Check if an operation has been marked as completed.

    Args:
        redis_url: Redis connection URL
        operation_id: Operation ID to check

    Returns:
        True if operation status is "completed", "failed", or "killed", False otherwise
    """
    client = await create_redis_client(redis_url, decode_responses=True)
    try:
        status_key = f"ares:op:{operation_id}:status"
        status_data = await client.get(status_key)
        if not status_data:
            return False
        data = json.loads(str(status_data))
        status = data.get("status", "")
        return status in ("completed", "failed", "killed")
    except Exception as e:
        logger.debug(f"Failed to check operation status for {operation_id}: {e}")
        return False
    finally:
        try:
            await client.aclose()
        except Exception:
            pass


async def get_active_operation_pointer(redis_url: str, max_operation_age: int = 300) -> str | None:
    """Fetch a valid active operation pointer from Redis, if present."""
    client = await create_redis_client(redis_url, decode_responses=True)
    try:
        active_key = await client.get("ares:op:active")
        if not active_key:
            return None
        op_id = str(active_key)
        # Check redis-native state format
        meta_key = f"ares:op:{op_id}:meta"
        if not await client.exists(meta_key):
            return None
        # Get started_at from meta hash (JSON-encoded by set_meta)
        started_at_raw = await client.hget(meta_key, "started_at")
        if not started_at_raw:
            return op_id
        # Decode JSON, handling potentially double-encoded strings
        started_at = _unwrap_json_string(str(started_at_raw))
        checkpoint_time = datetime.fromisoformat(started_at)
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


async def get_worker_credentials(redis_url: str, operation_id: str) -> dict[str, str] | None:
    """Fetch API credentials for workers from Redis.

    These credentials are persisted by the orchestrator when an operation starts,
    allowing workers in separate pods to authenticate with LLM providers.
    """
    client = await create_redis_client(redis_url, decode_responses=True)
    try:
        raw = await client.get(f"ares:op:{operation_id}:worker_credentials")
        if not raw:
            return None
        data = json.loads(raw)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items() if v}
        logger.warning(f"Unexpected worker credentials payload type: {type(data)}")
        return None
    except Exception as e:
        logger.warning(f"Failed to read worker credentials for {operation_id}: {e}")
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
    "get_worker_credentials",
    "is_operation_completed",
]
