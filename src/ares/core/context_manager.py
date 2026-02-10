"""Context management for multi-agent operations.

This module provides context offloading and management to prevent
context window exhaustion in long-running agent operations.

Based on industry patterns from:
- LangChain Deep Agents SDK (tool output offloading)
- Google ADK (conversation compaction)
- Manus Framework (context reduction/isolation)
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from loguru import logger

if TYPE_CHECKING:
    from redis.asyncio import Redis

# Threshold for offloading tool outputs (characters)
# Outputs larger than this are stored in Redis with a reference
DEFAULT_OFFLOAD_THRESHOLD = 5000

# TTL for offloaded outputs (seconds) - 4 hours
OFFLOAD_TTL = 14400


def _hash_content(content: str) -> str:
    """Generate a short hash for content identification."""
    return hashlib.sha256(content.encode()).hexdigest()[:12]


def estimate_tokens(text: str) -> int:
    """Estimate token count from text.

    Uses a simple heuristic: ~4 characters per token for English text.
    This is conservative for code/structured output.
    """
    return len(text) // 4


async def offload_large_output(
    redis: Redis,
    operation_id: str,
    task_id: str,
    output: str,
    threshold: int = DEFAULT_OFFLOAD_THRESHOLD,
) -> tuple[str, bool]:
    """Offload large output to Redis, return summary + reference.

    Args:
        redis: Redis client
        operation_id: Current operation ID
        task_id: Task that produced the output
        output: Full output text
        threshold: Character threshold for offloading

    Returns:
        Tuple of (output_or_summary, was_offloaded)
    """
    if len(output) <= threshold:
        return output, False

    # Generate storage key
    content_hash = _hash_content(output)
    redis_key = f"ares:operation:{operation_id}:output:{task_id}:{content_hash}"

    # Store full output in Redis
    await redis.set(redis_key, output, ex=OFFLOAD_TTL)

    # Generate summary with reference
    lines = output.split("\n")
    preview_lines = lines[:10]
    preview = "\n".join(preview_lines)
    if len(preview) > 500:
        preview = preview[:500]

    summary = (
        f"{preview}\n\n"
        f"[Output truncated - {len(output):,} chars, {len(lines)} lines]\n"
        f"[Full output stored: {redis_key}]\n"
        f"[Use retrieve_task_output(task_id='{task_id}') to fetch full content]"
    )

    logger.debug(
        f"Offloaded {len(output):,} chars to Redis: {redis_key} "
        f"(preview: {len(summary)} chars)"
    )

    return summary, True


async def retrieve_offloaded_output(
    redis: Redis,
    operation_id: str,
    task_id: str,
) -> str | None:
    """Retrieve full output for a task from Redis.

    Args:
        redis: Redis client
        operation_id: Current operation ID
        task_id: Task to retrieve output for

    Returns:
        Full output text, or None if not found
    """
    # Search for keys matching this task
    pattern = f"ares:operation:{operation_id}:output:{task_id}:*"
    keys = []
    async for key in redis.scan_iter(pattern):
        keys.append(key)

    if not keys:
        return None

    # Get the most recent (last key alphabetically by hash)
    keys.sort()
    key = keys[-1]

    output = await redis.get(key)
    if output:
        return output.decode() if isinstance(output, bytes) else output

    return None


def summarize_task_result(
    result: dict[str, Any],
    task_type: str,
    max_output_chars: int = 2000,
) -> dict[str, Any]:
    """Summarize a task result for orchestrator context.

    Extracts structured discoveries while truncating raw output.
    The orchestrator only needs to know WHAT was found, not the raw text.

    Args:
        result: Full task result dict
        task_type: Type of task (recon, exploit, etc.)
        max_output_chars: Max chars to keep in output field

    Returns:
        Summarized result dict
    """
    summarized = {}

    # Always preserve structured discoveries (these are what matter)
    structured_fields = [
        "discovered_hosts",
        "discovered_credentials",
        "discovered_hashes",
        "discovered_shares",
        "discovered_users",
        "discovered_vulnerabilities",
        "trusted_domains",
        "credential",
        "credentials",
        "hash",
        "hashes",
        "share",
        "shares",
        "success",
        "error",
        "task_id",
    ]

    for field in structured_fields:
        if field in result:
            summarized[field] = result[field]

    # Summarize output fields
    output_fields = ["output", "stdout", "stderr"]
    for field in output_fields:
        if field in result and result[field]:
            output = str(result[field])
            if len(output) > max_output_chars:
                lines = output.split("\n")
                # Keep first and last portions
                head_lines = lines[:15]
                tail_lines = lines[-5:] if len(lines) > 20 else []

                head = "\n".join(head_lines)
                tail = "\n".join(tail_lines)

                if len(head) > max_output_chars // 2:
                    head = head[:max_output_chars // 2]

                summarized[field] = (
                    f"{head}\n"
                    f"[... {len(lines) - 20} lines omitted ...]\n"
                    f"{tail}"
                ) if tail_lines else f"{head}\n[... {len(lines) - 15} lines omitted ...]"
            else:
                summarized[field] = output

    # Add metadata about what was summarized
    if "output" in result and len(str(result.get("output", ""))) > max_output_chars:
        summarized["_output_truncated"] = True
        summarized["_original_output_chars"] = len(str(result["output"]))

    return summarized


class ContextOffloader:
    """Manages context offloading for an operation.

    Tracks offloaded outputs and provides retrieval capabilities.
    """

    def __init__(
        self,
        redis: Redis,
        operation_id: str,
        offload_threshold: int = DEFAULT_OFFLOAD_THRESHOLD,
    ):
        self.redis = redis
        self.operation_id = operation_id
        self.offload_threshold = offload_threshold
        self._offloaded_tasks: set[str] = set()

    async def process_task_result(
        self,
        task_id: str,
        result: dict[str, Any],
        task_type: str = "",
    ) -> dict[str, Any]:
        """Process a task result, offloading large outputs.

        Args:
            task_id: Task identifier
            result: Full task result
            task_type: Type of task

        Returns:
            Processed result with large outputs offloaded
        """
        # First, summarize to extract structured data
        processed = summarize_task_result(result, task_type)

        # Check if output should be offloaded
        output = result.get("output", "") or ""
        stdout = result.get("stdout", "") or ""
        stderr = result.get("stderr", "") or ""

        full_output = "\n".join(filter(None, [str(output), str(stdout), str(stderr)]))

        if len(full_output) > self.offload_threshold:
            # Store full output in Redis
            summary, was_offloaded = await offload_large_output(
                self.redis,
                self.operation_id,
                task_id,
                full_output,
                self.offload_threshold,
            )

            if was_offloaded:
                self._offloaded_tasks.add(task_id)
                processed["_full_output_available"] = True
                processed["_offloaded_key"] = f"ares:operation:{self.operation_id}:output:{task_id}"

                # Keep summary in output field
                processed["output"] = summary

        return processed

    async def retrieve_output(self, task_id: str) -> str | None:
        """Retrieve full output for a task.

        Args:
            task_id: Task to retrieve output for

        Returns:
            Full output or None
        """
        return await retrieve_offloaded_output(
            self.redis,
            self.operation_id,
            task_id,
        )

    @property
    def offloaded_task_count(self) -> int:
        """Number of tasks with offloaded outputs."""
        return len(self._offloaded_tasks)


__all__ = [
    "ContextOffloader",
    "DEFAULT_OFFLOAD_THRESHOLD",
    "estimate_tokens",
    "offload_large_output",
    "retrieve_offloaded_output",
    "summarize_task_result",
]
