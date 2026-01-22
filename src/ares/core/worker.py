"""Worker agent loop for multi-agent red team operations.

This module provides the worker loop that specialized agents use to:
- Poll the Redis task queue for assigned tasks (Kubernetes multi-pod mode)
- Poll the dispatcher for assigned tasks (single-process fallback mode)
- Process tasks using their specialized toolsets
- Report results back to the orchestrator via Redis
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import re
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.config import get_redis_url
from ares.core.dispatcher import RedTeamDispatcher
from ares.core.exceptions import AuthenticationError, ConfigurationError, CriticalWorkerError
from ares.core.factories.red_agents import create_agent_info, create_specialized_agent
from ares.core.litellm_env import configure_litellm_env
from ares.core.messages import (
    AgentMessage,
    DomainAdminAchieved,
    GoldenTicketForged,
    MessageType,
    OperationComplete,
)
from ares.core.models import AgentRole
from ares.core.redis_client import create_redis_client
from ares.core.task_queue import RedisTaskQueue, TaskMessage
from ares.tools.red import CrackerCallbackTools, LateralCallbackTools

if TYPE_CHECKING:
    from dreadnode.agent import Agent


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
        logger.warning("Unexpected model overrides payload type: {}", type(data))
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


# Mapping of message types to task prompt generators (for dispatcher-based messaging)
TASK_PROMPTS: dict[MessageType, callable] = {
    MessageType.CRACK_REQUEST: lambda msg: (
        f"Crack this hash for user {msg.username}@{msg.domain}:\n"
        f"Hash: {msg.hash_value}\n"
        f"Type: {msg.hash_type}\n"
        f"Wordlist: {msg.wordlist}\n"
        f"Task ID: {msg.task_id}\n\n"
        "Use hashcat or john to crack this hash. Report the result using task_complete."
    ),
    MessageType.LATERAL_REQUEST: lambda msg: (
        f"Perform lateral movement to {msg.target_host}:\n"
        f"Username: {msg.domain}\\{msg.username}\n"
        f"Credential: {'password' if msg.password else 'hash'}\n"
        f"Method: {msg.method or 'auto-select'}\n"
        f"Task ID: {msg.task_id}\n\n"
        "Try to establish access using psexec, evil-winrm, or wmi. "
        "If successful, run secretsdump to harvest credentials. "
        "Report the result using task_complete."
    ),
    MessageType.ACL_ANALYSIS_REQUEST: lambda msg: (
        f"Analyze ACLs and find attack paths:\n"
        f"Target User: {msg.target_user}\n"
        f"Domain: {msg.domain}\n"
        f"Find Path To: {msg.find_path_to}\n"
        f"Task ID: {msg.task_id}\n\n"
        "Run BloodHound collection if needed, then find shortest paths. "
        "Execute any viable ACL abuse attacks. Report the result using task_complete."
    ),
    MessageType.EXPLOIT_REQUEST: lambda msg: (
        f"Exploit vulnerability:\n"
        f"Type: {msg.vuln_type}\n"
        f"Target: {msg.target}\n"
        f"Vuln ID: {msg.vuln_id}\n"
        f"Params: {msg.params}\n"
        f"Task ID: {msg.task_id}\n\n"
        "Execute the appropriate exploitation technique. "
        "Report any credentials or access obtained using task_complete.\n"
        "If you obtain credentials or hashes, include a JSON block:\n"
        "```json\n"
        '{"credential": {"username": "", "password": "", "domain": "", "is_admin": false}}\n'
        "```\n"
        "or\n"
        "```json\n"
        '{"hash": {"username": "", "hash_value": "", "hash_type": "NTLM", "domain": ""}}\n'
        "```"
    ),
    MessageType.POISON_REQUEST: lambda msg: (
        f"Start network poisoning:\n"
        f"Interface: {msg.interface}\n"
        f"Techniques: {', '.join(msg.techniques)}\n"
        f"Duration: {msg.duration}s\n"
        f"Task ID: {msg.task_id}\n\n"
        "Start responder/mitm6 and capture any hashes. "
        "Report captured credentials using task_complete."
    ),
}


def generate_prompt_from_task(task: TaskMessage) -> str | None:
    """
    Generate agent prompt from Redis TaskMessage.

    This is used when polling tasks from Redis queue instead of dispatcher.

    Args:
        task: TaskMessage from Redis queue

    Returns:
        Prompt string for the agent
    """
    payload = task.payload

    if task.task_type == "crack":
        return (
            f"Crack this hash for user {payload.get('username', 'unknown')}"
            f"@{payload.get('domain', '')}:\n"
            f"Hash: {payload['hash_value']}\n"
            f"Type: {payload['hash_type']}\n"
            f"Wordlist: {payload.get('wordlist', 'rockyou.txt')}\n"
            f"Task ID: {task.task_id}\n\n"
            "Use hashcat or john to crack. Report when done."
        )

    if task.task_type == "lateral":
        cred_type = "password" if payload.get("password") else "hash"
        return (
            f"Perform lateral movement to {payload['target_host']}:\n"
            f"Username: {payload.get('domain', '')}\\{payload['username']}\n"
            f"Credential: {cred_type}\n"
            f"Method: {payload.get('method') or 'auto-select'}\n"
            f"Task ID: {task.task_id}\n\n"
            "Try at most two methods (psexec then winrm/wmi), no loops. "
            "If access succeeds, run secretsdump once. "
            "If access fails, report_lateral_failed with a concise reason."
        )

    if task.task_type == "acl_analysis":
        return (
            f"Analyze ACLs and find attack paths:\n"
            f"Target User: {payload['target_user']}\n"
            f"Domain: {payload['domain']}\n"
            f"Find Path To: {payload.get('find_path_to', 'Domain Admins')}\n"
            f"Task ID: {task.task_id}\n\n"
            "Run BloodHound collection if needed. Execute viable ACL abuse attacks."
        )

    if task.task_type == "exploit":
        return (
            f"Exploit vulnerability:\n"
            f"Type: {payload['vuln_type']}\n"
            f"Target: {payload['target']}\n"
            f"Vuln ID: {payload.get('vuln_id', 'unknown')}\n"
            f"Params: {payload}\n"
            f"Task ID: {task.task_id}\n\n"
            "Execute the exploitation technique. Report credentials obtained.\n"
            "If you obtain credentials or hashes, include a JSON block:\n"
            "```json\n"
            '{"credential": {"username": "", "password": "", "domain": "", "is_admin": false}}\n'
            "```\n"
            "or\n"
            "```json\n"
            '{"hash": {"username": "", "hash_value": "", "hash_type": "NTLM", "domain": ""}}\n'
            "```"
        )

    if task.task_type == "poison":
        techniques = payload.get("techniques", ["LLMNR", "NBT-NS"])
        return (
            f"Start network poisoning:\n"
            f"Interface: {payload.get('interface', 'eth0')}\n"
            f"Techniques: {', '.join(techniques)}\n"
            f"Duration: {payload.get('duration', 300)}s\n"
            f"Task ID: {task.task_id}\n\n"
            "Start responder/mitm6 and capture hashes."
        )

    # "command" tasks are handled specially - executed directly, not via agent
    if task.task_type == "command":
        # Return None to signal direct execution
        return None

    # Generic fallback
    return f"Execute task: {task.task_type}\nPayload: {payload}\nTask ID: {task.task_id}"


def _extract_structured_payload(result_text: str) -> dict[str, Any] | None:
    """Extract structured JSON payload from agent output if present."""
    match = re.search(r"```json\\s*(\\{.*?\\})\\s*```", result_text, re.DOTALL)
    if not match:
        return None
    try:
        payload = json.loads(match.group(1))
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _extract_asrep_hashes(result_text: str) -> list[dict[str, str]]:
    """Extract Kerberos AS-REP hashes from raw tool output."""
    hashes: list[dict[str, str]] = []
    matches = re.findall(
        r"(\$krb5asrep\$\d+\$[^\s:$]+@[^\s:$]+:[0-9a-fA-F]{32}\$[0-9a-fA-F]+)",
        result_text,
    )
    for value in matches:
        username = "Unknown"
        domain = ""
        parts = value.split("$", 3)
        if len(parts) >= 4:
            user_realm_part = parts[3]
            user_realm = user_realm_part.split(":", 1)[0]
            if "@" in user_realm:
                username, domain = user_realm.split("@", 1)
            elif user_realm:
                username = user_realm
        hashes.append(
            {
                "username": username,
                "hash_value": value,
                "hash_type": "AS-REP",
                "domain": domain,
            }
        )
    return hashes


class RedisWorkerAgent:
    """
    Worker agent that polls Redis task queue for work.

    This is the preferred worker mode for Kubernetes multi-pod deployments
    where in-memory queues cannot be shared across pods.
    """

    def __init__(
        self,
        role: AgentRole,
        task_queue: RedisTaskQueue,
        agent: Agent,
        agent_name: str,
        pod_name: str | None = None,
        operation_id: str | None = None,
        redis_url: str | None = None,
        pointer_check_interval: float = 30.0,
        max_operation_age: int = 300,
    ):
        self.role = role
        self.task_queue = task_queue
        self.agent = agent
        self.agent_name = agent_name
        self.pod_name = pod_name or os.environ.get("HOSTNAME", "unknown")
        self.operation_id = operation_id
        self.redis_url = redis_url
        self.pointer_check_interval = pointer_check_interval
        self.max_operation_age = max_operation_age
        self._running = False
        self._current_task: str | None = None
        self._tasks_completed = 0
        self._pointer_switched = False

    async def start(self) -> None:
        """Start the Redis worker loop."""
        self._running = True
        self._pointer_switched = False
        logger.info(f"Redis worker {self.agent_name} starting...")

        # Start heartbeat task
        heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        try:
            await self._worker_loop()
        finally:
            self._running = False
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass

    async def stop(self) -> None:
        """Stop the worker loop."""
        self._running = False
        logger.info(f"Redis worker {self.agent_name} stopping...")

    @property
    def pointer_switched(self) -> bool:
        return self._pointer_switched

    async def _worker_loop(self) -> None:
        """Main worker loop - poll Redis for tasks."""
        logger.info(f"Worker {self.agent_name} polling Redis for {self.role.value} tasks")

        # Exponential backoff for connection errors
        retry_delay = 1.0  # Start with 1 second
        max_retry_delay = 60.0  # Cap at 60 seconds
        last_pointer_check = time.monotonic()

        while self._running:
            try:
                if (
                    self.redis_url
                    and self.operation_id
                    and self.pointer_check_interval > 0
                    and (time.monotonic() - last_pointer_check) >= self.pointer_check_interval
                ):
                    last_pointer_check = time.monotonic()
                    if await self._check_for_pointer_switch():
                        return

                # Poll Redis queue (blocks up to 5 seconds)
                task = await self.task_queue.poll_task(
                    role=self.role.value,
                    timeout=5.0,
                )

                if task:
                    await self._process_task(task)

                # Reset retry delay on successful poll
                retry_delay = 1.0

            except asyncio.CancelledError:  # noqa: PERF203
                break
            except (AuthenticationError, ConfigurationError, CriticalWorkerError) as e:
                # Fatal errors that should stop the worker immediately
                logger.critical(
                    f"FATAL ERROR in worker loop - stopping execution: {type(e).__name__}: {e}",
                    exc_info=True,
                )
                # Send an offline heartbeat to notify orchestrator
                try:
                    if self.task_queue:
                        await self.task_queue.send_heartbeat(
                            agent_name=self.agent_name,
                            status="offline",
                            pod_name=self.pod_name,
                        )
                except Exception as hb_error:
                    logger.error(f"Failed to send offline heartbeat: {hb_error}")
                raise  # Re-raise to stop the worker
            except Exception as e:
                # Check if it's a connection error
                error_str = str(e).lower()
                is_connection_error = any(
                    keyword in error_str
                    for keyword in [
                        "connection",
                        "connect",
                        "closed",
                        "timeout",
                        "broken pipe",
                        "reset",
                    ]
                )

                if is_connection_error:
                    logger.warning(
                        f"Worker loop connection error, retrying in {retry_delay:.1f}s: {e}"
                    )
                    await asyncio.sleep(retry_delay)
                    # Exponential backoff
                    retry_delay = min(retry_delay * 2, max_retry_delay)
                else:
                    # Non-connection error, log with stack trace and continue with short delay
                    logger.error(f"Worker loop error: {e}", exc_info=True)
                    await asyncio.sleep(5)
                    retry_delay = 1.0  # Reset backoff for non-connection errors

    async def _process_task(self, task: TaskMessage) -> None:  # noqa: PLR0912
        """Process a task from the Redis queue."""
        self._current_task = task.task_id
        started_at = datetime.now(timezone.utc).isoformat()
        payload_snapshot = task.payload
        try:
            await self.task_queue.set_task_status(
                task_id=task.task_id,
                status="running",
                operation_id=self.operation_id,
                role=self.role.value,
                agent_name=self.agent_name,
                pod_name=self.pod_name,
                task_type=task.task_type,
                payload=payload_snapshot,
                started_at=started_at,
            )
        except Exception as e:
            logger.warning(f"[{self.agent_name}] Failed to record task status: {e}")
        logger.info(
            f"[{self.agent_name}] Processing task {task.task_id} "
            f"(type={task.task_type}, payload={payload_snapshot})"
        )

        try:
            # Handle "command" tasks directly via subprocess (no agent needed)
            if task.task_type == "command":
                await self._execute_command_task(task)
                return

            # Generate prompt from task
            prompt = generate_prompt_from_task(task)

            if prompt is None:
                # Task type not supported for agent execution
                await self.task_queue.send_result(
                    task_id=task.task_id,
                    success=False,
                    error=f"Unsupported task type: {task.task_type}",
                    worker_pod=self.pod_name,
                )
                return

            # Run agent
            logger.info(f"[{self.agent_name}] Running agent for task {task.task_id}")
            result = await self.agent.run(prompt)
            result_text = self._extract_result(result)
            agent_error = self._extract_agent_error(result)
            result_summary = self._summarize_agent_result(result)
            if result_summary:
                logger.info(f"[{self.agent_name}] Agent result summary: {result_summary}")

            result_payload: dict[str, Any] = {"output": result_text, "task_type": task.task_type}
            structured = _extract_structured_payload(result_text)
            if structured:
                for key in ("credential", "hash"):
                    if key in structured:
                        result_payload[key] = structured[key]
            asrep_hashes = _extract_asrep_hashes(result_text)
            if asrep_hashes:
                existing = set()
                if isinstance(result_payload.get("hash"), dict):
                    existing.add(result_payload["hash"].get("hash_value"))
                filtered = [h for h in asrep_hashes if h.get("hash_value") not in existing]
                if filtered:
                    if "hash" not in result_payload and len(filtered) == 1:
                        result_payload["hash"] = filtered[0]
                    else:
                        result_payload["hashes"] = filtered

            if agent_error:
                if "Maximum steps reached" in agent_error:
                    self._dump_task_trace(task, prompt, result_text, result)
                    excerpt = result_text[-800:] if result_text else ""
                    logger.error(
                        f"[{self.agent_name}] Max steps reached for task {task.task_id}; "
                        f"output_excerpt={excerpt!r}"
                    )
                await self.task_queue.send_result(
                    task_id=task.task_id,
                    success=False,
                    result=result_payload,
                    error=agent_error,
                    worker_pod=self.pod_name,
                )
                try:
                    await self.task_queue.set_task_status(
                        task_id=task.task_id,
                        status="failed",
                        operation_id=self.operation_id,
                        role=self.role.value,
                        agent_name=self.agent_name,
                        pod_name=self.pod_name,
                        task_type=task.task_type,
                        ended_at=datetime.now(timezone.utc).isoformat(),
                        error=agent_error,
                    )
                except Exception as e:
                    logger.warning(f"[{self.agent_name}] Failed to record task status: {e}")
                logger.error(f"[{self.agent_name}] Task {task.task_id} failed: {agent_error}")
                return

            # Send success result via Redis
            await self.task_queue.send_result(
                task_id=task.task_id,
                success=True,
                result=result_payload,
                worker_pod=self.pod_name,
            )
            try:
                await self.task_queue.set_task_status(
                    task_id=task.task_id,
                    status="completed",
                    operation_id=self.operation_id,
                    role=self.role.value,
                    agent_name=self.agent_name,
                    pod_name=self.pod_name,
                    task_type=task.task_type,
                    ended_at=datetime.now(timezone.utc).isoformat(),
                )
            except Exception as e:
                logger.warning(f"[{self.agent_name}] Failed to record task status: {e}")
            self._tasks_completed += 1
            logger.success(f"[{self.agent_name}] Task {task.task_id} completed")

        except (AuthenticationError, ConfigurationError, CriticalWorkerError) as e:
            # Fatal errors - log with full context and re-raise to stop worker
            logger.critical(
                f"[{self.agent_name}] FATAL ERROR during task {task.task_id}: {type(e).__name__}: {e}",
                exc_info=True,
            )
            try:
                await self.task_queue.send_result(
                    task_id=task.task_id,
                    success=False,
                    error=f"FATAL: {type(e).__name__}: {e!s}",
                    worker_pod=self.pod_name,
                )
                await self.task_queue.set_task_status(
                    task_id=task.task_id,
                    status="failed",
                    operation_id=self.operation_id,
                    role=self.role.value,
                    agent_name=self.agent_name,
                    pod_name=self.pod_name,
                    task_type=task.task_type,
                    ended_at=datetime.now(timezone.utc).isoformat(),
                    error=str(e),
                )
            except Exception as send_error:
                logger.error(
                    f"[{self.agent_name}] Failed to send fatal result for task {task.task_id}: "
                    f"{type(send_error).__name__}: {send_error}",
                    exc_info=True,
                )
            self._current_task = None
            raise  # Re-raise to stop worker
        except Exception as e:
            # Non-fatal task errors - log with stack trace and continue
            logger.error(
                f"[{self.agent_name}] Task {task.task_id} failed: {type(e).__name__}: {e}",
                exc_info=True,
            )
            await self.task_queue.send_result(
                task_id=task.task_id,
                success=False,
                error=f"{type(e).__name__}: {e!s}",
                worker_pod=self.pod_name,
            )
            try:
                await self.task_queue.set_task_status(
                    task_id=task.task_id,
                    status="failed",
                    operation_id=self.operation_id,
                    role=self.role.value,
                    agent_name=self.agent_name,
                    pod_name=self.pod_name,
                    task_type=task.task_type,
                    ended_at=datetime.now(timezone.utc).isoformat(),
                    error=str(e),
                )
            except Exception as status_error:
                logger.warning(f"[{self.agent_name}] Failed to record task status: {status_error}")
        finally:
            self._current_task = None

    async def _check_for_pointer_switch(self) -> bool:
        """Return True if a switch is requested and the worker should exit."""
        if not self.redis_url or not self.operation_id:
            return False
        active_op = await get_active_operation_pointer(
            self.redis_url, max_operation_age=self.max_operation_age
        )
        if not active_op or active_op == self.operation_id:
            return False
        logger.warning(
            "Active operation pointer changed from "
            f"{self.operation_id} to {active_op}; shutting down to reattach"
        )
        self._pointer_switched = True
        self._running = False
        return True

    async def _execute_command_task(self, task: TaskMessage) -> None:
        """Execute a command task locally."""
        import subprocess

        payload = task.payload
        command = payload.get("command", "")
        working_dir = payload.get("working_directory", "/tmp")  # noqa: S108  # nosec B108
        timeout = payload.get("timeout_seconds", 300)

        logger.info(f"[{self.agent_name}] Executing command: {command[:100]}...")

        try:
            result = await asyncio.to_thread(  # noqa: S604  # nosec B602
                subprocess.run,
                command,
                shell=True,  # nosec B602 B604
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=working_dir,
                check=False,
            )

            await self.task_queue.send_result(
                task_id=task.task_id,
                success=True,
                result={
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "return_code": result.returncode,
                },
                worker_pod=self.pod_name,
            )
            try:
                await self.task_queue.set_task_status(
                    task_id=task.task_id,
                    status="completed",
                    operation_id=self.operation_id,
                    role=self.role.value,
                    agent_name=self.agent_name,
                    pod_name=self.pod_name,
                    task_type=task.task_type,
                    ended_at=datetime.now(timezone.utc).isoformat(),
                )
            except Exception as e:
                logger.warning(f"[{self.agent_name}] Failed to record task status: {e}")
            self._tasks_completed += 1
            logger.success(f"[{self.agent_name}] Command completed: exit code {result.returncode}")

        except subprocess.TimeoutExpired:
            await self.task_queue.send_result(
                task_id=task.task_id,
                success=False,
                error=f"Command timed out after {timeout}s",
                worker_pod=self.pod_name,
            )
            try:
                await self.task_queue.set_task_status(
                    task_id=task.task_id,
                    status="failed",
                    operation_id=self.operation_id,
                    role=self.role.value,
                    agent_name=self.agent_name,
                    pod_name=self.pod_name,
                    task_type=task.task_type,
                    ended_at=datetime.now(timezone.utc).isoformat(),
                    error=f"Command timed out after {timeout}s",
                )
            except Exception as e:
                logger.warning(f"[{self.agent_name}] Failed to record task status: {e}")
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            await self.task_queue.send_result(
                task_id=task.task_id,
                success=False,
                error=str(e),
                worker_pod=self.pod_name,
            )
            try:
                await self.task_queue.set_task_status(
                    task_id=task.task_id,
                    status="failed",
                    operation_id=self.operation_id,
                    role=self.role.value,
                    agent_name=self.agent_name,
                    pod_name=self.pod_name,
                    task_type=task.task_type,
                    ended_at=datetime.now(timezone.utc).isoformat(),
                    error=str(e),
                )
            except Exception as status_error:
                logger.warning(f"[{self.agent_name}] Failed to record task status: {status_error}")

    def _extract_result(self, result: Any) -> str:
        """Extract text result from agent output."""
        if hasattr(result, "output"):
            return str(result.output)
        if hasattr(result, "content"):
            return str(result.content)
        return str(result)

    def _extract_agent_error(self, result: Any) -> str | None:
        """Pull error details from an agent result without raising."""
        error = getattr(result, "error", None)
        if error:
            return str(error)
        last_error = getattr(result, "last_error", None)
        if last_error:
            return str(last_error)
        stop_reason = getattr(result, "stop_reason", None)
        failed = bool(getattr(result, "failed", False))
        if failed and stop_reason:
            return f"Agent failed (stop_reason={stop_reason})"
        if failed:
            return "Agent failed"
        if stop_reason == "error":
            return "Agent stopped with error"
        return None

    def _summarize_agent_result(self, result: Any) -> str:
        """Summarize agent outcome for logging."""
        summary_parts = []
        for key in ("run_id", "id", "stop_reason", "failed", "model", "steps"):
            value = getattr(result, key, None)
            if value is not None:
                summary_parts.append(f"{key}={value}")
        usage = getattr(result, "usage", None)
        if usage:
            summary_parts.append(f"usage={usage}")
        return ", ".join(summary_parts)

    def _dump_task_trace(
        self, task: TaskMessage, prompt: str, result_text: str, result: Any
    ) -> None:
        """Persist a task trace for debugging max-step failures."""
        try:
            trace_path = Path(tempfile.gettempdir()) / f"ares-task-{task.task_id}.log"
            summary = self._summarize_agent_result(result)
            trace_path.write_text(
                "\n".join(
                    [
                        f"task_id: {task.task_id}",
                        f"task_type: {task.task_type}",
                        f"role: {self.role.value}",
                        f"agent: {self.agent_name}",
                        f"pod: {self.pod_name}",
                        f"operation_id: {self.operation_id}",
                        f"payload: {task.payload}",
                        f"summary: {summary}",
                        "prompt:",
                        prompt,
                        "result:",
                        result_text,
                    ]
                ),
                encoding="utf-8",
            )
            logger.warning(
                f"[{self.agent_name}] Task trace saved to {trace_path} for {task.task_id}"
            )
        except Exception as e:
            logger.warning(f"[{self.agent_name}] Failed to write task trace: {e}")

    async def _heartbeat_loop(self) -> None:
        """Send heartbeats to Redis with automatic reconnection on failure."""
        retry_delay = 1.0
        max_retry_delay = 60.0

        while self._running:
            try:
                status = "busy" if self._current_task else "idle"
                await self.task_queue.send_heartbeat(
                    agent_name=self.agent_name,
                    status=status,
                    current_task=self._current_task,
                    pod_name=self.pod_name,
                    role=self.role.value,
                    operation_id=self.operation_id,
                )
                # Reset retry delay on success
                retry_delay = 1.0

            except Exception as e:
                error_str = str(e).lower()
                is_connection_error = any(
                    keyword in error_str
                    for keyword in [
                        "connection",
                        "connect",
                        "closed",
                        "timeout",
                        "broken pipe",
                        "reset",
                    ]
                )

                if is_connection_error:
                    logger.warning(f"Heartbeat connection error, will retry: {e}")
                    await asyncio.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, max_retry_delay)
                    continue  # Skip the regular sleep and retry immediately
                logger.warning(f"Heartbeat failed: {e}")

            await asyncio.sleep(15)


class WorkerAgent:
    """
    Worker agent that processes tasks from the dispatcher.

    This class wraps a specialized Dreadnode Agent and adds:
    - Dispatcher integration for receiving tasks
    - Heartbeat monitoring
    - Task completion reporting
    """

    def __init__(
        self,
        role: AgentRole,
        dispatcher: RedTeamDispatcher,
        agent: Agent,
        agent_name: str,
        operation_id: str | None = None,
        redis_url: str | None = None,
        pointer_check_interval: float = 30.0,
        max_operation_age: int = 300,
    ):
        self.role = role
        self.dispatcher = dispatcher
        self.agent = agent
        self.agent_name = agent_name
        self.operation_id = operation_id
        self.redis_url = redis_url
        self.pointer_check_interval = pointer_check_interval
        self.max_operation_age = max_operation_age
        self._running = False
        self._current_task: str | None = None
        self._tasks_completed = 0
        self._pointer_switched = False

    async def start(self) -> None:
        """Start the worker loop."""
        self._running = True
        self._pointer_switched = False
        logger.info(f"Worker {self.agent_name} starting...")

        # Start heartbeat task
        heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        try:
            await self._worker_loop()
        finally:
            self._running = False
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass

    async def stop(self) -> None:
        """Stop the worker loop."""
        self._running = False
        logger.info(f"Worker {self.agent_name} stopping...")

    @property
    def pointer_switched(self) -> bool:
        return self._pointer_switched

    async def _worker_loop(self) -> None:
        """Main worker loop - poll for messages and process tasks."""
        logger.info(f"Worker {self.agent_name} entering main loop")
        last_pointer_check = time.monotonic()

        while self._running:
            try:
                if (
                    self.redis_url
                    and self.operation_id
                    and self.pointer_check_interval > 0
                    and (time.monotonic() - last_pointer_check) >= self.pointer_check_interval
                ):
                    last_pointer_check = time.monotonic()
                    if await self._check_for_pointer_switch():
                        return

                # Poll for messages
                messages = await self.dispatcher.get_messages(self.agent_name, timeout=1.0)

                for msg in messages:
                    await self._handle_message(msg)

                # Small sleep to prevent busy-waiting
                await asyncio.sleep(0.5)

            except asyncio.CancelledError:  # noqa: PERF203
                break
            except Exception as e:
                logger.error(f"Worker loop error: {e}")
                await asyncio.sleep(5)  # Back off on error

    async def _check_for_pointer_switch(self) -> bool:
        """Return True if a switch is requested and the worker should exit."""
        if not self.redis_url or not self.operation_id:
            return False
        active_op = await get_active_operation_pointer(
            self.redis_url, max_operation_age=self.max_operation_age
        )
        if not active_op or active_op == self.operation_id:
            return False
        logger.warning(
            "Active operation pointer changed from "
            f"{self.operation_id} to {active_op}; shutting down to reattach"
        )
        self._pointer_switched = True
        self._running = False
        return True

    async def _handle_message(self, msg: AgentMessage) -> None:
        """Handle an incoming message."""
        logger.info(f"[{self.agent_name}] Received message: {msg.type}")

        # Check for operation-level messages
        if isinstance(msg, DomainAdminAchieved):
            logger.success(
                f"🎯 Domain Admin achieved by {msg.source_agent}: {msg.domain}\\{msg.username}"
            )
            return

        if isinstance(msg, GoldenTicketForged):
            logger.success(f"🎫 Golden Ticket forged for {msg.domain}")
            return

        if isinstance(msg, OperationComplete):
            logger.info(f"Operation complete: {msg.summary}")
            self._running = False
            return

        # Route task requests to agent
        await self._process_task(msg)

    async def _process_task(self, msg: AgentMessage) -> None:
        """Process a task request message."""
        task_id = getattr(msg, "task_id", None)
        if not task_id:
            logger.warning(f"Message {msg.type} has no task_id, skipping")
            return

        self._current_task = task_id
        logger.info(f"[{self.agent_name}] Processing task {task_id}")

        try:
            # Generate prompt based on message type
            prompt = self._generate_task_prompt(msg)
            if not prompt:
                logger.warning(f"No prompt generator for message type {msg.type}")
                await self.dispatcher.complete_task(
                    task_id=task_id,
                    success=False,
                    error=f"Unsupported message type: {msg.type}",
                    source_agent=self.agent_name,
                )
                return

            # Run the agent
            logger.info(f"[{self.agent_name}] Running agent for task {task_id}")
            result = await self.agent.run(prompt)

            # Extract result from agent output
            result_text = self._extract_result(result)

            result_payload: dict[str, Any] = {"output": result_text, "task_type": msg.type.value}
            structured = _extract_structured_payload(result_text)
            if structured:
                for key in ("credential", "hash"):
                    if key in structured:
                        result_payload[key] = structured[key]
            asrep_hashes = _extract_asrep_hashes(result_text)
            if asrep_hashes:
                existing = set()
                if isinstance(result_payload.get("hash"), dict):
                    existing.add(result_payload["hash"].get("hash_value"))
                filtered = [h for h in asrep_hashes if h.get("hash_value") not in existing]
                if filtered:
                    if "hash" not in result_payload and len(filtered) == 1:
                        result_payload["hash"] = filtered[0]
                    else:
                        result_payload["hashes"] = filtered

            # Report completion
            await self.dispatcher.complete_task(
                task_id=task_id,
                success=True,
                result=result_payload,
                source_agent=self.agent_name,
            )
            self._tasks_completed += 1
            logger.success(f"[{self.agent_name}] Task {task_id} completed")

        except Exception as e:
            logger.error(f"[{self.agent_name}] Task {task_id} failed: {e}")
            await self.dispatcher.complete_task(
                task_id=task_id,
                success=False,
                error=str(e),
                source_agent=self.agent_name,
            )

        finally:
            self._current_task = None

    def _generate_task_prompt(self, msg: AgentMessage) -> str | None:
        """Generate a prompt for the agent based on message type."""
        prompt_generator = TASK_PROMPTS.get(msg.type)
        if prompt_generator:
            return prompt_generator(msg)
        return None

    def _extract_result(self, result: Any) -> str:
        """Extract text result from agent output."""
        if hasattr(result, "output"):
            return str(result.output)
        if hasattr(result, "content"):
            return str(result.content)
        return str(result)

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats to dispatcher with automatic reconnection on failure."""
        retry_delay = 1.0
        max_retry_delay = 60.0

        while self._running:
            try:
                status = "busy" if self._current_task else "idle"
                await self.dispatcher.heartbeat(
                    agent_name=self.agent_name,
                    status=status,
                    current_task=self._current_task,
                )
                # Reset retry delay on success
                retry_delay = 1.0

            except Exception as e:
                error_str = str(e).lower()
                is_connection_error = any(
                    keyword in error_str
                    for keyword in [
                        "connection",
                        "connect",
                        "closed",
                        "timeout",
                        "broken pipe",
                        "reset",
                    ]
                )

                if is_connection_error:
                    logger.warning(f"Heartbeat connection error, will retry: {e}")
                    await asyncio.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, max_retry_delay)
                    continue  # Skip the regular sleep and retry immediately
                logger.warning(f"Heartbeat failed: {e}")

            await asyncio.sleep(15)


async def run_worker(  # noqa: PLR0912
    role: AgentRole,
    operation_id: str | None = None,
    redis_url: str | None = None,
    model: str | None = None,
    max_steps: int | None = None,
    discover_operation: bool = True,
    discovery_timeout: int | None = None,
    use_redis_queue: bool = True,
) -> None:
    """
    Run a specialized worker agent.

    In Kubernetes multi-pod mode (use_redis_queue=True), uses Redis task queues
    for cross-pod communication. In single-process mode (use_redis_queue=False),
    uses in-memory dispatcher queues.

    Args:
        role: The agent role (cracker, acl, privesc, lateral, poisoning).
        operation_id: The operation ID to join (optional - will discover if not provided).
        redis_url: Redis URL for task queue and state (default: from config).
        model: LLM model to use.
        max_steps: Override default max steps for role.
        discover_operation: If True and operation_id is None/empty, discover from Redis.
        discovery_timeout: Max seconds to wait for operation discovery (default: None = wait forever).
        use_redis_queue: If True, poll Redis queue for tasks (Kubernetes mode).
    """
    configure_litellm_env()

    # Resolve config defaults
    redis_url = redis_url or get_redis_url()
    resolved_model = (
        model
        or os.getenv(f"ARES_AGENT_{role.value.upper()}_MODEL")
        or os.getenv("ARES_WORKER_MODEL")
        or os.getenv("ARES_MODEL")
    )

    pod_name = os.environ.get("HOSTNAME", f"local-{role.value}")
    if not os.environ.get("ARES_ROLE"):
        os.environ["ARES_ROLE"] = role.value
    if not os.environ.get("ARES_EXECUTION_MODE") and os.path.exists(
        "/var/run/secrets/kubernetes.io/serviceaccount"
    ):
        os.environ["ARES_EXECUTION_MODE"] = "local"

    # Handle empty string operation IDs from k8s configmaps
    if operation_id == "":
        operation_id = None

    try:
        pointer_check_interval = float(os.getenv("ARES_OPERATION_POINTER_REFRESH_SECONDS", "30"))
    except ValueError:
        pointer_check_interval = 30.0
    try:
        max_operation_age = int(os.getenv("ARES_OPERATION_POINTER_MAX_AGE", "300"))
    except ValueError:
        max_operation_age = 300

    reattach_attempt = 0
    while True:
        # Discover operation if not provided
        if operation_id is None and discover_operation:
            if discovery_timeout is None:
                logger.info(
                    "No operation ID provided, waiting indefinitely for an active operation..."
                )
            else:
                logger.info(
                    "No operation ID provided, waiting up to "
                    f"{discovery_timeout}s for an active operation..."
                )
            operation_id = await discover_active_operation(redis_url, max_wait=discovery_timeout)

            if operation_id is None:
                logger.error("No active operation found within timeout and none specified")
                return

        if operation_id is None:
            logger.error("Operation ID required but not provided and discovery disabled")
            return

        overrides = await get_operation_model_overrides(redis_url, operation_id)
        if overrides:
            role_key = f"ARES_AGENT_{role.value.upper()}_MODEL"
            if overrides.get(role_key):
                resolved_model = overrides[role_key]
            elif overrides.get("ARES_WORKER_MODEL"):
                resolved_model = overrides["ARES_WORKER_MODEL"]
            elif overrides.get("ARES_MODEL"):
                resolved_model = overrides["ARES_MODEL"]

        if not resolved_model:
            resolved_model = await get_operation_model(redis_url, operation_id)

        if not resolved_model:
            logger.error(
                "No model specified for worker. Provide a model argument, set "
                "ARES_AGENT_<ROLE>_MODEL/ARES_WORKER_MODEL/ARES_MODEL, "
                "or submit an operation model."
            )
            return

        logger.info(f"Starting {role.value} worker for operation {operation_id}")
        logger.info(f"Pod: {pod_name}, Redis: {redis_url}, Redis Queue: {use_redis_queue}")

        # Create Redis task queue for direct polling (Kubernetes mode)
        task_queue: RedisTaskQueue | None = None
        if use_redis_queue:
            task_queue = RedisTaskQueue(redis_url)
            await task_queue.connect()
            logger.info("Worker connected to Redis task queue")

        # Create dispatcher for state management and fallback messaging
        dispatcher = RedTeamDispatcher(redis_url=redis_url)
        await dispatcher.start(operation_id)

        # Try to recover existing state
        recovered = await dispatcher.recover_state(operation_id)
        if recovered:
            logger.info(f"Recovered state: {len(recovered.all_credentials)} credentials")

        shared_state = dispatcher.shared_state

        # Create agent info and register (even in Redis mode for state tracking)
        agent_info = create_agent_info(role, pod_name=pod_name)
        await dispatcher.register(agent_info)

        # Add role-specific callback tools
        additional_tools: list[Any] = []
        if role == AgentRole.CRACKER:
            cracker_callbacks = CrackerCallbackTools()
            cracker_callbacks.set_dispatcher(dispatcher)
            additional_tools.append(cracker_callbacks)
        elif role == AgentRole.LATERAL:
            lateral_callbacks = LateralCallbackTools()
            lateral_callbacks.set_dispatcher(dispatcher)
            additional_tools.append(lateral_callbacks)

        # Create the specialized agent
        agent = create_specialized_agent(
            role=role,
            model=resolved_model,
            shared_state=shared_state,
            dispatcher=dispatcher,
            pod_name=pod_name,
            max_steps=max_steps,
            additional_tools=additional_tools if additional_tools else None,
        )

        pointer_switched = False
        try:
            worker: RedisWorkerAgent | WorkerAgent
            if use_redis_queue and task_queue:
                # Kubernetes multi-pod mode: poll Redis queue directly
                worker = RedisWorkerAgent(
                    role=role,
                    task_queue=task_queue,
                    agent=agent,
                    agent_name=agent_info.name,
                    pod_name=pod_name,
                    operation_id=operation_id,
                    redis_url=redis_url,
                    pointer_check_interval=pointer_check_interval,
                    max_operation_age=max_operation_age,
                )
                logger.info(f"Starting Redis worker for role {role.value}")
            else:
                # Single-process mode: use dispatcher in-memory queues
                worker = WorkerAgent(
                    role=role,
                    dispatcher=dispatcher,
                    agent=agent,
                    agent_name=agent_info.name,
                    operation_id=operation_id,
                    redis_url=redis_url,
                    pointer_check_interval=pointer_check_interval,
                    max_operation_age=max_operation_age,
                )
                logger.info(f"Starting dispatcher worker for role {role.value}")

            await worker.start()
            pointer_switched = worker.pointer_switched
        finally:
            if task_queue:
                await task_queue.disconnect()
            await dispatcher.stop()
            logger.info(f"Worker {agent_info.name} shutdown complete")

        if pointer_switched and discover_operation:
            reattach_attempt += 1
            # Using random for jitter, not cryptographic purposes
            delay = min(30.0, 2.0 + (reattach_attempt * 2.0) + random.random())  # noqa: S311  # nosec B311
            logger.info(
                f"Pointer switch detected; reattaching after {delay:.1f}s (attempt {reattach_attempt})"
            )
            await asyncio.sleep(delay)
            operation_id = None
            continue

        break


__all__ = [
    "RedisWorkerAgent",
    "WorkerAgent",
    "discover_active_operation",
    "generate_prompt_from_task",
    "run_worker",
]
