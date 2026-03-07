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
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from loguru import logger
from opentelemetry import trace
from opentelemetry.trace import SpanKind

from ares.core.config import (
    get_agent_task_timeout,
    get_rate_limit_backoff_delays,
    get_rate_limit_max_retries,
    get_redis_url,
)
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
from ares.core.models import AgentRole, SharedRedTeamState
from ares.core.redis_client import create_redis_client
from ares.core.task_queue import RedisTaskQueue, TaskMessage
from ares.core.tracing import create_agent_span_attributes
from ares.core.worker.cleanup import close_litellm_clients
from ares.core.worker.operations import (
    discover_active_operation,
    get_active_operation_pointer,
    get_operation_model,
    get_operation_model_overrides,
    get_worker_credentials,
    is_operation_completed,
)
from ares.core.worker.prompts import (
    TASK_PROMPTS,
    format_state_context,
    generate_prompt_from_task,
)
from ares.tools.red import CrackerCallbackTools, CrackingTools, LateralCallbackTools
from ares.tools.red.common import clear_credential_context, set_credential_context

if TYPE_CHECKING:
    from dreadnode.agent import Agent

_tracer = trace.get_tracer("ares.worker")


def _update_etc_hosts(hosts_list: list, written_ips: set[str], agent_name: str) -> set[str]:
    """Update /etc/hosts with discovered hosts for DNS resolution.

    Adds entries for hosts with both IP and hostname to /etc/hosts, enabling
    AD hostname resolution without relying on DNS. Entries include both
    FQDN and short hostname aliases on a single line.

    For domain controllers, also adds the bare domain name as an alias to enable
    Kerberos realm resolution (e.g., "192.168.58.10  dc01.contoso.local dc01 contoso.local").

    Args:
        hosts_list: List of Host objects from shared state
        written_ips: Set of IPs already written (to avoid duplicates)
        agent_name: Agent name for logging

    Returns:
        Updated set of written IPs
    """
    new_entries: list[str] = []

    for host in hosts_list:
        if not host.ip or not host.hostname:
            continue
        if host.ip in written_ips:
            continue

        # Build entry with all aliases on one line:
        # DC: "192.168.58.10  dc01.contoso.local dc01 contoso.local"
        # Non-DC: "192.168.58.22  ws01.contoso.local ws01"
        hostname = host.hostname.lower()
        parts = hostname.split(".")
        short_name = parts[0] if parts else hostname

        # Start with FQDN and short name
        aliases = [hostname]
        if short_name != hostname:
            aliases.append(short_name)

        # For domain controllers, add bare domain as alias for Kerberos realm resolution
        if host.is_dc and len(parts) >= 2:
            domain = ".".join(parts[1:])
            if domain:
                aliases.append(domain)

        entry = f"{host.ip}  {' '.join(aliases)}"
        new_entries.append(entry)
        written_ips.add(host.ip)

    if new_entries:
        try:
            # Append new entries to /etc/hosts
            with open("/etc/hosts", "a") as f:
                f.write(f"\n# Ares discovered hosts ({agent_name})\n")
                for entry in new_entries:
                    f.write(f"{entry}\n")
            logger.info(f"[{agent_name}] Updated /etc/hosts with {len(new_entries)} entries")
            for entry in new_entries:
                logger.debug(f"[{agent_name}] Added hosts entry: {entry}")
        except PermissionError:
            logger.warning(f"[{agent_name}] Cannot update /etc/hosts: permission denied")
        except OSError as e:
            logger.warning(f"[{agent_name}] Cannot update /etc/hosts: {e}")

    return written_ips


def _is_rate_limit_error(exc: Exception) -> bool:
    """Check if an exception is a rate limit error from the LLM provider."""
    exc_str = str(exc).lower()
    exc_type = type(exc).__name__

    # Direct litellm/openai rate limit errors
    if "ratelimit" in exc_type.lower() or "rate_limit" in exc_type.lower():
        return True

    # Check exception message for rate limit indicators
    rate_limit_indicators = [
        "rate limit",
        "rate_limit",
        "ratelimit",
        "too many requests",
        "429",
        "quota exceeded",
        "tokens per min",
        "requests per min",
        "tpm limit",
        "rpm limit",
    ]
    return any(indicator in exc_str for indicator in rate_limit_indicators)


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
        shared_state: Any | None = None,
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
        self.shared_state = shared_state
        self._running = False
        self._current_task: str | None = None
        self._tasks_completed = 0
        self._pointer_switched = False
        self._run_agent_in_thread = self.role == AgentRole.ACL
        self._state_refresh_client = None
        # Threaded heartbeat to avoid blocking by sync tool execution
        self._heartbeat_thread: threading.Thread | None = None
        self._heartbeat_stop_event = threading.Event()
        # Threaded state subscriber for real-time pub/sub updates
        self._state_subscriber_thread: threading.Thread | None = None
        self._state_subscriber_stop_event = threading.Event()
        # Track hosts written to /etc/hosts to avoid duplicates
        self._hosts_written_to_etc: set[str] = set()

    def _run_agent_sync(self, prompt: str) -> Any:
        """Run the async agent in a dedicated event loop (thread-safe helper)."""
        return asyncio.run(self.agent.run(prompt))

    def _serialize_state_discoveries(self) -> dict[str, Any]:
        """Serialize local state discoveries for inclusion in task results.

        Workers have their own local SharedRedTeamState that tools populate
        when they discover hosts, credentials, hashes, etc. This method
        serializes those discoveries so they can be sent back to the
        orchestrator's dispatcher, which will merge them into the canonical
        shared state that gets checkpointed to Redis.

        Returns:
            Dictionary with discovered_hosts, discovered_credentials,
            discovered_hashes, discovered_shares, and discovered_users.
        """
        if not self.shared_state:
            return {}

        discoveries: dict[str, Any] = {}

        # Serialize discovered hosts
        if self.shared_state.all_hosts:
            discoveries["discovered_hosts"] = [
                {
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "os": h.os,
                    "roles": list(h.roles) if h.roles else [],
                    "services": list(h.services) if h.services else [],
                    "is_dc": h.is_dc,
                }
                for h in self.shared_state.all_hosts
            ]

        # Serialize discovered credentials
        if self.shared_state.all_credentials:
            discoveries["discovered_credentials"] = [
                {
                    "username": c.username,
                    "password": c.password,
                    "domain": c.domain,
                    "source": c.source,
                    "is_admin": c.is_admin,
                }
                for c in self.shared_state.all_credentials
            ]

        # Serialize discovered hashes
        if self.shared_state.all_hashes:
            discoveries["discovered_hashes"] = [
                {
                    "username": h.username,
                    "hash_value": h.hash_value,
                    "hash_type": h.hash_type,
                    "domain": h.domain,
                    "cracked_password": h.cracked_password,
                    "source": h.source,
                }
                for h in self.shared_state.all_hashes
            ]

        # Serialize discovered shares
        if self.shared_state.all_shares:
            discoveries["discovered_shares"] = [
                {
                    "host": s.host,
                    "name": s.name,
                    "permissions": s.permissions,
                    "comment": s.comment,
                }
                for s in self.shared_state.all_shares
            ]

        # Serialize discovered users
        if self.shared_state.all_users:
            discoveries["discovered_users"] = [
                {
                    "username": u.username,
                    "domain": u.domain,
                    "is_admin": u.is_admin,
                }
                for u in self.shared_state.all_users
            ]

        # Serialize discovered vulnerabilities (delegation, ADCS, etc.)
        if self.shared_state.discovered_vulnerabilities:
            discoveries["discovered_vulnerabilities"] = [
                {
                    "vuln_id": v.vuln_id,
                    "vuln_type": v.vuln_type,
                    "target": v.target,
                    "discovered_by": v.discovered_by,
                    "details": v.details,
                    "priority": v.priority,
                    "recommended_agent": v.recommended_agent,
                }
                for v in self.shared_state.discovered_vulnerabilities.values()
            ]

        return discoveries

    async def _run_agent(self, prompt: str) -> Any:
        """Run the agent without blocking the worker event loop."""
        if self._run_agent_in_thread:
            return await asyncio.to_thread(self._run_agent_sync, prompt)
        return await self.agent.run(prompt)

    async def start(self) -> None:
        """Start the Redis worker loop."""
        self._running = True
        self._pointer_switched = False
        self._heartbeat_stop_event.clear()
        self._state_subscriber_stop_event.clear()
        logger.info(f"Redis worker {self.agent_name} starting...")

        # Start heartbeat in a separate thread to avoid blocking by sync tool execution.
        # Tools call blocking code (future.result()) which prevents asyncio tasks from running.
        self._heartbeat_thread = threading.Thread(
            target=self._threaded_heartbeat_loop,
            name=f"{self.agent_name}-heartbeat",
            daemon=True,
        )
        self._heartbeat_thread.start()
        logger.debug(f"Heartbeat thread started for {self.agent_name}")

        # Start state subscriber thread for real-time pub/sub updates from orchestrator
        if self.operation_id and self.redis_url:
            self._state_subscriber_thread = threading.Thread(
                target=self._threaded_state_subscriber_loop,
                name=f"{self.agent_name}-state-subscriber",
                daemon=True,
            )
            self._state_subscriber_thread.start()
            logger.debug(f"State subscriber thread started for {self.agent_name}")

        try:
            await self._worker_loop()
        finally:
            self._running = False
            # Signal heartbeat thread to stop and wait for it
            self._heartbeat_stop_event.set()
            if self._heartbeat_thread and self._heartbeat_thread.is_alive():
                self._heartbeat_thread.join(timeout=5.0)
                if self._heartbeat_thread.is_alive():
                    logger.warning(
                        f"Heartbeat thread for {self.agent_name} did not stop gracefully"
                    )
            # Signal state subscriber thread to stop and wait for it
            self._state_subscriber_stop_event.set()
            if self._state_subscriber_thread and self._state_subscriber_thread.is_alive():
                self._state_subscriber_thread.join(timeout=5.0)
                if self._state_subscriber_thread.is_alive():
                    logger.warning(
                        f"State subscriber thread for {self.agent_name} did not stop gracefully"
                    )
            # Close state refresh client if it was created
            if self._state_refresh_client:
                try:
                    await self._state_refresh_client.aclose()
                except Exception:
                    pass
                self._state_refresh_client = None

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

            except asyncio.CancelledError:
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

    async def _process_task(self, task: TaskMessage) -> None:
        """Process a task from the Redis queue."""
        self._current_task = task.task_id
        started_at = datetime.now(timezone.utc).isoformat()
        payload_snapshot = task.payload

        # Create CONSUMER span for Tempo service graph (explicit span management)
        # This pairs with the PRODUCER span from submit_task
        # Extract target info from payload for span metrics
        target_host = (
            payload_snapshot.get("target")
            or payload_snapshot.get("target_ip")
            or payload_snapshot.get("dc_ip")
            or payload_snapshot.get("host")
            or payload_snapshot.get("hostname")
        )

        # Refresh state BEFORE span creation to get target.environment from Redis
        await self._refresh_shared_state()

        # Get target environment from shared state for tracing
        target_env = None
        if self.shared_state and self.shared_state.target:
            env_val = self.shared_state.target.environment
            # Ensure it's a string (OTel requires primitive types)
            if isinstance(env_val, str) and env_val:
                target_env = env_val
            elif env_val:
                target_env = str(env_val)
        span_attrs = create_agent_span_attributes(
            self.role.value, "red", target_host=target_host, target_environment=target_env
        )
        span_attrs.update(
            {
                "task.id": task.task_id,
                "task.type": task.task_type,
                "task.source_agent": task.source_agent,
                "worker.pod": self.pod_name,
                "worker.agent": self.agent_name,
            }
        )
        _task_span = _tracer.start_span(
            "process_task", kind=SpanKind.CONSUMER, attributes=span_attrs
        )

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

        # Set credential context from task payload for attack chain tracking
        # This allows tools (e.g., secretsdump) to set parent_id on discoveries
        if payload_snapshot:
            parent_cred_id = payload_snapshot.get("parent_credential_id")
            parent_step = payload_snapshot.get("parent_attack_step", 0)
            source_user = payload_snapshot.get("username", "")
            source_domain = payload_snapshot.get("domain", "")
            if parent_cred_id or source_user:
                set_credential_context(
                    parent_id=parent_cred_id,
                    attack_step=parent_step,
                    source_username=source_user,
                    source_domain=source_domain,
                    task_id=task.task_id,
                )
                logger.debug(
                    f"Credential context set: parent_id={parent_cred_id}, "
                    f"step={parent_step}, user={source_domain}\\{source_user}, task={task.task_id}"
                )

        try:
            # State already refreshed above (before span creation)
            # Handle "command" tasks directly via subprocess (no agent needed)
            if task.task_type == "command":
                await self._execute_command_task(task)
                return
            # Handle crack tasks directly (avoid LLM stalls for deterministic cracking)
            if task.task_type == "crack":
                await self._execute_crack_task(task)
                return

            # Generate prompt from task with state context
            prompt = generate_prompt_from_task(task, state=self.shared_state)

            if prompt is None:
                # Task type not supported for agent execution
                await self.task_queue.send_result(
                    task_id=task.task_id,
                    success=False,
                    error=f"Unsupported task type: {task.task_type}",
                    worker_pod=self.pod_name,
                    agent_name=self.agent_name,
                )
                return

            # Run agent with rate limit retry and task-level timeout
            # Note: Rate limit errors can appear as:
            # 1. Exceptions raised during _run_agent()
            # 2. Errors returned in result.error or result.last_error (dreadnode SDK catches them)
            result = None
            last_rate_limit_error: str | Exception | None = None
            agent_timeout = get_agent_task_timeout()
            rate_limit_delays = get_rate_limit_backoff_delays()
            rate_limit_max_retries = get_rate_limit_max_retries()
            try:
                async with asyncio.timeout(agent_timeout):
                    for attempt in range(rate_limit_max_retries + 1):
                        try:
                            attempt_msg = (
                                f" (retry {attempt}/{rate_limit_max_retries})"
                                if attempt > 0
                                else ""
                            )
                            logger.info(
                                f"[{self.agent_name}] Running agent for task {task.task_id}{attempt_msg}"
                            )
                            result = await self._run_agent(prompt)

                            # Check if rate limit error was returned in result (SDK catches exceptions)
                            result_error = getattr(result, "error", None) or getattr(
                                result, "last_error", None
                            )
                            if result_error and _is_rate_limit_error(Exception(str(result_error))):
                                if attempt < rate_limit_max_retries:
                                    delay = rate_limit_delays[attempt]
                                    logger.warning(
                                        f"[{self.agent_name}] ⏳ Rate limit in result for task {task.task_id}, "
                                        f"backing off {delay}s (attempt {attempt + 1}/{rate_limit_max_retries}): "
                                        f"{result_error}"
                                    )
                                    last_rate_limit_error = str(result_error)
                                    result = None  # Clear result to retry
                                    await asyncio.sleep(delay)
                                    continue
                                # Out of retries - will be handled below
                                last_rate_limit_error = str(result_error)
                                result = None
                                break

                            if attempt > 0:
                                logger.success(
                                    f"[{self.agent_name}] Task {task.task_id} succeeded after {attempt} retries"
                                )
                            break  # Success, exit retry loop
                        except Exception as e:
                            if _is_rate_limit_error(e) and attempt < rate_limit_max_retries:
                                delay = rate_limit_delays[attempt]
                                logger.warning(
                                    f"[{self.agent_name}] ⏳ Rate limit exception for task {task.task_id}, "
                                    f"backing off {delay}s (attempt {attempt + 1}/{rate_limit_max_retries}): {e}"
                                )
                                last_rate_limit_error = e
                                await asyncio.sleep(delay)
                                continue
                            raise  # Re-raise if not rate limit or out of retries
            except TimeoutError:
                logger.warning(
                    f"[{self.agent_name}] ⏱️ Task {task.task_id} timed out after "
                    f"{agent_timeout}s - agent stuck in retry loop"
                )
                # Preserve any discoveries made before timeout (e.g., nmap found hosts)
                timeout_payload: dict[str, Any] = {
                    "output": "",
                    "task_type": task.task_type,
                }
                state_discoveries = self._serialize_state_discoveries()
                if state_discoveries:
                    timeout_payload.update(state_discoveries)
                    logger.info(
                        f"[{self.agent_name}] Preserving state from timed-out task: "
                        f"{len(state_discoveries.get('discovered_hosts', []))} hosts, "
                        f"{len(state_discoveries.get('discovered_credentials', []))} creds, "
                        f"{len(state_discoveries.get('discovered_hashes', []))} hashes"
                    )
                await self.task_queue.send_result(
                    task_id=task.task_id,
                    success=False,
                    result=timeout_payload if state_discoveries else None,
                    error=f"Task timeout: agent exceeded {agent_timeout}s limit",
                    worker_pod=self.pod_name,
                    agent_name=self.agent_name,
                )
                return

            if result is None:
                # All retries exhausted due to rate limits
                error_msg = (
                    str(last_rate_limit_error)
                    if last_rate_limit_error
                    else "Agent returned no result"
                )
                raise RuntimeError(f"Rate limit retries exhausted: {error_msg}")

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

            stop_reason = getattr(result, "stop_reason", None)
            if task.task_type == "credential_access" and stop_reason == "stalled":
                result_payload.setdefault(
                    "summary",
                    "Credential access stalled after exhausting available techniques with current credentials.",
                )
                result_payload.setdefault(
                    "next_steps",
                    [
                        "Provide additional credentials or hashes.",
                        "Provide known file paths on accessible shares to target.",
                        "Authorize exploitation or privilege escalation attempts.",
                        "Expand scope/targets or upload additional tooling.",
                    ],
                )
                if not agent_error:
                    agent_error = "Credential access stalled; no new credentials found."

            if task.task_type == "lateral" and stop_reason == "stalled":
                result_payload.setdefault(
                    "summary",
                    "Lateral movement stalled after exhausting available methods with current credentials.",
                )
                result_payload.setdefault(
                    "next_steps",
                    [
                        "Provide additional credentials or hashes.",
                        "Provide a specific lateral method to try (psexec/wmiexec/winrm).",
                        "Confirm target reachability and required ports.",
                    ],
                )
                if not agent_error:
                    agent_error = "Lateral movement stalled; no access achieved."

            if agent_error:
                if "Maximum steps reached" in agent_error:
                    self._dump_task_trace(task, prompt, result_text, result)

                    # Check if max steps was caused by model refusing to execute
                    is_refusing, refusal_count, sample_refusal = self._detect_model_refusal(result)
                    if is_refusing:
                        logger.critical(
                            f"[{self.agent_name}] 🚨 MODEL REFUSAL DETECTED for task {task.task_id}! "
                            f"Model refused {refusal_count} times. This model may not support security testing. "
                            f"Sample refusal: {sample_refusal!r}"
                        )
                        agent_error = (
                            f"MODEL REFUSAL: Model refused to execute security tasks {refusal_count} times. "
                            f"Consider switching to a model that supports authorized security testing."
                        )
                    else:
                        excerpt = result_text[-800:] if result_text else ""
                        logger.error(
                            f"[{self.agent_name}] Max steps reached for task {task.task_id}; "
                            f"output_excerpt={excerpt!r}"
                        )
                # Even on failure, preserve any discoveries made during the task
                state_discoveries = self._serialize_state_discoveries()
                if state_discoveries:
                    result_payload.update(state_discoveries)
                    logger.info(
                        f"[{self.agent_name}] Preserving state from failed task: "
                        f"{len(state_discoveries.get('discovered_hosts', []))} hosts, "
                        f"{len(state_discoveries.get('discovered_credentials', []))} creds, "
                        f"{len(state_discoveries.get('discovered_hashes', []))} hashes"
                    )
                await self.task_queue.send_result(
                    task_id=task.task_id,
                    success=False,
                    result=result_payload,
                    error=agent_error,
                    worker_pod=self.pod_name,
                    agent_name=self.agent_name,
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

            # Serialize local state discoveries into result payload
            # Workers have their own SharedRedTeamState that tools populate.
            # This ensures discoveries are sent back to the orchestrator.
            state_discoveries = self._serialize_state_discoveries()
            if state_discoveries:
                result_payload.update(state_discoveries)
                logger.info(
                    f"[{self.agent_name}] Serialized state: "
                    f"{len(state_discoveries.get('discovered_hosts', []))} hosts, "
                    f"{len(state_discoveries.get('discovered_credentials', []))} creds, "
                    f"{len(state_discoveries.get('discovered_hashes', []))} hashes"
                )

            # Send success result via Redis
            await self.task_queue.send_result(
                task_id=task.task_id,
                success=True,
                result=result_payload,
                worker_pod=self.pod_name,
                agent_name=self.agent_name,
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
                # Preserve any discoveries made before the fatal error
                fatal_result = self._serialize_state_discoveries()
                await self.task_queue.send_result(
                    task_id=task.task_id,
                    success=False,
                    result=fatal_result or None,
                    error=f"FATAL: {type(e).__name__}: {e!s}",
                    worker_pod=self.pod_name,
                    agent_name=self.agent_name,
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
            # Preserve any discoveries made before the exception
            exception_result = self._serialize_state_discoveries()
            await self.task_queue.send_result(
                task_id=task.task_id,
                success=False,
                result=exception_result or None,
                error=f"{type(e).__name__}: {e!s}",
                worker_pod=self.pod_name,
                agent_name=self.agent_name,
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
            # Clear credential context to prevent leakage between tasks
            clear_credential_context()
            # End the CONSUMER span for Tempo service graph
            _task_span.end()

    async def _refresh_shared_state(self) -> None:
        if not self.redis_url or not self.operation_id:
            return
        try:
            if self._state_refresh_client is None:
                self._state_refresh_client = await create_redis_client(
                    self.redis_url, decode_responses=False
                )

            from ares.core.state_backend import RedisStateBackend

            backend = RedisStateBackend(self._state_refresh_client, self.operation_id)
            fresh = SharedRedTeamState(operation_id=self.operation_id)

            # Load collections from Redis backend
            fresh.all_credentials.extend(await backend.get_credentials())
            fresh.all_hashes.extend(await backend.get_hashes())
            fresh.all_hosts.extend(await backend.get_hosts())
            fresh.all_users.extend(await backend.get_users())
            fresh.all_shares.extend(await backend.get_shares())
            fresh.all_domains.extend(await backend.get_domains())
            (
                fresh.has_domain_admin,
                fresh.domain_admin_path,
                fresh.da_hash_id,
            ) = await backend.get_domain_admin()
            fresh.has_golden_ticket = await backend.get_golden_ticket()
            # Load DC map for child domain resolution
            fresh.domain_controllers.update(await backend.get_all_dcs())

            # Reconstruct Target from meta for environment tracking
            target_ip = await backend.get_meta("target_ip", default="")
            target_domain = await backend.get_meta("target_domain", default="")
            target_env = await backend.get_meta("target_environment", default="")
            if target_ip or target_domain:
                from ares.core.models import Target

                fresh.target = Target(
                    ip=target_ip or "",
                    domain=target_domain or "",
                    environment=target_env or "",
                )

            self._merge_shared_state(fresh)
        except Exception as e:
            logger.debug(f"[{self.agent_name}] Failed to refresh shared state: {e}")

    def _merge_shared_state(self, fresh: SharedRedTeamState) -> None:
        if self.shared_state is None:
            logger.debug(
                f"[{self.agent_name}] Initial state: "
                f"{len(fresh.all_credentials)} creds, {len(fresh.all_hashes)} hashes, "
                f"{len(fresh.all_hosts)} hosts"
            )
            self.shared_state = fresh
            # Update /etc/hosts with any hosts present in initial state
            self._hosts_written_to_etc = _update_etc_hosts(
                fresh.all_hosts, self._hosts_written_to_etc, self.agent_name
            )
            return

        # Track counts before merge
        old_creds = len(self.shared_state.all_credentials)
        old_hashes = len(self.shared_state.all_hashes)
        old_hosts = len(self.shared_state.all_hosts)
        old_shares = len(self.shared_state.all_shares)

        # Preserve local discoveries before they get overwritten.
        # Workers discover shares/hosts/creds locally, but if a Redis state update
        # arrives before the task result is sent back, these would be lost.
        local_shares = list(self.shared_state.all_shares)
        local_hosts = list(self.shared_state.all_hosts)
        local_creds = list(self.shared_state.all_credentials)
        local_hashes = list(self.shared_state.all_hashes)
        local_users = list(self.shared_state.all_users)
        local_weaknesses = list(self.shared_state.all_weaknesses)

        current = self.shared_state
        for attr in (
            "operation_id",
            "target",
            "started_at",
            "all_domains",
            "domain_controllers",
            "all_credentials",
            "all_hashes",
            "all_hosts",
            "all_users",
            "all_shares",
            "all_weaknesses",
            "discovered_vulnerabilities",
            "exploited_vulnerabilities",
            "pending_tasks",
            "completed_tasks",
            "completed",
            "has_domain_admin",
            "has_golden_ticket",
            "domain_admin_path",
            "registered_agents",
            "operation_timeline",
            "identified_techniques",
            "pending_credential_findings",
            # Reset scanned_targets to prevent false "already scanned" skips
            # This set is not persisted to Redis, so we reset it on each refresh
            "scanned_targets",
        ):
            setattr(current, attr, getattr(fresh, attr))

        # Populate weakness dedup keys from the merged weakness list
        # This is critical to prevent duplicate weakness recording across workers
        current._weakness_dedup_keys.clear()
        for weakness in current.all_weaknesses:
            dedup_key = current._extract_weakness_dedup_key(weakness)
            current._weakness_dedup_keys.add(dedup_key)

        # Re-add local discoveries that may not be in the fresh state yet.
        # This preserves discoveries made during the current task before they're
        # serialized and sent back to the orchestrator.
        for share in local_shares:
            current.add_share(share)
        for host in local_hosts:
            current.add_host(host)
        for cred in local_creds:
            current.add_credential(cred, self.agent_name)
        for hash_obj in local_hashes:
            current.add_hash(hash_obj, self.agent_name)
        for user in local_users:
            current.add_user(user.username, user.domain, user.source)
        for weakness in local_weaknesses:
            current.add_weakness(weakness)  # Uses normalized dedup

        # Merge dynamic tracking attributes (set via object.__setattr__)
        # These track queried hosts and tested credentials to avoid duplicates
        for dynamic_attr in ("_queried_hosts", "_tested_credentials"):
            fresh_value = getattr(fresh, dynamic_attr, None)
            if fresh_value is not None:
                current_value: set = getattr(current, dynamic_attr, set())
                merged = current_value | fresh_value
                object.__setattr__(current, dynamic_attr, merged)

        # Log if state changed
        new_creds = len(current.all_credentials)
        new_hashes = len(current.all_hashes)
        new_hosts = len(current.all_hosts)
        new_shares = len(current.all_shares)
        if (
            new_creds != old_creds
            or new_hashes != old_hashes
            or new_hosts != old_hosts
            or new_shares != old_shares
        ):
            logger.debug(
                f"[{self.agent_name}] State merged: "
                f"creds {old_creds}->{new_creds}, "
                f"hashes {old_hashes}->{new_hashes}, "
                f"hosts {old_hosts}->{new_hosts}, "
                f"shares {old_shares}->{new_shares}"
            )

        # Update /etc/hosts with newly discovered hosts for DNS resolution
        self._hosts_written_to_etc = _update_etc_hosts(
            current.all_hosts, self._hosts_written_to_etc, self.agent_name
        )

    async def _execute_crack_task(self, task: TaskMessage) -> None:
        payload = task.payload or {}
        hash_value = payload.get("hash_value", "")
        hash_type = (payload.get("hash_type") or "").upper()
        username = payload.get("username", "")
        domain = payload.get("domain", "")
        # Only use explicit wordlist if specified; otherwise pass None to use DEFAULT_WORDLISTS
        # which includes rockyou.txt AND SecLists for better coverage
        explicit_wordlist = payload.get("wordlist")
        wordlist_path = (
            self._resolve_wordlist_path(explicit_wordlist) if explicit_wordlist else None
        )

        # Skip if password is already known for this user
        if self.shared_state and username:
            for cred in self.shared_state.all_credentials:
                cred_user = cred.username.lower() if cred.username else ""
                cred_domain = (cred.domain or "").lower()
                if (
                    cred_user == username.lower()
                    and cred_domain == domain.lower()
                    and cred.password
                ):
                    logger.info(
                        f"[{self.agent_name}] Skipping crack task for {domain}\\{username} - "
                        f"password already known"
                    )
                    await self.task_queue.send_result(
                        task_id=task.task_id,
                        success=True,
                        result={
                            "output": f"Skipped - password already known for {domain}\\{username}",
                            "task_type": task.task_type,
                            "credential": {
                                "username": username,
                                "password": cred.password,
                                "domain": domain,
                            },
                        },
                        worker_pod=self.pod_name,
                        agent_name=self.agent_name,
                    )
                    return

        if not hash_value:
            await self.task_queue.send_result(
                task_id=task.task_id,
                success=False,
                error="Missing hash_value in crack task payload",
                worker_pod=self.pod_name,
                agent_name=self.agent_name,
            )
            return

        crack_tools = CrackingTools()
        if self.shared_state is not None:
            crack_tools.set_state(self.shared_state)

        hashcat_mode = 13100
        john_format = "krb5tgs"
        if hash_type in {"AS-REP", "ASREP", "KRB5ASREP"}:
            hashcat_mode = 18200
            john_format = "krb5asrep"
        elif hash_type == "NTLM":
            hashcat_mode = 1000
            john_format = "ntlm"

        hashcat_time_limit: int | None = 10
        if hash_type in {"AS-REP", "ASREP", "KRB5ASREP"}:
            hashcat_time_limit = None

        output = await crack_tools.crack_with_hashcat(
            hash_value=hash_value,
            hashcat_mode=hashcat_mode,
            wordlist_path=wordlist_path,
            max_time_minutes=hashcat_time_limit,
            use_dynamic_wordlist=False,
        )
        password = self._extract_cracked_password(hash_value, output)

        if not password:
            output = await crack_tools.crack_with_hashcat(
                hash_value=hash_value,
                hashcat_mode=hashcat_mode,
                wordlist_path=wordlist_path,
                use_dynamic_wordlist=True,
            )
            password = self._extract_cracked_password(hash_value, output)

        if not password:
            output = await crack_tools.crack_with_john(
                hash_value=hash_value,
                hash_format=john_format,
                wordlist_path=wordlist_path,
                use_dynamic_wordlist=False,
            )
            password = self._extract_cracked_password(hash_value, output)

        if not password:
            output = await crack_tools.crack_with_john(
                hash_value=hash_value,
                hash_format=john_format,
                wordlist_path=wordlist_path,
                use_dynamic_wordlist=True,
            )
            password = self._extract_cracked_password(hash_value, output)

        result_payload: dict[str, Any] = {
            "output": output,
            "task_type": task.task_type,
        }
        if password:
            result_payload["credential"] = {
                "username": username,
                "password": password,
                "domain": domain,
                "source": f"cracked:{self.agent_name}",
            }
            result_payload["hash"] = {
                "username": username,
                "hash_value": hash_value,
                "hash_type": hash_type or "NTLM",
                "domain": domain,
                "cracked_password": password,
            }
            await self.task_queue.send_result(
                task_id=task.task_id,
                success=True,
                result=result_payload,
                worker_pod=self.pod_name,
                agent_name=self.agent_name,
            )
            return

        await self.task_queue.send_result(
            task_id=task.task_id,
            success=False,
            result=result_payload,
            error="Cracking failed: no password found",
            worker_pod=self.pod_name,
            agent_name=self.agent_name,
        )

    def _resolve_wordlist_path(self, wordlist_path: str) -> str:
        """Resolve wordlist path, decompressing .gz if needed."""
        if not os.path.isabs(wordlist_path):  # noqa: PTH117
            wordlist_path = os.path.join("/usr/share/wordlists", wordlist_path)  # noqa: PTH118
        if os.path.exists(wordlist_path) or wordlist_path.endswith(".gz"):
            return wordlist_path
        gz_path = f"{wordlist_path}.gz"
        if not os.path.exists(gz_path):
            return wordlist_path
        import tempfile

        tmp_wordlist = os.path.join(tempfile.gettempdir(), os.path.basename(wordlist_path))  # noqa: PTH118, PTH119
        if os.path.exists(tmp_wordlist):
            return tmp_wordlist
        try:
            import gzip
            import shutil

            with gzip.open(gz_path, "rb") as src, open(tmp_wordlist, "wb") as dst:
                shutil.copyfileobj(src, dst)
            logger.info(f"[{self.agent_name}] Decompressed wordlist {gz_path} to {tmp_wordlist}")
            return tmp_wordlist
        except Exception as exc:
            logger.warning(f"[{self.agent_name}] Failed to decompress wordlist {gz_path}: {exc}")
            return wordlist_path

    @staticmethod
    def _extract_cracked_password(hash_value: str, output: str) -> str:
        if not output:
            return ""
        for line in output.splitlines():
            if hash_value in line and ":" in line:
                return line.rsplit(":", 1)[-1].strip()
        return ""

    async def _check_for_pointer_switch(self) -> bool:
        """Return True if a switch is requested and the worker should exit."""
        if not self.redis_url or not self.operation_id:
            return False

        # Check if operation has completed
        if await is_operation_completed(self.redis_url, self.operation_id):
            logger.info(f"Operation {self.operation_id} has completed; shutting down worker")
            self._running = False
            return True

        # Check if active pointer switched to different operation
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
                agent_name=self.agent_name,
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
                agent_name=self.agent_name,
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
                agent_name=self.agent_name,
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

    # Patterns that indicate a model is refusing to execute security tasks
    MODEL_REFUSAL_PATTERNS: ClassVar[list[str]] = [
        r"I can'?t do that",
        r"I can'?t assist with",
        r"I can'?t comply with",
        r"I can'?t help with",
        r"I'?m not able to",
        r"I cannot (?:assist|help|comply|do)",
        r"(?:is |are )?disallowed",
        r"(?:is |are )?not allowed",
        r"against (?:my |the )?policy",
        r"violates? (?:my |the )?(?:policy|guidelines)",
        r"Denied by policy",
        r"lateral movement.{0,50}credential.{0,50}disallowed",
        r"secretsdump.{0,30}disallowed",
    ]

    def _detect_model_refusal(self, result: Any) -> tuple[bool, int, str | None]:
        """
        Detect if the model is refusing to execute tasks.

        Checks agent messages for refusal patterns that indicate the model
        won't execute security testing tasks (e.g., GPT refusing lateral movement).

        Returns:
            Tuple of (is_refusing, refusal_count, sample_refusal_message)
        """
        messages = getattr(result, "messages", None)
        if not messages:
            return False, 0, None

        try:
            messages_list = list(messages) if not isinstance(messages, list) else messages
        except Exception:
            return False, 0, None

        refusal_count = 0
        sample_message = None

        for msg in messages_list:
            # Extract content from message dict or object
            if isinstance(msg, dict):
                role = msg.get("role", "")
                content = msg.get("content", "")
            else:
                role = getattr(msg, "role", "")
                content = getattr(msg, "content", "")

            # Only check assistant messages
            if role != "assistant":
                continue

            content_str = str(content) if content else ""

            # Check for refusal patterns
            for pattern in self.MODEL_REFUSAL_PATTERNS:
                if re.search(pattern, content_str, re.IGNORECASE):
                    refusal_count += 1
                    if sample_message is None:
                        # Capture a sample, truncated for logging
                        sample_message = (
                            content_str[:200] + "..." if len(content_str) > 200 else content_str
                        )
                    break  # Count each message only once

        # Consider it a refusal loop if >30% of assistant messages are refusals
        # and there are at least 5 refusals
        assistant_count = sum(
            1
            for msg in messages_list
            if (isinstance(msg, dict) and msg.get("role") == "assistant")
            or (hasattr(msg, "role") and msg.role == "assistant")
        )

        is_refusing = refusal_count >= 5 and (
            assistant_count == 0 or refusal_count / max(assistant_count, 1) > 0.3
        )

        return is_refusing, refusal_count, sample_message

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

    def _format_agent_messages(
        self, result: Any, max_messages: int = 50, max_chars: int = 2000
    ) -> tuple[list[str], int]:
        """Format agent messages for debug traces without ballooning file size."""
        messages = getattr(result, "messages", None)
        if not messages:
            return [], 0

        try:
            total = len(messages)
        except Exception:
            total = 0

        if isinstance(messages, dict):
            messages_list = [messages]
        else:
            try:
                messages_list = list(messages)
            except Exception:
                messages_list = [messages]

        if total == 0:
            total = len(messages_list)

        trimmed = messages_list[-max_messages:]
        start_index = max(total - len(trimmed), 0)
        lines = []
        for idx, message in enumerate(trimmed, start=start_index + 1):
            if isinstance(message, dict):
                serialized = json.dumps(message, ensure_ascii=True)
            else:
                serialized = json.dumps(str(message), ensure_ascii=True)
            if len(serialized) > max_chars:
                serialized = f"{serialized[:max_chars]}...(truncated)"
            lines.append(f"{idx}: {serialized}")
        return lines, total

    def _dump_task_trace(
        self, task: TaskMessage, prompt: str, result_text: str, result: Any
    ) -> None:
        """Persist a task trace for debugging max-step failures."""
        try:
            trace_path = Path(tempfile.gettempdir()) / f"ares-task-{task.task_id}.log"
            summary = self._summarize_agent_result(result)
            message_lines, message_total = self._format_agent_messages(result)
            trace_lines = [
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
            if message_lines:
                trace_lines.append(
                    f"messages: showing last {len(message_lines)} of {message_total}"
                )
                trace_lines.extend(message_lines)
            trace_path.write_text(
                "\n".join(trace_lines),
                encoding="utf-8",
            )
            logger.warning(
                f"[{self.agent_name}] Task trace saved to {trace_path} for {task.task_id}"
            )
        except Exception as e:
            logger.warning(f"[{self.agent_name}] Failed to write task trace: {e}")

    def _threaded_heartbeat_loop(self) -> None:
        """Send heartbeats from a dedicated thread to avoid blocking by sync tool execution.

        Tools call blocking code (e.g., future.result() in remote.py) which prevents
        asyncio tasks from running. By running heartbeats in a separate thread with
        its own event loop, we ensure heartbeats continue even when the main thread
        is blocked by tool execution.
        """
        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # Create a dedicated task queue for heartbeats (can't share async connections across threads)
        heartbeat_queue: RedisTaskQueue | None = None
        retry_delay = 1.0
        max_retry_delay = 60.0

        try:
            while not self._heartbeat_stop_event.is_set() and self._running:
                try:
                    # Lazily connect on first use or reconnect if needed
                    if heartbeat_queue is None or not heartbeat_queue._connected:
                        redis_url = self.redis_url or get_redis_url()
                        heartbeat_queue = RedisTaskQueue(redis_url)
                        loop.run_until_complete(heartbeat_queue.connect())
                        logger.debug(f"Heartbeat thread connected to Redis for {self.agent_name}")

                    status = "busy" if self._current_task else "idle"
                    loop.run_until_complete(
                        heartbeat_queue.send_heartbeat(
                            agent_name=self.agent_name,
                            status=status,
                            current_task=self._current_task,
                            pod_name=self.pod_name,
                            role=self.role.value,
                            operation_id=self.operation_id,
                        )
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
                        # Close the TaskQueue's internal Redis client before creating new one
                        if heartbeat_queue:
                            try:
                                loop.run_until_complete(heartbeat_queue.disconnect())
                            except Exception:
                                pass
                            heartbeat_queue = None
                        # Wait with exponential backoff before retry
                        self._heartbeat_stop_event.wait(retry_delay)
                        retry_delay = min(retry_delay * 2, max_retry_delay)
                        continue  # Skip the regular sleep and retry immediately
                    logger.warning(f"Heartbeat failed: {e}")

                # Wait 15 seconds or until stop event is set
                self._heartbeat_stop_event.wait(15)

        finally:
            # Clean up
            if heartbeat_queue:
                try:
                    loop.run_until_complete(heartbeat_queue.disconnect())
                except Exception:
                    pass
            loop.close()
            logger.debug(f"Heartbeat thread stopped for {self.agent_name}")

    def _threaded_state_subscriber_loop(self) -> None:
        """Subscribe to Redis pub/sub for real-time state updates from orchestrator.

        When the orchestrator checkpoints state changes (new credentials, hosts, etc.),
        it publishes a notification to a channel. This thread subscribes to that channel
        and refreshes the local shared_state when notifications arrive, enabling
        near-instant state propagation instead of waiting for task boundaries.
        """
        # Ensure we have an operation_id before starting subscriber
        if not self.operation_id:
            logger.warning(
                f"[{self.agent_name}] Cannot start state subscriber: operation_id not set"
            )
            return

        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        subscriber_queue: RedisTaskQueue | None = None
        state_client = None
        pubsub = None
        retry_delay = 1.0
        max_retry_delay = 60.0

        try:
            while not self._state_subscriber_stop_event.is_set() and self._running:
                try:
                    # Lazily connect on first use or reconnect if needed
                    if subscriber_queue is None or not subscriber_queue._connected:
                        redis_url = self.redis_url or get_redis_url()
                        subscriber_queue = RedisTaskQueue(redis_url)
                        loop.run_until_complete(subscriber_queue.connect())
                        # Create separate client for state fetching (can't mix pubsub and regular commands)
                        state_client = loop.run_until_complete(
                            create_redis_client(redis_url, decode_responses=False)
                        )
                        # Subscribe to state updates channel
                        pubsub = loop.run_until_complete(
                            subscriber_queue.subscribe_state_updates(self.operation_id)
                        )
                        logger.info(
                            f"State subscriber connected for {self.agent_name} "
                            f"(operation: {self.operation_id})"
                        )

                    # Listen for messages with a timeout so we can check stop event
                    message = loop.run_until_complete(
                        self._wait_for_pubsub_message(pubsub, timeout=5.0)
                    )

                    if message and message.get("type") == "message":
                        # Received state update notification - refresh state
                        logger.debug(
                            f"[{self.agent_name}] Received state update notification via pub/sub"
                        )
                        loop.run_until_complete(self._fetch_and_merge_state(state_client))

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
                        logger.warning(f"State subscriber connection error, will retry: {e}")
                        # Close all clients to avoid resource leaks on reconnect
                        if pubsub:
                            try:
                                loop.run_until_complete(pubsub.aclose())
                            except Exception:
                                pass
                            pubsub = None
                        if state_client:
                            try:
                                loop.run_until_complete(state_client.aclose())
                            except Exception:
                                pass
                            state_client = None
                        # Close the TaskQueue's internal Redis client before creating new one
                        if subscriber_queue:
                            try:
                                loop.run_until_complete(subscriber_queue.disconnect())
                            except Exception:
                                pass
                            subscriber_queue = None
                        # Wait with exponential backoff before retry
                        self._state_subscriber_stop_event.wait(retry_delay)
                        retry_delay = min(retry_delay * 2, max_retry_delay)
                        continue
                    logger.warning(f"State subscriber error: {e}")

        finally:
            # Clean up
            if pubsub:
                try:
                    loop.run_until_complete(pubsub.unsubscribe())
                    loop.run_until_complete(pubsub.aclose())
                except Exception:
                    pass
            if state_client:
                try:
                    loop.run_until_complete(state_client.aclose())
                except Exception:
                    pass
            if subscriber_queue:
                try:
                    loop.run_until_complete(subscriber_queue.disconnect())
                except Exception:
                    pass
            loop.close()
            logger.debug(f"State subscriber thread stopped for {self.agent_name}")

    async def _wait_for_pubsub_message(self, pubsub, timeout: float = 5.0) -> dict | None:
        """Wait for a pub/sub message with timeout."""
        try:
            # get_message with timeout returns None if no message
            return await asyncio.wait_for(
                pubsub.get_message(ignore_subscribe_messages=True, timeout=timeout),
                timeout=timeout + 1.0,  # Slightly longer to let internal timeout work
            )
        except asyncio.TimeoutError:
            return None

    async def _fetch_and_merge_state(self, redis_client) -> None:
        """Fetch state from Redis and merge into local shared_state."""
        if not self.operation_id:
            return
        try:
            from ares.core.state_backend import RedisStateBackend

            backend = RedisStateBackend(redis_client, self.operation_id)
            fresh = SharedRedTeamState(operation_id=self.operation_id)

            # Load collections from Redis backend
            fresh.all_credentials.extend(await backend.get_credentials())
            fresh.all_hashes.extend(await backend.get_hashes())
            fresh.all_hosts.extend(await backend.get_hosts())
            fresh.all_users.extend(await backend.get_users())
            fresh.all_shares.extend(await backend.get_shares())
            fresh.all_domains.extend(await backend.get_domains())
            (
                fresh.has_domain_admin,
                fresh.domain_admin_path,
                fresh.da_hash_id,
            ) = await backend.get_domain_admin()
            fresh.has_golden_ticket = await backend.get_golden_ticket()
            # Load DC map for child domain resolution
            fresh.domain_controllers.update(await backend.get_all_dcs())

            # Reconstruct Target from meta for environment tracking
            target_ip = await backend.get_meta("target_ip", default="")
            target_domain = await backend.get_meta("target_domain", default="")
            target_env = await backend.get_meta("target_environment", default="")
            if target_ip or target_domain:
                from ares.core.models import Target

                fresh.target = Target(
                    ip=target_ip or "",
                    domain=target_domain or "",
                    environment=target_env or "",
                )

            self._merge_shared_state(fresh)
        except Exception as e:
            logger.debug(f"[{self.agent_name}] Failed to fetch/merge state: {e}")


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
        self._run_agent_in_thread = self.role == AgentRole.ACL
        # Threaded heartbeat to avoid blocking by sync tool execution
        self._heartbeat_thread: threading.Thread | None = None
        self._heartbeat_stop_event = threading.Event()

    def _run_agent_sync(self, prompt: str) -> Any:
        """Run the async agent in a dedicated event loop (thread-safe helper)."""
        return asyncio.run(self.agent.run(prompt))

    async def _run_agent(self, prompt: str) -> Any:
        """Run the agent without blocking the worker event loop."""
        if self._run_agent_in_thread:
            return await asyncio.to_thread(self._run_agent_sync, prompt)
        return await self.agent.run(prompt)

    async def start(self) -> None:
        """Start the worker loop."""
        self._running = True
        self._pointer_switched = False
        self._heartbeat_stop_event.clear()
        logger.info(f"Worker {self.agent_name} starting...")

        # Start heartbeat in a separate thread to avoid blocking by sync tool execution.
        # Tools call blocking code (future.result()) which prevents asyncio tasks from running.
        self._heartbeat_thread = threading.Thread(
            target=self._threaded_heartbeat_loop,
            name=f"{self.agent_name}-heartbeat",
            daemon=True,
        )
        self._heartbeat_thread.start()
        logger.debug(f"Heartbeat thread started for {self.agent_name}")

        try:
            await self._worker_loop()
        finally:
            self._running = False
            # Signal heartbeat thread to stop and wait for it
            self._heartbeat_stop_event.set()
            if self._heartbeat_thread and self._heartbeat_thread.is_alive():
                self._heartbeat_thread.join(timeout=5.0)
                if self._heartbeat_thread.is_alive():
                    logger.warning(
                        f"Heartbeat thread for {self.agent_name} did not stop gracefully"
                    )

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

                # Small sleep to prevent busy-waiting
                await asyncio.sleep(0.5)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker loop error: {e}")
                await asyncio.sleep(5)  # Back off on error

    async def _check_for_pointer_switch(self) -> bool:
        """Return True if a switch is requested and the worker should exit."""
        if not self.redis_url or not self.operation_id:
            return False

        # Check if operation has completed
        if await is_operation_completed(self.redis_url, self.operation_id):
            logger.info(f"Operation {self.operation_id} has completed; shutting down worker")
            self._running = False
            return True

        # Check if active pointer switched to different operation
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
            result = await self._run_agent(prompt)

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
        """Generate a prompt for the agent based on message type with state context."""
        prompt_generator = TASK_PROMPTS.get(msg.type)
        if not prompt_generator:
            return None

        base_prompt = prompt_generator(msg)

        # Determine task type for state context
        task_type_map = {
            MessageType.LATERAL_MOVEMENT_REQUEST: "lateral",
            MessageType.CREDENTIAL_ACCESS_REQUEST: "credential_access",
            MessageType.EXPLOIT_REQUEST: "exploit",
            MessageType.COERCION_REQUEST: "coercion",
            MessageType.ACL_ANALYSIS_REQUEST: "acl_analysis",
        }
        task_type = task_type_map.get(msg.type, "")

        # Get current target if available
        current_target = getattr(msg, "target_host", None) or getattr(msg, "target", None)

        # Append state context
        state = self.dispatcher.shared_state if self.dispatcher else None
        if state and task_type:
            state_context = format_state_context(state, task_type, current_target=current_target)
            return base_prompt + state_context

        return base_prompt

    def _extract_result(self, result: Any) -> str:
        """Extract text result from agent output."""
        if hasattr(result, "output"):
            return str(result.output)
        if hasattr(result, "content"):
            return str(result.content)
        return str(result)

    def _threaded_heartbeat_loop(self) -> None:
        """Send heartbeats from a dedicated thread to avoid blocking by sync tool execution.

        Tools call blocking code (e.g., future.result() in remote.py) which prevents
        asyncio tasks from running. By running heartbeats in a separate thread with
        its own event loop, we ensure heartbeats continue even when the main thread
        is blocked by tool execution.
        """
        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        retry_delay = 1.0
        max_retry_delay = 60.0

        try:
            while not self._heartbeat_stop_event.is_set() and self._running:
                try:
                    status = "busy" if self._current_task else "idle"
                    loop.run_until_complete(
                        self.dispatcher.heartbeat(
                            agent_name=self.agent_name,
                            status=status,
                            current_task=self._current_task,
                        )
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
                        # Wait with exponential backoff before retry
                        self._heartbeat_stop_event.wait(retry_delay)
                        retry_delay = min(retry_delay * 2, max_retry_delay)
                        continue  # Skip the regular sleep and retry immediately
                    logger.warning(f"Heartbeat failed: {e}")

                # Wait 15 seconds or until stop event is set
                self._heartbeat_stop_event.wait(15)

        finally:
            loop.close()
            logger.debug(f"Heartbeat thread stopped for {self.agent_name}")


async def run_worker(
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
        role: The agent role (credential_access, cracker, acl, privesc, lateral, coercion).
        operation_id: The operation ID to join (optional - will discover if not provided).
        redis_url: Redis URL for task queue and state (default: from config).
        model: LLM model to use.
        max_steps: Override default max steps for role.
        discover_operation: If True and operation_id is None/empty, discover from Redis.
        discovery_timeout: Max seconds to wait for operation discovery (default: None = wait forever).
        use_redis_queue: If True, poll Redis queue for tasks (Kubernetes mode).
    """
    # Apply rigging patches for case-insensitive tool parameters
    from ares.core.rigging_patches import apply as apply_rigging_patches

    apply_rigging_patches()

    configure_litellm_env()

    # Configure OTEL tracing to export to OTLP endpoint (e.g., Alloy/Tempo)
    # This is required because the dreadnode SDK doesn't auto-configure from OTEL env vars
    from ares.core.tracing import setup_otel_tracing

    setup_otel_tracing()

    # Initialize replay system if configured
    from ares.core.config import (
        get_replay_fallback,
        get_replay_file,
        get_replay_mode,
        get_replay_seed,
    )
    from ares.core.replay import initialize_replay

    replay_mode = get_replay_mode()
    if replay_mode:
        replay_file = get_replay_file()
        if replay_file:
            from pathlib import Path

            base_path = Path(replay_file).parent
            base_path.mkdir(parents=True, exist_ok=True)
            # Per-role file to avoid conflicts between worker pods
            replay_file = str(base_path / f"{role.value}.jsonl")

        initialize_replay(
            mode=replay_mode,
            path=replay_file,
            seed=get_replay_seed(),
            fallback=get_replay_fallback(),
        )

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

        # Fetch and set worker credentials (API keys) from Redis
        # These are persisted by the orchestrator when the operation starts
        credentials = await get_worker_credentials(redis_url, operation_id)
        if credentials:
            for key, value in credentials.items():
                if value and not os.environ.get(key):
                    os.environ[key] = value
                    logger.debug(f"Set credential from Redis: {key}")
            logger.info(f"Loaded {len(credentials)} credentials from operation config")
        # Check if we already have the key in env (e.g., mounted secret)
        elif not os.environ.get("OPENAI_API_KEY"):
            logger.warning(
                "No worker credentials found in Redis and OPENAI_API_KEY not in environment. "
                "LLM calls may fail."
            )

        logger.info(f"Starting {role.value} worker for operation {operation_id}")
        logger.info(f"Pod: {pod_name}, Redis: {redis_url}, Redis Queue: {use_redis_queue}")

        # Create Redis task queue for direct polling (Kubernetes mode)
        task_queue: RedisTaskQueue | None = None
        if use_redis_queue:
            task_queue = RedisTaskQueue(redis_url)
            await task_queue.connect()
            logger.info("Worker connected to Redis task queue")

        # Create dispatcher for state management and fallback messaging
        # Workers don't need result consumer (they send results, not consume them)
        dispatcher = RedTeamDispatcher(redis_url=redis_url, is_orchestrator=False)
        await dispatcher.start(operation_id)

        # Try to recover existing state
        recovered = await dispatcher.recover_state(operation_id)
        if recovered:
            logger.info(f"Recovered state: {len(recovered.all_credentials)} credentials")

        shared_state = dispatcher.shared_state
        # Enable real-time publishing of discoveries to Redis
        shared_state.set_dispatcher(dispatcher)

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
            additional_tools=additional_tools or None,
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
                    shared_state=shared_state,
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
            from ares.core.replay import shutdown_replay

            shutdown_replay()

            if task_queue:
                await task_queue.disconnect()
            await dispatcher.stop()
            await close_litellm_clients()
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
            # Reset replay normalization context for new operation
            from ares.core.replay.wrappers import reset_normalization_context

            reset_normalization_context()
            continue

        break


__all__ = [
    "RedisWorkerAgent",
    "WorkerAgent",
    "discover_active_operation",
    "generate_prompt_from_task",
    "run_worker",
]
