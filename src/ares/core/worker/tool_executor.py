"""Thin tool executor for Rust-driven agent loops.

When the Rust orchestrator drives LLM agent loops natively, Python workers
become thin tool executors: they BRPOP individual tool call requests from
Redis, execute the corresponding Python tool method, and LPUSH the result
back.

Redis protocol (must match ares-orchestrator/src/tool_dispatcher.rs):

  Request queue:  ares:tool_exec:{role}
  Result mailbox: ares:tool_results:{call_id}

  Request JSON:
    {"call_id": str, "task_id": str, "tool_name": str, "arguments": dict}

  Response JSON:
    {"call_id": str, "output": str, "error": str | null}
"""

from __future__ import annotations

import asyncio
import inspect
import json
import signal
import traceback
from typing import Any

import redis.asyncio as aioredis
from loguru import logger

from ares.core.capability_registry import (
    CAPABILITY_REGISTRY,
    get_enabled_tools,
)
from ares.core.config import get_agent_config
from ares.core.factories.red_agents import ALL_TOOLSETS, ROLE_CALLBACK_TOOLS
from ares.core.models import AgentRole, SharedRedTeamState
from ares.core.state_backend import RedisStateBackend
from ares.tools.red import RedTeamReportingTools

# Redis key prefixes — must match Rust's tool_dispatcher.rs
TOOL_EXEC_PREFIX = "ares:tool_exec"
TOOL_RESULT_PREFIX = "ares:tool_results"

# TTL for result keys (1 hour) — matches Rust constant
RESULT_TTL_SECS = 3600

# BRPOP timeout (seconds) — short so we can check shutdown flag
POLL_TIMEOUT = 5


class ToolExecutor:
    """Thin tool executor that services Rust-driven agent loops.

    Discovers all tool methods from toolset classes, then runs a BRPOP loop
    that executes individual tool calls and returns results via Redis.
    """

    def __init__(
        self,
        role: str,
        redis_url: str,
        shared_state: SharedRedTeamState | None = None,
        dispatcher: Any = None,
    ) -> None:
        self.role = role
        self.redis_url = redis_url
        self.shared_state = shared_state
        self.dispatcher = dispatcher
        self._running = False

        # Build tool method lookup: tool_name → bound method
        self._tool_map: dict[str, Any] = {}
        self._build_tool_map()

    def _build_tool_map(self) -> None:
        """Discover all tool methods for this role and build a name→method map."""
        # Get capabilities from agent config
        try:
            agent_config = get_agent_config(self.role)
            capabilities = set(agent_config.capabilities)
        except Exception:
            # Fallback: enable all capabilities
            logger.warning(f"Could not load agent config for role={self.role}, enabling all tools")
            capabilities = set(CAPABILITY_REGISTRY.keys())

        enabled_tools = get_enabled_tools(capabilities)
        logger.info(f"Tool executor: {len(enabled_tools)} tools enabled for role={self.role}")

        # Build toolset instances
        toolset_classes = list(ALL_TOOLSETS)

        # Add role-specific callback tools
        try:
            role_enum = AgentRole(self.role)
            if role_enum in ROLE_CALLBACK_TOOLS:
                toolset_classes.extend(ROLE_CALLBACK_TOOLS[role_enum])
        except ValueError:
            pass

        # Always include reporting tools
        toolset_classes.append(RedTeamReportingTools)

        # Instantiate and filter
        for cls in toolset_classes:
            try:
                toolset = cls()

                if hasattr(toolset, "set_state") and self.shared_state is not None:
                    toolset.set_state(self.shared_state)
                if hasattr(toolset, "set_dispatcher") and self.dispatcher is not None:
                    toolset.set_dispatcher(self.dispatcher)

                # Discover tool methods via get_tools() if available (dreadnode SDK)
                if hasattr(toolset, "get_tools"):
                    for tool in toolset.get_tools():
                        if tool.name in enabled_tools or tool.name in _ALWAYS_AVAILABLE:
                            self._tool_map[tool.name] = getattr(toolset, tool.name)
                else:
                    # Fallback: scan for @dn.tool_method decorated methods
                    for name in dir(toolset):
                        if name.startswith("_"):
                            continue
                        method = getattr(toolset, name, None)
                        if callable(method) and name in enabled_tools:
                            self._tool_map[name] = method
            except Exception as e:
                logger.warning(f"Failed to initialize toolset {cls.__name__}: {e}")

        logger.info(
            f"Tool executor ready: {len(self._tool_map)} tool methods registered "
            f"for role={self.role}"
        )
        if logger.level("DEBUG"):
            for name in sorted(self._tool_map):
                logger.debug(f"  - {name}")

    async def run(self) -> None:
        """Run the BRPOP loop until stopped."""
        self._running = True
        queue_key = f"{TOOL_EXEC_PREFIX}:{self.role}"

        conn = aioredis.from_url(self.redis_url, decode_responses=True)

        logger.info(f"Tool executor starting BRPOP loop on {queue_key}")

        try:
            while self._running:
                try:
                    result = await conn.brpop(queue_key, timeout=POLL_TIMEOUT)
                    if result is None:
                        continue  # Timeout, check shutdown flag

                    _key, data = result
                    await self._handle_request(conn, data)

                except aioredis.ConnectionError as e:
                    logger.warning(f"Redis connection error: {e}, reconnecting...")
                    await asyncio.sleep(1)
                    conn = aioredis.from_url(self.redis_url, decode_responses=True)

                except Exception as e:
                    logger.error(f"Unexpected error in tool executor loop: {e}")
                    await asyncio.sleep(1)
        finally:
            await conn.aclose()
            logger.info("Tool executor stopped")

    async def _handle_request(self, conn: aioredis.Redis, data: str) -> None:
        """Parse a tool exec request, execute the tool, and push the result."""
        try:
            request = json.loads(data)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in tool exec request: {e}")
            return

        call_id = request.get("call_id", "unknown")
        tool_name = request.get("tool_name", "")
        arguments = request.get("arguments", {})
        task_id = request.get("task_id", "")

        logger.info(f"Executing tool: {tool_name} (call_id={call_id}, task_id={task_id})")

        output = ""
        error = None

        try:
            method = self._tool_map.get(tool_name)
            if method is None:
                error = f"Unknown tool: {tool_name}"
                logger.warning(f"Tool not found: {tool_name} (call_id={call_id})")
            else:
                # Call the tool method with unpacked arguments
                result = method(**arguments)

                # Handle async tool methods
                if inspect.isawaitable(result):
                    result = await result

                # Normalize result to string
                if isinstance(result, dict):
                    output = json.dumps(result)
                elif result is None:
                    output = ""
                else:
                    output = str(result)

        except TypeError as e:
            # Likely argument mismatch
            error = f"Tool argument error for {tool_name}: {e}"
            logger.warning(f"Argument error calling {tool_name}: {e}")
        except Exception as e:
            error = f"Tool execution error: {e}"
            logger.error(
                f"Error executing {tool_name} (call_id={call_id}): {e}\n{traceback.format_exc()}"
            )

        # Build response
        response = json.dumps(
            {
                "call_id": call_id,
                "output": output,
                "error": error,
            }
        )

        # Push result to mailbox
        result_key = f"{TOOL_RESULT_PREFIX}:{call_id}"
        try:
            await conn.lpush(result_key, response)
            await conn.expire(result_key, RESULT_TTL_SECS)
            logger.debug(
                f"Tool result pushed: {tool_name} → {result_key} "
                f"(output={len(output)} chars, error={error is not None})"
            )
        except Exception as e:
            logger.error(f"Failed to push tool result for {call_id}: {e}")

    def stop(self) -> None:
        """Signal the executor to stop."""
        self._running = False


# Tools always available regardless of capability filtering
# (reporting tools, callback tools that Rust handles but may also exist in Python)
_ALWAYS_AVAILABLE: set[str] = {
    "report_finding",
    "report_lateral_success",
    "report_lateral_failed",
    "report_cracked_credential",
    "report_crack_failed",
    "task_complete",
    "request_assistance",
    "complete_operation",
    # Reporting
    "write_section",
    "add_evidence",
    "add_attack_path",
    "add_recommendation",
    "set_executive_summary",
    "finalize_report",
    "get_report_status",
}


def main() -> None:
    """CLI entry point for the thin tool executor."""
    import os

    redis_url = os.environ.get("ARES_REDIS_URL")
    if not redis_url:
        logger.error("ARES_REDIS_URL is required")
        raise SystemExit(1)

    role = os.environ.get("ARES_WORKER_ROLE")
    if not role:
        logger.error("ARES_WORKER_ROLE is required")
        raise SystemExit(1)

    # Create SharedRedTeamState with operation_id for state writeback to Redis
    operation_id = os.environ.get("ARES_OPERATION_ID")
    shared_state: SharedRedTeamState | None = None

    if operation_id:
        logger.info(f"Operation ID from env: {operation_id}")
        shared_state = SharedRedTeamState(operation_id=operation_id)
    else:
        # Try to discover active operation from Redis
        logger.info("No ARES_OPERATION_ID set, attempting discovery...")
        try:
            from ares.core.worker.operations import discover_active_operation

            discovered_id = asyncio.run(discover_active_operation(redis_url, max_wait=30))
            if discovered_id:
                logger.info(f"Discovered active operation: {discovered_id}")
                operation_id = discovered_id
                shared_state = SharedRedTeamState(operation_id=operation_id)
            else:
                logger.warning("No active operation found, state writeback disabled")
        except Exception as e:
            logger.warning(f"Failed to discover operation: {e}, state writeback disabled")

    logger.info(f"Starting tool executor: role={role}, redis={redis_url}")
    asyncio.run(run_tool_executor(redis_url=redis_url, role=role, shared_state=shared_state))


async def _load_state_from_backend(
    state: SharedRedTeamState,
    backend: Any,
) -> None:
    """Load essential state from Redis backend into SharedRedTeamState.

    Hydrates credentials, hashes, hosts, users, shares, weaknesses, domains,
    vulnerabilities, and domain controller mappings so tools have current context.

    This is a simplified version of recovery.py's _load_state_from_backend,
    loading only the collections that tool methods typically read.

    Args:
        state: Shared state object to populate.
        backend: RedisStateBackend instance.
    """
    try:
        state.all_credentials.extend(await backend.get_credentials())
        state.all_hashes.extend(await backend.get_hashes())
        state.all_hosts.extend(await backend.get_hosts())
        state.all_users.extend(await backend.get_users())
        state.all_shares.extend(await backend.get_shares())
        state.all_domains.extend(await backend.get_domains())
        state.discovered_vulnerabilities.update(await backend.get_vulnerabilities())

        dc_map = await backend.get_all_dcs()
        state.domain_controllers.update(dc_map)

        netbios_map = await backend.get_all_netbios_mappings()
        state.netbios_to_fqdn.update(netbios_map)

        (
            state.has_domain_admin,
            state.domain_admin_path,
            state.da_hash_id,
        ) = await backend.get_domain_admin()

        total = (
            len(state.all_credentials)
            + len(state.all_hashes)
            + len(state.all_hosts)
            + len(state.all_users)
        )
        logger.info(
            f"Loaded state from Redis: {len(state.all_credentials)} creds, "
            f"{len(state.all_hashes)} hashes, {len(state.all_hosts)} hosts, "
            f"{len(state.all_users)} users ({total} total items)"
        )
    except Exception as e:
        logger.warning(f"Failed to load initial state from Redis: {e}")


async def run_tool_executor(
    redis_url: str,
    role: str,
    shared_state: SharedRedTeamState | None = None,
    dispatcher: Any = None,
) -> None:
    """Entry point to run a thin tool executor for a given role.

    When shared_state has an operation_id, a RedisStateBackend is wired up
    so that tool-discovered credentials, hosts, etc. persist to Redis and
    become visible to the Rust orchestrator via its state_refresh task.

    Args:
        redis_url: Redis connection URL.
        role: Agent role (e.g., "recon", "credential_access").
        shared_state: Optional shared operation state.
        dispatcher: Optional dispatcher for inter-agent communication.
    """
    # Wire up Redis state backend for state writeback
    if shared_state is not None and shared_state.operation_id:
        try:
            # Use decode_responses=False because RedisStateBackend handles
            # its own serialization and expects bytes from Redis
            client = aioredis.from_url(redis_url, decode_responses=False)
            backend = RedisStateBackend(client, shared_state.operation_id)
            shared_state.set_backend(backend)
            logger.info(f"State writeback enabled for operation {shared_state.operation_id}")

            # Load existing state so tools see current credentials/hosts
            await _load_state_from_backend(shared_state, backend)
        except Exception as e:
            logger.warning(f"Failed to set up state backend: {e}")

    executor = ToolExecutor(
        role=role,
        redis_url=redis_url,
        shared_state=shared_state,
        dispatcher=dispatcher,
    )

    # Handle graceful shutdown
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, executor.stop)

    await executor.run()
