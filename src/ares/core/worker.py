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
from ares.core.models import AgentRole, SharedRedTeamState
from ares.core.redis_client import create_redis_client
from ares.core.task_queue import RedisTaskQueue, TaskMessage
from ares.tools.red import CrackerCallbackTools, CrackingTools, LateralCallbackTools

if TYPE_CHECKING:
    from dreadnode.agent import Agent


def _is_pass_the_hash_compatible(hash_value: str | None) -> bool:
    if not hash_value:
        return False
    normalized = hash_value.strip()
    if "$" in normalized:
        return False
    if ":" in normalized:
        parts = normalized.split(":")
        if len(parts) != 2:
            return False
        lm_part, ntlm_part = parts
        if lm_part and not re.fullmatch(r"[0-9a-fA-F]{32}", lm_part):
            return False
        return bool(re.fullmatch(r"[0-9a-fA-F]{32}", ntlm_part))
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}", normalized))


def format_state_context(  # noqa: PLR0912
    state: SharedRedTeamState | None,
    task_type: str,
    current_target: str | None = None,
) -> str:
    """
    Format shared state as context for task prompts.

    This provides workers with visibility into all discovered credentials,
    hosts, hashes, and opportunities so they can make strategic decisions.

    Args:
        state: The shared red team state
        task_type: Type of task (lateral, credential_access, exploit, coercion)
        current_target: The primary target of this task (for prioritization)

    Returns:
        Formatted state context string to append to task prompts
    """
    if not state:
        return ""

    lines = ["\n\n## SHARED STATE CONTEXT (use this intelligence!)"]

    # Domains
    if state.all_domains:
        lines.append(f"\n### Discovered Domains ({len(state.all_domains)})")
        for domain in state.all_domains[:10]:
            lines.append(f"  - {domain}")

    # Credentials - CRITICAL for lateral/privesc
    if state.all_credentials:
        lines.append(f"\n### Available Credentials ({len(state.all_credentials)})")
        lines.append("**TRY THESE for authentication/lateral movement:**")
        for cred in state.all_credentials[:15]:
            admin_marker = " [ADMIN]" if cred.is_admin else ""
            lines.append(f"  - {cred.domain}\\{cred.username}:{cred.password}{admin_marker}")

    # Hashes - show cracked vs uncracked
    if state.all_hashes:
        cracked = [h for h in state.all_hashes if h.cracked_password]
        uncracked = [h for h in state.all_hashes if not h.cracked_password]

        if cracked:
            lines.append(f"\n### Cracked Hashes ({len(cracked)}) - USE THESE!")
            for h in cracked[:10]:
                lines.append(
                    f"  - {h.domain}\\{h.username}:{h.cracked_password} (from {h.hash_type})"
                )

        if uncracked:
            lines.append(f"\n### Uncracked Hashes ({len(uncracked)}) - awaiting crack")
            for h in uncracked[:8]:
                hash_preview = h.hash_value[:40] + "..." if len(h.hash_value) > 40 else h.hash_value
                lines.append(f"  - {h.domain}\\{h.username} ({h.hash_type}): {hash_preview}")

    # Hosts with role-specific prioritization
    if state.all_hosts:
        lines.append(f"\n### Discovered Hosts ({len(state.all_hosts)})")

        # Categorize hosts by role
        dcs = []
        mssql_hosts = []
        adcs_hosts = []
        other_hosts = []

        for host in state.all_hosts:
            hostname_lower = (host.hostname or "").lower()
            services_lower = " ".join(host.services).lower() if host.services else ""
            roles_lower = " ".join(host.roles).lower() if host.roles else ""

            is_dc = (
                "dc" in hostname_lower
                or "domain controller" in roles_lower
                or "88/tcp" in services_lower
                or "389/tcp" in services_lower
            )
            is_mssql = (
                "mssql" in services_lower or "1433" in services_lower or "sql" in hostname_lower
            )
            is_adcs = (
                "certsrv" in services_lower
                or "adcs" in roles_lower
                or "certenroll" in services_lower
            )

            if is_dc:
                dcs.append(host)
            elif is_mssql:
                mssql_hosts.append(host)
            elif is_adcs:
                adcs_hosts.append(host)
            else:
                other_hosts.append(host)

        if dcs:
            lines.append("\n**Domain Controllers (HIGH VALUE - DCSync/NTDS.dit):**")
            for h in dcs:
                marker = " ← CURRENT TARGET" if h.ip == current_target else ""
                lines.append(f"  - {h.ip} ({h.hostname or 'unknown'}){marker}")

        if mssql_hosts:
            lines.append("\n**MSSQL Servers (linked server pivot opportunity):**")
            for h in mssql_hosts:
                marker = " ← CURRENT TARGET" if h.ip == current_target else ""
                lines.append(f"  - {h.ip} ({h.hostname or 'unknown'}){marker}")

        if adcs_hosts:
            lines.append("\n**ADCS Servers (certificate attacks ESC1-ESC8):**")
            for h in adcs_hosts:
                marker = " ← CURRENT TARGET" if h.ip == current_target else ""
                lines.append(f"  - {h.ip} ({h.hostname or 'unknown'}){marker}")

        if other_hosts and len(other_hosts) <= 10:
            lines.append("\n**Other Hosts:**")
            for h in other_hosts:
                marker = " ← CURRENT TARGET" if h.ip == current_target else ""
                lines.append(f"  - {h.ip} ({h.hostname or 'unknown'}){marker}")

    # Shares - highlight writable and interesting ones
    if state.all_shares:
        interesting_shares = []
        for share in state.all_shares:
            name_lower = share.name.lower()
            perms_lower = (share.permissions or "").lower()
            is_interesting = (
                "write" in perms_lower
                or name_lower in ("sysvol", "netlogon", "certenroll")
                or "admin" in name_lower
            )
            if is_interesting:
                interesting_shares.append(share)

        if interesting_shares:
            lines.append(f"\n### Interesting Shares ({len(interesting_shares)})")
            for share in interesting_shares[:10]:
                lines.append(f"  - {share.host}/{share.name} [{share.permissions}]")

    # Vulnerabilities discovered but not exploited
    if hasattr(state, "discovered_vulnerabilities") and state.discovered_vulnerabilities:
        unexploited = [
            v
            for v in state.discovered_vulnerabilities.values()
            if v.vuln_id not in state.exploited_vulnerabilities
        ]
        if unexploited:
            lines.append(f"\n### Pending Vulnerabilities ({len(unexploited)})")
            for vuln in unexploited[:5]:
                lines.append(f"  - {vuln.vuln_type} on {vuln.target} (ID: {vuln.vuln_id})")

    # Task-specific guidance
    if task_type == "lateral":
        lines.append("\n### LATERAL MOVEMENT PRIORITIES")
        lines.append("1. Try ALL available credentials above against the target")
        lines.append("2. If DC: run secretsdump for NTDS.dit → krbtgt hash → golden ticket")
        lines.append("3. If MSSQL: check for linked servers and xp_cmdshell")
        lines.append("4. After access: harvest creds with secretsdump/lsassy")

    elif task_type == "credential_access":
        lines.append("\n### CREDENTIAL ACCESS PRIORITIES")
        lines.append("1. gpp_password_finder + sysvol_script_search on DCs (low-hanging fruit)")
        lines.append("2. Kerberoast service accounts (sql_svc, etc.)")
        lines.append("3. AS-REP roast users without pre-auth")
        lines.append("4. secretsdump on hosts where we have admin")
        lines.append("5. LAPS dump if we have read access")

    elif task_type == "exploit":
        lines.append("\n### EXPLOITATION PRIORITIES")
        lines.append("1. Try ALL available credentials against the target")
        lines.append("2. For MSSQL: enumerate linked servers for cross-domain pivot")
        lines.append("3. For ADCS: certipy find → ESC1/ESC4/ESC8 attacks")
        lines.append("4. Check for delegation (constrained/unconstrained)")

    elif task_type == "coercion":
        lines.append("\n### COERCION PRIORITIES")
        lines.append("1. Target DCs with PetitPotam for ESC8 relay")
        lines.append("2. Use LLMNR/NBT-NS for hash capture")
        lines.append("3. Coordinate relay targets with hosts lacking SMB signing")

    return "\n".join(lines)


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
        f"Credential ({'password' if msg.password else 'hash'}): "
        f"{msg.password or msg.hash_value or 'N/A'}\n"
        f"Method: {msg.method or 'auto-select'}\n"
        f"Task ID: {msg.task_id}\n\n"
        "Use the exact credential value above; do not substitute placeholders. "
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
        "Use provided ACL/BloodHound context if available. "
        "If pathing data is missing, request BloodHound analysis from recon/orchestrator. "
        "Execute any viable ACL abuse attacks. Report the result using task_complete."
    ),
    MessageType.CREDENTIAL_ACCESS_REQUEST: lambda msg: (
        "Perform credential access against the target environment:\n"
        f"Domain: {msg.domain}\n"
        f"Targets: {', '.join(msg.target_ips) if msg.target_ips else 'N/A'}\n"
        f"Username: {msg.username or 'N/A'}\n"
        f"Credential ({'password' if msg.password else 'hash' if msg.hash_value else 'none'}): "
        f"{msg.password or msg.hash_value or 'N/A'}\n"
        f"Techniques: {', '.join(msg.techniques) if msg.techniques else 'auto-select'}\n"
        f"Task ID: {msg.task_id}\n\n"
        "Use the exact credential value above; do not substitute placeholders. "
        "Prioritize GetNPUsers/AS-REP roast, Kerberoast, secretsdump, and LSASS "
        "if credentials allow. Report any hashes or credentials using task_complete."
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
    MessageType.COERCION_REQUEST: lambda msg: (
        f"Start network coercion:\n"
        f"Interface: {msg.interface}\n"
        f"Techniques: {', '.join(msg.techniques)}\n"
        f"Duration: {msg.duration}s\n"
        f"Task ID: {msg.task_id}\n\n"
        "Start responder/mitm6 and capture any hashes. "
        "Report captured credentials using task_complete."
    ),
}


def generate_prompt_from_task(  # noqa: PLR0912
    task: TaskMessage,
    state: SharedRedTeamState | None = None,
) -> str | None:
    """
    Generate agent prompt from Redis TaskMessage.

    This is used when polling tasks from Redis queue instead of dispatcher.

    Args:
        task: TaskMessage from Redis queue
        state: Optional shared state to include context about all discovered
               credentials, hosts, hashes, and vulnerabilities

    Returns:
        Prompt string for the agent
    """
    payload = task.payload

    if task.task_type == "crack":
        # Crack tasks don't need state context - they're deterministic
        return (
            f"Crack this hash for user {payload.get('username', 'unknown')}"
            f"@{payload.get('domain', '')}:\n"
            f"Hash: {payload['hash_value']}\n"
            f"Type: {payload['hash_type']}\n"
            f"Wordlist: {payload.get('wordlist', 'rockyou.txt')}\n"
            f"Task ID: {task.task_id}\n\n"
            "Use hashcat or john to crack. "
            "When cracked, call report_cracked_credential(task_id, username, password, hash, domain). "
            "If cracking fails, call report_crack_failed(task_id, hash, reason)."
        )

    if task.task_type == "lateral":
        cred_type = "password" if payload.get("password") else "hash"
        cred_value = payload.get("password") or payload.get("hash_value") or "N/A"
        target_host = payload.get("target_host", "")
        base_prompt = (
            f"Perform lateral movement to {target_host}:\n"
            f"Username: {payload.get('domain', '')}\\{payload['username']}\n"
            f"Credential ({cred_type}): {cred_value}\n"
            f"Method: {payload.get('method') or 'auto-select'}\n"
            f"Task ID: {task.task_id}\n\n"
            "Use the exact credential value above; do not substitute placeholders. "
            "Try psexec, then wmiexec or evil-winrm if needed. "
            "If access succeeds, run secretsdump to harvest credentials. "
            "Call report_lateral_success(task_id, target, method, new_credentials, new_hashes) "
            "with any credentials/hashes found as JSON. "
            "If access fails, call report_lateral_failed(task_id, target, reason)."
        )
        state_context = format_state_context(state, "lateral", current_target=target_host)
        return base_prompt + state_context

    if task.task_type == "acl_analysis":
        base_prompt = (
            f"Analyze ACLs and find attack paths:\n"
            f"Target User: {payload['target_user']}\n"
            f"Domain: {payload['domain']}\n"
            f"Find Path To: {payload.get('find_path_to', 'Domain Admins')}\n"
            f"Task ID: {task.task_id}\n\n"
            "Use provided ACL/BloodHound context if available. "
            "If pathing data is missing, request BloodHound analysis from recon/orchestrator. "
            "Execute viable ACL abuse attacks (shadow credentials, targeted kerberoast, "
            "ForceChangePassword, WriteDACL, etc.)."
        )
        state_context = format_state_context(state, "acl_analysis")
        return base_prompt + state_context

    if task.task_type == "credential_access":
        hash_value = payload.get("hash_value")
        hash_is_pth = _is_pass_the_hash_compatible(hash_value)
        techniques = payload.get("techniques", []) or []
        if hash_value and not hash_is_pth:
            techniques = [
                technique
                for technique in techniques
                if technique.lower() not in {"secretsdump", "lsassy"}
            ]
        cred_type = (
            "password"
            if payload.get("password")
            else "hash"
            if payload.get("hash_value")
            else "none"
        )
        targets = payload.get("target_ips") or []
        dc_ip = payload.get("dc_ip") or ""
        reason = payload.get("reason") or ""
        source = payload.get("credential_source") or ""
        hash_type = payload.get("hash_type") or ""
        reason_line = f"Reason: {reason}\n" if reason else ""
        source_line = f"Credential Source: {source}\n" if source else ""
        hash_type_line = f"Hash Type: {hash_type}\n" if hash_type else ""
        hash_note = ""
        if hash_value and not hash_is_pth:
            cred_type = "hash (non-NTLM)"
            hash_note = (
                "NOTE: Provided hash is not NTLM pass-the-hash compatible; "
                "do not attempt secretsdump/lsassy with it.\n"
            )
        # Check if this is a low_hanging_fruit task
        has_sysvol = any(t in techniques for t in ("sysvol_script_search", "gpp_password_finder"))
        has_spray = any(t in techniques for t in ("username_as_password", "password_spray"))
        has_low_hanging = "low_hanging_fruit" in reason.lower() or has_sysvol or has_spray

        if has_low_hanging and payload.get("password"):
            # Low hanging fruit with creds - prioritize SYSVOL/GPP
            base_prompt = (
                "Perform LOW HANGING FRUIT credential harvesting:\n"
                f"Domain: {payload.get('domain', '')}\n"
                f"DC IP: {dc_ip or 'N/A'}\n"
                f"Username: {payload.get('username') or 'N/A'}\n"
                f"Password: {payload.get('password')}\n"
                f"Task ID: {task.task_id}\n\n"
                "**EXECUTE IN THIS ORDER:**\n"
                "1. gpp_password_finder(target=DC_IP, username=USER, password=PASS, domain=DOMAIN)\n"
                "2. sysvol_script_search(target=DC_IP, username=USER, password=PASS, domain=DOMAIN)\n"
                "3. ldap_search_descriptions(...) - check for passwords in LDAP descriptions\n"
                "4. username_as_password(...) - check for user=password accounts\n\n"
                "These are HIGH SUCCESS RATE techniques that find hardcoded credentials.\n"
                "Report any credentials found immediately."
            )
            state_context = format_state_context(state, "credential_access", current_target=dc_ip)
            return base_prompt + state_context

        # Specific username_as_password task (for new users without creds)
        is_username_spray = "username_as_password" in techniques and "new_users" in reason.lower()
        if is_username_spray:
            username = payload.get("username") or ""
            password = payload.get("password") or ""
            cred_line = ""
            if username and password:
                cred_line = (
                    f"**Use these credentials for user enumeration:**\n"
                    f"Username: {username}\n"
                    f"Password: {password}\n\n"
                )
            base_prompt = (
                "Perform USERNAME_AS_PASSWORD spray to find weak credentials:\n"
                f"Domain: {payload.get('domain', '')}\n"
                f"DC IP: {dc_ip or 'N/A'}\n"
                f"Task ID: {task.task_id}\n\n"
                f"{cred_line}"
                "**EXECUTE username_as_password:**\n"
                f"1. First save users: save_users_to_file(target='{dc_ip}', username='{username}', password='{password}', domain='{payload.get('domain', '')}')\n"
                f"2. Then spray: username_as_password(target='{dc_ip}', domain='{payload.get('domain', '')}', users_file='/tmp/users.txt')\n\n"
                "This tests if users have username=password (e.g., hodor:hodor).\n"
                "Zero lockout risk, one attempt per user.\n"
                "Report any credentials found immediately."
            )
            state_context = format_state_context(state, "credential_access", current_target=dc_ip)
            return base_prompt + state_context

        # Share spider task - search SMB shares for credentials
        is_share_spider = "share_spider" in techniques
        if is_share_spider and payload.get("password"):
            username = payload.get("username") or ""
            password = payload.get("password") or ""
            domain = payload.get("domain") or ""
            target_ip = targets[0] if targets else ""
            # Extract share name from reason if present (auto_share_spider_SHARENAME)
            share_name = ""
            if "auto_share_spider_" in reason.lower():
                share_name = reason.lower().split("auto_share_spider_")[-1]

            base_prompt = (
                "**SHARE SPIDER TASK - Search SMB shares for credentials**\n\n"
                f"Target: {target_ip}\n"
                f"Domain: {domain}\n"
                f"Username: {username}\n"
                f"Password: {password}\n"
                f"Share hint: {share_name or 'enumerate all readable shares'}\n"
                f"Task ID: {task.task_id}\n\n"
                "**INSTRUCTIONS:**\n"
                f"1. Use smbclient_spider(target='{target_ip}', share='{share_name or 'all'}', "
                f"username='{username}', password='{password}', domain='{domain}')\n"
                "2. Look for interesting files containing credentials:\n"
                "   - *.txt files (passwords, connection strings)\n"
                "   - *.xml, *.ini, *.config files (configuration with creds)\n"
                "   - *.ps1, *.bat, *.cmd files (scripts with hardcoded passwords)\n"
                "3. If files are found, use smb_download_file to retrieve them\n"
                "4. Parse downloaded files for credentials\n\n"
                "**COMMON FINDINGS:**\n"
                "- Service account passwords in config files\n"
                "- Database connection strings with credentials\n"
                "- Admin passwords in deployment scripts\n"
                "- User credentials in text files (e.g., secret.txt)\n\n"
                "Report any credentials found immediately!"
            )
            state_context = format_state_context(
                state, "credential_access", current_target=target_ip
            )
            return base_prompt + state_context

        # Low hanging fruit WITHOUT credentials - use anonymous/null session techniques
        if has_low_hanging and not payload.get("password") and not payload.get("hash_value"):
            base_prompt = (
                "Perform LOW HANGING FRUIT credential discovery (NO CREDENTIALS):\n"
                f"Domain: {payload.get('domain', '')}\n"
                f"DC IP: {dc_ip or 'N/A'}\n"
                f"Task ID: {task.task_id}\n\n"
                "**CRITICAL: These techniques work WITHOUT credentials to discover passwords:**\n"
                "1. username_as_password(target=DC_IP, domain=DOMAIN) - HIGH SUCCESS RATE\n"
                "   Tests if users have username=password (e.g., hodor:hodor)\n"
                "   Zero lockout risk, one attempt per user\n\n"
                "2. password_spray(target=DC_IP, domain=DOMAIN, password='Password1')  # pragma: allowlist secret\n"
                "   Try common passwords: Password1, Welcome1, Summer2024, Winter2024, Company123\n\n"
                "3. password_policy(target=DC_IP, domain=DOMAIN) - Check lockout before spraying\n\n"
                "These are the FIRST techniques to run when you have no credentials.\n"
                "Report any credentials found immediately."
            )
            state_context = format_state_context(state, "credential_access", current_target=dc_ip)
            return base_prompt + state_context

        base_prompt = (
            "Perform credential access against the target environment:\n"
            f"Domain: {payload.get('domain', '')}\n"
            f"Targets: {', '.join(targets) if targets else 'N/A'}\n"
            f"DC IP: {dc_ip or 'N/A'}\n"
            f"Username: {payload.get('username') or 'N/A'}\n"
            f"Credential ({cred_type}): {payload.get('password') or payload.get('hash_value') or 'N/A'}\n"
            f"{hash_type_line}"
            f"{source_line}"
            f"{reason_line}"
            f"Techniques: {', '.join(techniques) or 'auto-select'}\n"
            f"Task ID: {task.task_id}\n\n"
            f"{hash_note}"
            "Use the exact credential value above; do not substitute placeholders. "
            "If DC IP is provided, pass -dc-ip to Kerberos/LDAP tools to avoid DNS issues. "
            "**PRIORITY ORDER when creds available:**\n"
            "1. gpp_password_finder + sysvol_script_search (LOW HANGING FRUIT - run first!)\n"
            "2. Kerberoast for service account hashes\n"
            "3. secretsdump if admin access exists\n"
            "4. LSASS dumping if viable\n"
            "Report any hashes or credentials found."
        )
        state_context = format_state_context(state, "credential_access", current_target=dc_ip)
        return base_prompt + state_context

    if task.task_type == "exploit":
        vuln_type = payload.get("vuln_type", "")
        target = payload.get("target", "")
        base_prompt = (
            f"Exploit vulnerability:\n"
            f"Type: {vuln_type}\n"
            f"Target: {target}\n"
            f"Vuln ID: {payload.get('vuln_id', 'unknown')}\n"
            f"Params: {payload}\n"
            f"Task ID: {task.task_id}\n\n"
        )

        # Special handling for ADCS enumeration
        if vuln_type == "adcs_enumerate":
            domain = payload.get("domain", "")
            dc_ip = payload.get("dc_ip", target)
            username = payload.get("username", "")
            password = payload.get("password", "")

            adcs_prompt = (
                f"**ADCS ENUMERATION TASK**\n\n"
                f"Target CA Server: {target}\n"
                f"Domain: {domain}\n"
                f"DC IP: {dc_ip}\n"
                f"Credentials: {domain}\\{username}\n"
                f"Task ID: {task.task_id}\n\n"
                "**INSTRUCTIONS:**\n"
                "1. Run certipy_find to enumerate ADCS vulnerabilities:\n"
                f"   certipy_find(domain='{domain}', username='{username}', "
                f"password='{password}', dc_ip='{dc_ip}')\n\n"
                "2. Look for ESC1-ESC15 vulnerabilities in the output\n"
                "3. Report any vulnerable templates found\n"
                "4. If ESC1/ESC4 found: can request cert with arbitrary UPN\n"
                "5. If ESC8 found: web enrollment relay attack possible\n\n"
                "**CRITICAL**: Run certipy_find FIRST before any exploitation!\n"
                "Report discovered vulnerabilities so they can be queued for exploitation."
            )
            state_context = format_state_context(state, "exploit", current_target=target)
            return adcs_prompt + state_context

        # Special handling for MSSQL vulnerabilities
        if vuln_type.startswith("mssql_"):
            available_creds = payload.get("available_credentials", [])
            creds_section = ""
            if available_creds:
                creds_section = "\n**AVAILABLE SQL CREDENTIALS (use these!):**\n"
                for cred in available_creds:
                    is_sql = cred.get("is_sql_account", "False") == "True"
                    marker = " [SQL SERVICE ACCOUNT]" if is_sql else ""
                    creds_section += (
                        f"- {cred.get('domain', '')}\\{cred.get('username', '')}: "
                        f"{cred.get('password', '')}{marker}\n"
                    )

            mssql_prompt = (
                base_prompt + "**MSSQL EXPLOITATION WORKFLOW:**\n"
                "1. Use mssql_enum_linked_servers() to find linked servers\n"
                "2. Check for impersonation: EXECUTE AS LOGIN / EXECUTE AS USER\n"
                "3. If impersonation available, use mssql_impersonate() to escalate to 'sa'\n"
                "4. If linked servers exist, use mssql_exec_linked() to pivot cross-domain\n"
                "5. Enable xp_cmdshell if sysadmin and get code execution\n"
                + creds_section
                + "\nTry EACH credential against the target - SQL accepts Windows auth.\n"
                "Report credentials obtained.\n"
                "If you obtain credentials or hashes, include a JSON block:\n"
                "```json\n"
                '{"credential": {"username": "", "password": "", "domain": "", "is_admin": false}}\n'
                "```"
            )
            state_context = format_state_context(state, "exploit", current_target=target)
            return mssql_prompt + state_context

        # Default exploit prompt
        default_prompt = (
            base_prompt + "Execute the exploitation technique. Report credentials obtained.\n"
            "If you obtain credentials or hashes, include a JSON block:\n"
            "```json\n"
            '{"credential": {"username": "", "password": "", "domain": "", "is_admin": false}}\n'
            "```\n"
            "or\n"
            "```json\n"
            '{"hash": {"username": "", "hash_value": "", "hash_type": "NTLM", "domain": ""}}\n'
            "```"
        )
        state_context = format_state_context(state, "exploit", current_target=target)
        return default_prompt + state_context

    if task.task_type == "coercion":
        techniques = payload.get("techniques", ["LLMNR", "NBT-NS"])
        base_prompt = (
            f"Start network coercion:\n"
            f"Interface: {payload.get('interface', 'eth0')}\n"
            f"Techniques: {', '.join(techniques)}\n"
            f"Duration: {payload.get('duration', 300)}s\n"
            f"Task ID: {task.task_id}\n\n"
            "Start responder/mitm6 and capture hashes. "
            "For ESC8 relay attacks, coordinate PetitPotam against DCs."
        )
        state_context = format_state_context(state, "coercion")
        return base_prompt + state_context

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
            await self._refresh_shared_state()
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
                )
                return

            # Run agent
            logger.info(f"[{self.agent_name}] Running agent for task {task.task_id}")
            result = await self._run_agent(prompt)
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
                    result=fatal_result if fatal_result else None,
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
            # Preserve any discoveries made before the exception
            exception_result = self._serialize_state_discoveries()
            await self.task_queue.send_result(
                task_id=task.task_id,
                success=False,
                result=exception_result if exception_result else None,
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

    async def _refresh_shared_state(self) -> None:
        if not self.redis_url or not self.operation_id:
            return
        try:
            if self._state_refresh_client is None:
                self._state_refresh_client = await create_redis_client(
                    self.redis_url, decode_responses=False
                )
            key = f"ares:operation:{self.operation_id}:state"
            data = await self._state_refresh_client.get(key)
            if not data:
                return
            fresh = SharedRedTeamState.from_bytes(data)
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

        current = self.shared_state
        for attr in (
            "operation_id",
            "target",
            "started_at",
            "all_domains",
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
        ):
            setattr(current, attr, getattr(fresh, attr))

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
            current.add_user(user.username, user.domain)

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

    async def _execute_crack_task(self, task: TaskMessage) -> None:
        payload = task.payload or {}
        hash_value = payload.get("hash_value", "")
        hash_type = (payload.get("hash_type") or "").upper()
        username = payload.get("username", "")
        domain = payload.get("domain", "")
        wordlist_path = self._resolve_wordlist_path(
            payload.get("wordlist") or "/usr/share/wordlists/rockyou.txt"
        )

        if not hash_value:
            await self.task_queue.send_result(
                task_id=task.task_id,
                success=False,
                error="Missing hash_value in crack task payload",
                worker_pod=self.pod_name,
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
            )
            return

        await self.task_queue.send_result(
            task_id=task.task_id,
            success=False,
            result=result_payload,
            error="Cracking failed: no password found",
            worker_pod=self.pod_name,
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
            logger.info(
                "[%s] Decompressed wordlist %s to %s", self.agent_name, gz_path, tmp_wordlist
            )
            return tmp_wordlist
        except Exception as exc:
            logger.warning(
                "[%s] Failed to decompress wordlist %s: %s", self.agent_name, gz_path, exc
            )
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
                        # Mark queue as disconnected to force reconnection
                        if heartbeat_queue:
                            heartbeat_queue._connected = False
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

    def _threaded_state_subscriber_loop(self) -> None:  # noqa: PLR0912
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

                except Exception as e:  # noqa: PERF203
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
                        # Mark as disconnected to force reconnection
                        if subscriber_queue:
                            subscriber_queue._connected = False
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
            key = f"ares:operation:{self.operation_id}:state"
            data = await redis_client.get(key)
            if not data:
                return
            fresh = SharedRedTeamState.from_bytes(data)
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
        role: The agent role (credential_access, cracker, acl, privesc, lateral, coercion).
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
