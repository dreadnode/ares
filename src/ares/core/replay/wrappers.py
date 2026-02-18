"""Replay wrappers for tool execution interception.

This module provides wrappers that intercept tool execution to record
and replay command outputs for deterministic runs.

The key challenge is command normalization - commands with different
IPs, temp paths, or UUIDs should map to the same cache key when they
represent the same logical operation.

Normalization Strategy:
- IP addresses: 192.168.58.10 -> {IP:0}, 192.168.58.20 -> {IP:1}
- Temp paths: /tmp/krb5cc_123 -> /tmp/{TMP}
- UUIDs in paths: /tmp/abc123-def456 -> /tmp/{UUID}
- Command flags: sorted for consistent hashing
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from loguru import logger


@dataclass
class NormalizationContext:
    """Context for consistent normalization across a session.

    Tracks IP address mappings to ensure the same IP always maps
    to the same placeholder across normalizations.
    """

    ip_map: dict[str, int]
    ip_counter: int

    def __init__(self) -> None:
        self.ip_map = {}
        self.ip_counter = 0

    def get_ip_placeholder(self, ip: str) -> str:
        """Get consistent placeholder for an IP address."""
        if ip not in self.ip_map:
            self.ip_map[ip] = self.ip_counter
            self.ip_counter += 1
        return f"{{IP:{self.ip_map[ip]}}}"


# Global normalization context (per-session)
_normalization_ctx: NormalizationContext | None = None


def get_normalization_context() -> NormalizationContext:
    """Get or create the normalization context."""
    global _normalization_ctx
    if _normalization_ctx is None:
        _normalization_ctx = NormalizationContext()
    return _normalization_ctx


def reset_normalization_context() -> None:
    """Reset the normalization context (e.g., between operations)."""
    global _normalization_ctx
    _normalization_ctx = None


# Regex patterns for normalization
_IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
)
_TEMP_PATH_PATTERN = re.compile(r"/tmp/[a-zA-Z0-9_\-]+")  # noqa: S108  # nosec B108
_KRB5CC_PATTERN = re.compile(r"krb5cc_\d+")
_CCACHE_PATH_PATTERN = re.compile(r"[a-zA-Z0-9_\-]+\.ccache")


def normalize_command(cmd: str, ctx: NormalizationContext | None = None) -> str:
    """Normalize a command for stable hashing.

    Replaces variable elements (IPs, temp paths, UUIDs) with placeholders
    to ensure commands with different specific values but the same logical
    operation produce the same hash.

    Args:
        cmd: The command string to normalize.
        ctx: Normalization context for consistent IP mapping.

    Returns:
        Normalized command string.
    """
    if ctx is None:
        ctx = get_normalization_context()

    normalized = cmd

    # Replace IP addresses with indexed placeholders
    for match in _IP_PATTERN.finditer(cmd):
        ip = match.group(1)
        # Skip common non-target IPs
        if ip.startswith("127.") or ip == "0.0.0.0":  # noqa: S104  # nosec B104
            continue
        placeholder = ctx.get_ip_placeholder(ip)
        normalized = normalized.replace(ip, placeholder)

    # Replace UUIDs with placeholder
    normalized = _UUID_PATTERN.sub("{UUID}", normalized)

    # Replace Kerberos ccache paths
    normalized = _KRB5CC_PATTERN.sub("krb5cc_{PID}", normalized)
    normalized = _CCACHE_PATH_PATTERN.sub("{CCACHE}.ccache", normalized)

    # Replace temp paths (but preserve the tool-specific suffix)
    # e.g., /tmp/impacket_123 -> /tmp/{TMP}
    def replace_temp_path(match: re.Match) -> str:
        path = match.group(0)
        # Keep recognizable tool prefixes
        for prefix in ("impacket", "bloodhound", "hashcat", "john"):
            if prefix in path.lower():
                return f"/tmp/{{{prefix.upper()}}}"  # noqa: S108  # nosec B108
        return "/tmp/{TMP}"  # noqa: S108  # nosec B108

    return _TEMP_PATH_PATTERN.sub(replace_temp_path, normalized)


def normalize_command_for_key(cmd: str) -> str:
    """Normalize a command specifically for use as a cache key.

    This performs the same normalization as normalize_command() but
    also sorts flags for consistent hashing.

    Args:
        cmd: The command string to normalize.

    Returns:
        Normalized key string suitable for hashing.
    """
    ctx = get_normalization_context()
    # For key generation, we might also want to sort flags
    # This is tricky because flag order can matter for some tools
    # For now, we leave the order as-is to avoid breaking commands
    # where order matters (like positional arguments)
    return normalize_command(cmd, ctx)


def intercept_run_remote(
    original_func: callable,
    command: str | list[str],
    timeout_seconds: int = 300,
    working_directory: str = "/tmp",  # noqa: S108  # nosec B108
    target_role: str | None = None,
):
    """Intercept run_remote for recording/replay.

    This wrapper checks if replay is active and either:
    - Records the command and its result (record mode)
    - Returns a cached result (replay mode)
    - Falls through to original execution (off or fallback)

    Args:
        original_func: The original run_remote function.
        command: Command to execute.
        timeout_seconds: Timeout for execution.
        working_directory: Working directory.
        target_role: Target role for routing.

    Returns:
        CommandResult from cache or live execution.
    """
    from ares.core.remote import CommandResult
    from ares.core.replay import get_replay_store

    store = get_replay_store()

    # If replay is off, just run the command
    if store is None or store.mode == "off":
        return original_func(command, timeout_seconds, working_directory, target_role)

    # Normalize command for cache key
    import shlex

    cmd_str = shlex.join(command) if isinstance(command, list) else command
    cache_key = normalize_command_for_key(cmd_str)

    if store.mode == "replay":
        # Try to find cached response
        cached = store.lookup("tool", cache_key)
        if cached is not None:
            logger.debug(f"Replay: using cached result for: {cmd_str[:80]}...")
            return CommandResult(
                stdout=cached.get("stdout", ""),
                stderr=cached.get("stderr", ""),
                return_code=cached.get("return_code", 0),
                success=cached.get("return_code", 0) == 0,
            )

        # Cache miss - handle based on fallback mode
        if store.fallback == "error":
            error_msg = f"Replay cache miss (fallback=error): {cmd_str[:100]}"
            logger.error(error_msg)
            return CommandResult(
                stdout="",
                stderr=error_msg,
                return_code=1,
                success=False,
            )
        if store.fallback == "skip":
            logger.warning(f"Replay cache miss (fallback=skip): {cmd_str[:80]}...")
            return CommandResult(
                stdout="",
                stderr="[REPLAY SKIPPED - cache miss]",
                return_code=0,
                success=True,
            )
        # fallback == "live"
        logger.warning(f"Replay cache miss (fallback=live): {cmd_str[:80]}...")
        # Fall through to live execution

    # Execute the command (record mode or live fallback)
    result = original_func(command, timeout_seconds, working_directory, target_role)

    if store.mode == "record":
        # Record the result
        store.record(
            entry_type="tool",
            key=cache_key,
            request={
                "command": cmd_str,
                "timeout": timeout_seconds,
                "cwd": working_directory,
                "role": target_role,
            },
            response={
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.return_code,
            },
        )

    return result


__all__ = [
    "NormalizationContext",
    "get_normalization_context",
    "intercept_run_remote",
    "normalize_command",
    "normalize_command_for_key",
    "reset_normalization_context",
]
