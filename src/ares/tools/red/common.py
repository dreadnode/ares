"""Common utilities and helper functions for Red Team tools.

This module contains shared helper functions, type aliases, and constants
used across all red team toolset modules.
"""

import logging
import os
import re
import shlex
import socket
import uuid
from typing import ClassVar

from ares.core.models import Credential, RedTeamState, SharedRedTeamState
from ares.core.remote import run_remote

# Type alias for state that works with both single-agent and multi-agent modes
AnyRedTeamState = RedTeamState | SharedRedTeamState

logger = logging.getLogger(__name__)

# Shared placeholder passwords used across multiple toolsets
PLACEHOLDER_PASSWORDS: ClassVar[set[str]] = {"password", "changeme", "<password>"}


def format_weakness_block(
    title: str,
    vulnerability: str,
    details: dict[str, str] | None = None,
    impact: str | None = None,
    discovery_method: str | None = None,
) -> str:
    """Format a markdown block describing a discovered weakness."""
    lines: list[str] = []
    if title:
        lines.append(f"### {title}")
    if vulnerability:
        lines.append(f"**Vulnerability:** {vulnerability}")
    if details:
        for label, value in details.items():
            if value:
                lines.append(f"- **{label}:** {value}")
    if discovery_method:
        lines.append(f"- **Discovery Method:** {discovery_method}")
    if impact:
        lines.append(f"- **Impact:** {impact}")
    return "\n".join(lines)


def track_cross_domain_reuse(state: AnyRedTeamState, credential: Credential) -> None:
    """Track credential reuse across domains and record as weakness."""
    if not state or not credential.domain:
        return
    same_creds = [
        c
        for c in state.credentials
        if c.username == credential.username and c.password == credential.password and c.domain
    ]
    domains = sorted({c.domain for c in same_creds})
    if len(domains) < 2:
        return
    has_admin = any(c.is_admin for c in same_creds)
    impact = (
        "Single credential grants admin access to multiple domains"
        if has_admin
        else "Single credential grants access to multiple domains"
    )
    block = format_weakness_block(
        "Credential Discovery - Cross-Domain Password Reuse",
        "Identical passwords used across trusted domains",
        {
            "Affected Account": credential.username,
            "Domains": ", ".join(domains),
        },
        impact,
        "Credential correlation",
    )
    if block not in state.weaknesses:
        state.weaknesses.append(block)


def is_ntlm_hash(value: str) -> bool:
    """Check if a string appears to be an NTLM hash."""
    if not value:
        return False
    normalized = value.strip()
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


def resolve_recon_route(cmd: list[str], target_role: str | None = None) -> str | None:
    """Route netexec/ldapsearch calls to recon when not running there."""
    if target_role:
        return target_role
    local_role = os.environ.get("ARES_ROLE", "").strip().lower()
    if local_role == "recon":
        return target_role
    if not cmd:
        return target_role
    base = cmd[0]
    if base in {"netexec", "ldapsearch"}:
        return "recon"
    if base in {"bash", "sh"} and len(cmd) >= 3 and cmd[1] in {"-c", "-lc"}:
        script = cmd[2]
        if re.search(r"\b(netexec|ldapsearch)\b", script):
            return "recon"
    return target_role


def run_tool(
    cmd: list[str],
    timeout_seconds: int = 300,
    target_role: str | None = None,
) -> tuple[str, str, int]:
    """Execute a command on the remote Kali attack box.

    Args:
        cmd: Command as list of arguments
        timeout_seconds: Maximum execution time
        target_role: Optional role to route command to

    Returns:
        Tuple of (stdout, stderr, return_code)
    """
    resolved_role = resolve_recon_route(cmd, target_role)
    result = run_remote(cmd, timeout_seconds=timeout_seconds, target_role=resolved_role)
    return result.stdout, result.stderr, result.return_code


def infer_listener_ip(target: str | None = None) -> str | None:
    """Infer a listener IP reachable from the target network."""
    for key in ("ARES_ESC8_LISTENER", "ARES_RELAY_LISTENER", "ARES_LISTENER_IP", "POD_IP"):
        value = os.getenv(key)
        if value:
            return value

    if not target:
        return None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.connect((target, 88))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return None


def write_users_file_remote(users: list[str], users_file: str) -> tuple[bool, str]:
    """Write a list of users to a file on the remote system."""
    if not users:
        return False, "no users provided"
    escaped_users = " ".join(shlex.quote(user) for user in users)
    cmd = f"printf '%s\\n' {escaped_users} > {shlex.quote(users_file)}"
    result = run_remote(["bash", "-lc", cmd], timeout_seconds=60)
    if result.return_code != 0:
        error = (result.stderr or result.stdout or "unknown error").strip()
        return False, error
    return True, ""


def remote_file_exists(path: str) -> tuple[bool, str]:
    """Check if a file exists and is non-empty on the remote system."""
    cmd = f"test -s {shlex.quote(path)}"
    result = run_remote(["bash", "-lc", cmd], timeout_seconds=30)
    if result.return_code == 0:
        return True, ""
    error = (result.stderr or result.stdout or "file not found").strip()
    return False, error


def find_remote_users_file(paths: list[str]) -> str | None:
    """Find the first existing users file from a list of paths."""
    for path in paths:
        ok, _ = remote_file_exists(path)
        if ok:
            return path
    return None


def sanitize_hostname(hostname: str) -> str:
    """Clean and sanitize a hostname string."""
    cleaned = hostname.strip()
    if not cleaned:
        return cleaned
    lowered = cleaned.lower()
    if lowered.startswith("ip-") and "compute.internal" in lowered:
        return ""
    return cleaned


def filter_users_file_remote(
    users_file: str,
    exclude_users: set[str],
) -> tuple[str, str | None]:
    """Filter a remote users file to exclude certain usernames."""
    if not exclude_users:
        return users_file, None
    result = run_remote(["bash", "-lc", f"cat {shlex.quote(users_file)}"], timeout_seconds=60)
    if result.return_code != 0:
        error = (result.stderr or result.stdout or "failed to read users file").strip()
        return users_file, error
    users: list[str] = []
    seen: set[str] = set()
    for line in (result.stdout or "").splitlines():
        user = line.strip()
        if not user:
            continue
        if user.lower() in exclude_users:
            continue
        if user.lower() in seen:
            continue
        users.append(user)
        seen.add(user.lower())
    if not users:
        return "", "all users already have credentials"
    filtered_file = f"/tmp/users_spray_filtered_{uuid.uuid4().hex}.txt"  # nosec B108  # noqa: S108
    ok, error = write_users_file_remote(users, filtered_file)
    if not ok:
        return users_file, error or "failed to write filtered users file"
    return filtered_file, None


def resolve_password(
    state: AnyRedTeamState | None,
    username: str,
    domain: str | None,
    password: str | None,
) -> str | None:
    """Resolve a placeholder password from shared state.

    If the password is a placeholder like 'password' or 'changeme',
    attempts to find the actual password for the user from state.
    """
    if not password:
        return password
    normalized = password.strip().lower()
    if normalized not in PLACEHOLDER_PASSWORDS:
        return password
    if not state:
        return password
    credentials = getattr(state, "all_credentials", None)
    if credentials is None:
        credentials = getattr(state, "credentials", [])
    username_key = username.strip().lower()
    domain_key = (domain or "").strip().lower()
    for cred in credentials:
        if cred.username.strip().lower() != username_key:
            continue
        if domain_key and cred.domain.strip().lower() != domain_key:
            continue
        if cred.password:
            logger.info(
                "Replaced placeholder password for %s\\%s from shared state",
                cred.domain or domain,
                cred.username,
            )
            return cred.password
    return password


def resolve_host_or_ip(state: AnyRedTeamState | None, host: str) -> str:
    """Resolve a hostname to IP using state host list if needed."""
    if not host:
        return host
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        return host
    try:
        socket.gethostbyname(host)
        return host
    except Exception:
        pass
    if state:
        for entry in state.hosts:
            if entry.hostname and entry.hostname.lower() == host.lower() and entry.ip:
                return entry.ip
    return host


def check_port(target: str, port: int, timeout_seconds: int = 5) -> bool:
    """Check if a port is reachable on a target."""
    cmd = ["nc", "-zv", "-w", str(timeout_seconds), target, str(port)]
    try:
        ssm_timeout = max(30, timeout_seconds + 5)
        _stdout, _stderr, returncode = run_tool(cmd, timeout_seconds=ssm_timeout)
        return returncode == 0
    except Exception:
        return False


def add_credential_to_state(
    state: AnyRedTeamState | None,
    cred: Credential,
    source_role: str = "recon",
    dispatcher=None,
) -> None:
    """Add a credential to state, handling both single and shared state types."""
    if not state or not cred.username:
        return
    if hasattr(state, "add_credential"):
        state.add_credential(cred, source_role)
        if dispatcher:
            dispatcher.signal_credential_access()
        return
    existing = any(
        c.username == cred.username and c.password == cred.password and c.domain == cred.domain
        for c in state.credentials
    )
    if existing:
        return
    state.credentials.append(cred)
    cred_key = state.get_credential_key(cred.username, cred.password, cred.domain)
    state.tested_credentials.add(cred_key)
    track_cross_domain_reuse(state, cred)
    if dispatcher:
        dispatcher.signal_credential_access()


def add_weakness_to_state(state: AnyRedTeamState | None, block: str) -> None:
    """Add a weakness block to state if not already present."""
    if not state or not block:
        return
    if block not in state.weaknesses:
        state.weaknesses.append(block)
