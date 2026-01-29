"""Common utilities and helper functions for Red Team tools.

This module contains shared helper functions, type aliases, and constants
used across all red team toolset modules.
"""

import logging
import os
import re
import shlex
import socket
import tempfile
import uuid
from typing import ClassVar

from ares.core.models import Credential, RedTeamState, SharedRedTeamState
from ares.core.remote import run_remote

# Type alias for state that works with both single-agent and multi-agent modes
AnyRedTeamState = RedTeamState | SharedRedTeamState

logger = logging.getLogger(__name__)

# Shared placeholder passwords used across multiple toolsets
PLACEHOLDER_PASSWORDS: ClassVar[set[str]] = {"password", "changeme", "<password>"}

# Characters that indicate Kali MOTD pollution (box-drawing characters)
# These appear when bash outputs the Kali "minimal installation" message
MOTD_GARBAGE_CHARS: frozenset[str] = frozenset("┏┃┗┓┛━─│┌┐└┘├┤┬┴┼╔╗╚╝║═")

# Patterns that indicate MOTD or system messages, not valid usernames
TEMP_USERS_PATTERN = f"{tempfile.gettempdir().rstrip(os.sep)}{os.sep}users".lower()

MOTD_GARBAGE_PATTERNS: tuple[str, ...] = (
    "message from kali",
    "minimal installation",
    "kali.org",
    "hushlogin",
    "supplementary tools",
    "learn how",
    TEMP_USERS_PATTERN,  # File path leaking as username
    ".txt",  # File extension leaking
)


def is_motd_line(line: str) -> bool:
    """Check if a line appears to be Kali MOTD garbage (for line-level filtering).

    This is a less strict check than is_motd_garbage(), used for filtering
    whole output lines before extracting usernames from them.

    Args:
        line: Line of output to check

    Returns:
        True if the line appears to be MOTD garbage, False otherwise
    """
    if not line:
        return False  # Empty lines are not garbage, just empty

    stripped = line.strip()
    if not stripped:
        return False

    # Check for box-drawing characters (Kali MOTD uses these)
    if any(char in MOTD_GARBAGE_CHARS for char in stripped):
        return True

    # Check for common MOTD patterns
    lower = stripped.lower()
    return any(pattern in lower for pattern in MOTD_GARBAGE_PATTERNS)


def is_motd_garbage(value: str) -> bool:
    """Check if a string appears to be Kali MOTD garbage or invalid username.

    This is a strict check used for validating extracted usernames.
    For line-level filtering, use is_motd_line() instead.

    Args:
        value: String to check (typically an extracted username)

    Returns:
        True if the value appears to be MOTD garbage, False otherwise
    """
    if not value:
        return True

    stripped = value.strip()
    if not stripped:
        return True

    # Check for box-drawing characters (Kali MOTD uses these)
    if any(char in MOTD_GARBAGE_CHARS for char in stripped):
        return True

    # Check for common MOTD patterns
    lower = stripped.lower()
    if any(pattern in lower for pattern in MOTD_GARBAGE_PATTERNS):
        return True

    # Check for non-ASCII characters (valid AD usernames are ASCII)
    try:
        stripped.encode("ascii")
    except UnicodeEncodeError:
        return True

    # Check for path-like strings
    if "/" in stripped or "\\" in stripped:
        return True

    # Valid usernames are typically alphanumeric with . _ - $
    # Reject if it has unusual characters
    return not re.match(r"^[A-Za-z0-9._$-]+$", stripped)


def filter_motd_garbage(users: list[str]) -> list[str]:
    """Filter out MOTD garbage from a list of usernames.

    Args:
        users: List of potential usernames

    Returns:
        Filtered list with MOTD garbage removed
    """
    return [u for u in users if not is_motd_garbage(u)]


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
    from ares.core.logging_utils import truncate_output

    resolved_role = resolve_recon_route(cmd, target_role)
    cmd_str = shlex.join(cmd) if isinstance(cmd, list) else cmd
    tool_name = cmd[0] if cmd else "unknown"

    logger.debug(f"Tool start: {tool_name} -> {cmd_str[:100]}")

    result = run_remote(cmd, timeout_seconds=timeout_seconds, target_role=resolved_role)

    if result.return_code != 0:
        logger.info(f"Tool {tool_name} returned {result.return_code}")
        if result.stderr:
            logger.debug(f"Tool stderr: {truncate_output(result.stderr, 300)}")

    return result.stdout, result.stderr, result.return_code


def fetch_remote_file(
    remote_path: str,
    target_role: str | None = None,
    timeout_seconds: int = 30,
) -> bytes | None:
    """Read a file from a remote pod and return its contents.

    Args:
        remote_path: Path to the file on the remote system
        target_role: Optional role to route the read to
        timeout_seconds: Timeout for the read operation

    Returns:
        File contents as bytes, or None if file doesn't exist or read failed
    """
    # Use base64 encoding to safely transfer binary content
    cmd = [
        "bash",
        "-lc",
        f"base64 -w0 {shlex.quote(remote_path)} 2>/dev/null",
    ]
    stdout, stderr, returncode = run_tool(
        cmd, timeout_seconds=timeout_seconds, target_role=target_role
    )

    if returncode != 0 or not stdout.strip():
        logger.debug(f"Failed to read remote file {remote_path}: {stderr}")
        return None

    import base64

    try:
        return base64.b64decode(stdout.strip())
    except Exception as e:
        logger.debug(f"Failed to decode remote file {remote_path}: {e}")
        return None


def store_remote_artifact(
    state: AnyRedTeamState,
    remote_path: str,
    artifact_key: str,
    target_role: str | None = None,
    source_agent: str = "",
) -> bool:
    """Fetch a file from a remote pod and store it as a shared artifact.

    This function reads a file from a remote pod (e.g., after downloading via smbclient)
    and stores it in the shared state so all agents can access it.

    Args:
        state: The shared state to store the artifact in
        remote_path: Path to the file on the remote system
        artifact_key: Key to store the artifact under (e.g., "sysvol/login.bat")
        target_role: Optional role where the file exists (same as where it was downloaded)
        source_agent: Name of the agent storing the artifact

    Returns:
        True if artifact was stored, False otherwise
    """
    if not isinstance(state, SharedRedTeamState):
        logger.debug("store_remote_artifact only works with SharedRedTeamState")
        return False

    content = fetch_remote_file(remote_path, target_role=target_role)
    if content is None:
        logger.debug(f"Could not fetch {remote_path} for artifact storage")
        return False

    return state.store_artifact(artifact_key, content, source_agent=source_agent)


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


def write_users_file_remote(
    users: list[str],
    users_file: str,
    target_role: str | None = None,
) -> tuple[bool, str]:
    """Write a list of users to a file on the remote system.

    Filters out MOTD garbage and invalid usernames before writing.

    Args:
        users: List of usernames to write
        users_file: Path to write the file
        target_role: Optional worker role to route the write to (e.g., "recon")
    """
    if not users:
        return False, "no users provided"

    # Filter out MOTD garbage and invalid usernames
    clean_users = filter_motd_garbage(users)
    if not clean_users:
        return False, "no valid users after filtering MOTD garbage"

    filtered_count = len(users) - len(clean_users)
    if filtered_count > 0:
        logger.debug(f"Filtered {filtered_count} MOTD garbage entries from users list")

    escaped_users = " ".join(shlex.quote(user) for user in clean_users)
    cmd = f"printf '%s\\n' {escaped_users} > {shlex.quote(users_file)}"
    result = run_remote(["bash", "-lc", cmd], timeout_seconds=60, target_role=target_role)
    if result.return_code != 0:
        error = (result.stderr or result.stdout or "unknown error").strip()
        return False, error
    return True, ""


def remote_file_exists(path: str, target_role: str | None = None) -> tuple[bool, str]:
    """Check if a file exists and is non-empty on the remote system.

    Args:
        path: Path to check
        target_role: Optional worker role to route the check to (e.g., "recon")
    """
    cmd = f"test -s {shlex.quote(path)}"
    result = run_remote(["bash", "-lc", cmd], timeout_seconds=30, target_role=target_role)
    if result.return_code == 0:
        return True, ""
    error = (result.stderr or result.stdout or "file not found").strip()
    return False, error


def filter_users_file_remote(
    users_file: str,
    exclude_users: set[str],
    target_role: str | None = None,
) -> tuple[str, str | None]:
    """Filter a remote users file to exclude certain usernames and MOTD garbage.

    Args:
        users_file: Path to the users file
        exclude_users: Set of usernames to exclude
        target_role: Optional worker role to route operations to (e.g., "recon")
    """
    if not exclude_users:
        # Still need to filter for MOTD garbage even with no exclude list
        exclude_users = set()
    result = run_remote(
        ["bash", "-lc", f"cat {shlex.quote(users_file)}"],
        timeout_seconds=60,
        target_role=target_role,
    )
    if result.return_code != 0:
        error = (result.stderr or result.stdout or "failed to read users file").strip()
        return users_file, error
    users: list[str] = []
    seen: set[str] = set()
    motd_filtered = 0
    excluded_count = 0
    valid_users_before_exclude = 0
    for line in (result.stdout or "").splitlines():
        user = line.strip()
        if not user:
            continue
        # Filter out MOTD garbage
        if is_motd_garbage(user):
            motd_filtered += 1
            continue
        valid_users_before_exclude += 1
        if user.lower() in exclude_users:
            excluded_count += 1
            continue
        if user.lower() in seen:
            continue
        users.append(user)
        seen.add(user.lower())

    if motd_filtered > 0:
        logger.debug(f"Filtered {motd_filtered} MOTD garbage entries from users file")

    if not users:
        # Only return "all users already have credentials" if we actually excluded users
        # and there were valid users to begin with
        if excluded_count > 0 and valid_users_before_exclude == excluded_count:
            return "", "all users already have credentials"
        # File was empty, only contained MOTD garbage, or had other issues
        # Don't skip spray - return original file and let netexec handle it
        logger.warning(
            f"Users file {users_file} yielded no users after filtering "
            f"(valid={valid_users_before_exclude}, excluded={excluded_count}, motd={motd_filtered})"
        )
        return users_file, None  # Return original file, no error - let spray proceed
    filtered_file = f"/tmp/users_spray_filtered_{uuid.uuid4().hex}.txt"  # nosec B108  # noqa: S108
    ok, error = write_users_file_remote(users, filtered_file, target_role=target_role)
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
    """Add a credential to state (real-time Redis publish handled by state.add_credential)."""
    if not state or not cred.username:
        return

    # SharedRedTeamState.add_credential() handles real-time Redis checkpoint internally
    if hasattr(state, "add_credential"):
        state.add_credential(cred, source_role)
    else:
        # Legacy single-agent state
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

    # Signal dispatcher if provided (for legacy compatibility)
    if dispatcher:
        dispatcher.signal_credential_access()


def add_weakness_to_state(state: AnyRedTeamState | None, block: str) -> None:
    """Add a weakness block to state if not already present."""
    if not state or not block:
        return
    if block not in state.weaknesses:
        state.weaknesses.append(block)


def add_host_to_state(
    state: AnyRedTeamState | None,
    host,
    source_role: str = "recon",
    dispatcher=None,
) -> None:
    """Add a host to state (real-time Redis publish handled by state.add_host)."""
    if not state or not host:
        return

    # SharedRedTeamState.add_host() handles real-time Redis checkpoint internally
    if hasattr(state, "add_host"):
        state.add_host(host)


def add_hash_to_state(
    state: AnyRedTeamState | None,
    hash_obj,
    source_role: str = "recon",
    dispatcher=None,
) -> None:
    """Add a hash to state (real-time Redis publish handled by state.add_hash)."""
    if not state or not hash_obj:
        return

    # SharedRedTeamState.add_hash() handles real-time Redis checkpoint internally
    if hasattr(state, "add_hash"):
        state.add_hash(hash_obj, source_role)

    # Signal dispatcher if provided (for legacy compatibility)
    if dispatcher:
        dispatcher.signal_credential_access()


def check_tool_result(
    stdout: str,
    stderr: str,
    return_code: int,
    tool_name: str,
    success_indicators: list[str] | None = None,
    error_indicators: list[str] | None = None,
) -> tuple[str, bool]:
    """Check tool result and return (formatted_output, is_success).

    This helper function inspects both the return code and output content
    to determine if a tool execution was successful.

    Args:
        stdout: Standard output from the tool
        stderr: Standard error from the tool
        return_code: Exit code from the tool
        tool_name: Name of the tool for logging
        success_indicators: Optional list of strings indicating success in output
        error_indicators: Optional list of strings indicating failure in output

    Returns:
        Tuple of (formatted_output, is_success) where is_success is True if
        the tool executed successfully based on return code and output analysis.
    """
    output = stdout or ""
    if stderr:
        output = output + "\n" + stderr if output else stderr

    # Check return code first
    if return_code != 0:
        # Some tools return non-zero even on partial success
        # Check if output has success indicators before declaring failure
        if success_indicators:
            output_lower = output.lower()
            for indicator in success_indicators:
                if indicator.lower() in output_lower:
                    logger.debug(f"{tool_name} returned {return_code} but has success indicator")
                    return output, True

        logger.warning(f"{tool_name} failed with return code {return_code}")
        return output, False

    # Check for error indicators in output
    if error_indicators:
        output_lower = output.lower()
        for indicator in error_indicators:
            if indicator.lower() in output_lower:
                logger.warning(f"{tool_name} output contains error indicator: {indicator}")
                return output, False

    return output, True
