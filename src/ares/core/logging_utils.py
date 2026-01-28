"""Logging utilities for Ares.

This module provides utility functions for safe logging, including
command sanitization to prevent sensitive data exposure in logs.
"""

from __future__ import annotations

import re

# Flags that typically precede sensitive values
SENSITIVE_FLAGS = frozenset(
    {
        "-p",
        "--password",
        "-H",
        "--hash",
        "-hashes",
        "--hashes",
        "--pw",
        "-k",
        "--aesKey",
        "--dc-ip",  # Not sensitive but included for potential masking
    }
)

# Patterns that indicate sensitive content
SENSITIVE_PATTERNS = [
    # user:password@host patterns (mask the password part)
    re.compile(r"([a-zA-Z0-9_\-\.]+):([^@\s]+)@([a-zA-Z0-9_\-\.]+)"),
    # NTLM hash patterns (LM:NT format)
    re.compile(r"([a-fA-F0-9]{32}:[a-fA-F0-9]{32})"),
    # Single hash patterns (32 hex chars that look like hashes)
    re.compile(r"\b([a-fA-F0-9]{32})\b"),
]


def sanitize_command(cmd: list[str] | str) -> str:
    """Sanitize command for logging, masking sensitive values.

    Masks:
    - Values following sensitive flags (-p, --password, -H, --hash, etc.)
    - Credentials in user:pass@host patterns
    - Hash values (NTLM, etc.)

    Args:
        cmd: Command as list of arguments or string.

    Returns:
        Sanitized command string safe for logging.
    """
    parts = list(cmd) if isinstance(cmd, list) else cmd.split()

    sanitized = []
    skip_next = False

    for part in parts:
        if skip_next:
            sanitized.append("***")
            skip_next = False
            continue

        # Check if this part is a sensitive flag
        # Handle both "-p value" and "-p=value" formats
        flag_base = part.split("=")[0] if "=" in part else part

        if flag_base in SENSITIVE_FLAGS:
            if "=" in part:
                # Format: --password=secret
                sanitized.append(f"{flag_base}=***")
            else:
                # Format: --password secret (mask next arg)
                sanitized.append(part)
                skip_next = True
            continue

        # Check for user:pass@host patterns
        masked_part = part
        for pattern in SENSITIVE_PATTERNS:
            if pattern == SENSITIVE_PATTERNS[0]:
                # user:pass@host -> user:***@host
                masked_part = pattern.sub(r"\1:***@\3", masked_part)
            else:
                # Hash patterns -> ***
                masked_part = pattern.sub("***", masked_part)

        sanitized.append(masked_part)

    return " ".join(sanitized)


def truncate_output(output: str, max_length: int = 500) -> str:
    """Truncate output string for logging.

    Args:
        output: String to truncate.
        max_length: Maximum length before truncation.

    Returns:
        Truncated string with indicator if truncated.
    """
    if not output:
        return ""
    output = output.strip()
    if len(output) <= max_length:
        return output
    return output[:max_length] + "... [truncated]"
