"""Logging utilities for Ares.

This module provides utility functions for safe logging.
"""

from __future__ import annotations


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
