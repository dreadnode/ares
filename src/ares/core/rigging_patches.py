"""Patches for rigging to handle common LLM quirks.

This module monkey-patches rigging's Tool.handle_tool_call to normalize
parameter names to snake_case, fixing issues where LLMs send capitalized
or space-separated parameter names (e.g., 'Username' or 'Dc Ip' instead
of 'username' or 'dc_ip').

Apply early in initialization by importing this module:
    from ares.core import rigging_patches
    rigging_patches.apply()
"""

import functools
import json
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from rigging.tools.base import Tool, ToolCall

_patched = False


def _normalize_tool_call_kwargs(arguments_json: str) -> str:
    """Normalize tool call argument keys to snake_case.

    LLMs sometimes return capitalized or space-separated parameter names
    (e.g., 'Username' or 'Dc Ip' instead of 'username' or 'dc_ip').
    This function normalizes all keys to snake_case to match Python conventions.

    Args:
        arguments_json: JSON string of tool call arguments

    Returns:
        JSON string with snake_case keys
    """
    try:
        kwargs = json.loads(arguments_json)
        if isinstance(kwargs, dict):
            # Lowercase and replace spaces with underscores
            normalized = {k.lower().replace(" ", "_"): v for k, v in kwargs.items()}
            return json.dumps(normalized)
    except (json.JSONDecodeError, TypeError):
        pass
    return arguments_json


def apply() -> None:
    """Apply rigging patches for LLM quirk handling.

    This patches Tool.handle_tool_call to normalize kwargs keys to snake_case
    before validation, preventing ValidationErrors from case/spacing mismatches.
    """
    global _patched
    if _patched:
        return

    from rigging.tools.base import Tool

    original_handle = Tool.handle_tool_call

    @functools.wraps(original_handle)
    async def patched_handle_tool_call(self: "Tool", tool_call: "ToolCall") -> tuple["Tool", bool]:
        # Normalize the arguments before processing
        original_args = tool_call.function.arguments
        normalized_args = _normalize_tool_call_kwargs(original_args)

        if normalized_args != original_args:
            # Create a copy of the tool call with normalized arguments
            tool_call.function.arguments = normalized_args
            logger.debug(
                f"Normalized tool call args for {tool_call.function.name}: "
                f"{original_args} -> {normalized_args}"
            )

        return await original_handle(self, tool_call)

    Tool.handle_tool_call = patched_handle_tool_call  # type: ignore[method-assign]
    _patched = True
    logger.debug("Applied rigging patch for case-insensitive tool parameters")
