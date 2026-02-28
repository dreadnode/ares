"""Utilities for working with MCP tool responses."""

from __future__ import annotations

import json
from typing import Any


def parse_mcp_text_content(result: Any) -> Any:
    """Parse MCP TextContent response into structured data.

    MCP tools return TextContent or list of TextContent objects with a .text
    attribute containing JSON. This function extracts and parses that JSON.

    Args:
        result: Raw MCP tool result (TextContent, list of TextContent, or other).

    Returns:
        Parsed JSON data, or fallback structure if parsing fails.
        For unparsable text, returns [{"line": text, "labels": {}}].
    """
    if isinstance(result, list):
        parsed = []
        for item in result:
            text = getattr(item, "text", None)
            if text:
                try:
                    parsed.append(json.loads(text))
                except json.JSONDecodeError:
                    parsed.append({"line": text, "labels": {}})
        return parsed

    if hasattr(result, "text"):
        try:
            return json.loads(result.text)
        except json.JSONDecodeError:
            return [{"line": result.text, "labels": {}}]

    return result
