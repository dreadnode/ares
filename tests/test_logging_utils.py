"""Tests for logging helpers."""

from __future__ import annotations

import pytest

from ares.core.logging_utils import truncate_output


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [
        pytest.param("", "", id="empty-string"),
        pytest.param("   ", "", id="whitespace-only"),
        pytest.param("  hello world  ", "hello world", id="strips-surrounding-whitespace"),
    ],
)
def test_truncate_output_handles_empty_and_simple_values(raw_value: str, expected: str):
    """truncate_output returns stripped values unchanged when they fit in the limit."""
    assert truncate_output(raw_value, max_length=20) == expected


def test_truncate_output_returns_original_when_within_limit():
    """truncate_output leaves strings at or under the limit untouched after stripping."""
    message = "abcde"

    assert truncate_output(message, max_length=5) == message


def test_truncate_output_appends_truncation_suffix_when_over_limit():
    """truncate_output trims long strings and appends a truncation marker."""
    result = truncate_output("abcdefghijklmnopqrstuvwxyz", max_length=10)

    assert result == "abcdefghij... [truncated]"
