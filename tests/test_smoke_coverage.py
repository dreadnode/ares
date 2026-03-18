"""Minimal smoke tests to keep package import coverage healthy."""

from __future__ import annotations


def test_src_ares_package_importable():
    """The top-level ares package is importable from the source tree."""
    import ares

    assert ares.__name__ == "ares"
