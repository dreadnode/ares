"""Tests for LiteLLM environment defaults."""

from __future__ import annotations

import os

from ares.core.litellm_env import configure_litellm_env


def test_configure_litellm_env_sets_expected_defaults(monkeypatch):
    """configure_litellm_env populates all expected default environment variables."""
    expected_keys = [
        "LITELLM_TELEMETRY",
        "LOGGING_WORKER_MAX_TIME_PER_COROUTINE",
        "LITELLM_NUM_RETRIES",
        "LITELLM_REQUEST_TIMEOUT",
    ]
    for key_name in expected_keys:
        monkeypatch.delenv(key_name, raising=False)

    configure_litellm_env()

    assert os.environ["LITELLM_TELEMETRY"] == "false"
    assert os.environ["LOGGING_WORKER_MAX_TIME_PER_COROUTINE"] == "60"
    assert os.environ["LITELLM_NUM_RETRIES"] == "3"
    assert os.environ["LITELLM_REQUEST_TIMEOUT"] == "60"


def test_configure_litellm_env_preserves_existing_values(monkeypatch):
    """configure_litellm_env does not overwrite values already defined by the caller."""
    monkeypatch.setenv("LITELLM_TELEMETRY", "true")
    monkeypatch.setenv("LOGGING_WORKER_MAX_TIME_PER_COROUTINE", "10")
    monkeypatch.setenv("LITELLM_NUM_RETRIES", "9")
    monkeypatch.setenv("LITELLM_REQUEST_TIMEOUT", "120")

    configure_litellm_env()

    assert os.environ["LITELLM_TELEMETRY"] == "true"
    assert os.environ["LOGGING_WORKER_MAX_TIME_PER_COROUTINE"] == "10"
    assert os.environ["LITELLM_NUM_RETRIES"] == "9"
    assert os.environ["LITELLM_REQUEST_TIMEOUT"] == "120"
