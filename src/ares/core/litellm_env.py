"""LiteLLM environment defaults for long-running agents."""

from __future__ import annotations

import os


def configure_litellm_env() -> None:
    """Set safe LiteLLM logging-worker defaults to reduce timeout noise."""
    os.environ.setdefault("LOGGING_WORKER_MAX_TIME_PER_COROUTINE", "60")
