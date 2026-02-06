"""LiteLLM environment defaults for long-running agents."""

from __future__ import annotations

import os


def configure_litellm_env() -> None:
    """Set safe LiteLLM defaults for long-running multi-agent operations.

    Configures:
    - Logging worker timeout to reduce noise
    - Retry logic for rate limit errors (critical for multi-agent systems)
    - Request timeout for long-running operations
    """
    # Reduce logging worker timeout noise
    os.environ.setdefault("LOGGING_WORKER_MAX_TIME_PER_COROUTINE", "60")

    # Rate limit retry configuration - critical for multi-agent systems
    # where multiple workers share the same API key
    os.environ.setdefault("LITELLM_NUM_RETRIES", "5")

    # Request timeout (seconds) - allow time for complex reasoning
    os.environ.setdefault("LITELLM_REQUEST_TIMEOUT", "300")
