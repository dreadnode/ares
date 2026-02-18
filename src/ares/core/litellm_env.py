"""LiteLLM environment defaults for long-running agents."""

from __future__ import annotations

import os


def configure_litellm_env() -> None:
    """Set safe LiteLLM defaults for long-running multi-agent operations.

    Configures:
    - Disable telemetry to prevent LoggingWorker timeouts
    - Logging worker timeout to reduce noise
    - Retry logic for rate limit errors (critical for multi-agent systems)
    - Request timeout for long-running operations
    """
    # Disable LiteLLM telemetry to prevent LoggingWorker TimeoutError noise.
    # LiteLLM's default telemetry can timeout when network is slow/blocked,
    # causing noisy errors in logging_worker.py:_process_log_task.
    os.environ.setdefault("LITELLM_TELEMETRY", "false")

    # Reduce logging worker timeout noise (for any remaining callbacks)
    os.environ.setdefault("LOGGING_WORKER_MAX_TIME_PER_COROUTINE", "60")

    # Rate limit retry configuration - critical for multi-agent systems
    # where multiple workers share the same API key
    os.environ.setdefault("LITELLM_NUM_RETRIES", "3")

    # Request timeout (seconds) - reduced from 300s to prevent 14+ minute freezes
    # when LLM API calls timeout and block the asyncio event loop.
    # With 3 retries @ 60s = max 3 min blocking instead of 25 min (5 retries @ 300s).
    os.environ.setdefault("LITELLM_REQUEST_TIMEOUT", "60")
