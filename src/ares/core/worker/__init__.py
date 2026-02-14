"""Worker package for multi-agent red team operations.

This package provides worker agents that execute tasks dispatched by the
orchestrator. Workers can run in two modes:

1. **Redis/K8s mode** (RedisWorkerAgent): Workers poll Redis task queues for
   assigned tasks and report results back via Redis. Used in Kubernetes
   multi-pod deployments.

2. **Single-process mode** (WorkerAgent): Workers poll the dispatcher directly
   for tasks. Used for local development/testing.

Package Structure:
    - _worker.py: Main worker classes and entry point
    - dc_resolution.py: Domain controller IP resolution helpers
    - operations.py: Operation discovery and model configuration
    - prompts.py: Task prompt generation and state formatting

Usage:
    from ares.core.worker import run_worker

    # Start a worker for a specific role
    await run_worker(
        redis_url="redis://localhost:6379",
        role="enum",
        model="gpt-4.1",
    )

Classes:
    RedisWorkerAgent: Worker for Kubernetes multi-pod mode (Redis-based)
    WorkerAgent: Worker for single-process mode (dispatcher-based)

Functions:
    run_worker: Main entry point for starting a worker
    discover_active_operation: Find active operation from Redis
    generate_prompt_from_task: Generate agent prompt from task payload
    format_state_context: Format shared state for agent context
"""

from __future__ import annotations

# Re-export config getters for backwards compatibility
from ares.core.config import (
    get_rate_limit_backoff_delays,
    get_rate_limit_max_retries,
)

# Re-export main classes and functions from _worker.py
from ares.core.worker._worker import (
    RedisWorkerAgent,
    WorkerAgent,
    logger,
    run_worker,
)

# Re-export from split modules
from ares.core.worker.dc_resolution import (
    resolve_dc_ip_for_domain,
)
from ares.core.worker.operations import (
    discover_active_operation,
    get_active_operation_pointer,
    get_operation_model,
    get_operation_model_overrides,
)
from ares.core.worker.prompts import (
    TASK_PROMPTS,
    format_state_context,
    generate_prompt_from_task,
)

__all__ = [
    "TASK_PROMPTS",
    "RedisWorkerAgent",
    "WorkerAgent",
    "discover_active_operation",
    "format_state_context",
    "generate_prompt_from_task",
    "get_active_operation_pointer",
    "get_operation_model",
    "get_operation_model_overrides",
    "get_rate_limit_backoff_delays",
    "get_rate_limit_max_retries",
    "logger",
    "resolve_dc_ip_for_domain",
    "run_worker",
]
