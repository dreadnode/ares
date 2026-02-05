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
    - (future) helpers.py: DC resolution, rate limiting helpers
    - (future) prompts.py: Task prompt generation

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

# Re-export main classes and functions
from ares.core.worker._worker import (
    RATE_LIMIT_BACKOFF_DELAYS,
    RATE_LIMIT_MAX_RETRIES,
    RedisWorkerAgent,
    WorkerAgent,
    discover_active_operation,
    format_state_context,
    generate_prompt_from_task,
    get_active_operation_pointer,
    get_operation_model,
    get_operation_model_overrides,
    logger,
    run_worker,
)

__all__ = [
    "RATE_LIMIT_BACKOFF_DELAYS",
    "RATE_LIMIT_MAX_RETRIES",
    "RedisWorkerAgent",
    "WorkerAgent",
    "discover_active_operation",
    "format_state_context",
    "generate_prompt_from_task",
    "get_active_operation_pointer",
    "get_operation_model",
    "get_operation_model_overrides",
    "logger",
    "run_worker",
]
