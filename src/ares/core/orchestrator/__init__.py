"""Orchestrator package for multi-agent red team operations.

This package provides the main orchestrator for coordinating multi-agent
red team operations in a Kubernetes environment.

Package Structure:
    - _orchestrator.py: Main orchestrator logic and entry point

Usage:
    from ares.core.orchestrator import run_multi_agent_operation

    await run_multi_agent_operation(
        target_ip="192.168.58.10",
        domain="contoso.local",
        model="claude-sonnet-4-20250514",
    )
"""

from __future__ import annotations

# Re-export config getters for backwards compatibility
from ares.core.config import (
    get_crack_task_grace_period,
    get_max_runtime,
)

# Re-export main entry point and helper functions used by tests
from ares.core.orchestrator._orchestrator import (
    _auto_adcs_enumeration,
    _auto_bloodhound,
    _auto_coercion,
    _auto_credential_access,
    _auto_delegation_enumeration,
    _auto_golden_ticket,
    _wait_for_crack_tasks,
    run_multi_agent_operation,
)

__all__ = [
    "_auto_adcs_enumeration",
    "_auto_bloodhound",
    "_auto_coercion",
    "_auto_credential_access",
    "_auto_delegation_enumeration",
    "_auto_golden_ticket",
    "_wait_for_crack_tasks",
    "get_crack_task_grace_period",
    "get_max_runtime",
    "run_multi_agent_operation",
]
