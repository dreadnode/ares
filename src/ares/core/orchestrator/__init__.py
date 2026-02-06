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

# Re-export main entry point and helper functions used by tests
from ares.core.orchestrator._orchestrator import (
    CRACK_TASK_GRACE_PERIOD,
    DEFAULT_MAX_RUNTIME,
    _auto_adcs_enumeration,
    _auto_bloodhound,
    _auto_coercion,
    _auto_credential_access,
    _auto_delegation_enumeration,
    _build_redteam_report_state,
    _wait_for_crack_tasks,
    run_multi_agent_operation,
)

__all__ = [
    "CRACK_TASK_GRACE_PERIOD",
    "DEFAULT_MAX_RUNTIME",
    "_auto_adcs_enumeration",
    "_auto_bloodhound",
    "_auto_coercion",
    "_auto_credential_access",
    "_auto_delegation_enumeration",
    "_build_redteam_report_state",
    "_wait_for_crack_tasks",
    "run_multi_agent_operation",
]
