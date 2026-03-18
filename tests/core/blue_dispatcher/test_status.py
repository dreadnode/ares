"""Tests for blue dispatcher status mixin."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from ares.core.blue_dispatcher.status import BlueStatusMixin


class StatusHarness(BlueStatusMixin):
    """Concrete harness for BlueStatusMixin tests."""

    def __init__(self, backend: AsyncMock, investigation_id: str = "inv-123") -> None:
        self._backend = backend
        self._investigation_id = investigation_id


@pytest.mark.asyncio
async def test_get_investigation_summary_uses_snapshot_defaults() -> None:
    """Summary falls back to empty/default values when snapshot keys are absent."""
    backend = AsyncMock()
    backend.snapshot.return_value = {}
    harness = StatusHarness(backend)

    result = await harness.get_investigation_summary()

    assert result == {
        "investigation_id": "inv-123",
        "stage": "triage",
        "evidence_count": 0,
        "timeline_events": 0,
        "techniques_identified": [],
        "technique_count": 0,
        "tactics_identified": [],
        "highest_pyramid_level": 0,
        "hosts_investigated": [],
        "users_investigated": [],
        "pending_tasks": 0,
        "completed_tasks": 0,
        "queued_pivots": 0,
        "queued_chains": 0,
        "escalated": False,
        "recommendations": [],
    }


@pytest.mark.asyncio
async def test_get_investigation_summary_counts_snapshot_content() -> None:
    """Summary reports counts and converted collections from snapshot content."""
    backend = AsyncMock()
    backend.snapshot.return_value = {
        "meta": {"stage": "lateral", "escalated": True},
        "evidence": [
            {"type": "ip", "pyramid_level": 2},
            {"type": "user", "pyramid_level": 5},
        ],
        "timeline": [{"id": "tl-1"}],
        "techniques": {"T1110", "T1078"},
        "tactics": {"credential-access"},
        "hosts": {"server01"},
        "users": {"alice"},
        "pending_tasks": {"p-1": {}},
        "completed_tasks": {"c-1": {}, "c-2": {}},
        "pivot_queue": [{"query": "pivot"}],
        "chain_queue": [{"query": "chain-1"}, {"query": "chain-2"}],
        "recommendations": ["isolate host"],
    }
    harness = StatusHarness(backend, investigation_id="inv-999")

    result = await harness.get_investigation_summary()

    assert result["investigation_id"] == "inv-999"
    assert result["stage"] == "lateral"
    assert result["evidence_count"] == 2
    assert result["timeline_events"] == 1
    assert set(result["techniques_identified"]) == {"T1110", "T1078"}
    assert result["technique_count"] == 2
    assert result["tactics_identified"] == ["credential-access"]
    assert result["highest_pyramid_level"] == 5
    assert result["hosts_investigated"] == ["server01"]
    assert result["users_investigated"] == ["alice"]
    assert result["pending_tasks"] == 1
    assert result["completed_tasks"] == 2
    assert result["queued_pivots"] == 1
    assert result["queued_chains"] == 2
    assert result["escalated"] is True
    assert result["recommendations"] == ["isolate host"]


@pytest.mark.asyncio
async def test_get_task_status_serializes_pending_and_completed_tasks() -> None:
    """Task status exposes simplified task details for both pending and completed tasks."""
    backend = AsyncMock()
    backend.snapshot.return_value = {
        "pending_tasks": {
            "task-a": {
                "task_id": "task-a",
                "task_type": "triage_alert",
                "assigned_role": "triage",
                "ignored": "value",
            }
        },
        "completed_tasks": {
            "task-b": {"task_id": "task-b", "success": True, "details": "done"}
        },
    }
    harness = StatusHarness(backend)

    result = await harness.get_task_status()

    assert result == {
        "pending_count": 1,
        "completed_count": 1,
        "pending_tasks": [
            {
                "task_id": "task-a",
                "task_type": "triage_alert",
                "assigned_role": "triage",
            }
        ],
        "completed_tasks": [{"task_id": "task-b", "success": True}],
    }


@pytest.mark.asyncio
async def test_get_evidence_summary_groups_by_type_level_and_technique_name() -> None:
    """Evidence summary aggregates evidence and maps technique IDs to friendly names."""
    backend = AsyncMock()
    backend.snapshot.return_value = {
        "evidence": [
            {"type": "ip", "pyramid_level": 2},
            {"type": "ip", "pyramid_level": 2},
            {"type": "user", "pyramid_level": 4},
            {"pyramid_level": 1},
        ],
        "techniques": {"T1078", "T1110"},
        "technique_names": {"T1078": "Valid Accounts"},
        "lateral_connections": [{"id": 1}, {"id": 2}],
    }
    harness = StatusHarness(backend)

    result = await harness.get_evidence_summary()

    assert result["total_evidence"] == 4
    assert result["by_type"] == {"ip": 2, "user": 1, "unknown": 1}
    assert result["by_pyramid_level"] == {2: 2, 4: 1, 1: 1}
    assert result["techniques"] == {"T1078": "Valid Accounts", "T1110": "T1110"}
    assert result["lateral_connections"] == 2
