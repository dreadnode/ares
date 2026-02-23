"""Investigation status queries for blue team dispatcher."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ares.core.blue_state_backend import BlueStateBackend


class BlueStatusMixin:
    """Provides investigation status and summary queries."""

    _backend: BlueStateBackend
    _investigation_id: str

    async def get_investigation_summary(self) -> dict[str, Any]:
        """Get a summary of the current investigation state.

        Returns:
            Dict with evidence counts, techniques, tasks, etc.
        """
        snapshot = await self._backend.snapshot()
        meta = snapshot.get("meta", {})

        evidence_list = snapshot.get("evidence", [])
        pyramid_levels = [e.get("pyramid_level", 0) for e in evidence_list]

        return {
            "investigation_id": self._investigation_id,
            "stage": meta.get("stage", "triage"),
            "evidence_count": len(evidence_list),
            "timeline_events": len(snapshot.get("timeline", [])),
            "techniques_identified": list(snapshot.get("techniques", set())),
            "technique_count": len(snapshot.get("techniques", set())),
            "tactics_identified": list(snapshot.get("tactics", set())),
            "highest_pyramid_level": max(pyramid_levels, default=0),
            "hosts_investigated": list(snapshot.get("hosts", set())),
            "users_investigated": list(snapshot.get("users", set())),
            "pending_tasks": len(snapshot.get("pending_tasks", {})),
            "completed_tasks": len(snapshot.get("completed_tasks", {})),
            "queued_pivots": len(snapshot.get("pivot_queue", [])),
            "queued_chains": len(snapshot.get("chain_queue", [])),
            "escalated": meta.get("escalated", False),
            "recommendations": snapshot.get("recommendations", []),
        }

    async def get_task_status(self) -> dict[str, Any]:
        """Get status of all tasks.

        Returns:
            Dict with pending and completed task summaries.
        """
        snapshot = await self._backend.snapshot()
        pending = snapshot.get("pending_tasks", {})
        completed = snapshot.get("completed_tasks", {})

        return {
            "pending_count": len(pending),
            "completed_count": len(completed),
            "pending_tasks": [
                {
                    "task_id": t.get("task_id"),
                    "task_type": t.get("task_type"),
                    "assigned_role": t.get("assigned_role"),
                }
                for t in pending.values()
            ],
            "completed_tasks": [
                {
                    "task_id": t.get("task_id"),
                    "success": t.get("success"),
                }
                for t in completed.values()
            ],
        }

    async def get_evidence_summary(self) -> dict[str, Any]:
        """Get a summary of collected evidence.

        Returns:
            Dict with evidence organized by type and pyramid level.
        """
        snapshot = await self._backend.snapshot()
        evidence_list = snapshot.get("evidence", [])

        by_type: dict[str, int] = {}
        by_level: dict[int, int] = {}
        for ev in evidence_list:
            ev_type = ev.get("type", "unknown")
            by_type[ev_type] = by_type.get(ev_type, 0) + 1
            level = ev.get("pyramid_level", 0)
            by_level[level] = by_level.get(level, 0) + 1

        technique_names = snapshot.get("technique_names", {})

        return {
            "total_evidence": len(evidence_list),
            "by_type": by_type,
            "by_pyramid_level": by_level,
            "techniques": {
                tid: technique_names.get(tid, tid)
                for tid in snapshot.get("techniques", set())
            },
            "lateral_connections": len(snapshot.get("lateral_connections", [])),
        }
