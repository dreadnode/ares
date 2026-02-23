"""Result processing for blue team dispatcher.

Handles merging worker discoveries into shared state and
auto-chaining follow-up tasks based on evidence.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.models import BlueTaskInfo, BlueTaskType, TaskStatus

if TYPE_CHECKING:
    from ares.core.blue_state_backend import BlueStateBackend


# Evidence type → detection methods to auto-chain
EVIDENCE_CHAIN_MAP: dict[str, list[str]] = {
    "kerberoast_hash": ["detect_pass_the_hash", "detect_lateral_movement"],
    "dcsync": ["detect_golden_ticket", "detect_lateral_movement"],
    "t1003": [
        "detect_dcsync",
        "detect_secretsdump",
        "detect_golden_ticket",
        "detect_pass_the_hash",
        "detect_credential_access",
    ],
    "golden_ticket": ["detect_lateral_movement", "detect_persistence"],
    "pass_the_hash": ["detect_lateral_movement", "detect_credential_access"],
    "lateral_movement": ["detect_pass_the_hash", "detect_credential_access"],
    "credential_access": ["detect_dcsync", "detect_kerberoasting"],
    "persistence": ["detect_scheduled_tasks", "detect_registry_modification"],
    "privilege_escalation": ["detect_token_manipulation", "detect_credential_access"],
}

# Users that require immediate escalation
CRITICAL_USERS: set[str] = {"krbtgt", "administrator", "domain admins", "enterprise admins"}


class BlueResultProcessingMixin:
    """Processes task results and auto-chains follow-up investigations."""

    _backend: BlueStateBackend
    _investigation_id: str

    async def complete_task(
        self,
        task_id: str,
        success: bool,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        """Mark a task as completed and merge results.

        Args:
            task_id: The task ID to complete.
            success: Whether the task succeeded.
            result: Task result data.
            error: Error message if failed.
        """
        result_dict = {
            "task_id": task_id,
            "success": success,
            "result": result or {},
            "error": error,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        await self._backend.complete_task(task_id, result_dict)

        if success and result:
            await self._process_result_chains(result)

        status = "completed" if success else "failed"
        logger.info(f"Task {task_id} {status}")

    async def _process_result_chains(self, result: dict[str, Any]) -> None:
        """Auto-chain follow-up queries based on task results.

        Examines the result for evidence types that should trigger
        additional detection queries.
        """
        result_type = result.get("type", "")

        # Check for techniques that should trigger chains
        techniques = result.get("techniques_found", [])
        for technique in techniques:
            technique_lower = technique.lower()
            # Map technique IDs to evidence types for chaining
            if "t1558" in technique_lower:
                await self._queue_chains_for("kerberoast_hash")
            elif "t1003" in technique_lower:
                await self._queue_chains_for("t1003")
            elif "t1550" in technique_lower:
                await self._queue_chains_for("pass_the_hash")

        # Check for critical users in results
        await self._check_critical_users(result)

    async def _queue_chains_for(self, evidence_type: str) -> None:
        """Queue chained detection methods for an evidence type."""
        chain_methods = EVIDENCE_CHAIN_MAP.get(evidence_type, [])
        for method in chain_methods:
            already_executed = await self._backend.is_query_type_executed(method)
            if not already_executed:
                await self._backend.queue_chain(method)
                logger.debug(f"Auto-chained: {evidence_type} -> {method}")

    async def _check_critical_users(self, result: dict[str, Any]) -> None:
        """Check if any critical users were found in results.

        If krbtgt, administrator, etc. appear, queue critical detections.
        """
        # Check users investigated
        users = result.get("users_investigated", [])
        for user in users:
            user_lower = user.lower().strip()
            if user_lower in CRITICAL_USERS:
                logger.warning(f"CRITICAL USER detected in results: {user}")
                # Queue golden ticket and DCSync detection
                for method in ["detect_golden_ticket", "detect_dcsync"]:
                    already_executed = await self._backend.is_query_type_executed(method)
                    if not already_executed:
                        await self._backend.queue_chain(method)

        # Also check evidence highlights for critical user mentions
        highlights = result.get("evidence_highlights", [])
        for highlight in highlights:
            highlight_lower = highlight.lower()
            for user in CRITICAL_USERS:
                if user in highlight_lower:
                    logger.warning(f"CRITICAL USER mentioned in evidence: {user}")
                    for method in ["detect_golden_ticket", "detect_dcsync"]:
                        already_executed = await self._backend.is_query_type_executed(method)
                        if not already_executed:
                            await self._backend.queue_chain(method)
                    break
