"""Task routing for blue team dispatcher."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.models import BlueRole, BlueTaskInfo, BlueTaskType, TaskStatus

if TYPE_CHECKING:
    from ares.core.blue_state_backend import BlueStateBackend


class BlueRoutingMixin:
    """Routes investigation tasks to appropriate worker roles."""

    _backend: BlueStateBackend
    _investigation_id: str

    def _create_task(
        self,
        task_type: BlueTaskType,
        role: BlueRole,
        params: dict[str, Any],
    ) -> BlueTaskInfo:
        """Create a task and register it as pending."""
        task = BlueTaskInfo(
            task_id=str(uuid.uuid4())[:8],
            task_type=task_type,
            investigation_id=self._investigation_id,
            status=TaskStatus.PENDING,
            assigned_role=role,
            params=params,
        )
        return task

    async def dispatch_triage(
        self,
        alert: dict[str, Any],
        correlation_context: dict[str, Any] | None = None,
    ) -> BlueTaskInfo:
        """Dispatch a triage task to the triage worker.

        Args:
            alert: The alert JSON to triage.
            correlation_context: Optional correlation context.

        Returns:
            BlueTaskInfo for the created task.
        """
        task = self._create_task(
            BlueTaskType.TRIAGE_ALERT,
            BlueRole.TRIAGE,
            {
                "alert": alert,
                "correlation_context": correlation_context or {},
            },
        )
        await self._register_pending_task(task)
        logger.info(f"Dispatched triage task {task.task_id}")
        return task

    async def dispatch_threat_hunt(
        self,
        technique_id: str = "",
        detection_method: str = "",
        hostname: str = "",
        username: str = "",
        context: str = "",
    ) -> BlueTaskInfo:
        """Dispatch a threat hunting task.

        Args:
            technique_id: MITRE technique to hunt for.
            detection_method: Specific detection query to run.
            hostname: Host to focus on.
            username: User to focus on.
            context: Additional context from prior investigation.

        Returns:
            BlueTaskInfo for the created task.
        """
        task = self._create_task(
            BlueTaskType.THREAT_HUNT,
            BlueRole.THREAT_HUNTER,
            {
                "technique_id": technique_id,
                "detection_method": detection_method,
                "hostname": hostname,
                "username": username,
                "context": context,
            },
        )
        await self._register_pending_task(task)
        logger.info(
            f"Dispatched threat hunt task {task.task_id}: "
            f"technique={technique_id}, method={detection_method}"
        )
        return task

    async def dispatch_lateral_analysis(
        self,
        focus_host: str = "",
        focus_user: str = "",
        context: str = "",
    ) -> BlueTaskInfo:
        """Dispatch a lateral movement analysis task.

        Args:
            focus_host: Primary host to analyze.
            focus_user: Primary user to analyze.
            context: Additional context from prior investigation.

        Returns:
            BlueTaskInfo for the created task.
        """
        task = self._create_task(
            BlueTaskType.LATERAL_ANALYSIS,
            BlueRole.LATERAL_ANALYST,
            {
                "focus_host": focus_host,
                "focus_user": focus_user,
                "context": context,
            },
        )
        await self._register_pending_task(task)
        logger.info(f"Dispatched lateral analysis task {task.task_id}: host={focus_host}, user={focus_user}")
        return task

    async def dispatch_host_investigation(self, hostname: str, context: str = "") -> BlueTaskInfo:
        """Dispatch a host-focused investigation task.

        Args:
            hostname: Host to investigate.
            context: Additional context.

        Returns:
            BlueTaskInfo for the created task.
        """
        task = self._create_task(
            BlueTaskType.HOST_INVESTIGATION,
            BlueRole.LATERAL_ANALYST,
            {"hostname": hostname, "context": context},
        )
        await self._register_pending_task(task)
        logger.info(f"Dispatched host investigation task {task.task_id}: {hostname}")
        return task

    async def dispatch_user_investigation(self, username: str, context: str = "") -> BlueTaskInfo:
        """Dispatch a user-focused investigation task.

        Args:
            username: User to investigate.
            context: Additional context.

        Returns:
            BlueTaskInfo for the created task.
        """
        task = self._create_task(
            BlueTaskType.USER_INVESTIGATION,
            BlueRole.THREAT_HUNTER,
            {"username": username, "context": context},
        )
        await self._register_pending_task(task)
        logger.info(f"Dispatched user investigation task {task.task_id}: {username}")
        return task

    async def _register_pending_task(self, task: BlueTaskInfo) -> None:
        """Register a task as pending in the backend."""
        import json
        from datetime import datetime, timezone

        task_dict = {
            "task_id": task.task_id,
            "task_type": task.task_type.value,
            "investigation_id": task.investigation_id,
            "status": task.status.value,
            "assigned_role": task.assigned_role.value,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "params": task.params,
        }
        await self._backend.add_pending_task(task.task_id, task_dict)
