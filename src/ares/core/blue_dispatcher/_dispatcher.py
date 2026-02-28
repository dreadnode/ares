"""Blue team multi-agent dispatcher.

Coordinates investigation work across triage, threat hunter, and
lateral analyst workers. All workers run in-process via asyncio.

Uses Redis (via BlueStateBackend) for shared state and task tracking.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.blue_dispatcher.publishing import BluePublishingMixin
from ares.core.blue_dispatcher.result_processing import BlueResultProcessingMixin
from ares.core.blue_dispatcher.routing import BlueRoutingMixin
from ares.core.blue_dispatcher.status import BlueStatusMixin
from ares.core.blue_state_backend import BlueStateBackend
from ares.core.models import (
    InvestigationStage,
    SharedBlueTeamState,
)

if TYPE_CHECKING:
    from redis.asyncio import Redis


class BlueTeamDispatcher(
    BlueRoutingMixin,
    BlueResultProcessingMixin,
    BluePublishingMixin,
    BlueStatusMixin,
):
    """Central coordinator for blue team multi-agent investigations.

    Manages shared state via Redis, routes tasks to workers, processes
    results, and auto-chains follow-up investigations.

    All workers run in-process (asyncio.create_task), so no cross-pod
    messaging is needed. Redis provides shared state persistence and
    deduplication.

    Attributes:
        _redis: Async Redis client.
        _backend: BlueStateBackend for Redis state operations.
        _shared_state: SharedBlueTeamState in-memory state object.
        _investigation_id: Current investigation ID.
        _task_results: Maps task_id -> asyncio.Event for result notification.
        _task_result_data: Maps task_id -> result data.
    """

    def __init__(self, redis_client: Redis) -> None:
        """Initialize the dispatcher.

        Args:
            redis_client: Connected async Redis client.
        """
        self._redis = redis_client
        self._backend: BlueStateBackend | None = None  # type: ignore[assignment]
        self._shared_state: SharedBlueTeamState | None = None
        self._investigation_id: str = ""
        self._task_events: dict[str, asyncio.Event] = {}
        self._task_result_data: dict[str, dict[str, Any]] = {}

    @property
    def backend(self) -> BlueStateBackend:
        """Get the backend (raises if not started)."""
        if not self._backend:
            raise RuntimeError("Dispatcher not started. Call start() first.")
        return self._backend

    @property
    def shared_state(self) -> SharedBlueTeamState:
        """Get the shared state (raises if not started)."""
        if not self._shared_state:
            raise RuntimeError("Dispatcher not started. Call start() first.")
        return self._shared_state

    @property
    def investigation_id(self) -> str:
        return self._investigation_id

    async def start(
        self,
        investigation_id: str,
        alert: dict[str, Any],
        correlation_context: dict[str, Any] | None = None,
    ) -> None:
        """Start the dispatcher for a new investigation.

        Creates the backend and shared state, stores initial alert data.

        Args:
            investigation_id: Unique investigation identifier.
            alert: The alert JSON that triggered the investigation.
            correlation_context: Optional alert correlation context.
        """
        self._investigation_id = investigation_id
        self._backend = BlueStateBackend(self._redis, investigation_id)
        self._shared_state = SharedBlueTeamState(
            investigation_id=investigation_id,
            alert=alert,
            correlation_context=correlation_context,
        )
        self._shared_state.set_backend(self._backend)

        # Store alert and meta in Redis
        await self._backend.set_meta("alert", alert)
        await self._backend.set_meta("stage", InvestigationStage.TRIAGE.value)
        await self._backend.set_meta("escalated", value=False)
        if correlation_context:
            await self._backend.set_meta("correlation_context", correlation_context)

        logger.info(f"Blue dispatcher started for investigation {investigation_id}")

    async def stop(self) -> None:
        """Stop the dispatcher and clean up."""
        self._task_events.clear()
        self._task_result_data.clear()
        logger.info(f"Blue dispatcher stopped for investigation {self._investigation_id}")

    async def notify_task_result(
        self,
        task_id: str,
        success: bool,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        """Notify that a task has completed (called by workers).

        This both persists the result and signals any waiters.

        Args:
            task_id: The completed task ID.
            success: Whether the task succeeded.
            result: Task result data.
            error: Error message if failed.
        """
        await self.complete_task(task_id, success, result, error)

        # Store result data and signal waiter
        self._task_result_data[task_id] = {
            "success": success,
            "result": result or {},
            "error": error,
        }
        event = self._task_events.get(task_id)
        if event:
            event.set()

    async def wait_for_result(
        self,
        task_id: str,
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        """Wait for a task to complete and return its result.

        Args:
            task_id: Task ID to wait for.
            timeout: Maximum seconds to wait.

        Returns:
            Result dict with success, result, error fields.

        Raises:
            asyncio.TimeoutError: If timeout exceeded.
        """
        # Check if already completed
        if task_id in self._task_result_data:
            return self._task_result_data[task_id]

        # Create event and wait
        event = asyncio.Event()
        self._task_events[task_id] = event

        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            return self._task_result_data.get(
                task_id,
                {
                    "success": False,
                    "result": {},
                    "error": "Result not found after notification",
                },
            )
        except asyncio.TimeoutError:
            # Use DEBUG for short poll timeouts, WARNING for real timeouts
            if timeout <= 30:
                logger.debug(f"Task {task_id} poll timeout after {timeout}s (still running)")
            else:
                logger.warning(f"Task {task_id} timed out after {timeout}s")
            return {
                "success": False,
                "result": {},
                "error": f"Task timed out after {timeout}s",
            }
        finally:
            self._task_events.pop(task_id, None)

    async def snapshot_to_shared_state(self) -> SharedBlueTeamState:
        """Refresh the shared state from Redis.

        Returns:
            Updated SharedBlueTeamState.
        """
        from ares.core.models import Evidence, PyramidLevel, TimelineEvent

        snapshot = await self.backend.snapshot()
        meta = snapshot.get("meta", {})

        state = self._shared_state
        if not state:
            state = SharedBlueTeamState(investigation_id=self._investigation_id)

        # Update fields from snapshot
        state.alert = meta.get("alert", state.alert)
        stage_val = meta.get("stage", "triage")
        state.stage = InvestigationStage(stage_val)
        state.escalated = meta.get("escalated", False)
        state.escalation_reason = meta.get("escalation_reason")
        state.attack_synopsis = meta.get("attack_synopsis")
        state.correlation_context = meta.get("correlation_context")

        # Rebuild evidence list from dicts
        state.evidence = []
        for ev_dict in snapshot.get("evidence", []):
            try:
                level_val = ev_dict.get("pyramid_level", 1)
                ts = None
                if ev_dict.get("timestamp"):
                    from datetime import datetime

                    ts = datetime.fromisoformat(str(ev_dict["timestamp"]))

                ev = Evidence(
                    id=ev_dict.get("id", ""),
                    type=ev_dict.get("type", ""),
                    value=ev_dict.get("value", ""),
                    source=ev_dict.get("source", ""),
                    timestamp=ts,
                    pyramid_level=PyramidLevel(min(max(int(level_val), 1), 6)),
                    mitre_techniques=ev_dict.get("mitre_techniques", []),
                    confidence=ev_dict.get("confidence", 0.5),
                    source_query_id=ev_dict.get("source_query_id"),
                    validated=ev_dict.get("validated", False),
                )
                state.evidence.append(ev)
            except Exception as e:
                logger.warning(f"Failed to deserialize evidence: {e}")

        # Rebuild timeline
        state.timeline = []
        for tl_dict in snapshot.get("timeline", []):
            try:
                from datetime import datetime

                ts = datetime.fromisoformat(str(tl_dict["timestamp"]))
                event = TimelineEvent(
                    id=tl_dict.get("id", ""),
                    timestamp=ts,
                    description=tl_dict.get("description", ""),
                    evidence_ids=tl_dict.get("evidence_ids", []),
                    mitre_techniques=tl_dict.get("mitre_techniques", []),
                    confidence=tl_dict.get("confidence", 0.5),
                )
                state.timeline.append(event)
            except Exception as e:
                logger.warning(f"Failed to deserialize timeline event: {e}")

        state.timeline.sort(key=lambda e: e.timestamp)

        # Simple fields
        state.identified_techniques = snapshot.get("techniques", set())
        state.identified_tactics = snapshot.get("tactics", set())
        state.technique_names = snapshot.get("technique_names", {})
        state.queried_hosts = snapshot.get("hosts", set())
        state.queried_users = snapshot.get("users", set())
        state.executed_query_types = snapshot.get("query_types", set())
        state.executed_queries = snapshot.get("queries", [])
        state.lateral_connections = snapshot.get("lateral_connections", [])
        state.queued_pivot_queries = snapshot.get("pivot_queue", [])
        state.queued_chain_queries = snapshot.get("chain_queue", [])
        state.recommendations = snapshot.get("recommendations", [])

        self._shared_state = state
        return state
