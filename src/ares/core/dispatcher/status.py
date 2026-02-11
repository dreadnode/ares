"""Status query methods for dispatcher state.

This module provides methods to query pending tasks, agent status,
and exploitation progress.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.models import TaskInfo, VulnerabilityInfo

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher


class StatusMixin:
    """Status query methods for dispatcher state."""

    def get_pending_tasks(self: RedTeamDispatcher) -> list[TaskInfo]:
        """Get all pending tasks."""
        return list(self.shared_state.pending_tasks.values())

    def get_agent_status(self: RedTeamDispatcher) -> dict[str, dict]:
        """Get status of all registered agents."""
        return {
            name: {
                "role": agent.role.value,
                "status": agent.status,
                "current_task": agent.current_task,
                "last_heartbeat": agent.last_heartbeat.isoformat(),
            }
            for name, agent in self._agents.items()
        }

    async def get_exploitation_status(self: RedTeamDispatcher) -> dict[str, Any]:  # noqa: PLR0912
        """Get status of discovered vs exploited vulnerabilities."""
        discovered: dict[str, VulnerabilityInfo] = dict(
            self.shared_state.discovered_vulnerabilities
        )
        succeeded: set[str] = set(self.shared_state.exploited_vulnerabilities)
        failed: dict[str, dict[str, Any]] = {}

        # Track (type, target) tuples to avoid logical duplicates with different UUIDs
        seen_type_target: set[tuple[str, str]] = {
            (v.vuln_type, v.target) for v in discovered.values()
        }

        if self._redis_client is not None:
            try:
                import json

                vuln_prefix = f"ares:operation:{self.shared_state.operation_id}:vulns:"
                async for key in self._redis_client.scan_iter(f"{vuln_prefix}*"):
                    key_str = key.decode() if isinstance(key, bytes) else str(key)
                    if not key_str.startswith(vuln_prefix):
                        continue
                    raw = await self._redis_client.get(key)
                    if not raw:
                        continue
                    try:
                        data = json.loads(raw)
                    except Exception as e:
                        logger.debug(f"Failed to parse vulnerability data for {key_str}: {e}")
                        continue
                    vuln_id = key_str[len(vuln_prefix) :]
                    if vuln_id in discovered:
                        continue
                    vuln_type = data.get("type", "unknown")
                    target = data.get("target", "unknown")
                    # Skip if we already have a vulnerability with same (type, target)
                    type_target_key = (vuln_type, target)
                    if type_target_key in seen_type_target:
                        logger.debug(
                            f"Skipping duplicate vulnerability {vuln_id} - "
                            f"already have {vuln_type} for {target}"
                        )
                        continue
                    seen_type_target.add(type_target_key)
                    discovered_by = data.get("discovered_by", "unknown")
                    details = data.get("details") or {}
                    priority = self._vulnerability_priorities.get(vuln_type, 99)
                    discovered_at = datetime.now(timezone.utc)
                    queued_at = data.get("queued_at")
                    if queued_at:
                        try:
                            discovered_at = datetime.fromisoformat(str(queued_at))
                        except Exception:
                            pass
                    discovered[vuln_id] = VulnerabilityInfo(
                        vuln_id=vuln_id,
                        vuln_type=vuln_type,
                        target=target,
                        discovered_by=discovered_by,
                        discovered_at=discovered_at,
                        details=details,
                        priority=priority,
                    )

                key_prefix = f"ares:operation:{self.shared_state.operation_id}:exploited:"
                async for key in self._redis_client.scan_iter(f"{key_prefix}*"):
                    key_str = key.decode() if isinstance(key, bytes) else str(key)
                    if not key_str.startswith(key_prefix):
                        continue
                    raw = await self._redis_client.get(key)
                    if not raw:
                        continue
                    try:
                        data = json.loads(raw)
                    except Exception as e:
                        logger.debug(f"Failed to parse exploit status for {key_str}: {e}")
                        continue
                    vuln_id = key_str[len(key_prefix) :]
                    if data.get("success"):
                        succeeded.add(vuln_id)
                    else:
                        failed[vuln_id] = data
            except Exception as e:
                logger.warning(f"Failed to load exploitation status from Redis: {e}")

        failed_ids = set(failed.keys())

        return {
            "total_discovered": len(discovered),
            "total_succeeded": len(succeeded),
            "total_failed": len(failed),
            "pending": [
                {"id": vid, "type": v.vuln_type, "target": v.target}
                for vid, v in discovered.items()
                if vid not in succeeded and vid not in failed_ids
            ],
            "succeeded": [
                {"id": vid, "type": discovered[vid].vuln_type, "target": discovered[vid].target}
                for vid in discovered
                if vid in succeeded
            ],
            "failed": [
                {
                    "id": vid,
                    "type": discovered[vid].vuln_type if vid in discovered else "unknown",
                    "target": discovered[vid].target if vid in discovered else "unknown",
                    "error": failed.get(vid, {}).get("result", {}).get("error")
                    or failed.get(vid, {}).get("error")
                    or "Unknown error",
                }
                for vid in failed
            ],
        }

    def get_throttle_status(self: RedTeamDispatcher) -> dict[str, Any]:
        """Get throttling and deferred queue status for monitoring.

        Returns dict with:
            - llm_task_count: Current number of LLM tasks in flight
            - max_concurrent_tasks: Configured limit
            - deferred_queue: Status of deferred task queue
            - phase: Current operation phase
        """
        from ares.core.config import get_max_concurrent_tasks

        deferred_status = self.get_deferred_queue_status()
        phase = self._get_operation_phase()

        return {
            "max_concurrent_tasks": get_max_concurrent_tasks(),
            "phase": phase,
            "deferred_queue": deferred_status,
        }


__all__ = ["StatusMixin"]
