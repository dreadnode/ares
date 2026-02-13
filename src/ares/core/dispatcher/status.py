"""Status query methods for dispatcher state.

This module provides methods to query pending tasks, agent status,
and exploitation progress.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, ClassVar

from loguru import logger

from ares.core.models import TaskInfo, VulnerabilityInfo

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher


class StatusMixin:
    """Status query methods for dispatcher state."""

    # Role-level circuit breaker tracking (class-level to persist across calls)
    # Tracks consecutive task failures per role to detect systemic issues
    _role_failure_counts: ClassVar[dict[str, int]] = {}
    _role_circuit_breaker_threshold: ClassVar[int] = 5  # Trips after 5 consecutive failures
    _role_circuit_breaker_tripped: ClassVar[set[str]] = set()
    _role_circuit_breaker_reset_time: ClassVar[dict[str, float]] = {}  # When CB can be reset
    _role_circuit_breaker_cooldown: ClassVar[float] = 300.0  # 5 minute cooldown after trip

    def get_pending_tasks(self: RedTeamDispatcher) -> list[TaskInfo]:
        """Get all pending tasks."""
        return list(self.shared_state.pending_tasks.values())

    def is_role_online(self: RedTeamDispatcher, role: str) -> bool:
        """Check if any workers are online for a given role.

        Args:
            role: Worker role name (e.g., "privesc", "recon", "lateral")

        Returns:
            True if at least one worker for this role is online/idle/busy
        """
        now = datetime.now(timezone.utc)
        stale_threshold = max(60, self._agent_heartbeat_timeout)

        for agent_info in self._agents.values():
            if agent_info.role.value.lower() == role.lower():
                # Check if heartbeat is fresh
                elapsed = (now - agent_info.last_heartbeat).total_seconds()
                if elapsed <= stale_threshold and agent_info.status != "offline":
                    return True
        return False

    def get_role_health(self: RedTeamDispatcher, role: str) -> dict[str, Any]:
        """Get comprehensive health status for a worker role.

        Args:
            role: Worker role name

        Returns:
            Dict with online status, circuit breaker state, and failure count
        """
        role_lower = role.lower()
        is_online = self.is_role_online(role)
        is_tripped = role_lower in StatusMixin._role_circuit_breaker_tripped
        failure_count = StatusMixin._role_failure_counts.get(role_lower, 0)

        # Check if cooldown has expired
        reset_time = StatusMixin._role_circuit_breaker_reset_time.get(role_lower, 0)
        cooldown_remaining = max(0, reset_time - time.monotonic())

        return {
            "role": role,
            "is_online": is_online,
            "circuit_breaker_tripped": is_tripped,
            "consecutive_failures": failure_count,
            "cooldown_remaining_seconds": cooldown_remaining,
            "can_dispatch": is_online and not is_tripped,
        }

    def record_role_task_success(self: RedTeamDispatcher, role: str) -> None:
        """Record a successful task completion for a role, resetting circuit breaker."""
        role_lower = role.lower()
        StatusMixin._role_failure_counts[role_lower] = 0

        # Reset circuit breaker if it was tripped and cooldown has passed
        if role_lower in StatusMixin._role_circuit_breaker_tripped:
            reset_time = StatusMixin._role_circuit_breaker_reset_time.get(role_lower, 0)
            if time.monotonic() >= reset_time:
                StatusMixin._role_circuit_breaker_tripped.discard(role_lower)
                logger.info(f"🔌 Role {role} circuit breaker reset after successful task")

    def record_role_task_failure(
        self: RedTeamDispatcher, role: str, is_circuit_breaker: bool = False
    ) -> None:
        """Record a task failure for a role, potentially tripping circuit breaker.

        Args:
            role: Worker role name
            is_circuit_breaker: True if this failure was due to worker circuit breaker
        """
        role_lower = role.lower()
        count = StatusMixin._role_failure_counts.get(role_lower, 0) + 1
        StatusMixin._role_failure_counts[role_lower] = count

        # Circuit breaker failures count more heavily
        if is_circuit_breaker:
            count += 2  # Triple count for circuit breaker failures

        if (
            count >= StatusMixin._role_circuit_breaker_threshold
            and role_lower not in StatusMixin._role_circuit_breaker_tripped
        ):
            StatusMixin._role_circuit_breaker_tripped.add(role_lower)
            StatusMixin._role_circuit_breaker_reset_time[role_lower] = (
                time.monotonic() + StatusMixin._role_circuit_breaker_cooldown
            )
            logger.warning(
                f"🔌 CIRCUIT BREAKER TRIPPED for role {role}! "
                f"{count} consecutive failures. "
                f"Suspending dispatches for {StatusMixin._role_circuit_breaker_cooldown}s"
            )

    def can_dispatch_to_role(self: RedTeamDispatcher, role: str) -> tuple[bool, str]:
        """Check if tasks can be dispatched to a role.

        Args:
            role: Worker role name

        Returns:
            Tuple of (can_dispatch, reason)
        """
        role_lower = role.lower()

        # Check if any workers are online
        if not self.is_role_online(role):
            return False, f"No workers online for role {role}"

        # Check circuit breaker
        if role_lower in StatusMixin._role_circuit_breaker_tripped:
            reset_time = StatusMixin._role_circuit_breaker_reset_time.get(role_lower, 0)
            remaining = max(0, reset_time - time.monotonic())
            if remaining > 0:
                return False, f"Circuit breaker tripped for {role}, {remaining:.0f}s remaining"
            # Cooldown expired - reset circuit breaker on next success
            # But still allow dispatch to test if role has recovered

        return True, "OK"

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
