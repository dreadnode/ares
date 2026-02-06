"""Rate limiting and phase detection for task dispatch.

This module provides throttling logic to prevent overwhelming the LLM API
and phase-aware priority adjustments based on operation progress.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.config import (
    get_lateral_movement_admin_creds_threshold,
    get_lateral_movement_owned_hosts_threshold,
    get_max_concurrent_tasks,
    get_min_slots_per_role,
    get_rate_limit_backoff,
    get_rate_limit_threshold,
    get_task_dispatch_delay,
)
from ares.core.models import TaskStatus

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher


class ThrottlingMixin:
    """Rate limiting and phase detection for task dispatch."""

    # Task types that don't use LLM (shouldn't count against LLM rate limit)
    # - crack: runs hashcat/john directly
    # - command: direct shell execution for remote ops
    NON_LLM_TASK_TYPES = frozenset({"crack", "command"})

    async def _get_pending_task_count(self: RedTeamDispatcher) -> int:
        """Get the number of pending/in-progress tasks."""
        if not self._shared_state:
            return 0
        # Clean up phantom empty-string task from throttle drops
        self._shared_state.pending_tasks.pop("", None)
        self._redis_task_ids.discard("")
        pending = len(self._shared_state.pending_tasks)
        in_progress = sum(
            1
            for t in self._shared_state.pending_tasks.values()
            if t.status == TaskStatus.IN_PROGRESS
        )
        return pending + in_progress

    async def _get_pending_count_by_role(self: RedTeamDispatcher, role: str) -> int:
        """Get pending/in-progress task count for a specific role."""
        if not self._shared_state:
            return 0
        return sum(
            1
            for t in self._shared_state.pending_tasks.values()
            if t.assigned_agent == role and t.status in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS)
        )

    async def _get_llm_task_count(self: RedTeamDispatcher) -> int:
        """Get count of pending LLM-using tasks (excludes crack, command)."""
        if not self._shared_state:
            return 0
        return sum(
            1
            for t in self._shared_state.pending_tasks.values()
            if t.task_type not in self.NON_LLM_TASK_TYPES
            and t.status in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS)
        )

    def _get_operation_phase(self: RedTeamDispatcher) -> str:
        """
        Determine current engagement phase from state.

        Uses heuristics from expert red team analysis (see PRIORITY.md).
        Logs phase transitions for observability.

        Returns:
            'initial_access' - No creds yet, scanning/poisoning
            'enumeration' - First valid creds, BloodHound/Kerberoast
            'privilege_escalation' - Vulns identified, paths available
            'lateral_movement' - Multiple admin creds, expanding footprint
            'domain_dominance' - Path to DA or post-DA
        """
        phase = self._detect_phase_internal()

        # Log phase transitions
        if phase != self._last_phase:
            logger.info(f"Operation phase transition: {self._last_phase} → {phase}")
            self._last_phase = phase

        return phase

    def _detect_phase_internal(self: RedTeamDispatcher) -> str:
        """Internal phase detection logic."""
        if not self._shared_state:
            return "initial_access"

        state = self._shared_state

        # Phase 5: Domain Dominance - have DA or krbtgt
        if state.has_domain_admin or state.has_golden_ticket or state.completed:
            return "domain_dominance"

        # Check for krbtgt or Administrator hash (imminent DA)
        for h in state.all_hashes:
            if h.username and h.username.lower() in ("krbtgt", "administrator"):
                return "domain_dominance"

        # Phase 4: Lateral Movement - multiple admin creds, expanding footprint
        admin_creds = [c for c in state.all_credentials if c.is_admin]
        owned_hosts = len([h for h in state.all_hosts if h.owned])
        if (
            len(admin_creds) >= get_lateral_movement_admin_creds_threshold()
            or owned_hosts >= get_lateral_movement_owned_hosts_threshold()
        ):
            return "lateral_movement"

        # Phase 3: Privilege Escalation - vulns identified or have admin creds
        if state.discovered_vulnerabilities or admin_creds:
            return "privilege_escalation"

        # Phase 2: Enumeration - have valid creds
        if state.all_credentials or state.all_hashes:
            return "enumeration"

        # Phase 1: Initial Access - no creds yet
        return "initial_access"

    def _get_phase_priority_adjustment(
        self: RedTeamDispatcher, task_type: str, target_role: str
    ) -> int:
        """
        Get priority adjustment based on operation phase.

        Based on expert red team analysis (see PRIORITY.md).
        Lower values = higher priority. Returns adjustment to add to base priority.

        Args:
            task_type: Type of task (e.g., 'recon', 'exploit', 'lateral')
            target_role: Target worker role (fallback if task_type not in matrix)

        Returns:
            Priority adjustment (-3 to +3, negative = boost, positive = lower priority)

        Note:
            If task_type is not found in the phase matrix, falls back to target_role.
            If neither found, returns 0 (neutral priority). This handles new task types
            gracefully without requiring matrix updates for every new type.
        """
        phase = self._get_operation_phase()

        # Phase-aware priority matrix based on PRIORITY.md weights
        # Weights converted to adjustments: 0.35+ = -2, 0.20-0.34 = -1, 0.10-0.19 = 0,
        # 0.05-0.09 = +1, 0.00-0.04 = +2, explicit 0.00 = +3
        phase_adjustments: dict[str, dict[str, int]] = {
            "initial_access": {
                # RECON critical (scanning), COERCION critical (Responder)
                # CREDENTIAL_ACCESS limited (spray only), others useless
                "recon": -2,  # 0.40 - scanning, SMB signing, anon shares
                "coercion": -2,  # 0.35 - Responder for LLMNR/NBT-NS poisoning
                "credential_access": -1,  # 0.20 - password spray if usernames found
                "crack": +1,  # 0.05 - waiting for hashes
                "acl_analysis": +3,  # 0.00 - needs authenticated LDAP
                "exploit": +3,  # 0.00 - no foothold yet
                "privesc_enumeration": +3,  # 0.00 - no foothold
                "lateral": +3,  # 0.00 - no creds to move with
            },
            "enumeration": {
                # RECON critical (BloodHound), CREDENTIAL_ACCESS critical (Kerberoast)
                # CRACKER high (TGS hashes), COERCION high (relay)
                "credential_access": -2,  # 0.35 - Kerberoast, AS-REP, GPP
                "recon": -2,  # 0.30 - BloodHound, LDAP enum, Certipy find
                "crack": -1,  # 0.15 - crack TGS/AS-REP hashes
                "coercion": 0,  # 0.10 - NTLM relay to LDAP/ADCS
                "acl_analysis": +1,  # 0.05 - analyze BloodHound paths
                "exploit": +1,  # 0.05 - scan for ADCS, delegation
                "privesc_enumeration": +1,  # 0.05 - vuln discovery
                "lateral": +2,  # 0.00 - limited, often low-priv creds
            },
            "privilege_escalation": {
                # PRIVESC critical (S4U, ESC1-8), ACL critical (WriteDACL)
                # CREDENTIAL_ACCESS high (secretsdump), LATERAL growing
                "exploit": -2,  # 0.35 - S4U, ESC1/4/8, MSSQL impersonation
                "acl_analysis": -2,  # 0.25 - shadow creds, password resets
                "credential_access": -1,  # 0.15 - secretsdump owned hosts
                "crack": 0,  # 0.10 - NTLM from secretsdump
                "lateral": 0,  # 0.10 - test new creds, expand footprint
                "coercion": +1,  # 0.05 - ESC8 relay, DC coercion
                "recon": +2,  # 0.00 - most discovery done
                "privesc_enumeration": +1,  # enum continues as part of exploit
            },
            "lateral_movement": {
                # LATERAL critical (PSExec everywhere), CREDENTIAL_ACCESS critical
                # CRACKER high (NTLM volume), PRIVESC situational
                "lateral": -2,  # 0.40 - PSExec/WMI/WinRM, secretsdump
                "credential_access": -2,  # 0.30 - secretsdump each host
                "crack": -1,  # 0.15 - high volume of NTLM hashes
                "exploit": 0,  # 0.10 - new delegation paths, MSSQL
                "acl_analysis": +1,  # 0.05 - usually paths exhausted
                "coercion": +2,  # 0.00 - mostly done
                "recon": +2,  # 0.00 - environment well-mapped
                "privesc_enumeration": +1,  # situational
            },
            "domain_dominance": {
                # PRIVESC critical (Golden Ticket, DCSync), LATERAL high (DC access)
                # CREDENTIAL_ACCESS high (DC dump), others minimal
                "exploit": -2,  # 0.40 - Golden Ticket, DCSync, krbtgt
                "lateral": -2,  # 0.30 - access DC, validate DA
                "credential_access": -1,  # 0.25 - secretsdump DC, NTDS.dit
                "crack": +1,  # 0.05 - usually have what we need
                "acl_analysis": +2,  # 0.00 - already have DA
                "coercion": +2,  # 0.00 - already have DA
                "recon": +2,  # 0.00 - already have DA
                "privesc_enumeration": +2,  # 0.00 - DA achieved
            },
        }

        adjustments = phase_adjustments.get(phase, {})
        return adjustments.get(task_type, adjustments.get(target_role, 0))

    async def _should_throttle(self: RedTeamDispatcher) -> tuple[bool, float, str]:
        """
        Check if task dispatch should be throttled.

        Returns:
            Tuple of (should_wait, wait_seconds, reason)
        """
        now = asyncio.get_event_loop().time()

        # Check global backoff (rate limit triggered)
        if now < self._global_backoff_until:
            wait_time = self._global_backoff_until - now
            return (True, wait_time, "global rate limit backoff")

        # Check concurrent LLM task limit (non-LLM tasks like crack don't count)
        # This prevents rate limit storms while allowing non-LLM workers to stay busy
        max_tasks = get_max_concurrent_tasks()
        llm_task_count = await self._get_llm_task_count()
        if llm_task_count >= max_tasks:
            return (True, 2.0, f"max concurrent tasks ({llm_task_count}/{max_tasks} LLM tasks)")

        # Check dispatch delay
        dispatch_delay = get_task_dispatch_delay()
        time_since_last = now - self._last_dispatch_time
        if time_since_last < dispatch_delay:
            wait_time = dispatch_delay - time_since_last
            return (True, wait_time, "dispatch delay")

        return (False, 0.0, "")

    async def _throttled_submit_task(
        self: RedTeamDispatcher,
        task_type: str,
        target_role: str,
        payload: dict[str, Any],
        source_agent: str,
        priority: int = 5,
        max_wait: float = 60.0,
    ) -> str:
        """
        Submit a task with throttling to prevent overwhelming the LLM API.

        Args:
            task_type: Type of task (e.g., "exploit", "recon")
            target_role: Role to route to (e.g., "privesc", "lateral")
            payload: Task payload dict
            source_agent: Agent requesting the task
            priority: Task priority (lower = higher priority)
            max_wait: Maximum time to wait for throttle to clear

        Returns:
            Task ID if submitted, empty string on failure
        """
        if not self._task_queue:
            logger.warning("No task queue available for throttled submit")
            return ""

        async with self._throttle_lock:
            start_wait = asyncio.get_event_loop().time()
            total_waited = 0.0

            while total_waited < max_wait:
                should_wait, wait_time, reason = await self._should_throttle()

                if not should_wait:
                    break

                # Cap wait time to remaining max_wait
                actual_wait = min(wait_time, max_wait - total_waited)
                if actual_wait <= 0:
                    break

                logger.debug(f"Throttling task dispatch: {reason}, waiting {actual_wait:.1f}s")
                await asyncio.sleep(actual_wait)
                total_waited = asyncio.get_event_loop().time() - start_wait

            # Final check - smart throttling to balance worker utilization
            should_wait, _, reason = await self._should_throttle()
            if should_wait and "max concurrent tasks" in reason:
                # Check if this role has any pending tasks
                role_pending = await self._get_pending_count_by_role(target_role)

                # Non-LLM tasks (crack, command) don't hit rate limits - always allow
                if task_type in self.NON_LLM_TASK_TYPES:
                    logger.debug(
                        f"Throttle at {reason} but ALLOWING {task_type} task "
                        f"(non-LLM task, no rate limit impact)"
                    )
                # Guarantee each role has at least min_slots_per_role tasks
                # This prevents worker starvation - no role is completely idle
                elif role_pending < get_min_slots_per_role():
                    logger.info(
                        f"Throttle at {reason} but ALLOWING {task_type} task for {target_role} "
                        f"(role has {role_pending} pending, min={get_min_slots_per_role()})"
                    )
                else:
                    # Role already has tasks queued - check phase priority
                    phase = self._get_operation_phase()
                    adjustment = self._get_phase_priority_adjustment(task_type, target_role)

                    # In domain_dominance phase, only allow high-priority tasks
                    # (exploit, lateral, credential_access for final DC dump)
                    if phase == "domain_dominance" and adjustment >= 0:
                        logger.debug(
                            f"Throttle at {reason} - DROPPING {task_type} task "
                            f"(domain_dominance phase, low priority adj={adjustment})"
                        )
                        return ""
                    # In other phases, drop only clearly low-priority tasks (adj > 1)
                    if adjustment > 1:
                        logger.debug(
                            f"Throttle at {reason} - DROPPING {task_type} task "
                            f"({phase} phase, low priority adj={adjustment})"
                        )
                        return ""
                    logger.info(
                        f"Throttle at {reason} but ALLOWING {task_type} task "
                        f"({phase} phase, priority adj={adjustment})"
                    )

            # Apply phase-aware priority adjustment
            adjusted_priority = priority + self._get_phase_priority_adjustment(
                task_type, target_role
            )
            # Clamp to valid range (1-10)
            adjusted_priority = max(1, min(10, adjusted_priority))

            # Update last dispatch time
            self._last_dispatch_time = asyncio.get_event_loop().time()

            # Submit the task (call underlying queue directly, not recursively)
            return await self._task_queue.submit_task(
                task_type=task_type,
                target_role=target_role,
                payload=payload,
                source_agent=source_agent,
                priority=adjusted_priority,
            )

    def record_rate_limit_error(self: RedTeamDispatcher) -> None:
        """
        Record a rate limit error and potentially trigger global backoff.

        Call this when a worker reports a rate limit error.
        """
        self._rate_limit_errors += 1
        threshold = get_rate_limit_threshold()

        if self._rate_limit_errors >= threshold:
            backoff = get_rate_limit_backoff()
            self._global_backoff_until = asyncio.get_event_loop().time() + backoff
            logger.warning(
                f"Rate limit threshold reached ({self._rate_limit_errors} errors), "
                f"applying {backoff}s global backoff"
            )
            # Reset error count after applying backoff
            self._rate_limit_errors = 0

    def clear_rate_limit_backoff(self: RedTeamDispatcher) -> None:
        """Clear rate limit state after successful task completion."""
        if self._rate_limit_errors > 0:
            self._rate_limit_errors = max(0, self._rate_limit_errors - 1)


__all__ = ["ThrottlingMixin"]
