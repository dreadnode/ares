"""Rate limiting and phase detection for task dispatch.

This module provides throttling logic to prevent overwhelming the LLM API
and phase-aware priority adjustments based on operation progress.
"""

from __future__ import annotations

import asyncio
import threading
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

    # Type annotation for lazy-init lock (allows None before first use)
    _throttle_lock: asyncio.Lock | None

    # Task types that don't use LLM (shouldn't count against LLM rate limit)
    # - crack: runs hashcat/john directly
    # - command: direct shell execution for remote ops
    NON_LLM_TASK_TYPES = frozenset({"crack", "command"})

    # Task types that bypass hard cap throttling (critical path to DA)
    # These still use LLM and count against limits, but won't be deferred at hard cap
    # NOTE: "exploit" alone is too broad - MSSQL impersonation is lower value than delegation.
    # Use CRITICAL_PATH_VULN_TYPES for fine-grained control of which exploit subtypes bypass.
    # NOTE: privesc_enumeration removed - it discovers vulns but doesn't exploit them.
    # Letting enumeration bypass hard cap starves lateral movement and credential access.
    CRITICAL_PATH_TASK_TYPES = frozenset({"exploit"})

    # Maximum number of tasks that can bypass hard cap at once
    # Prevents runaway task accumulation when workers can't keep up
    MAX_BYPASS_TASKS = 3

    # High-value exploit subtypes that should bypass hard cap (checked via vuln_type in payload)
    # - constrained_delegation: S4U attack → impersonate Administrator → secretsdump → DA
    # - unconstrained_delegation: TGT capture → DCSync → DA
    # - esc1, esc4, esc8: ADCS attacks → domain user cert → DA
    # - krbtgt_hash: already have DA material
    # - mssql_cross_forest_pivot: linked server RCE into foreign forest (may be ONLY path)
    # MSSQL (other): Only critical in multi-forest mode (may be the ONLY path to foreign forest)
    CRITICAL_PATH_VULN_TYPES = frozenset(
        {
            "constrained_delegation",
            "unconstrained_delegation",
            "esc1",
            "esc4",
            "esc8",
            "krbtgt_hash",
            "adcs_esc1",
            "adcs_esc4",
            "adcs_esc8",
            "mssql_cross_forest_pivot",
            "trust_raise_child",
        }
    )

    # MSSQL exploit subtypes - elevated to critical path in multi-forest mode only
    # (cross-forest Kerberos is broken in impacket, MSSQL linked servers may be the only pivot)
    MSSQL_VULN_TYPES = frozenset(
        {"mssql_impersonation", "mssql_linked_server", "mssql_linked", "mssql_cross_forest_pivot"}
    )

    # ESC8-related techniques that should bypass hard cap when dispatched as coercion tasks
    # ESC8 is a critical path to DA via ADCS web enrollment relay
    ESC8_COERCION_TECHNIQUES = frozenset({"ntlmrelayx_to_adcs", "petitpotam"})

    def _get_throttle_lock(self: RedTeamDispatcher) -> asyncio.Lock:
        """Get or create the throttle lock (lazy init for event loop safety)."""
        lock = self._throttle_lock
        if lock is None:
            lock = asyncio.Lock()
            self._throttle_lock = lock
        return lock

    async def _get_pending_task_count(self: RedTeamDispatcher) -> int:
        """Get the number of pending/in-progress tasks."""
        if not self._shared_state:
            return 0
        # Clean up phantom empty-string task from throttle drops
        self._shared_state.pending_tasks.pop("", None)
        pending = len(self._shared_state.pending_tasks)
        # Snapshot to avoid "dict changed size during iteration"
        in_progress = sum(
            1
            for t in list(self._shared_state.pending_tasks.values())
            if t.status == TaskStatus.IN_PROGRESS
        )
        return pending + in_progress

    async def _get_pending_count_by_role(self: RedTeamDispatcher, role: str) -> int:
        """Get pending/in-progress task count for a specific role."""
        if not self._shared_state:
            return 0
        # Snapshot to avoid "dict changed size during iteration"
        return sum(
            1
            for t in list(self._shared_state.pending_tasks.values())
            if t.assigned_agent == role and t.status in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS)
        )

    async def _get_queue_length(self: RedTeamDispatcher, role: str, task_queue: Any = None) -> int:
        """Get Redis queue length for a specific role (tasks waiting to be picked up).

        Args:
            role: Worker role (e.g., "privesc", "lateral")
            task_queue: Optional task queue to use (threaded consumer passes its own)
        """
        # Use passed task_queue (from threaded consumer) or fall back to self._task_queue
        effective_queue = task_queue if task_queue is not None else self._task_queue
        if not effective_queue or not effective_queue._client:
            return 0
        try:
            urgent_key = f"ares:stream:tasks:{role}:urgent"
            normal_key = f"ares:stream:tasks:{role}:normal"
            urgent_len = await effective_queue._client.xlen(urgent_key)
            normal_len = await effective_queue._client.xlen(normal_key)
            return urgent_len + normal_len
        except Exception as e:
            logger.debug(f"Failed to get queue length for {role}: {e}")
            return 0

    async def _get_llm_task_count(self: RedTeamDispatcher) -> int:
        """Get count of pending LLM-using tasks (excludes crack, command)."""
        if not self._shared_state:
            return 0
        # Snapshot to avoid "dict changed size during iteration"
        return sum(
            1
            for t in list(self._shared_state.pending_tasks.values())
            if t.task_type not in self.NON_LLM_TASK_TYPES
            and t.status in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS)
        )

    async def _check_llm_throttle_drop(
        self: RedTeamDispatcher,
        task_type: str,
        target_role: str,
        reason: str,
        payload: dict[str, Any] | None = None,
    ) -> bool:
        """
        Check if an LLM task should be dropped due to throttling.

        Args:
            task_type: Type of task (e.g., "exploit", "recon")
            target_role: Target worker role
            reason: Reason for throttle check (for logging)
            payload: Optional task payload for fine-grained exploit type checking

        Returns True if the task should be dropped, False if it should proceed.
        """
        # Non-LLM tasks (crack, command) don't hit rate limits - always allow
        if task_type in self.NON_LLM_TASK_TYPES:
            logger.debug(
                f"Throttle at {reason} but ALLOWING {task_type} task "
                f"(non-LLM task, no rate limit impact)"
            )
            return False

        # LLM task - apply throttling rules
        role_pending = await self._get_pending_count_by_role(target_role)
        llm_count = await self._get_llm_task_count()
        max_tasks = get_max_concurrent_tasks()

        # HARD CAP: If we're 1.5x over the limit, DEFER most tasks
        # Exception: High-value exploit subtypes bypass hard cap (not all exploits)
        # BUT limit total bypass tasks to prevent runaway accumulation
        hard_cap = int(max_tasks * 1.5)
        if llm_count >= hard_cap:
            # Check if this is a critical path exploit (delegation, ADCS)
            vuln_type = (payload.get("vuln_type") or "").lower() if payload else ""
            is_critical_exploit = (
                task_type in self.CRITICAL_PATH_TASK_TYPES
                and vuln_type in self.CRITICAL_PATH_VULN_TYPES
            )

            # Demote exploits targeting already-dominated domains — they're redundant
            # and waste bypass slots that cross-forest pivots need
            if is_critical_exploit and self._shared_state:
                target_domain = (payload.get("domain") or "").lower() if payload else ""
                if not target_domain:
                    # Try to infer from target_ip
                    target_ips = payload.get("target_ips", []) if payload else []
                    tip = (
                        target_ips[0]
                        if target_ips
                        else ((payload.get("target_ip") or "") if payload else "")
                    )
                    if tip:
                        for h in self._shared_state.all_hosts:
                            if h.ip == tip and h.hostname and "." in h.hostname:
                                target_domain = ".".join(h.hostname.lower().split(".")[1:])
                                break
                da_domains = {d.lower() for d in self._shared_state.domain_admin_domains}
                if target_domain and target_domain in da_domains:
                    # Check parent domains too (north.sevenkingdoms.local → sevenkingdoms.local)
                    is_dominated = True
                elif target_domain:
                    # Check if target is a child of a dominated domain
                    is_dominated = any(target_domain.endswith("." + d) for d in da_domains)
                else:
                    is_dominated = False
                if is_dominated and vuln_type != "mssql_cross_forest_pivot":
                    logger.debug(
                        f"Throttle: demoting {vuln_type} on {target_domain} "
                        f"(DA already achieved — saving bypass slots for undominated forests)"
                    )
                    is_critical_exploit = False

            # In multi-forest mode, MSSQL exploits become critical path
            # (cross-forest Kerberos broken in impacket - MSSQL may be only pivot)
            if (
                not is_critical_exploit
                and task_type in self.CRITICAL_PATH_TASK_TYPES
                and vuln_type in self.MSSQL_VULN_TYPES
            ):
                from ares.core.config import get_multi_forest_mode

                if (
                    get_multi_forest_mode()
                    and self._shared_state
                    and not self._shared_state.all_forests_dominated()
                ):
                    is_critical_exploit = True

            # Also check for delegation enumeration - these discover constrained delegation
            # which is a critical path to DA. Without this, find_delegation tasks get deferred
            # for 60s+ and can be evicted from deferred queue before processing.
            techniques = payload.get("techniques", []) if payload else []
            is_delegation_enum = task_type == "privesc_enumeration" and any(
                "delegation" in t.lower() for t in techniques
            )

            # Check for ESC8-related coercion tasks (ntlmrelayx_to_adcs, petitpotam)
            # ESC8 is a critical path to DA via ADCS web enrollment relay, but is
            # dispatched as coercion tasks rather than exploit tasks
            is_esc8_coercion = task_type == "coercion" and any(
                t.lower() in self.ESC8_COERCION_TECHNIQUES for t in techniques
            )

            # mssql_cross_forest_pivot is the highest priority — it may be the ONLY
            # path to the foreign forest. Always bypass, even above MAX_BYPASS_TASKS.
            is_cross_forest_pivot = (
                task_type in self.CRITICAL_PATH_TASK_TYPES
                and vuln_type == "mssql_cross_forest_pivot"
            )
            multi_forest_mssql_critical = is_cross_forest_pivot or (
                task_type in self.CRITICAL_PATH_TASK_TYPES
                and vuln_type in self.MSSQL_VULN_TYPES
                and vuln_type not in self.CRITICAL_PATH_VULN_TYPES
                and is_critical_exploit
            )

            if is_critical_exploit or is_delegation_enum or is_esc8_coercion:
                # Count how many tasks are already bypassing hard cap
                bypass_count = llm_count - hard_cap
                if bypass_count >= self.MAX_BYPASS_TASKS and not multi_forest_mssql_critical:
                    # Already have MAX_BYPASS_TASKS above hard cap - defer this one too
                    if is_critical_exploit:
                        bypass_reason = f"{task_type}/{vuln_type}"
                    elif is_esc8_coercion:
                        bypass_reason = f"{task_type}/esc8_relay"
                    else:
                        bypass_reason = f"{task_type}/find_delegation"
                    logger.warning(
                        f"Throttle HARD CAP: {llm_count} running (limit: {max_tasks}, hard cap: {hard_cap}) - "
                        f"DEFERRING {bypass_reason} (already {bypass_count} bypass tasks, max={self.MAX_BYPASS_TASKS})"
                    )
                    return True

                if is_critical_exploit:
                    bypass_reason = f"{task_type}/{vuln_type}"
                elif is_esc8_coercion:
                    bypass_reason = f"{task_type}/esc8_relay"
                else:
                    bypass_reason = f"{task_type}/find_delegation"
                if multi_forest_mssql_critical and bypass_count >= self.MAX_BYPASS_TASKS:
                    logger.warning(
                        f"Throttle HARD CAP: {llm_count} running (limit: {max_tasks}, hard cap: {hard_cap}) - "
                        f"ALLOWING {bypass_reason} (multi-forest MSSQL critical path bypassed cap)"
                    )
                    return False
                logger.info(
                    f"Throttle HARD CAP: {llm_count} running (limit: {max_tasks}, hard cap: {hard_cap}) - "
                    f"ALLOWING {bypass_reason} (high-value DA path, bypass {bypass_count + 1}/{self.MAX_BYPASS_TASKS})"
                )
                return False

            # Not a critical path task - defer it
            task_desc = f"{task_type}/{vuln_type}" if vuln_type else task_type
            logger.warning(
                f"Throttle HARD CAP: {llm_count} running (limit: {max_tasks}, hard cap: {hard_cap}) - "
                f"DEFERRING {task_desc} (1.5x over limit)"
            )
            return True

        # SOFT CAP: If we're over the limit but under hard cap, apply selective throttling
        # Allow through if role needs minimum slots OR task has high priority
        if llm_count >= max_tasks:
            # Guarantee each role has at least min_slots_per_role tasks
            if role_pending < get_min_slots_per_role():
                logger.info(
                    f"Throttle SOFT CAP: {llm_count} running (limit: {max_tasks}) - ALLOWING {task_type} for {target_role} "
                    f"(role has {role_pending} pending, min={get_min_slots_per_role()})"
                )
                return False

            # Check phase priority - only high priority tasks get through
            phase = self._get_operation_phase()
            adjustment = self._get_phase_priority_adjustment(task_type, target_role)
            if adjustment < 0:  # Negative = high priority for current phase
                logger.info(
                    f"Throttle SOFT CAP: {llm_count} running (limit: {max_tasks}) - ALLOWING {task_type} "
                    f"(high priority adj={adjustment} in {phase} phase)"
                )
                return False

            # At capacity and not high priority - defer
            logger.debug(
                f"Throttle SOFT CAP: {llm_count} running (limit: {max_tasks}) - DEFERRING {task_type} "
                f"({phase} phase, priority adj={adjustment})"
            )
            return True

        # Below soft cap - use original role-based logic
        # Guarantee each role has at least min_slots_per_role tasks
        if role_pending < get_min_slots_per_role():
            logger.info(
                f"Throttle at {reason} but ALLOWING {task_type} task for {target_role} "
                f"(role has {role_pending} pending, min={get_min_slots_per_role()})"
            )
            return False

        # Role already has tasks queued - check phase priority
        phase = self._get_operation_phase()
        adjustment = self._get_phase_priority_adjustment(task_type, target_role)

        # In domain_dominance phase, only allow high-priority tasks
        if phase == "domain_dominance" and adjustment >= 0:
            logger.debug(
                f"Throttle at {reason} - DEFERRING {task_type} task "
                f"(domain_dominance phase, low priority adj={adjustment})"
            )
            return True

        # In other phases, defer only clearly low-priority tasks (adj > 1)
        if adjustment > 1:
            logger.debug(
                f"Throttle at {reason} - DEFERRING {task_type} task "
                f"({phase} phase, low priority adj={adjustment})"
            )
            return True

        logger.info(
            f"Throttle at {reason} but ALLOWING {task_type} task "
            f"({phase} phase, priority adj={adjustment})"
        )
        return False

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
                # CREDENTIAL_ACCESS critical (secretsdump feeds lateral), LATERAL growing
                "exploit": -2,  # 0.35 - S4U, ESC1/4/8, MSSQL impersonation
                "acl_analysis": -2,  # 0.25 - shadow creds, password resets
                "credential_access": -2,  # 0.20 - secretsdump owned hosts → feeds lateral
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
        task_queue: Any = None,
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
            task_queue: Optional task queue for direct dispatch (threaded consumer passes its own).

        Returns:
            Task ID if submitted, empty string on failure
        """
        # HALT: If DA achieved, reject new tasks UNLESS multi-forest mode is active
        # and other forests remain undominated
        if self._shared_state and self._shared_state.has_domain_admin:
            from ares.core.config import get_multi_forest_mode

            if get_multi_forest_mode() and not self._shared_state.all_forests_dominated():
                # Multi-forest mode: continue accepting tasks to attack other forests
                pass
            else:
                logger.debug(
                    f"Rejecting {task_type} task - Domain Admin achieved, halting new tasks"
                )
                return ""

        # Check if this is a critical path task BEFORE the threading check
        # Critical path tasks can be dispatched directly from threaded consumer
        techniques = payload.get("techniques", []) if payload else []
        is_delegation_enum = task_type == "privesc_enumeration" and any(
            "delegation" in t.lower() for t in techniques
        )
        vuln_type = (payload.get("vuln_type") or "").lower() if payload else ""
        is_critical_exploit = (
            task_type in self.CRITICAL_PATH_TASK_TYPES
            and vuln_type in self.CRITICAL_PATH_VULN_TYPES
        )
        # In multi-forest mode, MSSQL exploits become critical path
        if (
            not is_critical_exploit
            and task_type in self.CRITICAL_PATH_TASK_TYPES
            and vuln_type in self.MSSQL_VULN_TYPES
        ):
            from ares.core.config import get_multi_forest_mode

            if (
                get_multi_forest_mode()
                and self._shared_state
                and not self._shared_state.all_forests_dominated()
            ):
                is_critical_exploit = True
        is_esc8_coercion = task_type == "coercion" and any(
            t.lower() in self.ESC8_COERCION_TECHNIQUES for t in techniques
        )
        is_critical_path = is_delegation_enum or is_critical_exploit or is_esc8_coercion

        # When called from non-main thread (threaded consumer):
        # - If task_queue is provided AND task is critical path, dispatch directly
        #   This prevents freezes when main loop is blocked on LLM calls
        # - Otherwise queue for main loop to avoid asyncio cross-loop errors
        if threading.current_thread() is not threading.main_thread():
            if task_queue is not None and is_critical_path:
                # CRITICAL PATH: Bypass throttling and dispatch directly from threaded consumer
                # These tasks (delegation checks, S4U exploits) are DA-critical and shouldn't
                # wait for the main loop which may be blocked on slow LLM API calls
                logger.info(
                    f"🚀 Direct dispatch from threaded consumer: {task_type} -> {target_role} "
                    f"(delegation_enum={is_delegation_enum}, critical_exploit={is_critical_exploit})"
                )
                return await task_queue.submit_task(
                    task_type=task_type,
                    target_role=target_role,
                    payload=payload,
                    source_agent=source_agent,
                    priority=priority,
                )
            # Non-critical: queue for main loop to use proper throttling
            with self._pending_dispatch_lock:
                self._pending_dispatches.append(
                    (task_type, target_role, payload.copy(), source_agent, priority, max_wait)
                )
            self._dispatch_requested.set()
            logger.debug(
                f"Queued task dispatch for main loop: {task_type} -> {target_role} "
                f"(priority {priority})"
            )
            return "queued"  # Task accepted for dispatch on main loop

        # Use provided task_queue (from threaded consumer) or fall back to self._task_queue
        effective_task_queue = task_queue if task_queue is not None else self._task_queue
        if not effective_task_queue:
            logger.warning("No task queue available for throttled submit")
            return ""

        # Don't bury tasks in a role stream with no active consumer. If the target
        # role is registered but currently offline, keep the task in the deferred
        # queue so it remains visible and can be submitted when the worker returns.
        role_health = self.get_role_health(target_role)
        if role_health.get("is_registered") and role_health.get("online_count", 0) == 0:
            logger.warning(
                f"Target role {target_role} is offline "
                f"(stale agents: {role_health.get('stale_agents', [])}) - "
                f"deferring {task_type} task until a worker is online"
            )
            queued = await self._enqueue_deferred_task(
                task_type=task_type,
                target_role=target_role,
                payload=payload,
                source_agent=source_agent,
                priority=priority,
            )
            return "deferred" if queued else ""

        start_wait = asyncio.get_event_loop().time()
        total_waited = 0.0

        # FAILSAFE: If target worker is idle (queue empty), skip throttle wait entirely.
        # No point burning time waiting when the worker has nothing to do.
        # Check WITHOUT holding lock to avoid blocking other tasks.
        # Pass effective_task_queue to use thread's Redis client when called from threaded consumer
        role_queue_len = await self._get_queue_length(target_role, effective_task_queue)
        role_pending = await self._get_pending_count_by_role(target_role)

        # Skip wait loop for critical path tasks (already computed above)

        if role_queue_len == 0 and role_pending == 0:
            logger.debug(
                f"Bypassing throttle for {task_type} - {target_role} worker is idle "
                f"(queue={role_queue_len}, pending={role_pending})"
            )
            # Skip directly to submit (acquire lock below)
        elif is_critical_path:
            logger.debug(f"Bypassing throttle wait for {task_type} - critical path task")
            # Skip directly to submit - critical path tasks bypass 60s wait loop
        else:
            # Wait loop - DO NOT hold the lock during sleep to avoid deadlock.
            # Multiple tasks waiting for the lock while one sleeps causes timeout.
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

        # Acquire lock only for the final check and submit - this is the critical section
        async with self._get_throttle_lock():
            # Final check - smart throttling to balance worker utilization
            should_wait, _, reason = await self._should_throttle()
            if should_wait and "max concurrent tasks" in reason:
                drop_task = await self._check_llm_throttle_drop(
                    task_type, target_role, reason, payload=payload
                )
                if drop_task:
                    # Instead of dropping, queue for later dispatch
                    adjusted_priority = priority + self._get_phase_priority_adjustment(
                        task_type, target_role
                    )
                    adjusted_priority = max(1, min(10, adjusted_priority))

                    queued = await self._enqueue_deferred_task(
                        task_type=task_type,
                        target_role=target_role,
                        payload=payload,
                        source_agent=source_agent,
                        priority=adjusted_priority,
                    )
                    # Return "deferred" marker so callers can distinguish from dropped tasks
                    # The deferred queue processor will submit this task when slots open up
                    if queued:
                        return "deferred"  # Task queued, will be processed later
                    # Queue rejected the task (full with higher priority tasks)
                    logger.warning(
                        f"Task {task_type} for {target_role} dropped - "
                        f"throttled and deferred queue rejected"
                    )
                    return ""

            # Apply phase-aware priority adjustment
            adjusted_priority = priority + self._get_phase_priority_adjustment(
                task_type, target_role
            )
            # Clamp to valid range (1-10)
            adjusted_priority = max(1, min(10, adjusted_priority))

            # Update last dispatch time
            self._last_dispatch_time = asyncio.get_event_loop().time()

            # Submit the task (call underlying queue directly, not recursively)
            return await effective_task_queue.submit_task(
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
