"""Workflow automation for multi-agent red team operations.

This module provides automated workflows for credential expansion,
exploitation orchestration, and coordinated multi-agent attacks.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from loguru import logger

if TYPE_CHECKING:
    from ares.core.dispatcher import RedTeamDispatcher
    from ares.core.models import Credential, Host, SharedRedTeamState


@dataclass
class CredentialTestingTracker:
    """
    Track which credential/host combinations have been tested.

    This prevents redundant testing and ensures systematic coverage
    of all credential/host pairs during lateral movement.
    """

    tested_pairs: set[str] = field(default_factory=set)
    successful_pairs: set[str] = field(default_factory=set)
    failed_pairs: set[str] = field(default_factory=set)

    def _make_pair_id(self, credential: Credential, host: Host) -> str:
        """Generate unique ID for credential/host pair."""
        return f"{credential.username}@{credential.domain}:{host.ip}"

    def has_tested(self, credential: Credential, host: Host) -> bool:
        """Check if credential was tested against host."""
        pair_id = self._make_pair_id(credential, host)
        return pair_id in self.tested_pairs

    def mark_tested(self, credential: Credential, host: Host, success: bool = False) -> None:
        """Mark credential/host as tested."""
        pair_id = self._make_pair_id(credential, host)
        self.tested_pairs.add(pair_id)
        if success:
            self.successful_pairs.add(pair_id)
        else:
            self.failed_pairs.add(pair_id)

    def get_stats(self) -> dict[str, int]:
        """Get testing statistics."""
        return {
            "total_tested": len(self.tested_pairs),
            "successful": len(self.successful_pairs),
            "failed": len(self.failed_pairs),
        }


def _has_admin_access(state: SharedRedTeamState, host: Host) -> bool:
    """
    Check if we already have admin access on this host.

    Looks for successful secretsdump or admin credential for this host.
    """
    # Check compromised hosts tracking
    for cred in state.all_credentials:
        if cred.is_admin and (
            host.ip in cred.source or host.hostname.lower() in cred.source.lower()
        ):
            return True

    # Check completed tasks for successful secretsdump on this host
    for result in state.completed_tasks.values():
        if result.success and result.result:
            result_data = result.result
            if (
                isinstance(result_data, dict)
                and result_data.get("task_type") == "secretsdump"
                and result_data.get("target") == host.ip
            ):
                return True

    return False


def _collect_candidate_domains(state: SharedRedTeamState) -> set[str]:
    domains: set[str] = set()
    for domain in getattr(state, "all_domains", []):
        if domain:
            domains.add(domain)
    if state.target and state.target.domain:
        domains.add(state.target.domain)
    for cred in state.all_credentials:
        if cred.domain:
            domains.add(cred.domain)
    for user in state.all_users:
        if user.domain:
            domains.add(user.domain)
    return domains


def _select_domain_credential(state: SharedRedTeamState, domain: str) -> Credential | None:
    admin_first = [c for c in state.all_credentials if c.domain == domain and c.password]
    for cred in admin_first:
        if cred.is_admin:
            return cred
    return admin_first[0] if admin_first else None


def _is_child_domain(child_domain: str, parent_domain: str) -> bool:
    if not child_domain or not parent_domain:
        return False
    if child_domain == parent_domain:
        return False
    return child_domain.endswith(f".{parent_domain}")


async def credential_expansion_loop(  # noqa: PLR0912
    dispatcher: RedTeamDispatcher,
    max_iterations: int = 10,
    delay_between_tests: float = 5.0,
) -> CredentialTestingTracker:
    """
    Automatically test new credentials against all known hosts.

    Workflow:
    1. Get all credentials from shared state
    2. Get all hosts from shared state
    3. For each credential/host pair not yet tested:
       - Dispatch lateral movement request
       - If successful, secretsdump will harvest more credentials
    4. Repeat until no new credentials or max iterations reached

    Args:
        dispatcher: The RedTeamDispatcher instance
        max_iterations: Maximum number of expansion iterations
        delay_between_tests: Delay between tests to avoid overwhelming targets

    Returns:
        CredentialTestingTracker with test results
    """
    tracker = CredentialTestingTracker()
    from ares.core.models import Credential as RuntimeCredential

    iterations = 0

    logger.info("Starting credential expansion loop")

    while iterations < max_iterations:
        state = dispatcher.shared_state

        credentials = state.all_credentials
        hosts = state.all_hosts
        candidate_domains = _collect_candidate_domains(state)
        new_tests = 0
        tasks_dispatched: list[str] = []

        logger.info(
            f"Iteration {iterations + 1}: {len(credentials)} credentials, {len(hosts)} hosts"
        )

        for cred in credentials:
            if cred.domain:
                domain_variants = {cred.domain}
            elif cred.password:
                domain_variants = {d for d in candidate_domains if d}
            else:
                domain_variants = set()

            hash_value = None
            if cred.username:
                matching_hashes = [
                    h
                    for h in state.all_hashes
                    if h.username == cred.username and (not cred.domain or h.domain == cred.domain)
                ]
                if matching_hashes:
                    hash_value = matching_hashes[0].hash_value

            for host in hosts:
                if not host.ip:
                    logger.debug(
                        f"Skipping lateral movement for {host.hostname or 'unknown-host'}: missing host IP"
                    )
                    continue
                for domain_override in domain_variants:
                    test_cred = RuntimeCredential(
                        username=cred.username,
                        password=cred.password,
                        domain=domain_override,
                        source=cred.source,
                        is_admin=cred.is_admin,
                    )

                    if tracker.has_tested(test_cred, host):
                        continue

                    # Skip if we already have admin access on this host
                    if _has_admin_access(state, host):
                        tracker.mark_tested(test_cred, host, success=True)
                        continue

                    # Dispatch lateral movement test
                    task_id = await dispatcher.request_lateral_movement(
                        target_host=host.ip,
                        username=cred.username,
                        source_agent="orchestrator",
                        password=cred.password or None,
                        hash_value=hash_value,
                        domain=domain_override,
                    )

                    if task_id and task_id != "deferred":
                        tasks_dispatched.append(task_id)
                        new_tests += 1
                        logger.debug(
                            f"Dispatched lateral test: {domain_override}\\{cred.username} -> {host.ip}"
                        )
                    elif task_id == "deferred":
                        # Task queued to deferred queue - count it but don't wait for it
                        new_tests += 1
                        logger.debug(
                            f"Deferred lateral test: {domain_override}\\{cred.username} -> {host.ip}"
                        )

                    tracker.mark_tested(test_cred, host)

                    # Small delay to avoid overwhelming
                    await asyncio.sleep(delay_between_tests)

        if new_tests == 0:
            logger.info("No new credential/host combinations to test")
            break

        # Wait for dispatched tasks to complete (with timeout)
        # Use shorter timeout (45s) to fail fast and try more combinations
        logger.info(f"Waiting for {len(tasks_dispatched)} lateral movement tasks...")

        for task_id in tasks_dispatched:
            try:
                result = await dispatcher.wait_for_task(task_id, timeout=45.0)
                if result.get("success"):
                    # Find the credential/host pair and mark as successful
                    logger.success(f"Task {task_id} succeeded")
            except asyncio.TimeoutError:  # noqa: PERF203
                logger.warning(f"Task {task_id} timed out (45s) - continuing with next")

        iterations += 1
        logger.info(f"Iteration {iterations} complete. Stats: {tracker.get_stats()}")

    logger.info(
        f"Credential expansion complete after {iterations} iterations. "
        f"Final stats: {tracker.get_stats()}"
    )

    return tracker


async def exploitation_workflow(  # noqa: PLR0912
    dispatcher: RedTeamDispatcher,
    check_interval: float = 10.0,
    max_runtime: float = 7200.0,  # 2 hours default
    max_concurrent_exploits: int = 3,
) -> dict[str, Any]:
    """
    Main exploitation loop with parallel exploit execution.

    Continuously:
    1. Get next highest priority vulnerabilities (up to max_concurrent_exploits)
    2. Route to appropriate agents for parallel exploitation
    3. Monitor results and update state
    4. If exploitation yields credentials -> trigger credential expansion
    5. If Domain Admin achieved -> halt and report

    Args:
        dispatcher: The RedTeamDispatcher instance
        check_interval: Seconds between queue checks when empty
        max_runtime: Maximum runtime in seconds
        max_concurrent_exploits: Maximum concurrent exploits (default: 3)

    Returns:
        Summary of exploitation results
    """
    start_time = asyncio.get_event_loop().time()
    exploited_count = 0
    credentials_gained = 0

    # Track failures by vuln_type to skip stuck exploits
    failure_counts: dict[str, int] = {}
    max_failures_per_type = 3

    # Track retry counts per vulnerability (prevent infinite retry loops)
    retry_counts: dict[str, int] = {}
    max_retries_per_vuln = 2  # Allow 2 retries (3 total attempts)

    # Semaphore for parallel exploitation
    exploit_semaphore = asyncio.Semaphore(max_concurrent_exploits)

    # Track active exploit tasks
    active_tasks: set[asyncio.Task[None]] = set()

    # Track in-flight vuln IDs to prevent duplicate dispatches (token burn prevention)
    in_flight_vulns: set[str] = set()

    logger.info(
        f"Starting exploitation workflow with max {max_concurrent_exploits} concurrent exploits"
    )

    async def process_exploit(vuln: dict[str, Any]) -> None:
        """Process a single exploit with semaphore protection."""
        nonlocal exploited_count, credentials_gained

        vuln_type = vuln["type"]
        vuln_id = vuln["id"]

        async with exploit_semaphore:
            # Check for DA before starting (may have been achieved by parallel exploit)
            if dispatcher.shared_state.has_domain_admin:
                logger.debug(f"Skipping {vuln_id} - Domain Admin already achieved")
                return

            logger.info(f"Processing vulnerability: {vuln_type} on {vuln['target']}")

            # Route to appropriate agent with timeout (reduced from 16min to 5min)
            exploit_started = asyncio.get_event_loop().time()
            try:
                async with asyncio.timeout(300):  # 5 min total (was 16 min)
                    result = await _exploit_vulnerability(dispatcher, vuln)
            except asyncio.TimeoutError:
                logger.error(f"Exploitation of {vuln_id} ({vuln_type}) timed out at dispatch level")
                result = {
                    "success": False,
                    "error": "Dispatch timeout - workflow blocked",
                    "retryable": True,
                }

            exploit_elapsed = asyncio.get_event_loop().time() - exploit_started
            logger.info(
                f"Exploit result for {vuln_id} ({vuln_type}): "
                f"success={result.get('success')} error={result.get('error')} "
                f"elapsed={exploit_elapsed:.1f}s"
            )

            # Check if this was a dispatch failure or timeout (retryable error)
            # vs an actual execution failure. Don't mark as exploited if retryable
            # so the vulnerability can be re-processed.
            dispatch_failed = result.get("error") == "Failed to dispatch task"
            is_retryable = result.get("retryable", False)

            if dispatch_failed or is_retryable:
                # Track retry count to prevent infinite loops
                current_retries = retry_counts.get(vuln_id, 0)
                if current_retries < max_retries_per_vuln:
                    retry_counts[vuln_id] = current_retries + 1
                    logger.warning(
                        f"Retryable failure for {vuln_id} ({vuln_type}): {result.get('error')} - "
                        f"retry {current_retries + 1}/{max_retries_per_vuln}"
                    )
                    in_flight_vulns.discard(vuln_id)
                    # Remove from dequeued tracking so it can be re-fetched
                    await dispatcher.requeue_vulnerability(vuln_id)
                    return  # Don't mark as exploited, don't count as failure
                logger.error(
                    f"Max retries ({max_retries_per_vuln}) exceeded for {vuln_id} ({vuln_type}) - "
                    f"marking as failed"
                )
                # Fall through to mark as failed

            # Mark as attempted (only for actual execution attempts)
            await dispatcher.mark_vulnerability_exploited(
                vuln_id,
                success=result.get("success", False),
                result=result,
            )

            # Remove from in-flight tracking (allows re-queue if needed, but won't duplicate)
            in_flight_vulns.discard(vuln_id)

            exploited_count += 1

            # Track failures by type
            if not result.get("success"):
                failure_counts[vuln_type] = failure_counts.get(vuln_type, 0) + 1
                if failure_counts[vuln_type] >= max_failures_per_type:
                    logger.warning(
                        f"{vuln_type} has failed {max_failures_per_type} times - "
                        f"will skip remaining {vuln_type} vulns"
                    )

            # If exploitation yielded credentials, trigger expansion
            result_payload: dict[str, Any] | None = None
            if isinstance(result, dict):
                result_payload = (
                    result.get("result") if isinstance(result.get("result"), dict) else result
                )

            if (
                result.get("success")
                and isinstance(result_payload, dict)
                and (result_payload.get("credential") or result_payload.get("hash"))
            ):
                credentials_gained += 1
                logger.info("Exploitation yielded credentials, triggering expansion loop")
                await credential_expansion_loop(dispatcher, max_iterations=5)

    while True:
        # Check runtime limit
        elapsed = asyncio.get_event_loop().time() - start_time
        if elapsed > max_runtime:
            logger.warning(f"Exploitation workflow reached max runtime ({max_runtime}s)")
            break

        # Check for Domain Admin success
        state = dispatcher.shared_state
        if state.has_domain_admin:
            logger.success("Domain Admin achieved! Halting exploitation workflow.")

            # Cancel all active exploitation tasks immediately
            if active_tasks:
                logger.info(f"Cancelling {len(active_tasks)} active exploit tasks...")
                for task in list(active_tasks):
                    if not task.done():
                        task.cancel()
                # Wait briefly for cancellations to propagate
                await asyncio.gather(*active_tasks, return_exceptions=True)
                active_tasks.clear()

            # Announce operation complete - sets Redis status key so workers detect completion
            await dispatcher.announce_operation_complete(
                source_agent="exploitation_workflow",
                success=True,
                summary=f"Domain Admin achieved via {state.domain_admin_path or 'unknown'}",
            )
            break

        # Clean up completed tasks
        done_tasks = {t for t in active_tasks if t.done()}
        for task in done_tasks:
            active_tasks.discard(task)
            # Check for exceptions
            if task.exception():
                logger.warning(f"Exploit task failed with exception: {task.exception()}")

        # Get next vulnerability if we have capacity
        if len(active_tasks) < max_concurrent_exploits:
            vuln = await dispatcher.get_next_vulnerability()
            if not vuln:
                if active_tasks:
                    # Wait for any active task to complete
                    await asyncio.sleep(1.0)
                    continue
                # No vulnerabilities and no active tasks, wait for discovery
                logger.debug("No vulnerabilities in queue, waiting...")
                await asyncio.sleep(check_interval)
                continue

            vuln_id = vuln["id"]
            vuln_type = vuln["type"]

            # FAILSAFE: Skip if already in-flight (prevents duplicate dispatch / token burn)
            if vuln_id in in_flight_vulns:
                logger.debug(f"Skipping {vuln_id} - already in-flight")
                continue

            # Skip vulnerability types that have failed too many times
            if failure_counts.get(vuln_type, 0) >= max_failures_per_type:
                logger.warning(
                    f"Skipping {vuln_type} - failed {max_failures_per_type} times, moving to next"
                )
                dispatcher.shared_state.mark_exploited(vuln["id"])
                await dispatcher.mark_vulnerability_exploited(
                    vuln["id"],
                    success=False,
                    result={"error": f"Skipped: {vuln_type} failed {max_failures_per_type} times"},
                )
                continue

            # Mark as in-flight BEFORE launching (prevents duplicate dispatch)
            in_flight_vulns.add(vuln_id)

            # Launch exploit task
            task = asyncio.create_task(process_exploit(vuln))
            active_tasks.add(task)
        else:
            # At capacity, wait briefly before checking again
            await asyncio.sleep(1.0)

    # Wait for remaining active tasks to complete
    if active_tasks:
        logger.info(f"Waiting for {len(active_tasks)} remaining exploit tasks...")
        await asyncio.gather(*active_tasks, return_exceptions=True)

    return {
        "runtime_seconds": asyncio.get_event_loop().time() - start_time,
        "vulnerabilities_processed": exploited_count,
        "credentials_gained": credentials_gained,
        "domain_admin_achieved": dispatcher.shared_state.has_domain_admin,
    }


async def _dispatch_exploit(
    dispatcher: RedTeamDispatcher,
    vuln_type: str,
    vuln_id: str,
    target: str,
    details: dict[str, Any],
) -> str:
    logger.debug(f"Dispatching exploit request: {vuln_type} on {target} (vuln_id={vuln_id})")
    try:
        async with asyncio.timeout(90):  # 90s timeout (must be > throttle max_wait of 60s)
            task_id = await dispatcher.request_exploit(
                vuln_type=vuln_type,
                vuln_id=vuln_id,
                target=target,
                source_agent="orchestrator",
                params=details,
            )
        logger.debug(f"Exploit dispatched successfully: task_id={task_id}")
        return task_id
    except asyncio.TimeoutError:
        logger.error(f"Exploit dispatch timed out for {vuln_id} - possible throttle deadlock")
        return ""


async def _dispatch_acl(dispatcher: RedTeamDispatcher, details: dict[str, Any]) -> str:
    return await dispatcher.request_acl_analysis(
        target_user=details.get("target_user", ""),
        domain=details.get("domain", ""),
        source_agent="orchestrator",
        find_path_to=details.get("find_path_to", "Domain Admins"),
    )


async def _dispatch_krbtgt(
    dispatcher: RedTeamDispatcher,
    vuln: dict[str, Any],
    target: str,
    details: dict[str, Any],
) -> str:
    krbtgt_domain = details.get("domain", "")
    parent_domain = (
        dispatcher.shared_state.target.domain
        if dispatcher.shared_state.target and dispatcher.shared_state.target.domain
        else ""
    )
    if _is_child_domain(krbtgt_domain, parent_domain):
        credential = _select_domain_credential(dispatcher.shared_state, krbtgt_domain)
        if credential:
            task_id = await dispatcher.request_exploit(
                vuln_type="trust_raise_child",
                vuln_id=vuln["id"],
                target=target,
                source_agent="orchestrator",
                params={
                    "child_domain": krbtgt_domain,
                    "target_domain": parent_domain,
                    "username": credential.username,
                    "password": credential.password,
                },
            )
            if task_id:
                return task_id
        else:
            logger.warning(
                f"krbtgt hash found for {krbtgt_domain} but no credential available for raise_child"
            )

    return await dispatcher.request_lateral_movement(
        target_host=target,
        username="Administrator",
        source_agent="orchestrator",
        hash_value=details.get("hash_value", ""),
        domain=krbtgt_domain,
    )


async def _wait_with_da_check(
    dispatcher: RedTeamDispatcher,
    task_id: str,
    timeout: float = 180.0,
    check_interval: float = 10.0,
) -> dict[str, Any]:
    """Wait for task completion with periodic DA checks.

    Instead of waiting for the full timeout, this function checks every
    `check_interval` seconds if DA has been achieved. If so, it abandons
    the wait early to allow the workflow to halt quickly.

    Args:
        dispatcher: The RedTeamDispatcher instance
        task_id: Task to wait for
        timeout: Total timeout in seconds (default 3 minutes - reduced from 20)
        check_interval: How often to check for DA (default 10 seconds)

    Returns:
        Task result dict, or abandoned result if DA achieved during wait
    """
    start = asyncio.get_event_loop().time()
    while (asyncio.get_event_loop().time() - start) < timeout:
        # Check if DA achieved during wait
        if dispatcher.shared_state.has_domain_admin:
            logger.info(f"DA achieved - abandoning wait for task {task_id}")
            return {"success": False, "error": "Cancelled: DA achieved", "abandoned": True}

        # Try to get result with short timeout
        try:
            return await dispatcher.wait_for_task(task_id, timeout=check_interval)
        except asyncio.TimeoutError:
            # Task still running, continue loop to check DA
            continue

    # Total timeout exceeded - mark as retryable so vuln can be re-processed
    logger.warning(f"Exploitation task {task_id} timed out after {timeout}s - will allow retry")
    return {"success": False, "error": "Task timed out", "retryable": True}


async def _exploit_vulnerability(
    dispatcher: RedTeamDispatcher,
    vuln: dict[str, Any],
) -> dict[str, Any]:
    """
    Route vulnerability to appropriate agent for exploitation.

    Args:
        dispatcher: The RedTeamDispatcher instance
        vuln: Vulnerability data dict

    Returns:
        Exploitation result dict
    """

    vuln_type = vuln["type"]
    target = vuln["target"]
    details = vuln.get("details", {})

    async def dispatch_exploit() -> str:
        return await _dispatch_exploit(dispatcher, vuln_type, vuln["id"], target, details)

    async def dispatch_acl() -> str:
        return await _dispatch_acl(dispatcher, details)

    async def dispatch_krbtgt() -> str:
        return await _dispatch_krbtgt(dispatcher, vuln, target, details)

    routes = [
        (lambda: vuln_type.startswith("ADCS_"), dispatch_exploit),
        (lambda: vuln_type == "acl_abuse", dispatch_acl),
        (lambda: "delegation" in vuln_type.lower(), dispatch_exploit),
        (lambda: vuln_type == "krbtgt_hash", dispatch_krbtgt),
        (lambda: vuln_type == "dcsync", dispatch_exploit),
        (lambda: vuln_type.startswith("mssql_"), dispatch_exploit),
        (lambda: True, dispatch_exploit),
    ]

    task_id = ""
    for predicate, handler in routes:
        if predicate():
            task_id = await handler()
            break

    if not task_id:
        logger.warning(f"Failed to dispatch exploitation for {vuln_type}")
        return {"success": False, "error": "Failed to dispatch task"}

    # Task was queued to deferred queue - will be processed by background processor
    # Return success so workflow moves on (don't wait for a non-existent task ID)
    if task_id == "deferred":
        logger.info(f"Exploit task for {vuln_type} deferred to background queue")
        return {"success": True, "deferred": True}

    # Wait for task completion with periodic DA checks
    # Uses chunked waits to detect DA achievement and abandon stale tasks early
    # Timeout reduced from 1200s (20min) to 180s (3min) to prevent workflow blocking
    return await _wait_with_da_check(dispatcher, task_id, timeout=180.0, check_interval=10.0)


__all__ = [
    "CredentialTestingTracker",
    "credential_expansion_loop",
    "exploitation_workflow",
]
