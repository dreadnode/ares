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


async def credential_expansion_loop(
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
    iterations = 0

    logger.info("Starting credential expansion loop")

    while iterations < max_iterations:
        state = dispatcher.shared_state

        credentials = state.all_credentials
        hosts = state.all_hosts
        new_tests = 0
        tasks_dispatched: list[str] = []

        logger.info(
            f"Iteration {iterations + 1}: {len(credentials)} credentials, {len(hosts)} hosts"
        )

        for cred in credentials:
            for host in hosts:
                if tracker.has_tested(cred, host):
                    continue

                # Skip if we already have admin access on this host
                if _has_admin_access(state, host):
                    tracker.mark_tested(cred, host, success=True)
                    continue

                # Dispatch lateral movement test
                task_id = await dispatcher.request_lateral_movement(
                    target_host=host.ip,
                    username=cred.username,
                    source_agent="orchestrator",
                    password=cred.password if cred.password else None,
                    domain=cred.domain,
                )

                if task_id:
                    tasks_dispatched.append(task_id)
                    new_tests += 1
                    logger.debug(
                        f"Dispatched lateral test: {cred.domain}\\{cred.username} -> {host.ip}"
                    )

                tracker.mark_tested(cred, host)

                # Small delay to avoid overwhelming
                await asyncio.sleep(delay_between_tests)

        if new_tests == 0:
            logger.info("No new credential/host combinations to test")
            break

        # Wait for dispatched tasks to complete (with timeout)
        logger.info(f"Waiting for {len(tasks_dispatched)} lateral movement tasks...")

        for task_id in tasks_dispatched:
            try:
                result = await dispatcher.wait_for_task(task_id, timeout=60.0)
                if result.get("success"):
                    # Find the credential/host pair and mark as successful
                    logger.success(f"Task {task_id} succeeded")
            except asyncio.TimeoutError:  # noqa: PERF203
                logger.warning(f"Task {task_id} timed out")

        iterations += 1
        logger.info(f"Iteration {iterations} complete. Stats: {tracker.get_stats()}")

    logger.info(
        f"Credential expansion complete after {iterations} iterations. "
        f"Final stats: {tracker.get_stats()}"
    )

    return tracker


async def exploitation_workflow(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 10.0,
    max_runtime: float = 7200.0,  # 2 hours default
) -> dict[str, Any]:
    """
    Main exploitation loop.

    Continuously:
    1. Get next highest priority vulnerability
    2. Route to appropriate agent for exploitation
    3. Monitor result and update state
    4. If exploitation yields credentials -> trigger credential expansion
    5. If Domain Admin achieved -> halt and report

    Args:
        dispatcher: The RedTeamDispatcher instance
        check_interval: Seconds between queue checks when empty
        max_runtime: Maximum runtime in seconds

    Returns:
        Summary of exploitation results
    """
    from ares.core.messages import (
        DomainAdminAchieved,
    )

    start_time = asyncio.get_event_loop().time()
    exploited_count = 0
    credentials_gained = 0

    logger.info("Starting exploitation workflow")

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
            await dispatcher._broadcast(
                DomainAdminAchieved(
                    source_agent="exploitation_workflow",
                    username="",  # Will be filled from state
                    domain=state.target.domain if state.target else "",
                    attack_path=state.domain_admin_path or "Unknown path",
                    credential_type="credential",
                )
            )
            break

        # Get next vulnerability to exploit
        vuln = await dispatcher.get_next_vulnerability()
        if not vuln:
            # No vulnerabilities in queue, wait for agents to discover more
            logger.debug("No vulnerabilities in queue, waiting...")
            await asyncio.sleep(check_interval)
            continue

        logger.info(f"Processing vulnerability: {vuln['type']} on {vuln['target']}")

        # Route to appropriate agent
        result = await _exploit_vulnerability(dispatcher, vuln)

        # Mark as attempted
        await dispatcher.mark_vulnerability_exploited(
            vuln["id"],
            success=result.get("success", False),
            result=result,
        )

        exploited_count += 1

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

    return {
        "runtime_seconds": asyncio.get_event_loop().time() - start_time,
        "vulnerabilities_processed": exploited_count,
        "credentials_gained": credentials_gained,
        "domain_admin_achieved": dispatcher.shared_state.has_domain_admin,
    }


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

    task_id = ""

    # Route based on vulnerability type
    if vuln_type.startswith("ADCS_"):
        # Route to PrivEsc agent
        task_id = await dispatcher.request_exploit(
            vuln_type=vuln_type,
            vuln_id=vuln["id"],
            target=target,
            source_agent="orchestrator",
            params=details,
        )

    elif vuln_type == "acl_abuse":
        # Route to ACL agent
        task_id = await dispatcher.request_acl_analysis(
            target_user=details.get("target_user", ""),
            domain=details.get("domain", ""),
            source_agent="orchestrator",
            find_path_to=details.get("find_path_to", "Domain Admins"),
        )

    elif "delegation" in vuln_type.lower():
        # Route to PrivEsc agent for delegation attacks
        task_id = await dispatcher.request_exploit(
            vuln_type=vuln_type,
            vuln_id=vuln["id"],
            target=target,
            source_agent="orchestrator",
            params=details,
        )

    elif vuln_type == "krbtgt_hash":
        # Golden ticket - route to lateral agent
        task_id = await dispatcher.request_lateral_movement(
            target_host=target,
            username="Administrator",
            source_agent="orchestrator",
            hash_value=details.get("hash_value", ""),
            domain=details.get("domain", ""),
        )

    elif vuln_type == "dcsync":
        # DCSync - route to privesc agent
        task_id = await dispatcher.request_exploit(
            vuln_type=vuln_type,
            vuln_id=vuln["id"],
            target=target,
            source_agent="orchestrator",
            params=details,
        )

    elif vuln_type.startswith("mssql_"):
        # MSSQL attacks - route to privesc agent
        task_id = await dispatcher.request_exploit(
            vuln_type=vuln_type,
            vuln_id=vuln["id"],
            target=target,
            source_agent="orchestrator",
            params=details,
        )

    else:
        # Default: route to privesc agent
        task_id = await dispatcher.request_exploit(
            vuln_type=vuln_type,
            vuln_id=vuln["id"],
            target=target,
            source_agent="orchestrator",
            params=details,
        )

    if not task_id:
        logger.warning(f"Failed to dispatch exploitation for {vuln_type}")
        return {"success": False, "error": "Failed to dispatch task"}

    # Wait for task completion (with timeout)
    try:
        return await dispatcher.wait_for_task(task_id, timeout=300)
    except asyncio.TimeoutError:
        logger.warning(f"Exploitation task {task_id} timed out")
        return {"success": False, "error": "Task timed out"}


__all__ = [
    "CredentialTestingTracker",
    "credential_expansion_loop",
    "exploitation_workflow",
]
