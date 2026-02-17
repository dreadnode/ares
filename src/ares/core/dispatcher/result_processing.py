"""Task result processing and data extraction.

This module provides the complete_task() method and all helper methods
for extracting hosts, users, credentials, shares, hashes, and vulnerabilities
from task output.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.models import (
    Credential,
    Hash,
    Host,
    Share,
    TaskResult,
    TaskStatus,
    User,
    VulnerabilityInfo,
)

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher


class ResultProcessingMixin:
    """Task result processing and data extraction."""

    async def complete_task(  # noqa: PLR0912
        self: RedTeamDispatcher,
        task_id: str,
        success: bool,
        result: Any = None,
        error: str | None = None,
        source_agent: str = "",
        skip_checkpoint: bool = False,
        task_queue: Any = None,
    ) -> None:
        """
        Mark a task as complete.

        Args:
            task_id: The task ID.
            success: Whether the task succeeded.
            result: Task result (if successful).
            error: Error message (if failed).
            source_agent: Agent completing the task.
            skip_checkpoint: If True, skip checkpointing (used when called from threaded consumer
                where the Redis client is bound to a different event loop).
            task_queue: Optional task queue for direct dispatch (threaded consumer passes its own).
        """
        # Use atomic pop to avoid TOCTOU race with _cleanup_stale_tasks()
        task_info = self.shared_state.pending_tasks.pop(task_id, None)
        if task_info is None:
            logger.warning(f"Unknown task: {task_id}")
            return
        was_retry = task_info.status == TaskStatus.RETRYING

        task_info.status = TaskStatus.COMPLETED if success else TaskStatus.FAILED
        task_info.completed_at = datetime.now(timezone.utc)
        task_info.result = result
        task_info.error = error

        if was_retry:
            logger.info(
                f"Retried task {task_id} completed after {task_info.retry_count} retries: "
                f"success={success}"
            )

        task_result = TaskResult(
            task_id=task_id,
            success=success,
            result=result,
            error=error,
        )
        self.shared_state.completed_tasks[task_id] = task_result

        # Mark targets as scanned after successful nmap recon
        if success and task_info.task_type == "recon":
            params = task_info.params or {}
            techniques = params.get("techniques", [])
            if "nmap_scan" in techniques:
                scanned_ips = params.get("target_ips", [])
                if scanned_ips:
                    for ip in scanned_ips:
                        self.shared_state.scanned_targets.add(ip)
                    logger.info(
                        f"Marked {len(scanned_ips)} targets as scanned: "
                        f"{', '.join(scanned_ips[:5])}{'...' if len(scanned_ips) > 5 else ''}"
                    )

        output = ""

        # Resolve target host for better logging
        target_label = source_agent
        task_params = task_info.params or {}
        target_ip = task_params.get("target") or task_params.get("target_host")
        if not target_ip and task_params.get("target_ips"):
            target_ips = task_params.get("target_ips", [])
            if target_ips:
                target_ip = target_ips[0] if isinstance(target_ips, list) else target_ips
        if target_ip:
            # Look up hostname from shared state
            for host in self.shared_state.all_hosts:
                if host.ip == target_ip:
                    target_label = f"{host.hostname or target_ip} ({target_ip})"
                    break
            else:
                target_label = target_ip

        # Extract parent credential tracking from task params for attack chain
        parent_credential_id = task_params.get("parent_credential_id")
        parent_attack_step = task_params.get("parent_attack_step", 0)

        # Process discoveries from result dict (even if task failed)
        # Workers serialize discoveries and send them regardless of success/failure
        if isinstance(result, dict):
            await self._process_discovered_data(
                result,
                source_agent,
                target_label,
                parent_credential_id,
                parent_attack_step,
                task_queue=task_queue,
            )

        # Process additional result fields only on success
        if success and isinstance(result, dict):
            await self._process_success_result_data(
                result, task_id, source_agent, parent_credential_id, parent_attack_step
            )
            output = self._extract_output_from_result(result)
        elif success and isinstance(result, str):
            output = result.strip()

        if output:
            await self._process_output_text(
                output,
                source_agent,
                parent_credential_id,
                parent_attack_step,
                task_queue=task_queue,
            )

        # Auto-chain secretsdump after successful S4U attack (any task type with ccache output)
        if success:
            chained = await self._auto_chain_s4u_lateral_movement(
                task_id=task_id,
                task_info=task_info,
                result=result if isinstance(result, dict) else {"output": str(result)},
                source_agent=source_agent,
                task_queue=task_queue,
            )
            if chained > 0:
                logger.info(f"🎫 Auto-S4U-chain: dispatched {chained} secretsdump task(s)")

        # Mark vulnerability as exploited when exploit task completes
        if task_info.task_type == "exploit":
            vuln_id = task_params.get("vuln_id", "")
            if vuln_id:
                result_dict = result if isinstance(result, dict) else {"output": str(result)}
                await self.mark_vulnerability_exploited(vuln_id, success, result_dict)
                if success:
                    logger.info(f"✅ Marked vulnerability {vuln_id} as exploited")

        # Resolve any waiting futures
        self._resolve_task_future(task_id, success, result, error)

        # Skip checkpoint when called from threaded consumer (different event loop)
        # The maintenance loop handles periodic checkpointing for this case
        if not skip_checkpoint:
            await self._checkpoint()
        logger.info(f"Task {task_id} completed: success={success}")

    async def _process_discovered_data(  # noqa: PLR0912
        self: RedTeamDispatcher,
        result: dict[str, Any],
        source_agent: str,
        target_label: str,
        parent_credential_id: str | None = None,
        parent_attack_step: int = 0,
        task_queue: Any = None,
    ) -> None:
        """Process discovered_* fields from worker result.

        Args:
            result: Task result dictionary.
            source_agent: Agent that produced the result.
            target_label: Label for logging.
            parent_credential_id: ID of credential used to discover these items (for attack chain).
            parent_attack_step: Attack step of parent credential.
            task_queue: Optional task queue for direct dispatch (threaded consumer passes its own).
        """
        discovered_hosts = result.get("discovered_hosts")
        if isinstance(discovered_hosts, list) and discovered_hosts:
            logger.info(f"Processing {len(discovered_hosts)} discovered hosts from {target_label}")
            for h in discovered_hosts:
                if not isinstance(h, dict):
                    continue
                host = Host(
                    ip=h.get("ip", ""),
                    hostname=h.get("hostname", ""),
                    os=h.get("os", ""),
                    roles=h.get("roles", []),
                    services=h.get("services", []),
                )
                # Preserve is_dc flag from worker's detection
                if h.get("is_dc"):
                    host.is_dc = True
                await self.publish_host(host, source_agent)

        discovered_credentials = result.get("discovered_credentials")
        if isinstance(discovered_credentials, list) and discovered_credentials:
            logger.info(
                f"Processing {len(discovered_credentials)} discovered credentials from {target_label}"
            )
            for c in discovered_credentials:
                if not isinstance(c, dict):
                    continue
                credential = Credential(
                    username=c.get("username", ""),
                    password=c.get("password", ""),
                    domain=c.get("domain", ""),
                    source=c.get("source", f"worker:{source_agent}"),
                    is_admin=c.get("is_admin", False),
                    parent_id=parent_credential_id,  # Track attack chain
                    attack_step=parent_attack_step + 1 if parent_credential_id else 0,
                )
                await self.publish_credential(credential, source_agent, task_queue=task_queue)

        discovered_hashes = result.get("discovered_hashes")
        if isinstance(discovered_hashes, list) and discovered_hashes:
            logger.info(
                f"Processing {len(discovered_hashes)} discovered hashes from {target_label}"
            )
            for h in discovered_hashes:
                if not isinstance(h, dict):
                    continue
                hash_obj = Hash(
                    username=h.get("username", ""),
                    hash_value=h.get("hash_value", ""),
                    hash_type=h.get("hash_type", "NTLM"),
                    domain=h.get("domain", ""),
                    cracked_password=h.get("cracked_password", ""),
                    source=h.get("source", ""),
                    parent_id=parent_credential_id,  # Track attack chain
                    attack_step=parent_attack_step + 1 if parent_credential_id else 0,
                )
                await self.publish_hash(hash_obj, source_agent)
                if hash_obj.cracked_password:
                    logger.debug(
                        f"Creating credential from cracked hash: {hash_obj.domain}\\{hash_obj.username}"
                    )
                    cracked_cred = Credential(
                        username=hash_obj.username,
                        password=hash_obj.cracked_password,
                        domain=hash_obj.domain,
                        source=f"cracked:{source_agent}",
                        is_admin=False,
                        parent_id=hash_obj.id,  # Cracked cred links to its hash
                        attack_step=hash_obj.attack_step + 1,
                    )
                    try:
                        await asyncio.wait_for(
                            self.publish_credential(
                                cracked_cred, source_agent, task_queue=task_queue
                            ),
                            timeout=30.0,
                        )
                    except asyncio.TimeoutError:
                        logger.error(
                            f"Timeout publishing cracked credential {hash_obj.domain}\\{hash_obj.username} - "
                            "publish_credential blocked for 30s"
                        )
                    except Exception as e:
                        logger.error(
                            f"Error publishing cracked credential {hash_obj.domain}\\{hash_obj.username}: {e}"
                        )

        # NOTE: discovered_shares from JSON is NOT processed here.
        # LLM agents parse netexec output non-deterministically, often returning
        # invalid permissions (e.g., "Basic", "Remote" from comment text).
        # Instead, shares are extracted deterministically from raw output via
        # _extract_shares_from_output() in _process_output_text().

        discovered_users = result.get("discovered_users")
        if isinstance(discovered_users, list):
            for u in discovered_users:
                if not isinstance(u, dict):
                    continue
                self._add_user(u.get("username", ""), u.get("domain", ""), source_agent)

        # Process trusted domains (from BloodHound, nltest, etc.)
        trusted_domains = result.get("trusted_domains")
        if isinstance(trusted_domains, list):
            for td in trusted_domains:
                if isinstance(td, str) and td.strip():
                    domain_lower = td.strip().lower()
                    if domain_lower not in self.shared_state.trusted_domains:
                        self.shared_state.trusted_domains.append(domain_lower)
                        logger.info(
                            f"Trusted domain discovered: {domain_lower} from {target_label}"
                        )

        # Process discovered vulnerabilities (delegation, ADCS, etc.)
        discovered_vulns = result.get("discovered_vulnerabilities")
        if isinstance(discovered_vulns, list) and discovered_vulns:
            await self._process_discovered_vulnerabilities(
                discovered_vulns, source_agent, task_queue=task_queue
            )

    async def _process_discovered_vulnerabilities(
        self: RedTeamDispatcher,
        vulnerabilities: list[dict[str, Any]],
        source_agent: str,
        task_queue: Any = None,
    ) -> None:
        """Process vulnerabilities discovered by workers and queue for exploitation.

        Args:
            vulnerabilities: List of vulnerability dicts from worker serialization
            source_agent: Agent that discovered the vulnerabilities
            task_queue: Optional task queue for direct dispatch (threaded consumer passes its own).
        """
        queued = 0
        for vuln_data in vulnerabilities:
            if not isinstance(vuln_data, dict):
                continue

            vuln_id = vuln_data.get("vuln_id", "")
            vuln_type = vuln_data.get("vuln_type", "")
            target = vuln_data.get("target", "")
            # Defensive: ensure details is always a dict (may be string from improper serialization)
            raw_details = vuln_data.get("details", {})
            details = raw_details if isinstance(raw_details, dict) else {}

            if not vuln_type or not target:
                continue

            # Check if already queued
            if vuln_id in self.shared_state.discovered_vulnerabilities:
                continue

            # Also check for logical duplicates (same type + target)
            already_exists = any(
                v.vuln_type == vuln_type and v.target.lower() == target.lower()
                for v in self.shared_state.discovered_vulnerabilities.values()
            )
            if already_exists:
                continue

            # For delegation vulnerabilities, check if we have credentials
            # (worker might not know about creds orchestrator has discovered)
            if vuln_type in ("constrained_delegation", "unconstrained_delegation"):
                account = details.get("account_name") or details.get("account") or target
                account_lower = account.lower().rstrip("$") if account else target.lower()
                for cred in self.shared_state.all_credentials:
                    if cred.username.lower() == account_lower and cred.password:
                        details["has_credentials"] = True
                        details["username"] = cred.username
                        details["password"] = cred.password
                        details["domain"] = cred.domain
                        break
                else:
                    details["has_credentials"] = False

            # Queue the vulnerability and get its ID
            vuln_id = await self.queue_vulnerability(
                vuln_type=vuln_type,
                target=target,
                details=details,
                discovered_by=source_agent,
            )
            if vuln_id:
                queued += 1

            # For delegation vulnerabilities with credentials, auto-dispatch exploit
            if vuln_type in ("constrained_delegation", "unconstrained_delegation") and vuln_id:
                await self._auto_dispatch_delegation_exploit(
                    vuln_type,
                    target,
                    details,
                    source_agent,
                    vuln_id,
                    task_queue=task_queue,
                )

        if queued > 0:
            logger.warning(
                f"🎫 Processed {queued} vulnerability(ies) from {source_agent} for exploitation"
            )

    async def _auto_dispatch_delegation_exploit(
        self: RedTeamDispatcher,
        vuln_type: str,
        target: str,
        details: dict[str, Any] | str,
        source_agent: str,
        vuln_id: str = "",
        task_queue: Any = None,
    ) -> None:
        """Auto-dispatch exploitation for delegation vulnerabilities with credentials.

        Args:
            vuln_type: Type of delegation vulnerability
            target: Target account for delegation
            details: Vulnerability details including credentials (may be string if improperly serialized)
            source_agent: Agent that discovered the vulnerability
            vuln_id: Vulnerability ID from queue_vulnerability (for tracking exploitation)
            task_queue: Optional task queue for direct dispatch (threaded consumer passes its own).
        """
        # Defensive: ensure details is a dict
        if not isinstance(details, dict):
            return

        if not details.get("has_credentials"):
            return

        account = details.get("account_name") or details.get("account", target)
        domain = details.get("domain", "")
        target_spn = details.get("target_spn", "")
        dc_ip = details.get("dc_ip", "")

        if vuln_type != "constrained_delegation" or not target_spn:
            return  # Only auto-dispatch constrained delegation with known SPN

        # Find credential for account
        account_lower = account.lower().rstrip("$")
        account_cred = None
        for cred in self.shared_state.all_credentials:
            if cred.username.lower() == account_lower and cred.password:
                account_cred = cred
                break

        if not account_cred:
            return

        # Use provided vuln_id or lookup from discovered_vulnerabilities
        exploit_vuln_id = vuln_id
        if not exploit_vuln_id:
            # Find matching vulnerability in discovered_vulnerabilities
            for vid, vuln in self.shared_state.discovered_vulnerabilities.items():
                if vuln.vuln_type != "constrained_delegation":
                    continue
                # Defensive: ensure vuln.details is a dict before calling .get()
                vuln_details = vuln.details if isinstance(vuln.details, dict) else {}
                vuln_account = vuln_details.get("account_name", vuln.target).lower().rstrip("$")
                if vuln_account == account_lower:
                    exploit_vuln_id = vid
                    break

        if not exploit_vuln_id:
            logger.warning(
                f"Cannot dispatch S4U attack for {account}: no matching vulnerability found"
            )
            return

        logger.warning(
            f"🚀 Auto-dispatching S4U attack for {account} -> {target_spn} "
            f"(have credentials, DC: {dc_ip}, vuln_id: {exploit_vuln_id})"
        )

        await self.request_exploit(
            vuln_type="constrained_delegation",
            vuln_id=exploit_vuln_id,
            target=account,
            source_agent="auto_delegation",
            params={
                "account": account,
                "account_name": account,
                "target_spn": target_spn,
                "domain": account_cred.domain or domain,
                "username": account_cred.username,
                "password": account_cred.password,
                "dc_ip": dc_ip,
            },
            task_queue=task_queue,
        )

    async def _process_success_result_data(
        self: RedTeamDispatcher,
        result: dict[str, Any],
        task_id: str,
        source_agent: str,
        parent_credential_id: str | None = None,
        parent_attack_step: int = 0,
    ) -> None:
        """Process credential/hash/share fields from successful result."""
        # Calculate attack_step for discoveries (parent + 1)
        discovery_step = parent_attack_step + 1 if parent_credential_id else 0

        cred_data = result.get("credential")
        if isinstance(cred_data, dict):
            self._add_user(cred_data.get("username", ""), cred_data.get("domain", ""), source_agent)
            credential = Credential(
                username=cred_data.get("username", ""),
                password=cred_data.get("password", ""),
                domain=cred_data.get("domain", ""),
                source=cred_data.get("source", f"task:{task_id}"),
                is_admin=cred_data.get("is_admin", False),
                parent_id=parent_credential_id,
                attack_step=discovery_step,
            )
            await self.publish_credential(credential, source_agent, task_queue=None)

        creds_data = result.get("credentials")
        if isinstance(creds_data, list):
            for cred in creds_data:
                if not isinstance(cred, dict):
                    continue
                self._add_user(cred.get("username", ""), cred.get("domain", ""), source_agent)
                credential = Credential(
                    username=cred.get("username", ""),
                    password=cred.get("password", ""),
                    domain=cred.get("domain", ""),
                    source=cred.get("source", f"task:{task_id}"),
                    is_admin=cred.get("is_admin", False),
                    parent_id=parent_credential_id,
                    attack_step=discovery_step,
                )
                await self.publish_credential(credential, source_agent, task_queue=None)

        hash_data = result.get("hash")
        if isinstance(hash_data, dict):
            hash_obj = Hash(
                username=hash_data.get("username", ""),
                hash_value=hash_data.get("hash_value", ""),
                hash_type=hash_data.get("hash_type", "NTLM"),
                domain=hash_data.get("domain", ""),
                cracked_password=hash_data.get("cracked_password", ""),
                parent_id=parent_credential_id,
                attack_step=discovery_step,
            )
            await self.publish_hash(hash_obj, source_agent)
            if hash_obj.cracked_password:
                cracked_cred = Credential(
                    username=hash_obj.username,
                    password=hash_obj.cracked_password,
                    domain=hash_obj.domain,
                    source=f"hash:{task_id}",
                    is_admin=False,
                    parent_id=hash_obj.id,
                    attack_step=hash_obj.attack_step + 1,
                )
                await self.publish_credential(cracked_cred, source_agent, task_queue=None)

        hashes_data = result.get("hashes")
        if isinstance(hashes_data, list):
            for h in hashes_data:
                if not isinstance(h, dict):
                    continue
                hash_obj = Hash(
                    username=h.get("username", ""),
                    hash_value=h.get("hash_value", ""),
                    hash_type=h.get("hash_type", "NTLM"),
                    domain=h.get("domain", ""),
                    cracked_password=h.get("cracked_password", ""),
                    parent_id=parent_credential_id,
                    attack_step=discovery_step,
                )
                await self.publish_hash(hash_obj, source_agent)
                if hash_obj.cracked_password:
                    cracked_cred = Credential(
                        username=hash_obj.username,
                        password=hash_obj.cracked_password,
                        domain=hash_obj.domain,
                        source=f"hash:{task_id}",
                        is_admin=False,
                        parent_id=hash_obj.id,
                        attack_step=hash_obj.attack_step + 1,
                    )
                    await self.publish_credential(cracked_cred, source_agent, task_queue=None)

        # NOTE: share/shares from JSON is NOT processed here.
        # LLM agents parse netexec output non-deterministically. Shares are
        # extracted deterministically from raw output via _extract_shares_from_output().

    def _extract_output_from_result(self: RedTeamDispatcher, result: dict[str, Any]) -> str:
        """Extract combined output text from result dict."""
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        output_field = result.get("output", "")
        output_parts = []
        for chunk in (stdout, stderr, output_field):
            if isinstance(chunk, str) and chunk.strip():
                output_parts.append(chunk.strip())
        return "\n".join(output_parts).strip()

    async def _process_output_text(  # noqa: PLR0912
        self: RedTeamDispatcher,
        output: str,
        source_agent: str,
        parent_credential_id: str | None = None,
        parent_attack_step: int = 0,
        task_queue: Any = None,
    ) -> None:
        """Process raw output text to extract discoveries.

        Args:
            output: Raw text output from tool.
            source_agent: Agent that produced the output.
            parent_credential_id: ID of credential used to run the command (for attack chain).
            parent_attack_step: Attack step of parent credential.
            task_queue: Optional task queue for direct dispatch (threaded consumer passes its own).
        """
        domain = ""
        if self.shared_state.target and self.shared_state.target.domain:
            domain = self.shared_state.target.domain

        for host in self._extract_hosts_from_output(output):
            # Use publish_host to ensure checkpoint is triggered for merged data
            await self.publish_host(host, source_agent)

        for username, extracted_domain in self._extract_users_from_output(output):
            # Use extracted domain if available, otherwise fall back to target domain
            user_domain = extracted_domain or domain
            self._add_user(username, user_domain, source_agent)

        creds = self._extract_plaintext_passwords_from_output(output)
        if "password :" in output.lower() and not creds and domain:
            self.shared_state.pending_credential_findings.add(f"{domain}:unknown")
        for username, password, extracted_domain in creds:
            # Resolve the correct domain using multiple strategies
            resolved_domain = self._resolve_credential_domain(username, extracted_domain)
            if not resolved_domain:
                # Fall back to target domain if we have one - better to add credential
                # with potentially wrong domain than to drop it entirely
                if domain:
                    resolved_domain = domain
                    logger.debug(
                        f"Domain resolution failed for {username}, falling back to target domain: {domain}"
                    )
                else:
                    logger.debug(
                        f"Skipping credential {username}:{password[:3]}*** - no domain available"
                    )
                    continue
            self.shared_state.pending_credential_findings.add(
                f"{resolved_domain}:{username}".lower()
            )
            self._add_user(username, resolved_domain, source_agent)
            credential = Credential(
                username=username,
                password=password,
                domain=resolved_domain,
                source="user_description",
                is_admin=False,
                parent_id=parent_credential_id,  # Track attack chain
                attack_step=parent_attack_step + 1 if parent_credential_id else 0,
            )
            await self.publish_credential(credential, source_agent, task_queue=task_queue)

        # Extract shares from netexec --shares output
        for share in self._extract_shares_from_output(output):
            await self.publish_share(share, source_agent)

        # Extract hashes (Kerberoast, AS-REP, NTLM) from tool output
        # Always extract as a backup - real-time hooks may fail silently or not complete
        # before worker crash. Duplicates are handled by dedup logic in add_hash().
        for hash_obj in self._extract_hashes_from_output(output):
            # Track attack chain
            if parent_credential_id:
                hash_obj.parent_id = parent_credential_id
                hash_obj.attack_step = parent_attack_step + 1
            await self.publish_hash(hash_obj, source_agent)

        # Extract and auto-queue delegation vulnerabilities from findDelegation output
        # Always extract as a backup - dedup handled in _auto_queue_delegation_vulnerabilities
        delegations = self._extract_delegation_from_output(output)
        if delegations:
            queued = await self._auto_queue_delegation_vulnerabilities(
                delegations, source_agent, task_queue=task_queue
            )
            if queued > 0:
                logger.warning(
                    f"🎫 Auto-delegation: queued {queued} delegation vulnerability(ies) "
                    f"for exploitation from {source_agent}"
                )

        # Extract and auto-queue BloodHound vulnerabilities (GPO abuse, local admin, ACL)
        bloodhound_vulns = self._extract_bloodhound_vulns_from_output(output)
        if bloodhound_vulns:
            queued = await self._auto_queue_bloodhound_vulnerabilities(
                bloodhound_vulns, source_agent
            )
            if queued > 0:
                logger.warning(
                    f"🩸 Auto-BloodHound: queued {queued} vulnerability(ies) "
                    f"for exploitation from {source_agent}"
                )

        # Extract and auto-queue gMSA accounts for password retrieval
        gmsa_accounts = self._extract_gmsa_from_output(output)
        if gmsa_accounts:
            queued = await self._auto_queue_gmsa_vulnerabilities(gmsa_accounts, source_agent)
            if queued > 0:
                logger.warning(
                    f"🔑 Auto-gMSA: queued {queued} gMSA account(s) "
                    f"for password retrieval from {source_agent}"
                )

        # Extract ACL chains from BloodHound shortest path output
        self._extract_acl_chains_from_output(output, source_agent)

    def _extract_acl_chains_from_output(
        self: RedTeamDispatcher, output: str, source_agent: str
    ) -> None:
        """
        Extract ACL chains from BloodHound output and register for tracking.

        Parses BloodHound shortest path output to identify multi-hop
        ACL abuse chains to Domain Admin.
        """
        from ares.core.dispatcher.acl_chains import ACLChainTracker

        # Only process if output looks like BloodHound path data
        path_indicators = ["shortest path", "attack path", "->", "-["]
        if not any(indicator in output.lower() for indicator in path_indicators):
            return

        # Initialize tracker if not present (with state for persistence!)
        if not hasattr(self, "_acl_chain_tracker"):
            self._acl_chain_tracker = ACLChainTracker(state=self.shared_state)
        elif self._acl_chain_tracker._state is None:
            self._acl_chain_tracker.set_state(self.shared_state)

        tracker: ACLChainTracker = self._acl_chain_tracker
        domain = ""
        if self.shared_state.target and self.shared_state.target.domain:
            domain = self.shared_state.target.domain

        # Split output into potential paths
        lines = output.split("\n")
        current_path: list[str] = []
        chains_found = 0

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                if current_path:
                    path_text = " ".join(current_path)
                    chain = tracker.create_chain_from_bloodhound_path(
                        path_text, domain, source_agent
                    )
                    if chain:
                        chains_found += 1
                    current_path = []
            elif "->" in line or "-[" in line:
                current_path.append(line)

        # Handle last path
        if current_path:
            path_text = " ".join(current_path)
            chain = tracker.create_chain_from_bloodhound_path(path_text, domain, source_agent)
            if chain:
                chains_found += 1

        if chains_found > 0:
            logger.warning(
                f"🔗 Extracted {chains_found} ACL chain(s) from BloodHound output ({source_agent})"
            )

    def _add_user(self: RedTeamDispatcher, username: str, domain: str, source: str = "") -> bool:
        """Add a user to the shared state.

        Args:
            username: The username.
            domain: The domain.
            source: Tool/method that discovered this user.
        """
        if not username:
            return False
        normalized = username.strip()
        if not normalized or normalized.lower() in {"(none)", "none", "null", "(null)"}:
            return False
        if "/" in normalized or "\\" in normalized or normalized.endswith(".txt"):
            return False
        # Skip machine accounts (ending in $) - these are computer accounts, not users
        if normalized.endswith("$"):
            return False
        for existing in self.shared_state.all_users:
            if existing.username == normalized and existing.domain == domain:
                return False
        self.shared_state.all_users.append(User(username=normalized, domain=domain, source=source))
        return True

    def _extract_hosts_from_output(self: RedTeamDispatcher, output: str) -> list[Host]:
        """Extract hosts from netexec SMB output.

        Parses two types of SMB output lines:
        1. Banner lines with [*]: "SMB 10.1.2.183 445 KINGSLANDING [*] Windows 10..."
           - Extracts IP, hostname, and OS from the banner details
        2. Non-banner lines: "SMB 10.1.2.240 445 WINTERFELL ADMIN$ Remote Admin"
           - Extracts IP and hostname only (OS will be "Unknown")
           - These appear in share enumeration, user enumeration, etc.
        """
        if not output:
            return []
        hosts: list[Host] = []
        seen: set[str] = set()
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Try banner line first (has OS info): "SMB IP PORT HOSTNAME [*] OS info..."
            smb_match = re.search(
                r"SMB\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+([A-Za-z0-9_.-]+)\s+\[\*\]\s+(.+)",
                stripped,
            )
            if smb_match:
                ip = smb_match.group(1)
                host_col = smb_match.group(2)
                details = smb_match.group(3)
                name_match = re.search(r"\(name:([^)]+)\)", details)
                domain_match = re.search(r"\(domain:([^)]+)\)", details)
                domain = domain_match.group(1) if domain_match else ""
                hostname = name_match.group(1) if name_match else host_col
                if domain and hostname and not hostname.lower().endswith(domain.lower()):
                    hostname = f"{hostname.lower()}.{domain}"
                os_match = re.search(r"^\s*([^(]+?)\s+\(name:", details)
                os_name = os_match.group(1).strip() if os_match else "Unknown"
                if ip in seen:
                    continue
                seen.add(ip)
                hosts.append(
                    Host(
                        ip=ip,
                        hostname=hostname,
                        os=os_name,
                        roles=[],
                        services=[],
                    )
                )
                continue

            # Fallback: non-banner SMB lines (share table, user enum, etc.)
            # Format: "SMB IP PORT HOSTNAME ..." where HOSTNAME is short name (no [*])
            # This catches hosts from share enumeration output that don't have banner lines
            simple_match = re.match(
                r"^SMB\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+([A-Za-z0-9_-]+)\s+",
                stripped,
            )
            if simple_match:
                ip = simple_match.group(1)
                hostname_short = simple_match.group(2)
                # Skip if we already have this IP (banner line takes precedence)
                if ip in seen:
                    continue
                # Skip if hostname looks like a table header or separator
                if hostname_short.lower() in ("share", "name", "permissions", "remark"):
                    continue
                seen.add(ip)
                hosts.append(
                    Host(
                        ip=ip,
                        hostname=hostname_short,  # Short name, will be upgraded later if FQDN found
                        os="Unknown",  # No OS info in non-banner lines
                        roles=[],
                        services=[],
                    )
                )

        return hosts

    def _extract_users_from_output(  # noqa: PLR0912
        self: RedTeamDispatcher, output: str
    ) -> list[tuple[str, str]]:
        """Extract (username, domain) tuples from various tool output formats.

        Returns:
            List of (username, domain) tuples. Domain may be empty if not
            extractable from output.
        """
        if not output:
            return []
        users: list[tuple[str, str]] = []
        seen: set[str] = set()
        # Track current domain context from output (e.g., from DOMAIN\user patterns)
        current_domain = ""

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Extract domain from (domain:XXX) patterns in output (e.g., NetExec SMB)
            domain_match = re.search(r"\(domain:([^)]+)\)", stripped, re.IGNORECASE)
            if domain_match:
                current_domain = domain_match.group(1).strip()

            # Extract domain from DOMAIN\user patterns
            domain_user_match = re.search(r"([A-Za-z0-9_.-]+)\\([A-Za-z0-9_.-]+)", stripped)
            if domain_user_match:
                extracted_domain = domain_user_match.group(1).strip()
                extracted_user = domain_user_match.group(2).strip()
                if extracted_user and extracted_user.lower() not in seen:
                    users.append((extracted_user, extracted_domain))
                    seen.add(extracted_user.lower())

            # Extract domain from user@domain UPN patterns
            upn_match = re.search(r"([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+)", stripped)
            if upn_match:
                extracted_user = upn_match.group(1).strip()
                extracted_domain = upn_match.group(2).strip()
                if extracted_user and extracted_user.lower() not in seen:
                    users.append((extracted_user, extracted_domain))
                    seen.add(extracted_user.lower())

            # user:[XXX] patterns (use current_domain as context)
            for match in re.findall(r"user:\[([^\]]+)\]", stripped, re.IGNORECASE):
                user = match.strip()
                if user and user.lower() not in seen:
                    users.append((user, current_domain))
                    seen.add(user.lower())

            # Account: XXX patterns
            account_match = re.search(r"Account:\s*([A-Za-z0-9_.-]+)", stripped)
            if account_match:
                user = account_match.group(1).strip()
                if user and user.lower() not in seen:
                    users.append((user, current_domain))
                    seen.add(user.lower())

            # samaccountname: XXX patterns
            sam_match = re.search(r"samaccountname:\s*([A-Za-z0-9_.-]+)", stripped, re.IGNORECASE)
            if sam_match:
                user = sam_match.group(1).strip()
                if user and user.lower() not in seen:
                    users.append((user, current_domain))
                    seen.add(user.lower())

            # SMB output with timestamp (user enum)
            smb_match = re.search(
                r"SMB\s+\S+\s+\d+\s+\S+\s+([A-Za-z0-9_.-]+)\s+\d{4}-\d{2}-\d{2}",
                stripped,
            )
            if smb_match:
                user = smb_match.group(1).strip()
                if user and user.lower() not in seen:
                    users.append((user, current_domain))
                    seen.add(user.lower())

        return users

    def _extract_plaintext_passwords_from_output(  # noqa: PLR0912
        self: RedTeamDispatcher, output: str
    ) -> list[tuple[str, str, str]]:
        """Extract username/password/domain tuples from tool output.

        Returns:
            List of (username, password, domain) tuples. Domain may be empty
            if not determinable from output.
        """
        if not output:
            return []
        creds: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str]] = set()
        current_user = ""
        current_domain = ""
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Extract domain from DOMAIN\user or user@domain patterns
            domain_user_match = re.search(r"([A-Za-z0-9_.-]+)\\([A-Za-z0-9_.-]+)", stripped)
            if domain_user_match:
                current_domain = domain_user_match.group(1).strip()
                current_user = domain_user_match.group(2).strip()

            upn_match = re.search(r"([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+)", stripped)
            if upn_match:
                current_user = upn_match.group(1).strip()
                current_domain = upn_match.group(2).strip()

            user_match = re.search(r"user:\[([^\]]+)\]", stripped, re.IGNORECASE)
            if user_match:
                current_user = user_match.group(1).strip()
            account_match = re.search(r"Account:\s*([A-Za-z0-9_.-]+)", stripped)
            if account_match:
                current_user = account_match.group(1).strip()
            sam_match = re.search(r"samaccountname:\s*([A-Za-z0-9_.-]+)", stripped, re.IGNORECASE)
            if sam_match:
                current_user = sam_match.group(1).strip()
            if "password" not in stripped.lower():
                continue
            pass_match = re.search(r"Password\s*:\s*([^\s\)]+)", stripped, re.IGNORECASE)
            if not pass_match:
                continue
            password = pass_match.group(1).strip()
            username = ""
            extracted_domain = current_domain
            smb_match = re.search(
                r"SMB\s+\S+\s+\d+\s+\S+\s+([A-Za-z0-9_.-]+)\s+\d{4}-\d{2}-\d{2}.*Password\s*:\s*",
                stripped,
            )
            if smb_match:
                username = smb_match.group(1).strip()
            elif current_user:
                username = current_user
            if not username:
                continue
            if "/" in username or "\\" in username or username.endswith(".txt"):
                continue
            if "/" in password or "\\" in password or password.endswith(".txt"):
                continue
            key = (username, password)
            if key in seen:
                continue
            seen.add(key)
            creds.append((username, password, extracted_domain))
        return creds

    def _resolve_credential_domain(  # noqa: PLR0912
        self: RedTeamDispatcher, username: str, extracted_domain: str
    ) -> str:
        """Resolve the correct domain for a credential.

        Uses multiple strategies to determine the correct domain:
        1. Use extracted domain if it's an FQDN
        2. Resolve NetBIOS domain to FQDN via known mappings
        3. Cross-reference with discovered users to find the correct domain
        4. Only use target domain if user is confirmed to exist there

        Args:
            username: The username to resolve domain for
            extracted_domain: Domain extracted from tool output (may be empty or NetBIOS)

        Returns:
            The resolved FQDN domain, or empty string if not determinable
        """
        username_lower = username.lower()

        # If we have an extracted FQDN domain, use it
        if extracted_domain and "." in extracted_domain:
            return extracted_domain.lower()

        # If we have a NetBIOS domain, try to resolve it
        if extracted_domain:
            netbios_lower = extracted_domain.lower()
            # Check authoritative NetBIOS -> FQDN mapping
            if netbios_lower in self.shared_state.netbios_to_fqdn:
                return self.shared_state.netbios_to_fqdn[netbios_lower]
            # Check known domains for matching FQDN pattern
            for domain in self.shared_state.all_domains:
                domain_lower = domain.lower()
                if domain_lower.startswith(netbios_lower + "."):
                    return domain_lower

        # Cross-reference with discovered users to find correct domain
        matching_domains: list[str] = []
        for user in self.shared_state.all_users:
            if user.username.lower() == username_lower and user.domain:
                matching_domains.append(user.domain.lower())

        # If user exists in exactly one domain, use it
        unique_domains = list(set(matching_domains))
        if len(unique_domains) == 1:
            return unique_domains[0]

        # If user exists in multiple domains, prefer the one matching extracted NetBIOS
        if len(unique_domains) > 1 and extracted_domain:
            netbios_lower = extracted_domain.lower()
            for domain in unique_domains:
                if domain.startswith(netbios_lower + "."):
                    return domain

        # If user exists in multiple domains with no NetBIOS hint, don't guess
        if len(unique_domains) > 1:
            logger.debug(f"Credential domain ambiguous for {username}: found in {unique_domains}")
            return ""

        # No user found - only use target domain if we have NetBIOS match
        if extracted_domain:
            target_domain = ""
            if self.shared_state.target and self.shared_state.target.domain:
                target_domain = self.shared_state.target.domain.lower()
            netbios_lower = extracted_domain.lower()
            if target_domain and target_domain.startswith(netbios_lower + "."):
                return target_domain

        # Cannot determine domain - return empty to avoid false positives
        logger.debug(f"Cannot determine domain for credential: {username}")
        return ""

    def _extract_shares_from_output(  # noqa: PLR0912
        self: RedTeamDispatcher, output: str, default_host: str = ""
    ) -> list[Share]:
        """Extract shares from netexec --shares output."""
        if not output:
            return []
        shares: list[Share] = []
        seen: set[tuple[str, str]] = set()
        in_table = False
        current_host = default_host

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Parse host from SMB line prefix: "SMB  192.168.58.1  445  HOSTNAME  ..."
            if stripped.startswith("SMB"):
                smb_match = re.match(r"^SMB\s+(\d+\.\d+\.\d+\.\d+)\s+", stripped)
                if smb_match:
                    current_host = smb_match.group(1)
                # Strip SMB prefix to get body
                body = re.sub(r"^SMB\s+\S+\s+\d+\s+\S+\s+", "", stripped).strip()
                if not body:
                    continue
                lower = body.lower()
                # Detect share table header
                if lower.startswith("share") and "permission" in lower:
                    in_table = True
                    continue
                # Skip separator lines
                if in_table and set(body) <= {"-", " "}:
                    continue
                # End of table
                if in_table and (body.startswith("[") or lower.startswith("smb")):
                    in_table = False
                    continue
                if not in_table:
                    continue
                # Parse share row
                parts = body.split(None, 2)
                if not parts:
                    continue
                name = parts[0].strip()
                if not name or name.lower() == "share":
                    continue
                # Validate permissions - netexec only outputs READ, WRITE, or READ,WRITE
                # If parts[1] isn't a valid permission, it's actually the comment
                # (happens when share has no permissions, e.g., "ADMIN$  Remote Admin")
                valid_perms = {"read", "write", "read,write", "write,read"}
                raw_perm = parts[1].strip().lower() if len(parts) > 1 else ""
                if raw_perm in valid_perms:
                    permissions = parts[1].strip().upper()
                    comment = parts[2].strip() if len(parts) > 2 else ""
                else:
                    # No valid permission - parts[1:] is actually the comment
                    permissions = ""
                    comment = " ".join(parts[1:]).strip() if len(parts) > 1 else ""
                key = (current_host.lower(), name.lower())
                if key in seen:
                    continue
                seen.add(key)
                shares.append(
                    Share(
                        host=current_host,
                        name=name,
                        permissions=permissions,
                        comment=comment,
                    )
                )
        return shares

    def _extract_hashes_from_output(self: RedTeamDispatcher, output: str) -> list[Hash]:
        """Extract Kerberos hashes (TGS, AS-REP) from tool output."""
        if not output:
            return []
        hashes: list[Hash] = []
        seen: set[str] = set()

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Match Kerberoast TGS hashes: $krb5tgs$23$*username$domain$...
            tgs_match = re.search(
                r"(\$krb5tgs\$\d+\$\*([^$*]+)\$([^$*]+)\$[^$]+\$[a-fA-F0-9$]+)",
                stripped,
            )
            if tgs_match:
                hash_value = tgs_match.group(1)
                username = tgs_match.group(2)
                domain = tgs_match.group(3)
                if hash_value not in seen:
                    seen.add(hash_value)
                    hashes.append(
                        Hash(
                            username=username,
                            hash_value=hash_value,
                            hash_type="TGS",
                            domain=domain,
                        )
                    )
                continue

            # Match AS-REP hashes: $krb5asrep$23$username@domain:...
            asrep_match = re.search(
                r"(\$krb5asrep\$\d+\$([^@:]+)@([^:]+):[a-fA-F0-9$]+)",
                stripped,
            )
            if asrep_match:
                hash_value = asrep_match.group(1)
                username = asrep_match.group(2)
                domain = asrep_match.group(3)
                if hash_value not in seen:
                    seen.add(hash_value)
                    hashes.append(
                        Hash(
                            username=username,
                            hash_value=hash_value,
                            hash_type="AS-REP",
                            domain=domain,
                        )
                    )
                continue

            # Match NTLM hashes from secretsdump: domain\user:rid:lmhash:nthash:::
            ntlm_match = re.search(
                r"([^\\:\s]+)\\([^:\\]+):\d+:([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::",
                stripped,
            )
            if ntlm_match:
                domain = ntlm_match.group(1)
                username = ntlm_match.group(2)
                lm_hash = ntlm_match.group(3)
                nt_hash = ntlm_match.group(4)
                hash_value = f"{lm_hash}:{nt_hash}"
                if hash_value not in seen:
                    seen.add(hash_value)
                    hashes.append(
                        Hash(
                            username=username,
                            hash_value=hash_value,
                            hash_type="NTLM",
                            domain=domain,
                        )
                    )
                continue

            # Match non-domain-prefixed NTLM: user:rid:lmhash:nthash:::
            # (SAM dump entries like Administrator:500:lmhash:nthash:::)
            ntlm_plain = re.match(
                r"([^:\\$\s]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::",
                stripped,
            )
            if ntlm_plain:
                username = ntlm_plain.group(1)
                lm_hash = ntlm_plain.group(3)
                nt_hash = ntlm_plain.group(4)
                hash_value = f"{lm_hash}:{nt_hash}"
                if hash_value not in seen:
                    seen.add(hash_value)
                    hashes.append(
                        Hash(
                            username=username,
                            hash_value=hash_value,
                            hash_type="NTLM",
                            domain="",
                        )
                    )

        return hashes

    def _extract_gmsa_from_output(self: RedTeamDispatcher, output: str) -> list[dict[str, str]]:
        """
        Extract gMSA (Group Managed Service Account) from LDAP/BloodHound output.

        Detects gMSA accounts from:
        - ldapsearch output (objectClass=msDS-GroupManagedServiceAccount)
        - BloodHound output (gMSA service accounts)
        - netexec ldap output with gMSA discovery

        Returns:
            List of dicts with 'account' and optionally 'principals_allowed' keys
        """
        if not output:
            return []

        gmsa_accounts: list[dict[str, str]] = []
        seen: set[str] = set()
        output_lower = output.lower()

        # Check if gMSA-related content is present
        if not any(
            kw in output_lower
            for kw in [
                "gmsa",
                "msds-groupmanagedserviceaccount",
                "managedserviceaccount",
                "msds-managedpassword",
            ]
        ):
            return []

        # Pattern 1: LDAP objectClass=msDS-GroupManagedServiceAccount with sAMAccountName
        # dn: CN=svc_gmsa,CN=Managed Service Accounts,DC=contoso,DC=local
        # sAMAccountName: svc_gmsa$
        ldap_pattern = re.compile(
            r"(?:samaccountname|cn)[:\s]+([a-zA-Z0-9_\-]+\$?)",
            re.IGNORECASE,
        )

        # Pattern 2: netexec/bloodhound gMSA output
        # gMSA: svc_gmsa$ - PrincipalsAllowedToRetrieveManagedPassword: SERVER01$
        gmsa_explicit_pattern = re.compile(
            r"gmsa[:\s]+([a-zA-Z0-9_\-]+\$?)(?:.*principals.*?allowed.*?:?\s*([^\n]+))?",
            re.IGNORECASE,
        )

        # Pattern 3: msDS-GroupManagedServiceAccount in objectClass
        objclass_pattern = re.compile(
            r"objectclass.*?msds-groupmanagedserviceaccount.*?(?:samaccountname|cn)[:\s]+([a-zA-Z0-9_\-]+\$?)",
            re.IGNORECASE | re.DOTALL,
        )

        for pattern in [gmsa_explicit_pattern, objclass_pattern]:
            for match in pattern.finditer(output):
                account = match.group(1).strip()
                if not account or account.lower() in seen:
                    continue
                seen.add(account.lower())

                gmsa_info: dict[str, str] = {"account": account}

                # Try to extract principals allowed to read password
                if match.lastindex and match.lastindex >= 2 and match.group(2):
                    gmsa_info["principals_allowed"] = match.group(2).strip()

                gmsa_accounts.append(gmsa_info)
                logger.info(f"[*] Detected gMSA account: {account}")

        # Also check for standalone mentions in msDS-GroupManagedServiceAccount context
        if "msds-groupmanagedserviceaccount" in output_lower:
            for match in ldap_pattern.finditer(output):
                account = match.group(1).strip()
                # gMSA accounts typically end with $
                if account.endswith("$") and account.lower() not in seen:
                    seen.add(account.lower())
                    gmsa_accounts.append({"account": account})
                    logger.info(f"[*] Detected gMSA account from LDAP: {account}")

        return gmsa_accounts

    async def _auto_queue_gmsa_vulnerabilities(
        self: RedTeamDispatcher,
        gmsa_accounts: list[dict[str, str]],
        source_agent: str,
    ) -> int:
        """
        Auto-queue gMSA accounts for password retrieval.

        Args:
            gmsa_accounts: List of gMSA findings from _extract_gmsa_from_output
            source_agent: Agent that discovered the gMSA accounts

        Returns:
            Number of gMSA retrieval tasks queued
        """
        queued = 0
        domain = ""
        if self.shared_state.target and self.shared_state.target.domain:
            domain = self.shared_state.target.domain

        # Get existing gMSA accounts from state to avoid duplicates
        existing_gmsa = {g.get("account", "").lower() for g in self.shared_state.gmsa_accounts}

        for gmsa in gmsa_accounts:
            account = gmsa.get("account", "")
            if not account:
                continue

            account_lower = account.lower()

            # Store in state.gmsa_accounts for persistence (persisted to Redis)
            if account_lower not in existing_gmsa:
                gmsa_entry = {
                    "account": account,
                    "domain": domain,
                    "principals_allowed": gmsa.get("principals_allowed", "unknown"),
                    "discovered_by": source_agent,
                    "discovered_at": datetime.now(timezone.utc).isoformat(),
                }
                self.shared_state.add_gmsa_account(gmsa_entry)
                existing_gmsa.add(account_lower)

            # Check if already queued as vulnerability
            vuln_key = f"gmsa_readable:{account_lower}"
            if vuln_key in [
                v.vuln_type + ":" + v.target.lower()
                for v in self.shared_state.discovered_vulnerabilities.values()
            ]:
                continue

            # Queue for gMSA password retrieval
            dc_ip = ""
            if self.shared_state.target:
                dc_ip = self.shared_state.target.ip

            vuln = VulnerabilityInfo(
                vuln_type="gmsa_readable",
                target=account,
                details={
                    "account": account,
                    "principals_allowed": gmsa.get("principals_allowed", "unknown"),
                    "domain": domain,
                    "dc_ip": dc_ip,
                    "action": f"Use gmsa_dump_passwords or gmsa_read_password_bloodyad to retrieve {account} NTLM hash",
                    "description": f"🔑 gMSA account {account} detected - may be readable for password retrieval",
                },
            )

            vuln_id = f"vuln-gmsa-{uuid.uuid4().hex[:8]}"
            self.shared_state.discovered_vulnerabilities[vuln_id] = vuln
            await self.queue_vulnerability(
                vuln.vuln_type, vuln.target, vuln.details, "gmsa_extractor"
            )
            queued += 1

            logger.info(f"🔑 Auto-queued gMSA password retrieval for {account}")

        return queued

    def _extract_delegation_from_output(  # noqa: PLR0912
        self: RedTeamDispatcher, output: str
    ) -> list[dict[str, str]]:
        """
        Extract delegation findings from impacket-findDelegation output.

        Output format:
        AccountName          AccountType    DelegationType      DelegationRightsTo
        -----------          -----------    ---------------     ------------------
        svc_sql              user           Constrained         cifs/srv01.corp.contoso.local
        WEB01$               computer       Unconstrained       N/A

        Returns list of dicts with keys: account, account_type, delegation_type, target_spn
        """
        if not output:
            return []

        delegations: list[dict[str, str]] = []
        seen: set[str] = set()
        in_table = False

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            lower = stripped.lower()

            # Detect table header
            if "accountname" in lower and "delegationtype" in lower:
                in_table = True
                continue

            # Skip separator lines (dashes)
            if in_table and set(stripped) <= {"-", " "}:
                continue

            # Stop at non-table content
            if in_table and stripped.startswith(("[", "Impacket")):
                in_table = False
                continue

            if not in_table:
                continue

            # Parse table row - handle fixed-width columns with multi-word delegation types
            parts = stripped.split()
            if len(parts) < 3:
                continue

            account = parts[0]
            account_type = parts[1] if len(parts) > 1 else ""

            # Find delegation type - look for Constrained/Unconstrained/RBCD keyword
            delegation_type = ""
            target_spn = ""
            lower_line = stripped.lower()

            if "unconstrained" in lower_line:
                delegation_type = "unconstrained"
            elif "constrained" in lower_line:
                delegation_type = "constrained"
            elif "rbcd" in lower_line:
                delegation_type = "rbcd"
            else:
                continue  # Not a delegation line

            # Extract target SPN - look for SPN pattern (service/host)
            for part in parts:
                if "/" in part and not part.startswith("[") and part not in ("w/", "w/o"):
                    slash_idx = part.find("/")
                    if slash_idx < len(part) - 1 and part[slash_idx + 1].isalpha():
                        target_spn = part
                        break
            if target_spn == "N/A":
                target_spn = ""

            # Deduplicate by account+delegation_type
            key = f"{account.lower()}:{delegation_type.lower()}"
            if key in seen:
                continue
            seen.add(key)

            delegations.append(
                {
                    "account": account,
                    "account_type": account_type,
                    "delegation_type": delegation_type,
                    "target_spn": target_spn,
                }
            )

        return delegations

    async def _auto_queue_delegation_vulnerabilities(  # noqa: PLR0912
        self: RedTeamDispatcher,
        delegations: list[dict[str, str]],
        source_agent: str,
        task_queue: Any = None,
    ) -> int:
        """
        Auto-queue delegation vulnerabilities for exploitation.

        Args:
            delegations: List of delegation findings from _extract_delegation_from_output
            source_agent: Agent that discovered the delegation
            task_queue: Optional task queue for direct dispatch (threaded consumer passes its own).

        Returns:
            Number of vulnerabilities queued
        """
        queued = 0

        for deleg in delegations:
            account = deleg.get("account", "")
            delegation_type = deleg.get("delegation_type", "").lower()
            target_spn = deleg.get("target_spn", "")

            if delegation_type == "constrained":
                vuln_type = "constrained_delegation"
            elif delegation_type == "unconstrained":
                vuln_type = "unconstrained_delegation"
            else:
                continue

            # Check if already queued
            already_queued = any(
                v.vuln_type == vuln_type and account.lower() in v.target.lower()
                for v in self.shared_state.discovered_vulnerabilities.values()
            )
            if already_queued:
                continue

            # Find credential for this account (needed for S4U attack)
            account_cred = None
            account_lower = account.lower().rstrip("$")
            for cred in self.shared_state.all_credentials:
                if cred.username.lower() == account_lower and cred.password:
                    account_cred = cred
                    break

            details: dict[str, Any] = {
                "account": account,
                "account_name": account,  # Normalized field for priority boost logic
                "delegation_type": delegation_type,
                "target_spn": target_spn,
                "discovered_by": source_agent,
                "has_credentials": account_cred is not None,
            }

            if account_cred:
                details["username"] = account_cred.username
                details["password"] = account_cred.password
                details["domain"] = account_cred.domain

            queued_vuln_id = await self.queue_vulnerability(
                vuln_type=vuln_type,
                target=account,
                details=details,
                discovered_by=source_agent,
            )

            logger.warning(
                f"🎫 Auto-queued {vuln_type} for {account} (target: {target_spn or 'any'})"
            )
            if queued_vuln_id:
                queued += 1

            # Auto-dispatch S4U attack if we have credentials for constrained delegation
            if account_cred and delegation_type == "constrained" and target_spn and queued_vuln_id:
                dc_ip = self._find_domain_controller_ip(account_cred.domain)
                # Fallback: extract DC IP from target SPN hostname or vulnerability details
                if not dc_ip:
                    spn_host = target_spn.split("/", 1)[-1] if "/" in target_spn else ""
                    for host in self.shared_state.all_hosts:
                        if host.hostname and spn_host and host.hostname.lower() == spn_host.lower():
                            dc_ip = host.ip
                            break
                        if host.ip == details.get("target_ip"):
                            dc_ip = host.ip
                            break
                # Last resort: use target_ip from vulnerability details directly
                if not dc_ip:
                    dc_ip = details.get("target_ip", "")
                logger.warning(
                    f"🚀 Auto-dispatching S4U attack for {account} -> {target_spn} "
                    f"(have credentials, DC: {dc_ip}, vuln_id: {queued_vuln_id})"
                )

                await self.request_exploit(
                    vuln_type="constrained_delegation",
                    vuln_id=queued_vuln_id,
                    target=account,
                    source_agent="auto_delegation",
                    params={
                        "account": account,
                        "target_spn": target_spn,
                        "domain": account_cred.domain,
                        "username": account_cred.username,
                        "password": account_cred.password,
                        "dc_ip": dc_ip,
                    },
                    task_queue=task_queue,
                )

        return queued

    def _extract_bloodhound_vulns_from_output(  # noqa: PLR0912
        self: RedTeamDispatcher, output: str
    ) -> list[dict[str, Any]]:
        """
        Extract BloodHound-identified vulnerabilities from tool output.

        Parses BloodHound JSON output and raw collection results for:
        - GPO edit permissions (WriteProperty/WriteDacl on GPO) → gpo_abuse vuln
        - Local admin memberships (AdminTo relationship) → local_admin vuln
        - ACL abuse paths (GenericAll/GenericWrite on user/computer)

        Returns list of dicts with keys: vuln_type, target, principal, details
        """
        if not output:
            return []

        vulns: list[dict[str, Any]] = []
        seen: set[str] = set()
        output_lower = output.lower()

        # Parse GPO-related patterns from BloodHound output
        gpo_patterns = [
            r"(?:has\s+)?(?:writeproperty|writedacl|genericall|genericwrite)\s+(?:on|to)\s+(?:gpo\s+)?['\"]?([^'\"]+)['\"]?",
            r"(?:gpo|group\s*policy)\s*[:=]\s*['\"]?([^'\"]+)['\"]?.*(?:writeproperty|writedacl|genericall)",
            r"(?:can\s+)?(?:edit|modify|write)\s+(?:gpo|group\s*policy)\s+['\"]?([^'\"]+)['\"]?",
        ]

        for pattern in gpo_patterns:
            for match in re.finditer(pattern, output_lower, re.IGNORECASE):
                gpo_name = match.group(1).strip()
                if not gpo_name or len(gpo_name) < 3:
                    continue

                key = f"gpo_abuse:{gpo_name.lower()}"
                if key in seen:
                    continue
                seen.add(key)

                vulns.append(
                    {
                        "vuln_type": "gpo_abuse",
                        "target": gpo_name,
                        "principal": "",
                        "details": {
                            "gpo_name": gpo_name,
                            "description": f"GPO edit permissions detected on '{gpo_name}'",
                        },
                    }
                )

        # Parse local admin / AdminTo patterns
        admin_patterns = [
            r"(\S+@\S+|\S+)\s+(?:is\s+)?(?:local\s*admin(?:istrator)?|AdminTo)\s+(?:on|→|->)\s+(\S+)",
            r"(?:local\s*admin|AdminTo)\s*[:=]\s*(\S+)\s+(?:on|→|->)\s+(\S+)",
            r"(\S+)\s+has\s+(?:local\s*)?admin(?:istrative)?\s+(?:access|rights)\s+(?:on|to)\s+(\S+)",
        ]

        for pattern in admin_patterns:
            for match in re.finditer(pattern, output_lower, re.IGNORECASE):
                principal = match.group(1).strip()
                target = match.group(2).strip()

                if not principal or not target or len(target) < 2:
                    continue

                key = f"local_admin:{principal.lower()}:{target.lower()}"
                if key in seen:
                    continue
                seen.add(key)

                vulns.append(
                    {
                        "vuln_type": "local_admin",
                        "target": target,
                        "principal": principal,
                        "details": {
                            "username": principal.split("@")[0] if "@" in principal else principal,
                            "domain": principal.split("@")[1] if "@" in principal else "",
                            "description": f"{principal} has local admin on {target}",
                        },
                    }
                )

        # Parse "Pwn3d!" output from CME/NetExec which indicates local admin
        pwned_pattern = r"(\d{1,3}(?:\.\d{1,3}){3}).*Pwn3d!"
        for match in re.finditer(pwned_pattern, output, re.IGNORECASE):
            target_ip = match.group(1)

            # Try to find associated credential from the same line or nearby context
            line_match = re.search(rf".*{re.escape(target_ip)}.*", output)
            if line_match:
                line = line_match.group(0)
                # Look for username pattern like "DOMAIN\user" or "user@domain"
                cred_match = re.search(r"([A-Za-z0-9_.-]+)[\\/@]([A-Za-z0-9_.-]+)", line)
                if cred_match:
                    domain_or_user = cred_match.group(1)
                    username = cred_match.group(2)

                    key = f"local_admin:{username.lower()}:{target_ip}"
                    if key in seen:
                        continue
                    seen.add(key)

                    vulns.append(
                        {
                            "vuln_type": "local_admin",
                            "target": target_ip,
                            "principal": f"{domain_or_user}\\{username}",
                            "details": {
                                "username": username,
                                "domain": domain_or_user,
                                "description": f"Pwn3d! - {domain_or_user}\\{username} has admin on {target_ip}",
                            },
                        }
                    )

        # Parse ACL abuse patterns (GenericAll, GenericWrite on users/computers)
        acl_patterns = [
            r"(\S+)\s+(?:has\s+)?(?:genericall|genericwrite|writedacl|writeowner)\s+(?:on|to)\s+(?:user|computer)?\s*(\S+)",
        ]

        for pattern in acl_patterns:
            for match in re.finditer(pattern, output_lower, re.IGNORECASE):
                principal = match.group(1).strip()
                target = match.group(2).strip()

                if not principal or not target:
                    continue

                is_computer = target.endswith("$") or "." in target

                key = f"acl_abuse:{principal.lower()}:{target.lower()}"
                if key in seen:
                    continue
                seen.add(key)

                vulns.append(
                    {
                        "vuln_type": "acl_abuse",
                        "target": target,
                        "principal": principal,
                        "details": {
                            "target_type": "computer" if is_computer else "user",
                            "description": f"{principal} has dangerous ACL permissions on {target}",
                        },
                    }
                )

        # HIGH PRIORITY: Detect GenericAll/WriteMember on Domain Admins (instant DA path)
        # This is the FASTEST path to DA - just add yourself to Domain Admins!
        da_acl_patterns = [
            # Pattern: "user has GenericAll on Domain Admins"
            r"(\S+)\s+(?:has\s+)?(?:genericall|writemember|writedacl|genericwrite)\s+(?:on|to)\s+(?:group\s+)?['\"]?(?:domain\s*admins|cn=domain\s*admins)['\"]?",
            # Pattern: "GenericAll: Domain Admins -> user"
            r"(?:genericall|writemember|writedacl|genericwrite)\s*[:\-=]\s*(?:domain\s*admins|cn=domain\s*admins)\s*(?:->|→|to)\s*(\S+)",
            # Pattern: "Domain Admins: GenericAll from user"
            r"(?:domain\s*admins|cn=domain\s*admins)\s*[:\-]\s*(?:genericall|writemember|writedacl)\s+(?:from|by)\s+(\S+)",
            # Pattern from bloodhound-python output
            r"(\S+).*(?:MemberOf|AddMember|GenericAll|WriteDacl).*(?:Domain\s*Admins|DOMAIN\s*ADMINS)",
        ]

        for pattern in da_acl_patterns:
            for match in re.finditer(pattern, output, re.IGNORECASE):
                principal = match.group(1).strip() if match.groups() else ""

                if not principal or len(principal) < 2:
                    continue

                # Skip if it's a built-in account or the target itself
                principal_lower = principal.lower()
                if principal_lower in (
                    "domain admins",
                    "enterprise admins",
                    "administrators",
                    "system",
                ):
                    continue

                key = f"genericall_domain_admins:{principal_lower}"
                if key in seen:
                    continue
                seen.add(key)

                vulns.append(
                    {
                        "vuln_type": "genericall_domain_admins",
                        "target": "Domain Admins",
                        "principal": principal,
                        "details": {
                            "instant_da": True,
                            "action": "Use bloodyad_add_group_member to add yourself to Domain Admins!",
                            "description": f"🚨 INSTANT DA PATH: {principal} has write access to Domain Admins group!",
                        },
                    }
                )
                logger.warning(
                    f"🚨 HIGH-VALUE: {principal} has GenericAll/WriteMember on Domain Admins - INSTANT DA PATH!"
                )

        # HIGH PRIORITY: Detect GPO write on DC-linked GPOs (gpo_write vuln)
        # Look for GPO permissions that include DC linking info
        gpo_dc_patterns = [
            # Pattern: GPO linked to Domain Controllers
            r"(?:gpo|group\s*policy)\s+['\"]?([^'\"]+)['\"]?\s+(?:linked\s+to|applies\s+to)\s+(?:domain\s*controllers|dc)",
            # Pattern: WriteProperty/WriteDacl on GPO with DC mention
            r"(?:writeproperty|writedacl|genericall|genericwrite)\s+(?:on|to)\s+(?:gpo\s+)?['\"]?([^'\"]+)['\"]?.*(?:domain\s*controllers|dc\s*ou)",
            # Pattern from BloodHound: GPO -> OU (Domain Controllers)
            r"['\"]?([^'\"]+)['\"]?\s*->\s*(?:domain\s*controllers\s*ou|ou=domain\s*controllers)",
        ]

        for pattern in gpo_dc_patterns:
            for match in re.finditer(pattern, output_lower, re.IGNORECASE):
                gpo_name = match.group(1).strip()

                if not gpo_name or len(gpo_name) < 3:
                    continue

                key = f"gpo_write:{gpo_name.lower()}"
                if key in seen:
                    continue
                seen.add(key)

                vulns.append(
                    {
                        "vuln_type": "gpo_write",
                        "target": gpo_name,
                        "principal": "",
                        "details": {
                            "gpo_name": gpo_name,
                            "dc_linked": True,
                            "action": "Use pygpoabuse_immediate_task to create scheduled task as SYSTEM on DC!",
                            "description": f"🚨 DA PATH: GPO '{gpo_name}' is linked to Domain Controllers and writable!",
                        },
                    }
                )
                logger.warning(
                    f"🚨 HIGH-VALUE: GPO '{gpo_name}' linked to DC with write permissions - DA PATH!"
                )

        # PERSISTENCE: Detect GenericAll on AdminSDHolder (persistence backdoor)
        # AdminSDHolder ACE propagates to all protected groups via SDProp
        adminsd_patterns = [
            # Pattern: GenericAll/WriteDacl on AdminSDHolder
            r"(\S+).*(?:genericall|writedacl|genericwrite).*(?:adminsdholder|cn=adminsdholder)",
            # Pattern: AdminSDHolder: GenericAll from user
            r"(?:adminsdholder|cn=adminsdholder).*(?:genericall|writedacl).*(?:from|by|->|→)\s*(\S+)",
            # BloodHound edge format
            r"(\S+)\s*-(?:GenericAll|WriteDacl)->.*AdminSDHolder",
        ]

        for pattern in adminsd_patterns:
            for match in re.finditer(pattern, output, re.IGNORECASE):
                principal = match.group(1).strip() if match.groups() else ""

                if not principal or len(principal) < 2:
                    continue

                principal_lower = principal.lower()
                if principal_lower in (
                    "domain admins",
                    "enterprise admins",
                    "administrators",
                    "system",
                ):
                    continue

                key = f"adminsd_holder_acl:{principal_lower}"
                if key in seen:
                    continue
                seen.add(key)

                vulns.append(
                    {
                        "vuln_type": "adminsd_holder_acl",
                        "target": "AdminSDHolder",
                        "principal": principal,
                        "details": {
                            "persistence": True,
                            "action": "Use adminsd_holder_add_ace to plant persistent backdoor on all protected groups!",
                            "description": f"🔒 PERSISTENCE PATH: {principal} can modify AdminSDHolder - permanent DA backdoor!",
                        },
                    }
                )
                logger.warning(
                    f"🔒 PERSISTENCE: {principal} has GenericAll on AdminSDHolder - can plant permanent backdoor!"
                )

        return vulns

    async def _auto_queue_bloodhound_vulnerabilities(
        self: RedTeamDispatcher, vulns: list[dict[str, Any]], source_agent: str
    ) -> int:
        """
        Auto-queue BloodHound-discovered vulnerabilities for exploitation.

        Args:
            vulns: List of vulnerability findings from _extract_bloodhound_vulns_from_output
            source_agent: Agent that discovered the vulnerabilities

        Returns:
            Number of vulnerabilities queued
        """
        queued = 0

        for vuln in vulns:
            vuln_type = vuln.get("vuln_type", "")
            target = vuln.get("target", "")
            principal = vuln.get("principal", "")
            details = vuln.get("details", {})

            if not vuln_type or not target:
                continue

            # Check if already queued
            already_queued = any(
                v.vuln_type == vuln_type and target.lower() in v.target.lower()
                for v in self.shared_state.discovered_vulnerabilities.values()
            )
            if already_queued:
                continue

            # Try to find credential for the principal
            principal_cred = None
            if principal:
                principal_name = principal.split("\\")[-1].split("@")[0].lower()
                for cred in self.shared_state.all_credentials:
                    if cred.username.lower() == principal_name and cred.password:
                        principal_cred = cred
                        break

            # Enrich details with credential info
            vuln_details: dict[str, Any] = dict(details)
            vuln_details["discovered_by"] = source_agent
            vuln_details["principal"] = principal

            if principal_cred:
                vuln_details["username"] = principal_cred.username
                vuln_details["password"] = principal_cred.password
                vuln_details["domain"] = principal_cred.domain

            await self.queue_vulnerability(
                vuln_type=vuln_type,
                target=target,
                details=vuln_details,
                discovered_by=source_agent,
            )

            logger.warning(
                f"🩸 Auto-queued BloodHound {vuln_type} for {target} "
                f"(principal: {principal or 'unknown'})"
            )
            queued += 1

            # For local_admin vulns, also update credential is_admin status
            if vuln_type == "local_admin" and principal_cred:
                for cred in self.shared_state.all_credentials:
                    if (
                        cred.username.lower() == principal_cred.username.lower()
                        and cred.domain.lower() == principal_cred.domain.lower()
                    ):
                        cred.is_admin = True
                        cred.source = f"{cred.source}; admin on {target}"
                        logger.info(
                            f"Marked {cred.domain}\\{cred.username} as admin "
                            f"(BloodHound: admin on {target})"
                        )
                        break

        return queued


__all__ = ["ResultProcessingMixin"]
