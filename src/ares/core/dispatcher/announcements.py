"""Announcements for major operation milestones.

This module provides methods to announce domain admin achievement,
golden ticket forging, and operation completion.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from loguru import logger

from ares.core.config import (
    get_multi_forest_mode,
    get_stop_on_domain_admin,
    get_stop_on_golden_ticket,
)
from ares.core.tracing import trace_discovery

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher


class AnnouncementMixin:
    """Announcements for major operation milestones."""

    async def announce_domain_admin(
        self: RedTeamDispatcher,
        username: str,
        domain: str,
        attack_path: str,
        credential_type: str,
        source_agent: str,
    ) -> None:
        """
        Record that domain admin has been achieved.

        Updates shared state and checkpoints. Workers detect this via
        state synchronization.

        Args:
            username: The domain admin username.
            domain: The domain.
            attack_path: Description of how it was achieved.
            credential_type: Type of credential (password, hash, ticket).
            source_agent: Agent that achieved it.
        """
        self.shared_state.has_domain_admin = True
        self.shared_state.domain_admin_path = attack_path

        # Track which domain we achieved DA on (for multi-forest mode)
        domain_lower = domain.lower()
        if domain_lower not in self.shared_state.domain_admin_domains:
            self.shared_state.domain_admin_domains.append(domain_lower)

        # Determine if we should mark operation as complete
        # These modes are mutually exclusive (validated in config)
        should_complete = False

        if get_stop_on_domain_admin():
            # Single-domain mode: stop on first DA
            should_complete = True
            logger.info("ARES_STOP_ON_DOMAIN_ADMIN enabled - marking operation complete")
        elif get_multi_forest_mode():
            # Multi-forest mode: stop only when ALL trusted forests are dominated
            if self.shared_state.all_forests_dominated():
                should_complete = True
                logger.info(
                    "ARES_MULTI_FOREST_MODE enabled - all trusted forests dominated, "
                    "marking operation complete"
                )
            else:
                undominated = self.shared_state.get_undominated_forests()
                logger.info(
                    f"ARES_MULTI_FOREST_MODE enabled - {len(undominated)} trusted "
                    f"forest(s) remaining: {undominated}"
                )
                # Auto-dispatch trust key extraction for cross-forest pivoting
                await self._auto_dispatch_trust_key_extraction(
                    da_domain=domain,
                    da_username=username,
                    undominated_forests=undominated,
                    source_agent=source_agent,
                )

        if should_complete:
            self.shared_state.completed = True
            if not self.shared_state.completed_at:
                self.shared_state.completed_at = datetime.now(timezone.utc)

        await self._checkpoint()
        logger.success(f"DOMAIN ADMIN ACHIEVED: {domain}\\{username}")

        # Trace the domain admin achievement for observability
        trace_discovery(
            discovery_type="domain_admin",
            source_agent=source_agent,
            operation_id=self.shared_state.operation_id,
            target_user=username,
            target_domain=domain,
            additional_attrs={
                "attack_path": attack_path,
                "credential_type": credential_type,
                "mitre.technique.id": "T1003.006",  # DCSync/credential dumping
            },
        )

    async def _auto_dispatch_trust_key_extraction(
        self: RedTeamDispatcher,
        da_domain: str,
        da_username: str,
        undominated_forests: list[str],
        source_agent: str,
    ) -> None:
        """Auto-dispatch trust key extraction for cross-forest pivoting.

        When DA is achieved on a domain and other forests remain undominated,
        automatically extract trust keys to enable cross-forest attacks.

        Args:
            da_domain: Domain where we just achieved DA.
            da_username: Username of the DA account.
            undominated_forests: List of foreign forests not yet dominated.
            source_agent: Agent that achieved DA.
        """
        # Deduplicate: only dispatch once per DA domain
        # This prevents multiple dispatches when both krbtgt and Administrator hashes trigger
        if not hasattr(self, "_trust_extraction_dispatched"):
            self._trust_extraction_dispatched: set[str] = set()

        da_domain_lower = da_domain.lower()
        if da_domain_lower in self._trust_extraction_dispatched:
            logger.debug(f"MULTI_FOREST_MODE: Trust extraction already dispatched for {da_domain}")
            return

        # Mark as dispatched BEFORE actual dispatch (fail-safe)
        self._trust_extraction_dispatched.add(da_domain_lower)

        # Get DC IP for the domain where we have DA
        dc_ip = self.shared_state.domain_controllers.get(da_domain_lower)

        # Validate DC actually belongs to this domain (not a stale mapping from
        # incomplete hostname resolution — e.g., NMAP gives ws01.contoso.local
        # before LDAP corrects it to ws01.child.contoso.local)
        if dc_ip:
            for h in self.shared_state.all_hosts:
                if h.ip == dc_ip and h.hostname:
                    h_domain = ".".join(h.hostname.lower().split(".")[1:])
                    if h_domain != da_domain_lower:
                        logger.warning(
                            f"MULTI_FOREST_MODE: DC {dc_ip} hostname {h.hostname} "
                            f"belongs to {h_domain}, not {da_domain_lower} — searching for correct DC"
                        )
                        dc_ip = None
                        # Try to find correct DC by hostname
                        for h2 in self.shared_state.all_hosts:
                            if (
                                h2.is_dc
                                and h2.hostname
                                and ".".join(h2.hostname.lower().split(".")[1:]) == da_domain_lower
                            ):
                                dc_ip = h2.ip
                                self.shared_state.domain_controllers[da_domain_lower] = dc_ip
                                logger.info(
                                    f"MULTI_FOREST_MODE: Found correct DC for {da_domain_lower}: "
                                    f"{h2.hostname} -> {dc_ip}"
                                )
                                break
                    break

        if not dc_ip:
            logger.warning(f"Cannot dispatch trust key extraction: no DC IP for {da_domain}")
            # Do NOT clear dedup flag — periodic retry loop will handle re-attempts.
            # Clearing allows duplicate dispatch from publishing.py path.
            return

        # Determine if this is a child domain
        # Trust accounts exist at forest root, so for child domains we need to escalate first
        domain_parts = da_domain_lower.split(".")
        is_child_domain = len(domain_parts) >= 3  # child.parent.tld
        parent_domain = ".".join(domain_parts[1:]) if is_child_domain else None
        cred_domain = parent_domain if is_child_domain else da_domain_lower
        cred_domain_lower = cred_domain.lower() if cred_domain else da_domain_lower

        if is_child_domain:
            logger.info(
                f"MULTI_FOREST_MODE: Child domain {da_domain} detected, "
                f"need parent domain {parent_domain} credentials for trust extraction"
            )

        # Find DA credential (password or hash) for the appropriate domain
        # For child domains, look for parent domain credentials (via golden ticket DCSync)
        da_hash = None
        da_password = None

        # Look for Administrator hash in the appropriate domain
        for h in self.shared_state.all_hashes:
            if (
                h.username.lower() == "administrator"
                and h.domain
                and h.domain.lower() == cred_domain_lower
                and h.hash_type.upper() == "NTLM"
            ):
                da_hash = h.hash_value
                break

        # Fallback to password credential
        if not da_hash:
            for cred in self.shared_state.all_credentials:
                if (
                    cred.domain
                    and cred.domain.lower() == cred_domain_lower
                    and cred.password
                    and cred.username.lower() in ("administrator", da_username.lower())
                ):
                    da_password = cred.password
                    da_username = cred.username
                    break

        if not da_hash and not da_password:
            if is_child_domain:
                # Child domain without parent creds - defer to golden ticket flow
                logger.warning(
                    f"MULTI_FOREST_MODE: Child domain {da_domain} has no parent credentials "
                    f"for {parent_domain}. Waiting for golden ticket flow to DCSync parent. "
                    f"Trust extraction deferred."
                )
            else:
                logger.warning(
                    f"Cannot dispatch trust key extraction: no DA credentials for {da_domain}"
                )
            # Do NOT clear dedup flag — periodic retry loop will handle re-attempts.
            # Clearing allows duplicate dispatch from publishing.py path.
            return

        # Determine the extraction domain and DC IP
        # For child domains, use parent (forest root) since trust accounts are there
        extraction_domain = parent_domain if is_child_domain else da_domain
        extraction_dc_ip = dc_ip

        if is_child_domain and parent_domain:
            # Get parent DC IP - MUST validate it's actually a parent DC
            # The cache may have incorrect mappings (e.g., child DC IP for parent domain)
            parent_dc_ip = None
            cached_dc_ip = self.shared_state.domain_controllers.get(parent_domain.lower())

            if cached_dc_ip:
                # Validate the cached IP is actually a parent DC, not a child DC
                for host in self.shared_state.all_hosts:
                    if (
                        host.ip == cached_dc_ip
                        and host.is_dc
                        and host.hostname
                        and host.hostname.lower().endswith(f".{parent_domain.lower()}")
                        and not host.hostname.lower().endswith(f".{da_domain_lower}")
                    ):
                        parent_dc_ip = cached_dc_ip
                        break

                if not parent_dc_ip:
                    logger.warning(
                        f"MULTI_FOREST_MODE: Cached DC {cached_dc_ip} for {parent_domain} "
                        f"is not a valid parent DC, searching for correct DC"
                    )

            if not parent_dc_ip:
                # Try to find parent DC from hosts by hostname
                for host in self.shared_state.all_hosts:
                    if (
                        host.is_dc
                        and host.hostname
                        and host.hostname.lower().endswith(f".{parent_domain.lower()}")
                        and not host.hostname.lower().endswith(f".{da_domain_lower}")
                    ):
                        parent_dc_ip = host.ip
                        logger.info(
                            f"MULTI_FOREST_MODE: Found parent DC via hostname: "
                            f"{host.hostname} -> {parent_dc_ip}"
                        )
                        break

            if parent_dc_ip:
                extraction_dc_ip = parent_dc_ip
            else:
                # Try DNS lookup for parent DC
                try:
                    import subprocess

                    dns_cmd = ["dig", "+short", f"_ldap._tcp.dc._msdcs.{parent_domain}", "SRV"]
                    result = subprocess.run(  # noqa: ASYNC221
                        dns_cmd, capture_output=True, text=True, timeout=10, check=False
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        for line in result.stdout.strip().split("\n"):
                            parts = line.split()
                            if len(parts) >= 4:
                                dc_hostname = parts[3].rstrip(".")
                                a_cmd = ["dig", "+short", dc_hostname, "A"]
                                a_result = subprocess.run(  # noqa: ASYNC221
                                    a_cmd, capture_output=True, text=True, timeout=10, check=False
                                )
                                if a_result.returncode == 0 and a_result.stdout.strip():
                                    extraction_dc_ip = a_result.stdout.strip().split("\n")[0]
                                    self.shared_state.domain_controllers[parent_domain.lower()] = (
                                        extraction_dc_ip
                                    )
                                    logger.info(
                                        f"MULTI_FOREST_MODE: Resolved parent DC via DNS: "
                                        f"{dc_hostname} -> {extraction_dc_ip}"
                                    )
                                    break
                except Exception as dns_err:
                    logger.warning(
                        f"MULTI_FOREST_MODE: DNS resolution failed for parent: {dns_err}"
                    )

        # Dispatch trust key extraction for each undominated forest
        for target_forest in undominated_forests:
            # Dedup key: source_domain:target_forest (persists across restarts via shared_state)
            extraction_domain_lower = extraction_domain.lower() if extraction_domain else ""
            dedup_key = f"{extraction_domain_lower}:{target_forest.lower()}"
            if dedup_key in self.shared_state.processed_trust_extractions:
                logger.debug(f"Trust key extraction already dispatched: {dedup_key}")
                continue

            self.shared_state.processed_trust_extractions.add(dedup_key)

            # Build task payload
            # extract_trust_key uses secretsdump -just-dc-user FORESTNETBIOS$
            # If hash is in LM:NT format, extract just the NT hash to avoid
            # the LLM agent prepending ":" and creating ":LM:NT" (3 values)
            hash_for_payload = da_hash
            if hash_for_payload and ":" in hash_for_payload:
                hash_for_payload = hash_for_payload.split(":")[-1]
            # Include target domain SID if cached (critical for inter-realm ticket)
            # Without this, the agent must call get_sid which fails cross-forest
            target_sid = self.shared_state.domain_sids.get(target_forest.lower(), "")
            source_sid = self.shared_state.domain_sids.get((extraction_domain or "").lower(), "")
            task_payload = {
                "tool": "extract_trust_key",
                "domain": extraction_domain,
                "username": "Administrator" if da_hash else da_username,
                "password": hash_for_payload or da_password,
                "dc_ip": extraction_dc_ip,
                "trusted_domain": target_forest,
                "use_hash": bool(da_hash),
                "target_sid": target_sid,
                "source_sid": source_sid,
            }

            logger.warning(
                f"🌲 Auto-dispatching trust key extraction: {extraction_domain} → {target_forest} "
                f"(DC: {extraction_dc_ip}, using {'hash' if da_hash else 'password'})"
            )

            # Dispatch to privesc worker (has KerberosTools with extract_trust_key)
            # Submit DIRECTLY to bypass throttling — this is the most critical
            # task in the multi-forest chain and must not be deferred/dropped
            if self._task_queue:
                try:
                    task_id = await self._task_queue.submit_task(
                        task_type="exploit",
                        target_role="privesc",
                        payload=task_payload,
                        source_agent="auto_trust_extraction",
                        priority=1,  # High priority - critical for multi-forest
                    )
                    logger.info(
                        f"🌲 Trust extraction task {task_id} submitted "
                        f"to ares:tasks:privesc (direct, bypassed throttle)"
                    )
                except Exception as e:
                    logger.error(f"Failed to dispatch trust key extraction: {e}")

    async def announce_golden_ticket(
        self: RedTeamDispatcher,
        domain: str,
        krbtgt_hash: str,
        ticket_path: str,
        source_agent: str,
        target_domain: str | None = None,
    ) -> None:
        """
        Record that golden ticket has been forged.

        Args:
            domain: The source domain (where krbtgt was obtained).
            krbtgt_hash: The krbtgt hash used.
            ticket_path: Path to the ticket file.
            source_agent: Agent that forged it.
            target_domain: The target domain for escalation (parent/forest root).
        """
        self.shared_state.has_golden_ticket = True

        # Only mark complete if stop_on_golden_ticket is enabled
        if get_stop_on_golden_ticket():
            self.shared_state.completed = True
            if not self.shared_state.completed_at:
                self.shared_state.completed_at = datetime.now(timezone.utc)
            logger.info("ARES_STOP_ON_GOLDEN_TICKET enabled - marking operation complete")

        await self._checkpoint()
        if target_domain:
            logger.success(f"GOLDEN TICKET FORGED: {domain} → {target_domain} (forest escalation)")
        else:
            logger.success(f"GOLDEN TICKET FORGED for {domain}")

        # Trace the golden ticket forging for observability
        trace_discovery(
            discovery_type="golden_ticket",
            source_agent=source_agent,
            operation_id=self.shared_state.operation_id,
            target_domain=target_domain or domain,
            additional_attrs={
                "source_domain": domain,
                "ticket_path": ticket_path,
                "is_forest_escalation": bool(target_domain),
                "mitre.technique.id": "T1558.001",  # Golden Ticket
            },
        )

        # Announce operation complete if stop_on_golden_ticket is enabled
        # This sets the Redis status key so workers detect completion
        if get_stop_on_golden_ticket():
            summary = (
                f"Golden Ticket forged for {domain}"
                if not target_domain
                else f"Golden Ticket forged: {domain} → {target_domain}"
            )
            await self.announce_operation_complete(
                source_agent=source_agent,
                success=True,
                summary=summary,
            )

    async def announce_operation_complete(
        self: RedTeamDispatcher,
        source_agent: str,
        success: bool,
        summary: str,
    ) -> None:
        """
        Announce that the operation is complete.

        Sets the Redis status key so remote workers can detect completion.

        Args:
            source_agent: Agent making the announcement.
            success: Whether the operation was successful.
            summary: Summary of the operation.
        """
        # CRITICAL: Set Redis status key so remote workers detect completion
        # Workers check is_operation_completed() which reads this key
        if self._redis_client is not None:
            try:
                status_key = f"ares:op:{self.shared_state.operation_id}:status"
                status_data = {
                    "status": "completed",
                    "success": success,
                    "summary": summary,
                    "domain_admin_achieved": self.shared_state.has_domain_admin,
                    "golden_ticket_forged": self.shared_state.has_golden_ticket,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
                await self._redis_client.setex(
                    status_key,
                    86400,  # 24 hour TTL
                    json.dumps(status_data),
                )
                logger.info(
                    f"Published operation completion to Redis: {self.shared_state.operation_id}"
                )
            except Exception as e:
                logger.warning(f"Failed to publish operation status to Redis: {e}")

        await self._checkpoint()
        logger.info(f"Operation complete: {summary}")


__all__ = ["AnnouncementMixin"]
