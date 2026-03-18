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
        # Get DC IP for the domain where we have DA
        da_domain_lower = da_domain.lower()
        dc_ip = self.shared_state.domain_controllers.get(da_domain_lower)
        if not dc_ip:
            logger.warning(f"Cannot dispatch trust key extraction: no DC IP for {da_domain}")
            return

        # Find DA credential (password or hash) for the domain
        # Look for krbtgt hash first (proves we have full DA access)
        da_hash = None
        da_password = None

        # Check for krbtgt hash (most reliable DA indicator)
        for h in self.shared_state.all_hashes:
            if (
                h.username.lower() == "krbtgt"
                and h.domain
                and h.domain.lower() == da_domain_lower
                and h.hash_type.upper() == "NTLM"
            ):
                # We have krbtgt, look for Administrator hash to use for secretsdump
                break

        # Look for Administrator hash or password
        for h in self.shared_state.all_hashes:
            if (
                h.username.lower() == "administrator"
                and h.domain
                and h.domain.lower() == da_domain_lower
                and h.hash_type.upper() == "NTLM"
            ):
                da_hash = h.hash_value
                break

        # Fallback to password credential
        if not da_hash:
            for cred in self.shared_state.all_credentials:
                if (
                    cred.domain
                    and cred.domain.lower() == da_domain_lower
                    and cred.password
                    and cred.username.lower() in ("administrator", da_username.lower())
                ):
                    da_password = cred.password
                    da_username = cred.username
                    break

        if not da_hash and not da_password:
            logger.warning(
                f"Cannot dispatch trust key extraction: no DA credentials for {da_domain}"
            )
            return

        # Dispatch trust key extraction for each undominated forest
        for target_forest in undominated_forests:
            # Dedup key: source_domain:target_forest (persists across restarts via shared_state)
            dedup_key = f"{da_domain_lower}:{target_forest.lower()}"
            if dedup_key in self.shared_state.processed_trust_extractions:
                logger.debug(f"Trust key extraction already dispatched: {dedup_key}")
                continue

            self.shared_state.processed_trust_extractions.add(dedup_key)

            # Build task payload
            # extract_trust_key uses secretsdump -just-dc-user FORESTNETBIOS$
            task_payload = {
                "tool": "extract_trust_key",
                "domain": da_domain,
                "username": "Administrator" if da_hash else da_username,
                "password": da_hash or da_password,
                "dc_ip": dc_ip,
                "trusted_domain": target_forest,
                "use_hash": bool(da_hash),
            }

            logger.warning(
                f"🌲 Auto-dispatching trust key extraction: {da_domain} → {target_forest} "
                f"(DC: {dc_ip}, using {'hash' if da_hash else 'password'})"
            )

            # Dispatch to privesc worker (has KerberosTools with extract_trust_key)
            if self._task_queue:
                try:
                    await self._throttled_submit_task(
                        task_type="exploit",
                        target_role="privesc",
                        payload=task_payload,
                        source_agent="auto_trust_extraction",
                        priority=1,  # High priority - critical for multi-forest
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
