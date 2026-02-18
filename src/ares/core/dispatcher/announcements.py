"""Announcements for major operation milestones.

This module provides methods to announce domain admin achievement,
golden ticket forging, and operation completion.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from loguru import logger

from ares.core.config import get_stop_on_domain_admin

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
        # Record completion time for accurate report duration
        if not self.shared_state.completed_at:
            self.shared_state.completed_at = datetime.now(timezone.utc)

        # Check if we should stop immediately on DA
        if get_stop_on_domain_admin():
            self.shared_state.completed = True
            logger.info("ARES_STOP_ON_DOMAIN_ADMIN enabled - marking operation complete")

        await self._checkpoint()
        logger.success(f"DOMAIN ADMIN ACHIEVED: {domain}\\{username}")

    async def announce_golden_ticket(
        self: RedTeamDispatcher,
        domain: str,
        krbtgt_hash: str,
        ticket_path: str,
        source_agent: str,
    ) -> None:
        """
        Record that golden ticket has been forged.

        Args:
            domain: The domain.
            krbtgt_hash: The krbtgt hash used.
            ticket_path: Path to the ticket file.
            source_agent: Agent that forged it.
        """
        self.shared_state.has_golden_ticket = True

        await self._checkpoint()
        logger.success(f"GOLDEN TICKET FORGED for {domain}")

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
