"""Announcements for major operation milestones.

This module provides methods to announce domain admin achievement,
golden ticket forging, and operation completion.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from loguru import logger

from ares.core.messages import (
    DomainAdminAchieved,
    GoldenTicketForged,
    OperationComplete,
)

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
        Announce that domain admin has been achieved.

        This triggers all agents to halt current tasks.

        Args:
            username: The domain admin username.
            domain: The domain.
            attack_path: Description of how it was achieved.
            credential_type: Type of credential (password, hash, ticket).
            source_agent: Agent that achieved it.
        """
        from datetime import datetime, timezone

        self.shared_state.has_domain_admin = True
        self.shared_state.domain_admin_path = attack_path
        # Record completion time for accurate report duration
        if not self.shared_state.completed_at:
            self.shared_state.completed_at = datetime.now(timezone.utc)

        await self._broadcast(
            DomainAdminAchieved(
                source_agent=source_agent,
                username=username,
                domain=domain,
                attack_path=attack_path,
                credential_type=credential_type,
            )
        )

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
        Announce that golden ticket has been forged.

        Args:
            domain: The domain.
            krbtgt_hash: The krbtgt hash used.
            ticket_path: Path to the ticket file.
            source_agent: Agent that forged it.
        """
        self.shared_state.has_golden_ticket = True

        await self._broadcast(
            GoldenTicketForged(
                source_agent=source_agent,
                domain=domain,
                krbtgt_hash=krbtgt_hash,
                ticket_path=ticket_path,
            )
        )

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

        This broadcasts the completion message to in-process agents AND
        sets the Redis status key so remote workers can detect completion.

        Args:
            source_agent: Agent making the announcement.
            success: Whether the operation was successful.
            summary: Summary of the operation.
        """
        import json
        from datetime import datetime, timezone

        # Broadcast to in-process agents (in-memory queues)
        await self._broadcast(
            OperationComplete(
                source_agent=source_agent,
                operation_id=self.shared_state.operation_id,
                success=success,
                summary=summary,
                total_credentials=len(self.shared_state.all_credentials),
                total_hosts=len(self.shared_state.all_hosts),
                domain_admin_achieved=self.shared_state.has_domain_admin,
            )
        )

        # CRITICAL: Set Redis status key so remote workers detect completion
        # Workers check is_operation_completed() which reads this key
        if self._redis_client is not None:
            try:
                status_key = f"ares:operations:{self.shared_state.operation_id}:status"
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

                # Publish shutdown notification via pub/sub for immediate worker notification
                # Workers subscribe to this channel and will stop immediately on receiving this
                if self._task_queue is not None:
                    await self._task_queue.publish_shutdown(self.shared_state.operation_id)

            except Exception as e:
                logger.warning(f"Failed to publish operation status to Redis: {e}")

        await self._checkpoint()
        logger.info(f"Operation complete: {summary}")


__all__ = ["AnnouncementMixin"]
