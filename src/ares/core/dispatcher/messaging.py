"""Message queue operations for inter-agent communication.

This module provides methods to get messages, send to agents, and broadcast.

NOTE: When called from the threaded result consumer (non-main thread), broadcast
and send operations are skipped because asyncio.Queue is bound to the main event loop.
"""

from __future__ import annotations

import asyncio
import threading
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher
    from ares.core.messages import AgentMessage


class MessagingMixin:
    """Message queue operations for inter-agent communication."""

    async def get_messages(
        self: RedTeamDispatcher, agent_name: str, timeout: float = 0.1
    ) -> list[AgentMessage]:
        """
        Get pending messages for an agent.

        Args:
            agent_name: Name of the agent to get messages for.
            timeout: How long to wait for messages (seconds).

        Returns:
            List of pending messages.
        """
        if agent_name not in self._message_queues:
            return []

        messages = []
        queue = self._message_queues[agent_name]

        try:
            # Get all available messages without blocking
            while not queue.empty():
                msg = queue.get_nowait()
                messages.append(msg)
        except asyncio.QueueEmpty:
            pass

        return messages

    async def send_to_agent(
        self: RedTeamDispatcher, agent_name: str, message: AgentMessage
    ) -> bool:
        """
        Send a message to a specific agent.

        Args:
            agent_name: Target agent name.
            message: Message to send.

        Returns:
            True if message was queued successfully.
        """
        # Skip when in non-main thread (asyncio.Queue is bound to main event loop)
        if threading.current_thread() is not threading.main_thread():
            return False

        if agent_name not in self._message_queues:
            logger.warning(f"Cannot send to unknown agent: {agent_name}")
            return False

        await self._message_queues[agent_name].put(message)
        return True

    async def _broadcast(
        self: RedTeamDispatcher, message: AgentMessage, exclude: str | None = None
    ) -> None:
        """
        Broadcast a message to all subscribed agents.

        Args:
            message: Message to broadcast.
            exclude: Agent name to exclude from broadcast.
        """
        # Skip when in non-main thread (asyncio.Queue is bound to main event loop)
        if threading.current_thread() is not threading.main_thread():
            return

        subscribers = self._subscribers.get(message.type, set())

        for agent_name in subscribers:
            if agent_name != exclude:
                await self._message_queues[agent_name].put(message)


__all__ = ["MessagingMixin"]
