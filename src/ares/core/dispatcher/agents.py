"""Agent registration and management.

This module provides methods to register, unregister, and query agents.
"""

from __future__ import annotations

from asyncio import Queue
from typing import TYPE_CHECKING

from loguru import logger

from ares.core.messages import (
    AgentRegistered,
    MessageType,
)
from ares.core.models import AgentInfo, AgentRole

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher


class AgentMixin:
    """Agent registration and management."""

    async def register(self: RedTeamDispatcher, agent: AgentInfo) -> None:
        """
        Register an agent with the dispatcher.

        Args:
            agent: Agent metadata including name, role, and capabilities.
        """
        self._agents[agent.name] = agent
        self._message_queues[agent.name] = Queue()
        self._role_queues[agent.role] = agent.name
        self.shared_state.registered_agents[agent.name] = agent

        # Subscribe agent to relevant message types based on role
        await self._setup_role_subscriptions(agent)

        # Broadcast registration
        await self._broadcast(
            AgentRegistered(
                source_agent="dispatcher",
                agent_name=agent.name,
                agent_role=agent.role.value,
                pod_name=agent.pod_name,
                capabilities=list(agent.capabilities),
            )
        )

        logger.info(f"Registered agent: {agent.name} (role: {agent.role.value})")

    async def unregister(self: RedTeamDispatcher, agent_name: str) -> None:
        """Unregister an agent from the dispatcher."""
        if agent_name in self._agents:
            agent = self._agents.pop(agent_name)
            del self._message_queues[agent_name]
            if agent.role in self._role_queues:
                del self._role_queues[agent.role]
            if agent_name in self.shared_state.registered_agents:
                del self.shared_state.registered_agents[agent_name]

            # Remove from subscriptions
            for subscribers in self._subscribers.values():
                subscribers.discard(agent_name)

            logger.info(f"Unregistered agent: {agent_name}")

    def get_agent(self: RedTeamDispatcher, agent_name: str) -> AgentInfo | None:
        """Get agent info by name."""
        return self._agents.get(agent_name)

    def get_agent_for_role(self: RedTeamDispatcher, role: AgentRole) -> AgentInfo | None:
        """Get the agent assigned to a specific role."""
        agent_name = self._role_queues.get(role)
        if agent_name:
            return self._agents.get(agent_name)
        return None

    async def _setup_role_subscriptions(self: RedTeamDispatcher, agent: AgentInfo) -> None:
        """Setup message subscriptions based on agent role."""
        # All agents subscribe to these
        common_subscriptions = {
            MessageType.CREDENTIAL_DISCOVERED,
            MessageType.DOMAIN_ADMIN_ACHIEVED,
            MessageType.OPERATION_COMPLETE,
        }

        # Role-specific subscriptions
        role_subscriptions = {
            AgentRole.ORCHESTRATOR: {
                # Orchestrator receives all task status updates and discoveries
                MessageType.TASK_COMPLETE,
                MessageType.TASK_FAILED,
                MessageType.TASK_PROGRESS,
                MessageType.VULNERABILITY_FOUND,
                MessageType.HASH_DISCOVERED,
                MessageType.HOST_DISCOVERED,
                MessageType.USER_DISCOVERED,
                MessageType.SHARE_DISCOVERED,
                MessageType.GOLDEN_TICKET_FORGED,
            },
            AgentRole.RECON: {
                MessageType.RECON_REQUEST,
                MessageType.TASK_COMPLETE,
                MessageType.TASK_FAILED,
            },
            AgentRole.CRACKER: {
                MessageType.CRACK_REQUEST,
                MessageType.HASH_DISCOVERED,
            },
            AgentRole.ACL: {
                MessageType.ACL_ANALYSIS_REQUEST,
                MessageType.VULNERABILITY_FOUND,
            },
            AgentRole.CREDENTIAL_ACCESS: {
                MessageType.CREDENTIAL_ACCESS_REQUEST,
            },
            AgentRole.PRIVESC: {
                MessageType.EXPLOIT_REQUEST,
                MessageType.VULNERABILITY_FOUND,
            },
            AgentRole.LATERAL: {
                MessageType.LATERAL_REQUEST,
                MessageType.HOST_DISCOVERED,
            },
            AgentRole.COERCION: {
                MessageType.COERCION_REQUEST,
            },
        }

        subscriptions = common_subscriptions | role_subscriptions.get(agent.role, set())

        for msg_type in subscriptions:
            if msg_type not in self._subscribers:
                self._subscribers[msg_type] = set()
            self._subscribers[msg_type].add(agent.name)


__all__ = ["AgentMixin"]
