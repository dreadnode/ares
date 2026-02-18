"""Agent registration and management.

This module provides methods to register, unregister, and query agents.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher
    from ares.core.models import AgentInfo, AgentRole


class AgentMixin:
    """Agent registration and management."""

    async def register(self: RedTeamDispatcher, agent: AgentInfo) -> None:
        """
        Register an agent with the dispatcher.

        Args:
            agent: Agent metadata including name, role, and capabilities.
        """
        self._agents[agent.name] = agent
        self._role_queues[agent.role] = agent.name
        self.shared_state.registered_agents[agent.name] = agent

        logger.info(f"Registered agent: {agent.name} (role: {agent.role.value})")

    async def unregister(self: RedTeamDispatcher, agent_name: str) -> None:
        """Unregister an agent from the dispatcher."""
        if agent_name in self._agents:
            agent = self._agents.pop(agent_name)
            if agent.role in self._role_queues:
                del self._role_queues[agent.role]
            if agent_name in self.shared_state.registered_agents:
                del self.shared_state.registered_agents[agent_name]

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


__all__ = ["AgentMixin"]
