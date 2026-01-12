"""Agent factories for creating configured blue and red team agents."""

from ares.core.factories.blue_factory import create_investigation_agent
from ares.core.factories.red_agents import (
    ROLE_TOOLSETS,
    create_agent_info,
    create_multi_agent_ensemble,
    create_role_hooks,
    create_specialized_agent,
    load_agent_instructions,
)
from ares.core.factories.red_factory import create_redteam_agent

__all__ = [
    # Multi-agent factories
    "ROLE_TOOLSETS",
    "create_agent_info",
    # Single-agent factories
    "create_investigation_agent",
    "create_multi_agent_ensemble",
    "create_redteam_agent",
    "create_role_hooks",
    "create_specialized_agent",
    "load_agent_instructions",
]
