"""Agent factories for creating configured blue and red team agents."""

from ares.core.factories.blue_factory import create_investigation_agent
from ares.core.factories.red_factory import create_redteam_agent

__all__ = [
    "create_investigation_agent",
    "create_redteam_agent",
]
