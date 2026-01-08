"""Core functionality for Ares agents."""

from ares.core.factories import create_investigation_agent, create_redteam_agent
from ares.core.models import InvestigationState, RedTeamState
from ares.core.templates import get_template_loader

__all__ = [
    "InvestigationState",
    "RedTeamState",
    "create_investigation_agent",
    "create_redteam_agent",
    "get_template_loader",
]
