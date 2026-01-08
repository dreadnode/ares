"""
Ares - Autonomous SOC Investigation and Red Team Agent.

A framework for autonomous security operations using LLM-powered agents.
"""

__version__ = "0.1.0"

from ares.agents import InvestigationOrchestrator, RedTeamOrchestrator
from ares.core import InvestigationState, RedTeamState, create_investigation_agent, create_redteam_agent
from ares.integrations import MITREAttackClient

__all__ = [
    "InvestigationOrchestrator",
    "RedTeamOrchestrator",
    "InvestigationState",
    "RedTeamState",
    "MITREAttackClient",
    "create_investigation_agent",
    "create_redteam_agent",
]
