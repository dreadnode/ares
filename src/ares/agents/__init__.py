"""Ares agent orchestrators for blue and red team operations."""

from ares.agents.blue.soc_investigator import InvestigationOrchestrator
from ares.agents.red.pentester import RedTeamOrchestrator

__all__ = [
    "InvestigationOrchestrator",
    "RedTeamOrchestrator",
]
