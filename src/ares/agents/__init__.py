"""Ares agent orchestrators for blue and red team operations.

Imports are lazy to prevent cross-contamination between blue and red team code.
"""

__all__ = [
    "InvestigationOrchestrator",
    "RedTeamOrchestrator",
]


def __getattr__(name: str):
    if name == "InvestigationOrchestrator":
        from ares.agents.blue.soc_investigator import InvestigationOrchestrator

        return InvestigationOrchestrator

    if name == "RedTeamOrchestrator":
        from ares.agents.red.pentester import RedTeamOrchestrator

        return RedTeamOrchestrator

    raise AttributeError(f"module 'ares.agents' has no attribute {name!r}")
