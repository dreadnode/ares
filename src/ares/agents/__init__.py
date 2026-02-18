"""Ares agent orchestrators for blue team operations.

Imports are lazy to prevent loading unnecessary dependencies.

Note: Red team operations now use the multi-agent orchestrator system
(see ares.core.orchestrator) instead of single-agent RedTeamOrchestrator.
"""

__all__ = [
    "InvestigationOrchestrator",
]


def __getattr__(name: str):
    if name == "InvestigationOrchestrator":
        from ares.agents.blue.soc_investigator import InvestigationOrchestrator

        return InvestigationOrchestrator

    raise AttributeError(f"module 'ares.agents' has no attribute {name!r}")
