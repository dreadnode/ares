"""Blue team agent orchestrators."""

from ares.agents.blue.soc_investigator import InvestigationOrchestrator, build_initial_prompt

__all__ = [
    "InvestigationOrchestrator",
    "build_initial_prompt",
]
