"""Blue team agent orchestrators."""

from ares.agents.blue.soc_investigator import InvestigationOrchestrator, build_initial_prompt

__all__ = [
    "BlueTeamOrchestrator",
    "EscalationTriageAgent",
    "InvestigationOrchestrator",
    "build_initial_prompt",
]


def __getattr__(name: str):
    if name == "BlueTeamOrchestrator":
        from ares.agents.blue.multi_agent_orchestrator import BlueTeamOrchestrator

        return BlueTeamOrchestrator

    if name == "EscalationTriageAgent":
        from ares.agents.blue.triage_agent import EscalationTriageAgent

        return EscalationTriageAgent

    raise AttributeError(f"module 'ares.agents.blue' has no attribute {name!r}")
