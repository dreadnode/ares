"""
Ares - Autonomous SOC Investigation and Red Team Agent.

A framework for autonomous security operations using LLM-powered agents.

All imports are lazy to prevent blue team code from crashing red team workers
(and vice versa) due to syntax errors or missing dependencies.
"""

__version__ = "0.1.0"

__all__ = [
    "InvestigationOrchestrator",
    "InvestigationState",
    "MITREAttackClient",
    "RedTeamOrchestrator",
    "RedTeamState",
    "create_investigation_agent",
    "create_redteam_agent",
]


def __getattr__(name: str):
    if name == "InvestigationOrchestrator":
        from ares.agents.blue.soc_investigator import InvestigationOrchestrator

        return InvestigationOrchestrator

    if name == "RedTeamOrchestrator":
        from ares.agents.red.pentester import RedTeamOrchestrator

        return RedTeamOrchestrator

    if name == "InvestigationState":
        from ares.core.models import InvestigationState

        return InvestigationState

    if name == "RedTeamState":
        from ares.core.models import RedTeamState

        return RedTeamState

    if name == "create_investigation_agent":
        from ares.core.factories.blue_factory import create_investigation_agent

        return create_investigation_agent

    if name == "create_redteam_agent":
        from ares.core.factories.red_factory import create_redteam_agent

        return create_redteam_agent

    if name == "MITREAttackClient":
        from ares.integrations.mitre import MITREAttackClient

        return MITREAttackClient

    raise AttributeError(f"module 'ares' has no attribute {name!r}")
