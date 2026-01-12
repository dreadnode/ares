"""Core functionality for Ares agents."""

from ares.core.dispatcher import RedTeamDispatcher
from ares.core.factories import create_investigation_agent, create_redteam_agent
from ares.core.factories.red_agents import (
    create_multi_agent_ensemble,
    create_specialized_agent,
)
from ares.core.k8s_executor import KubernetesPodExecutor
from ares.core.models import (
    AgentInfo,
    AgentLocalState,
    AgentRole,
    InvestigationState,
    RedTeamState,
    SharedRedTeamState,
)
from ares.core.recovery import OperationRecoveryManager
from ares.core.templates import get_template_loader

__all__ = [
    # Models
    "AgentInfo",
    "AgentLocalState",
    "AgentRole",
    "InvestigationState",
    # Multi-agent components
    "KubernetesPodExecutor",
    "OperationRecoveryManager",
    "RedTeamDispatcher",
    "RedTeamState",
    "SharedRedTeamState",
    # Factories
    "create_investigation_agent",
    "create_multi_agent_ensemble",
    "create_redteam_agent",
    "create_specialized_agent",
    # Utilities
    "get_template_loader",
]
