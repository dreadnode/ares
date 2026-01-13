"""Core functionality for Ares agents."""

from ares.core.config import (
    AgentConfig,
    OperationConfig,
    get_agent_config,
    get_namespace,
    get_redis_url,
    load_config,
)
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
from ares.core.orchestrator import run_multi_agent_operation
from ares.core.recovery import OperationRecoveryManager
from ares.core.task_queue import RedisTaskQueue, TaskMessage, TaskResult
from ares.core.templates import get_template_loader
from ares.core.worker import RedisWorkerAgent, WorkerAgent, run_worker
from ares.core.workflows import (
    CredentialTestingTracker,
    credential_expansion_loop,
    exploitation_workflow,
)

__all__ = [
    # Config
    "AgentConfig",
    # Models
    "AgentInfo",
    "AgentLocalState",
    "AgentRole",
    # Workflow components
    "CredentialTestingTracker",
    "InvestigationState",
    # Multi-agent components
    "KubernetesPodExecutor",
    "OperationConfig",
    "OperationRecoveryManager",
    "RedTeamDispatcher",
    "RedTeamState",
    # Redis task queue
    "RedisTaskQueue",
    "RedisWorkerAgent",
    "SharedRedTeamState",
    "TaskMessage",
    "TaskResult",
    "WorkerAgent",
    # Factories
    "create_investigation_agent",
    "create_multi_agent_ensemble",
    "create_redteam_agent",
    "create_specialized_agent",
    # Workflow functions
    "credential_expansion_loop",
    "exploitation_workflow",
    "get_agent_config",
    "get_namespace",
    "get_redis_url",
    # Utilities
    "get_template_loader",
    "load_config",
    "run_multi_agent_operation",
    # Worker
    "run_worker",
]
