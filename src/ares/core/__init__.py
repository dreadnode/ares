"""Core functionality for Ares agents.

Imports are lazy to prevent blue team code from crashing red team workers
and vice versa.
"""

__all__ = [
    "CAPABILITY_REGISTRY",
    "AgentConfig",
    "AgentInfo",
    "AgentLocalState",
    "AgentRole",
    "CredentialTestingTracker",
    "FilteredToolset",
    "InvestigationState",
    "KubernetesPodExecutor",
    "OperationConfig",
    "OperationRecoveryManager",
    "RedTeamDispatcher",
    "RedisTaskQueue",
    "RedisWorkerAgent",
    "SharedRedTeamState",
    "TaskMessage",
    "TaskResult",
    "WorkerAgent",
    "create_investigation_agent",
    "create_multi_agent_ensemble",
    "create_specialized_agent",
    "credential_expansion_loop",
    "exploitation_workflow",
    "get_agent_config",
    "get_enabled_tools",
    "get_namespace",
    "get_redis_url",
    "get_template_loader",
    "load_config",
    "run_multi_agent_operation",
    "run_worker",
]

# Mapping of attribute names to their (module_path, name) for lazy imports
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    # Capability registry
    "CAPABILITY_REGISTRY": ("ares.core.capability_registry", "CAPABILITY_REGISTRY"),
    "FilteredToolset": ("ares.core.capability_registry", "FilteredToolset"),
    "get_enabled_tools": ("ares.core.capability_registry", "get_enabled_tools"),
    # Config
    "AgentConfig": ("ares.core.config", "AgentConfig"),
    "OperationConfig": ("ares.core.config", "OperationConfig"),
    "get_agent_config": ("ares.core.config", "get_agent_config"),
    "get_namespace": ("ares.core.config", "get_namespace"),
    "get_redis_url": ("ares.core.config", "get_redis_url"),
    "load_config": ("ares.core.config", "load_config"),
    # Dispatcher
    "RedTeamDispatcher": ("ares.core.dispatcher", "RedTeamDispatcher"),
    # Factories - blue
    "create_investigation_agent": (
        "ares.core.factories.blue_factory",
        "create_investigation_agent",
    ),
    # Factories - red
    "create_multi_agent_ensemble": (
        "ares.core.factories.red_agents",
        "create_multi_agent_ensemble",
    ),
    "create_specialized_agent": ("ares.core.factories.red_agents", "create_specialized_agent"),
    # K8s
    "KubernetesPodExecutor": ("ares.core.k8s_executor", "KubernetesPodExecutor"),
    # Models
    "AgentInfo": ("ares.core.models", "AgentInfo"),
    "AgentLocalState": ("ares.core.models", "AgentLocalState"),
    "AgentRole": ("ares.core.models", "AgentRole"),
    "InvestigationState": ("ares.core.models", "InvestigationState"),
    "SharedRedTeamState": ("ares.core.models", "SharedRedTeamState"),
    # Orchestrator
    "run_multi_agent_operation": ("ares.core.orchestrator", "run_multi_agent_operation"),
    # Recovery
    "OperationRecoveryManager": ("ares.core.recovery", "OperationRecoveryManager"),
    # Task queue
    "RedisTaskQueue": ("ares.core.task_queue", "RedisTaskQueue"),
    "TaskMessage": ("ares.core.task_queue", "TaskMessage"),
    "TaskResult": ("ares.core.task_queue", "TaskResult"),
    # Templates
    "get_template_loader": ("ares.core.templates", "get_template_loader"),
    # Worker
    "RedisWorkerAgent": ("ares.core.worker", "RedisWorkerAgent"),
    "WorkerAgent": ("ares.core.worker", "WorkerAgent"),
    "run_worker": ("ares.core.worker", "run_worker"),
    # Workflows
    "CredentialTestingTracker": ("ares.core.workflows", "CredentialTestingTracker"),
    "credential_expansion_loop": ("ares.core.workflows", "credential_expansion_loop"),
    "exploitation_workflow": ("ares.core.workflows", "exploitation_workflow"),
}


def __getattr__(name: str):
    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        import importlib

        module = importlib.import_module(module_path)
        return getattr(module, attr_name)

    raise AttributeError(f"module 'ares.core' has no attribute {name!r}")
