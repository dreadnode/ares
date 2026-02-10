"""Configuration loader for multi-agent red team operations.

This module provides configuration loading from YAML files and environment
variables, with sensible defaults for local development.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from loguru import logger

# Default namespace - single source of truth
DEFAULT_NAMESPACE = "attack-simulation"


def get_default_network_interface() -> str:
    """
    Auto-detect the default network interface for coercion tools.

    Only runs on Linux (K8s pods with hostNetwork). On AWS, this typically
    returns 'ens5' instead of 'eth0'.

    Returns:
        Network interface name (e.g., 'ens5', 'eth0', 'eno1').
    """
    import socket

    # Environment variable override
    if env_iface := os.environ.get("ARES_NETWORK_INTERFACE"):
        return env_iface

    # Parse /proc/net/route for default gateway interface
    try:
        with open("/proc/net/route") as f:
            for line in f:
                fields = line.strip().split()
                # Skip header and non-default routes
                # Default route has Destination=00000000 and Flags with RTF_GATEWAY (0x0002)
                if len(fields) >= 4 and fields[1] == "00000000":
                    iface = fields[0]
                    if iface and not iface.startswith("lo"):
                        logger.debug(f"Auto-detected network interface from route table: {iface}")
                        return iface
    except (OSError, IndexError):
        pass

    # Fallback: prefer physical interface prefixes (eth, ens, eno, en)
    try:
        interfaces = socket.if_nameindex()
        interface_names = [name for _idx, name in interfaces if name and not name.startswith("lo")]

        # Prefer physical interfaces by common naming patterns
        preferred_prefixes = ("eth", "ens", "eno", "enp", "en")
        for prefix in preferred_prefixes:
            for name in interface_names:
                if name.startswith(prefix):
                    logger.debug(f"Auto-detected network interface from socket: {name}")
                    return name

        # Fall back to any non-loopback interface
        if interface_names:
            logger.debug(f"Auto-detected network interface from socket: {interface_names[0]}")
            return interface_names[0]
    except OSError:
        pass

    logger.warning("Could not auto-detect network interface, falling back to eth0")
    return "eth0"


def derive_redis_url(namespace: str, host: str = "redis", port: int = 6379) -> str:
    """Derive Redis URL from namespace using K8s service DNS.

    Args:
        namespace: Kubernetes namespace where Redis is deployed.
        host: Redis service name (default: "redis").
        port: Redis port (default: 6379).

    Returns:
        Redis URL in format redis://{host}.{namespace}.svc.cluster.local:{port}
    """
    return f"redis://{host}.{namespace}.svc.cluster.local:{port}"


@dataclass
class AgentConfig:
    """Configuration for a specific agent role."""

    model: str = ""
    max_steps: int = 200
    pod_selector: str = ""
    capabilities: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)


@dataclass
class OperationConfig:
    """Configuration for multi-agent operations."""

    # Operation settings
    name: str = "ares-multi-agent"
    namespace: str = DEFAULT_NAMESPACE
    redis_url: str = ""  # Derived from namespace if not explicitly set
    checkpoint_interval: int = 60

    # Context management settings
    # max_context_tokens: Trigger summarization when orchestrator exceeds this
    # (set to ~85% of model context window to leave room for response)
    max_context_tokens: int = 100_000
    # min_messages_to_keep: Keep this many recent messages after summarization
    min_messages_to_keep: int = 10
    # max_output_chars: Truncate task outputs to this size in broadcasts
    max_output_chars: int = 2000

    def __post_init__(self) -> None:
        """Derive redis_url from namespace if not explicitly set."""
        if not self.redis_url:
            self.redis_url = derive_redis_url(self.namespace)

    # Agent configurations
    agents: dict[str, AgentConfig] = field(default_factory=dict)

    # Timeouts
    agent_heartbeat_timeout: int = 180
    task_timeout: int = 300
    operation_timeout: int = 7200

    # Recovery
    recovery_enabled: bool = True
    max_retries: int = 3
    retry_delay: int = 10

    # Rate limiting / throttling
    # Maximum number of tasks that can be pending (in-flight) at once
    max_concurrent_tasks: int = 8
    # Minimum seconds between task dispatches (prevents burst dispatching)
    task_dispatch_delay: float = 1.5
    # Seconds to back off when global rate limit is detected
    rate_limit_backoff: float = 30.0
    # Number of rate limit errors before triggering global backoff
    rate_limit_threshold: int = 3

    # Phase detection thresholds (see PRIORITY.md)
    lateral_movement_admin_creds_threshold: int = 3
    lateral_movement_owned_hosts_threshold: int = 5
    min_slots_per_role: int = 1

    # Vulnerability priorities
    vulnerability_priorities: dict[str, int] = field(default_factory=dict)

    # Grafana integration
    grafana_url: str = ""
    grafana_api_key: str = ""


# Default config file locations (searched in order)
CONFIG_PATHS = [
    Path("config/multi-agent-production.yaml"),
    Path("config/multi-agent.yaml"),
    Path.home() / ".config/ares/multi-agent.yaml",
    Path("/etc/ares/multi-agent.yaml"),
]


_cached_config: OperationConfig | None = None


def load_config(config_path: str | Path | None = None) -> OperationConfig:
    """
    Load configuration from YAML file.

    Args:
        config_path: Optional explicit config file path. If not provided,
                     searches default locations.

    Returns:
        OperationConfig with loaded or default values.
    """
    global _cached_config

    if _cached_config is not None and config_path is None:
        return _cached_config

    config_data: dict[str, Any] = {}

    # Find config file
    if config_path:
        path = Path(config_path)
        if path.exists():
            config_data = _load_yaml(path)
    else:
        for path in CONFIG_PATHS:
            if path.exists():
                logger.debug(f"Loading config from {path}")
                config_data = _load_yaml(path)
                break

    # Build config from loaded data
    config = _build_config(config_data)

    # Override with environment variables
    config = _apply_env_overrides(config)

    if config_path is None:
        _cached_config = config

    return config


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load YAML file and return as dict."""
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, yaml.YAMLError) as e:
        logger.warning(f"Failed to load config from {path}: {e}")
        return {}


def _build_config(data: dict[str, Any]) -> OperationConfig:
    """Build OperationConfig from loaded data."""
    operation = data.get("operation", {})
    timeouts = data.get("timeouts", {})
    recovery = data.get("recovery", {})
    grafana = data.get("grafana", {})
    phase_detection = data.get("phase_detection", {})
    context_management = data.get("context_management", {})

    # Build agent configs
    agents: dict[str, AgentConfig] = {}
    for role, agent_data in data.get("agents", {}).items():
        if isinstance(agent_data, dict):
            agents[role] = AgentConfig(
                model=_resolve_env(agent_data.get("model", "")),
                max_steps=agent_data.get("max_steps", 200),
                pod_selector=agent_data.get("pod_selector", ""),
                capabilities=agent_data.get("capabilities", []),
                tools=agent_data.get("tools", []),
            )

    namespace = operation.get("namespace", DEFAULT_NAMESPACE)
    # Only use explicit redis_url from config, otherwise derive from namespace
    redis_url = operation.get("redis_url") or derive_redis_url(namespace)

    return OperationConfig(
        name=operation.get("name", "ares-multi-agent"),
        namespace=namespace,
        redis_url=redis_url,
        checkpoint_interval=operation.get("checkpoint_interval", 60),
        agents=agents,
        agent_heartbeat_timeout=timeouts.get("agent_heartbeat", 30),
        task_timeout=timeouts.get("task_timeout", 300),
        operation_timeout=timeouts.get("operation_timeout", 7200),
        recovery_enabled=recovery.get("enabled", True),
        max_retries=recovery.get("max_retries", 3),
        retry_delay=recovery.get("retry_delay", 10),
        vulnerability_priorities=data.get("vulnerability_priorities", {}),
        grafana_url=_resolve_env(grafana.get("base_url", "")),
        grafana_api_key=_resolve_env(grafana.get("api_key", "")),
        # Rate limiting from operation section
        max_concurrent_tasks=operation.get("max_concurrent_tasks", 8),
        task_dispatch_delay=operation.get("task_dispatch_delay", 1.5),
        rate_limit_backoff=operation.get("rate_limit_backoff", 30.0),
        rate_limit_threshold=operation.get("rate_limit_threshold", 3),
        # Phase detection thresholds
        lateral_movement_admin_creds_threshold=phase_detection.get(
            "lateral_movement_admin_creds", 3
        ),
        lateral_movement_owned_hosts_threshold=phase_detection.get(
            "lateral_movement_owned_hosts", 5
        ),
        min_slots_per_role=phase_detection.get("min_slots_per_role", 1),
        # Context management
        max_context_tokens=context_management.get("max_context_tokens", 100_000),
        min_messages_to_keep=context_management.get("min_messages_to_keep", 10),
        max_output_chars=context_management.get("max_output_chars", 2000),
    )


def _resolve_env(value: str) -> str:
    """Resolve environment variable references like ${VAR_NAME}."""
    if not isinstance(value, str):
        return value
    if value.startswith("${") and value.endswith("}"):
        env_var = value[2:-1]
        return os.environ.get(env_var, "")
    return value


def _apply_env_overrides(config: OperationConfig) -> OperationConfig:  # noqa: PLR0912
    """Apply environment variable overrides to config."""
    # Check for explicit Redis URL override
    explicit_redis_url = os.environ.get("ARES_REDIS_URL") or os.environ.get("REDIS_URL")
    if explicit_redis_url:
        config.redis_url = explicit_redis_url

    # Namespace override - re-derive redis_url if namespace changes and no explicit URL
    if namespace := os.environ.get("ARES_NAMESPACE"):
        config.namespace = namespace
        if not explicit_redis_url:
            config.redis_url = derive_redis_url(namespace)

    # Grafana overrides
    if grafana_url := os.environ.get("GRAFANA_URL"):
        config.grafana_url = grafana_url
    if grafana_key := os.environ.get("GRAFANA_API_KEY") or os.environ.get(
        "GRAFANA_SERVICE_ACCOUNT_TOKEN"
    ):
        config.grafana_api_key = grafana_key

    # Rate limiting overrides
    if max_tasks := os.environ.get("ARES_MAX_CONCURRENT_TASKS"):
        try:
            config.max_concurrent_tasks = int(max_tasks)
        except ValueError:
            pass
    if dispatch_delay := os.environ.get("ARES_TASK_DISPATCH_DELAY"):
        try:
            config.task_dispatch_delay = float(dispatch_delay)
        except ValueError:
            pass
    if rate_backoff := os.environ.get("ARES_RATE_LIMIT_BACKOFF"):
        try:
            config.rate_limit_backoff = float(rate_backoff)
        except ValueError:
            pass
    if rate_threshold := os.environ.get("ARES_RATE_LIMIT_THRESHOLD"):
        try:
            config.rate_limit_threshold = int(rate_threshold)
        except ValueError:
            pass

    # Context management overrides
    if max_tokens := os.environ.get("ARES_MAX_CONTEXT_TOKENS"):
        try:
            config.max_context_tokens = int(max_tokens)
        except ValueError:
            pass
    if min_messages := os.environ.get("ARES_MIN_MESSAGES_TO_KEEP"):
        try:
            config.min_messages_to_keep = int(min_messages)
        except ValueError:
            pass
    if max_output := os.environ.get("ARES_MAX_OUTPUT_CHARS"):
        try:
            config.max_output_chars = int(max_output)
        except ValueError:
            pass

    # Model overrides (Viper-style precedence: role-specific > orchestrator/worker > global)
    global_model = os.environ.get("ARES_MODEL")
    orchestrator_model = os.environ.get("ARES_ORCHESTRATOR_MODEL")
    worker_model = os.environ.get("ARES_WORKER_MODEL")

    def resolve_role_model(role: str) -> str | None:
        role_env = os.environ.get(f"ARES_AGENT_{role.upper()}_MODEL")
        if role_env:
            return role_env
        if role == "orchestrator" and orchestrator_model:
            return orchestrator_model
        if role != "orchestrator" and worker_model:
            return worker_model
        if global_model:
            return global_model
        return None

    # Apply overrides to configured agents
    for role, agent_config in config.agents.items():
        if not isinstance(agent_config, AgentConfig):
            continue
        if override := resolve_role_model(role):
            agent_config.model = override

    # If a role-specific env override exists without a config entry, add it
    for env_key, value in os.environ.items():
        if not env_key.startswith("ARES_AGENT_") or not env_key.endswith("_MODEL"):
            continue
        if not value:
            continue
        role = env_key[len("ARES_AGENT_") : -len("_MODEL")].lower()
        if role and role not in config.agents:
            logger.warning(
                f"Creating agent config for role '{role}' from env override without "
                "configured capabilities/tools."
            )
            config.agents[role] = AgentConfig(model=value)

    return config


def get_agent_config(role: str) -> AgentConfig:
    """
    Get configuration for a specific agent role.

    Args:
        role: Agent role name (e.g., 'cracker', 'lateral')

    Returns:
        AgentConfig for the role, or defaults if not configured.
    """
    config = load_config()
    return config.agents.get(role, AgentConfig())


def get_redis_url() -> str:
    """Get Redis URL from config or environment."""
    return load_config().redis_url


def get_namespace() -> str:
    """Get Kubernetes namespace from config or environment."""
    return load_config().namespace


def get_agent_heartbeat_timeout() -> int:
    """Get the agent heartbeat timeout (seconds) from config."""
    return load_config().agent_heartbeat_timeout


def get_max_concurrent_tasks() -> int:
    """Get maximum concurrent tasks allowed from config."""
    return load_config().max_concurrent_tasks


def get_task_dispatch_delay() -> float:
    """Get minimum delay between task dispatches (seconds) from config."""
    return load_config().task_dispatch_delay


def get_rate_limit_backoff() -> float:
    """Get rate limit backoff duration (seconds) from config."""
    return load_config().rate_limit_backoff


def get_rate_limit_threshold() -> int:
    """Get number of rate limit errors before global backoff from config."""
    return load_config().rate_limit_threshold


def get_lateral_movement_admin_creds_threshold() -> int:
    """Get threshold for transitioning to lateral_movement phase (admin creds count)."""
    return load_config().lateral_movement_admin_creds_threshold


def get_lateral_movement_owned_hosts_threshold() -> int:
    """Get threshold for transitioning to lateral_movement phase (owned hosts count)."""
    return load_config().lateral_movement_owned_hosts_threshold


def get_min_slots_per_role() -> int:
    """Get minimum task slots guaranteed per worker role."""
    return load_config().min_slots_per_role


def get_max_context_tokens() -> int:
    """Get max token threshold for triggering conversation summarization."""
    return load_config().max_context_tokens


def get_min_messages_to_keep() -> int:
    """Get minimum messages to keep after summarization."""
    return load_config().min_messages_to_keep


def get_max_output_chars() -> int:
    """Get max characters for task output in broadcasts."""
    return load_config().max_output_chars


def clear_config_cache() -> None:
    """Clear the cached configuration (useful for testing)."""
    global _cached_config
    _cached_config = None


__all__ = [
    "DEFAULT_NAMESPACE",
    "AgentConfig",
    "OperationConfig",
    "clear_config_cache",
    "derive_redis_url",
    "get_agent_config",
    "get_agent_heartbeat_timeout",
    "get_default_network_interface",
    "get_lateral_movement_admin_creds_threshold",
    "get_lateral_movement_owned_hosts_threshold",
    "get_max_concurrent_tasks",
    "get_max_context_tokens",
    "get_max_output_chars",
    "get_min_messages_to_keep",
    "get_min_slots_per_role",
    "get_namespace",
    "get_rate_limit_backoff",
    "get_rate_limit_threshold",
    "get_redis_url",
    "get_task_dispatch_delay",
    "load_config",
]
