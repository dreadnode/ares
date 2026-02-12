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
    except (OSError, IndexError) as e:
        logger.debug(f"Could not parse /proc/net/route: {e}")

    # Fallback: prefer physical interface prefixes (eth, ens, eno, en)
    try:
        interfaces = socket.if_nameindex()
        interface_names = [name for _idx, name in interfaces if name and not name.startswith("lo")]
        logger.debug(f"Available network interfaces: {interface_names}")

        # Prefer physical interfaces by common naming patterns
        preferred_prefixes = ("ens", "eno", "enp", "eth", "en")
        for prefix in preferred_prefixes:
            for name in interface_names:
                if name.startswith(prefix):
                    logger.debug(f"Auto-detected network interface from socket: {name}")
                    return name

        # Fall back to any non-loopback interface
        if interface_names:
            logger.debug(f"Auto-detected network interface from socket: {interface_names[0]}")
            return interface_names[0]
    except OSError as e:
        logger.debug(f"Could not enumerate interfaces via socket: {e}")

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

    # Task monitoring / resilience
    # Tasks pending longer than this are cleaned up (prevents throttle deadlock)
    stale_task_timeout: int = 180  # 3 minutes (reduced from 10 to prevent deadlock)
    # After this many consecutive Redis failures, crash for K8s restart
    max_redis_consecutive_failures: int = 30
    # Base delay between Redis retries (exponential backoff)
    redis_retry_base_delay: float = 1.0
    # Maximum delay between Redis retries
    redis_retry_max_delay: float = 10.0

    # Deferred queue settings (tasks queued when at capacity)
    # Total max queued tasks across all types
    max_deferred_total: int = 25
    # Max queued tasks per task_type (secondary limit)
    max_deferred_per_type: int = 10
    # Evict deferred tasks older than this (seconds)
    deferred_task_max_age: int = 300  # 5 minutes
    # How often to check deferred queue (seconds)
    deferred_queue_check_interval: float = 5.0
    # Priority 1-N tasks are critical, force-drain even at capacity
    critical_priority_threshold: int = 3

    # Worker agent settings
    # Timeout for agent tasks (prevents infinite retry loops)
    agent_task_timeout: int = 300  # 5 minutes

    # Context offloading settings
    # Tool outputs larger than this (chars) are offloaded to Redis
    offload_threshold: int = 5000
    # TTL for offloaded outputs (seconds)
    offload_ttl: int = 14400  # 4 hours

    # Evidence validation settings (blue team)
    # Maximum number of query results to store for validation
    max_stored_results: int = 10
    # Confidence penalty for unvalidated evidence
    unvalidated_confidence_penalty: float = 0.15

    # Blue team investigation query limits
    # Base query limit per investigation
    max_queries_per_investigation: int = 8
    # Higher limit for critical alerts
    max_queries_critical: int = 12
    # Max times same query can run before blocking
    max_duplicate_queries: int = 2
    # Bonus queries granted when evidence is found
    bonus_queries_for_evidence: int = 3
    # Bonus queries for reaching pyramid level 4+
    bonus_queries_for_pyramid_l4: int = 2
    # Hard cap to prevent runaway investigations
    max_total_queries: int = 25

    # Task retry settings
    # Default max retries for tasks interrupted by pod restarts
    default_max_retries: int = 3

    # Orchestrator runtime settings
    # Maximum operation runtime in seconds (default 60 minutes)
    max_runtime: float = 3600.0
    # Grace period for crack tasks when operation is completing (seconds)
    crack_task_grace_period: float = 300.0

    # Rate limit retry settings (for worker agents)
    # Delays between retries when rate limited (list of seconds)
    rate_limit_backoff_delays: list[float] = field(
        default_factory=lambda: [5.0, 10.0, 20.0, 40.0, 60.0, 60.0]
    )

    # Blue team investigation stage-based query limits
    query_limits_by_stage: dict[str, int] = field(
        default_factory=lambda: {
            "triage": 8,
            "causation": 14,
            "lateral": 20,
            "synthesis": 20,
        }
    )

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
    Path("/ares/config/multi-agent-production.yaml"),  # K8s pod PVC path
    Path("/ares/config/multi-agent.yaml"),
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
        # Task monitoring / resilience from operation section
        stale_task_timeout=operation.get("stale_task_timeout", 600),
        max_redis_consecutive_failures=operation.get("max_redis_consecutive_failures", 30),
        redis_retry_base_delay=operation.get("redis_retry_base_delay", 1.0),
        redis_retry_max_delay=operation.get("redis_retry_max_delay", 10.0),
        # Deferred queue settings from operation section
        max_deferred_total=operation.get("max_deferred_total", 25),
        max_deferred_per_type=operation.get("max_deferred_per_type", 10),
        deferred_task_max_age=operation.get("deferred_task_max_age", 300),
        deferred_queue_check_interval=operation.get("deferred_queue_check_interval", 5.0),
        critical_priority_threshold=operation.get("critical_priority_threshold", 3),
        # Worker settings from operation section
        agent_task_timeout=operation.get("agent_task_timeout", 300),
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
        offload_threshold=context_management.get("offload_threshold", 5000),
        offload_ttl=context_management.get("offload_ttl", 14400),
        # Evidence validation (blue team)
        max_stored_results=operation.get("max_stored_results", 10),
        unvalidated_confidence_penalty=operation.get("unvalidated_confidence_penalty", 0.15),
        # Blue team investigation query limits
        max_queries_per_investigation=operation.get("max_queries_per_investigation", 8),
        max_queries_critical=operation.get("max_queries_critical", 12),
        max_duplicate_queries=operation.get("max_duplicate_queries", 2),
        bonus_queries_for_evidence=operation.get("bonus_queries_for_evidence", 3),
        bonus_queries_for_pyramid_l4=operation.get("bonus_queries_for_pyramid_l4", 2),
        max_total_queries=operation.get("max_total_queries", 25),
        # Task retry settings
        default_max_retries=operation.get("default_max_retries", 3),
        # Orchestrator runtime settings
        max_runtime=operation.get("max_runtime", 3600.0),
        crack_task_grace_period=operation.get("crack_task_grace_period", 300.0),
        # Rate limit retry settings
        rate_limit_backoff_delays=operation.get(
            "rate_limit_backoff_delays", [5.0, 10.0, 20.0, 40.0, 60.0, 60.0]
        ),
        # Blue team stage-based query limits
        query_limits_by_stage=operation.get(
            "query_limits_by_stage",
            {"triage": 8, "causation": 14, "lateral": 20, "synthesis": 20},
        ),
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

    # Task monitoring / resilience overrides
    if stale_timeout := os.environ.get("ARES_STALE_TASK_TIMEOUT"):
        try:
            config.stale_task_timeout = int(stale_timeout)
        except ValueError:
            pass
    if redis_failures := os.environ.get("ARES_MAX_REDIS_CONSECUTIVE_FAILURES"):
        try:
            config.max_redis_consecutive_failures = int(redis_failures)
        except ValueError:
            pass
    if redis_base_delay := os.environ.get("ARES_REDIS_RETRY_BASE_DELAY"):
        try:
            config.redis_retry_base_delay = float(redis_base_delay)
        except ValueError:
            pass
    if redis_max_delay := os.environ.get("ARES_REDIS_RETRY_MAX_DELAY"):
        try:
            config.redis_retry_max_delay = float(redis_max_delay)
        except ValueError:
            pass

    # Deferred queue overrides
    if max_deferred := os.environ.get("ARES_MAX_DEFERRED_TOTAL"):
        try:
            config.max_deferred_total = int(max_deferred)
        except ValueError:
            pass
    if max_deferred_type := os.environ.get("ARES_MAX_DEFERRED_PER_TYPE"):
        try:
            config.max_deferred_per_type = int(max_deferred_type)
        except ValueError:
            pass
    if deferred_max_age := os.environ.get("ARES_DEFERRED_TASK_MAX_AGE"):
        try:
            config.deferred_task_max_age = int(deferred_max_age)
        except ValueError:
            pass
    if deferred_interval := os.environ.get("ARES_DEFERRED_QUEUE_CHECK_INTERVAL"):
        try:
            config.deferred_queue_check_interval = float(deferred_interval)
        except ValueError:
            pass
    if critical_priority := os.environ.get("ARES_CRITICAL_PRIORITY_THRESHOLD"):
        try:
            config.critical_priority_threshold = int(critical_priority)
        except ValueError:
            pass

    # Worker overrides
    if agent_timeout := os.environ.get("ARES_AGENT_TASK_TIMEOUT"):
        try:
            config.agent_task_timeout = int(agent_timeout)
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
    if offload_thresh := os.environ.get("ARES_OFFLOAD_THRESHOLD"):
        try:
            config.offload_threshold = int(offload_thresh)
        except ValueError:
            pass
    if offload_ttl_env := os.environ.get("ARES_OFFLOAD_TTL"):
        try:
            config.offload_ttl = int(offload_ttl_env)
        except ValueError:
            pass

    # Evidence validation overrides (blue team)
    if max_results := os.environ.get("ARES_MAX_STORED_RESULTS"):
        try:
            config.max_stored_results = int(max_results)
        except ValueError:
            pass
    if confidence_penalty := os.environ.get("ARES_UNVALIDATED_CONFIDENCE_PENALTY"):
        try:
            config.unvalidated_confidence_penalty = float(confidence_penalty)
        except ValueError:
            pass

    # Blue team investigation query limit overrides
    if max_queries := os.environ.get("ARES_MAX_QUERIES_PER_INVESTIGATION"):
        try:
            config.max_queries_per_investigation = int(max_queries)
        except ValueError:
            pass
    if max_queries_crit := os.environ.get("ARES_MAX_QUERIES_CRITICAL"):
        try:
            config.max_queries_critical = int(max_queries_crit)
        except ValueError:
            pass
    if max_dup := os.environ.get("ARES_MAX_DUPLICATE_QUERIES"):
        try:
            config.max_duplicate_queries = int(max_dup)
        except ValueError:
            pass
    if bonus_evidence := os.environ.get("ARES_BONUS_QUERIES_FOR_EVIDENCE"):
        try:
            config.bonus_queries_for_evidence = int(bonus_evidence)
        except ValueError:
            pass
    if bonus_pyramid := os.environ.get("ARES_BONUS_QUERIES_FOR_PYRAMID_L4"):
        try:
            config.bonus_queries_for_pyramid_l4 = int(bonus_pyramid)
        except ValueError:
            pass
    if max_total := os.environ.get("ARES_MAX_TOTAL_QUERIES"):
        try:
            config.max_total_queries = int(max_total)
        except ValueError:
            pass

    # Task retry overrides
    if default_retries := os.environ.get("ARES_DEFAULT_MAX_RETRIES"):
        try:
            config.default_max_retries = int(default_retries)
        except ValueError:
            pass

    # Orchestrator runtime overrides
    if max_runtime := os.environ.get("ARES_MAX_RUNTIME"):
        try:
            config.max_runtime = float(max_runtime)
        except ValueError:
            pass
    if crack_grace := os.environ.get("ARES_CRACK_GRACE_PERIOD"):
        try:
            config.crack_task_grace_period = float(crack_grace)
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


def get_stale_task_timeout() -> int:
    """Get timeout (seconds) after which pending tasks are cleaned up."""
    return load_config().stale_task_timeout


def get_max_redis_consecutive_failures() -> int:
    """Get max consecutive Redis failures before crashing for K8s restart."""
    return load_config().max_redis_consecutive_failures


def get_redis_retry_base_delay() -> float:
    """Get base delay (seconds) between Redis retries."""
    return load_config().redis_retry_base_delay


def get_redis_retry_max_delay() -> float:
    """Get maximum delay (seconds) between Redis retries."""
    return load_config().redis_retry_max_delay


def get_max_deferred_total() -> int:
    """Get max total deferred tasks across all types."""
    return load_config().max_deferred_total


def get_max_deferred_per_type() -> int:
    """Get max deferred tasks per task type."""
    return load_config().max_deferred_per_type


def get_deferred_task_max_age() -> int:
    """Get max age (seconds) for deferred tasks before eviction."""
    return load_config().deferred_task_max_age


def get_deferred_queue_check_interval() -> float:
    """Get interval (seconds) for checking deferred queue."""
    return load_config().deferred_queue_check_interval


def get_critical_priority_threshold() -> int:
    """Get priority threshold for critical tasks (1-N are critical)."""
    return load_config().critical_priority_threshold


def get_agent_task_timeout() -> int:
    """Get timeout (seconds) for agent tasks."""
    return load_config().agent_task_timeout


def get_offload_threshold() -> int:
    """Get character threshold for offloading tool outputs to Redis."""
    return load_config().offload_threshold


def get_offload_ttl() -> int:
    """Get TTL (seconds) for offloaded outputs in Redis."""
    return load_config().offload_ttl


def get_max_stored_results() -> int:
    """Get max query results to store for evidence validation."""
    return load_config().max_stored_results


def get_unvalidated_confidence_penalty() -> float:
    """Get confidence penalty for unvalidated evidence."""
    return load_config().unvalidated_confidence_penalty


def get_max_queries_per_investigation() -> int:
    """Get base query limit per investigation."""
    return load_config().max_queries_per_investigation


def get_max_queries_critical() -> int:
    """Get query limit for critical alerts."""
    return load_config().max_queries_critical


def get_max_duplicate_queries() -> int:
    """Get max times same query can run before blocking."""
    return load_config().max_duplicate_queries


def get_bonus_queries_for_evidence() -> int:
    """Get bonus queries granted when evidence is found."""
    return load_config().bonus_queries_for_evidence


def get_bonus_queries_for_pyramid_l4() -> int:
    """Get bonus queries for reaching pyramid level 4+."""
    return load_config().bonus_queries_for_pyramid_l4


def get_max_total_queries() -> int:
    """Get hard cap for total queries per investigation."""
    return load_config().max_total_queries


def get_default_max_retries() -> int:
    """Get default max retries for tasks interrupted by pod restarts."""
    return load_config().default_max_retries


def get_max_runtime() -> float:
    """Get maximum operation runtime in seconds."""
    return load_config().max_runtime


def get_crack_task_grace_period() -> float:
    """Get grace period for crack tasks when operation is completing (seconds)."""
    return load_config().crack_task_grace_period


def get_rate_limit_backoff_delays() -> list[float]:
    """Get list of delays (seconds) between rate limit retries."""
    return load_config().rate_limit_backoff_delays


def get_rate_limit_max_retries() -> int:
    """Get maximum number of rate limit retries (derived from backoff delays length)."""
    return len(load_config().rate_limit_backoff_delays)


def get_query_limits_by_stage() -> dict[str, int]:
    """Get stage-based query limits for blue team investigations."""
    return load_config().query_limits_by_stage


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
    "get_agent_task_timeout",
    "get_bonus_queries_for_evidence",
    "get_bonus_queries_for_pyramid_l4",
    "get_crack_task_grace_period",
    "get_critical_priority_threshold",
    "get_default_max_retries",
    "get_default_network_interface",
    "get_deferred_queue_check_interval",
    "get_deferred_task_max_age",
    "get_lateral_movement_admin_creds_threshold",
    "get_lateral_movement_owned_hosts_threshold",
    "get_max_concurrent_tasks",
    "get_max_context_tokens",
    "get_max_deferred_per_type",
    "get_max_deferred_total",
    "get_max_duplicate_queries",
    "get_max_output_chars",
    "get_max_queries_critical",
    "get_max_queries_per_investigation",
    "get_max_redis_consecutive_failures",
    "get_max_runtime",
    "get_max_stored_results",
    "get_max_total_queries",
    "get_min_messages_to_keep",
    "get_min_slots_per_role",
    "get_namespace",
    "get_offload_threshold",
    "get_offload_ttl",
    "get_query_limits_by_stage",
    "get_rate_limit_backoff",
    "get_rate_limit_backoff_delays",
    "get_rate_limit_max_retries",
    "get_rate_limit_threshold",
    "get_redis_retry_base_delay",
    "get_redis_retry_max_delay",
    "get_redis_url",
    "get_stale_task_timeout",
    "get_task_dispatch_delay",
    "get_unvalidated_confidence_penalty",
    "load_config",
]
