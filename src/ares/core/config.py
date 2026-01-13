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


@dataclass
class AgentConfig:
    """Configuration for a specific agent role."""

    model: str = "claude-sonnet-4-20250514"
    max_steps: int = 100
    pod_selector: str = ""
    capabilities: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)


@dataclass
class OperationConfig:
    """Configuration for multi-agent operations."""

    # Operation settings
    name: str = "ares-multi-agent"
    namespace: str = "ares"
    redis_url: str = "redis://localhost:6379"
    checkpoint_interval: int = 60

    # Agent configurations
    agents: dict[str, AgentConfig] = field(default_factory=dict)

    # Timeouts
    agent_heartbeat_timeout: int = 30
    task_timeout: int = 300
    operation_timeout: int = 7200

    # Recovery
    recovery_enabled: bool = True
    max_retries: int = 3
    retry_delay: int = 10

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
    except Exception as e:
        logger.warning(f"Failed to load config from {path}: {e}")
        return {}


def _build_config(data: dict[str, Any]) -> OperationConfig:
    """Build OperationConfig from loaded data."""
    operation = data.get("operation", {})
    timeouts = data.get("timeouts", {})
    recovery = data.get("recovery", {})
    grafana = data.get("grafana", {})

    # Build agent configs
    agents: dict[str, AgentConfig] = {}
    for role, agent_data in data.get("agents", {}).items():
        if isinstance(agent_data, dict):
            agents[role] = AgentConfig(
                model=agent_data.get("model", "claude-sonnet-4-20250514"),
                max_steps=agent_data.get("max_steps", 100),
                pod_selector=agent_data.get("pod_selector", ""),
                capabilities=agent_data.get("capabilities", []),
                tools=agent_data.get("tools", []),
            )

    return OperationConfig(
        name=operation.get("name", "ares-multi-agent"),
        namespace=operation.get("namespace", "ares"),
        redis_url=operation.get("redis_url", "redis://localhost:6379"),
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
    )


def _resolve_env(value: str) -> str:
    """Resolve environment variable references like ${VAR_NAME}."""
    if not isinstance(value, str):
        return value
    if value.startswith("${") and value.endswith("}"):
        env_var = value[2:-1]
        return os.environ.get(env_var, "")
    return value


def _apply_env_overrides(config: OperationConfig) -> OperationConfig:
    """Apply environment variable overrides to config."""
    # Redis URL override
    if redis_url := os.environ.get("ARES_REDIS_URL") or os.environ.get("REDIS_URL"):
        config.redis_url = redis_url

    # Namespace override
    if namespace := os.environ.get("ARES_NAMESPACE"):
        config.namespace = namespace

    # Grafana overrides
    if grafana_url := os.environ.get("GRAFANA_URL"):
        config.grafana_url = grafana_url
    if grafana_key := os.environ.get("GRAFANA_API_KEY") or os.environ.get(
        "GRAFANA_SERVICE_ACCOUNT_TOKEN"
    ):
        config.grafana_api_key = grafana_key

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


def clear_config_cache() -> None:
    """Clear the cached configuration (useful for testing)."""
    global _cached_config
    _cached_config = None


__all__ = [
    "AgentConfig",
    "OperationConfig",
    "clear_config_cache",
    "get_agent_config",
    "get_namespace",
    "get_redis_url",
    "load_config",
]
