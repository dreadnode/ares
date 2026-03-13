"""Configuration for persistent data store.

Supports configuration via environment variables and YAML config files.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal

from loguru import logger


@dataclass
class RetentionConfig:
    """Retention policy configuration for different data types."""

    # Days to keep operation metadata
    operations_default_days: int = 365
    # Days to keep operations that achieved domain admin
    operations_with_da_days: int = 730
    # Days to keep full credential data before anonymization
    credentials_anonymize_after_days: int = 90
    # Days to keep credentials total
    credentials_default_days: int = 365
    # Days to keep timeline events
    timeline_events_days: int = 365
    # Days to keep artifacts
    artifacts_days: int = 90
    # Max artifact size to persist (bytes)
    artifacts_max_size_bytes: int = 10 * 1024 * 1024  # 10MB


@dataclass
class PersistentStoreConfig:
    """Configuration for PostgreSQL persistent store."""

    # Connection settings
    database_url: str = ""
    # Connection pool settings
    pool_min_size: int = 2
    pool_max_size: int = 10
    pool_timeout: float = 30.0

    # Offload behavior
    # Mode: "sync" for immediate dual-write, "async" for background offload
    offload_mode: Literal["sync", "async", "disabled"] = "async"
    # Interval for async checkpoint offload (seconds)
    offload_interval: float = 30.0
    # Enable offload on operation completion
    offload_on_completion: bool = True

    # Retention policies
    retention: RetentionConfig = field(default_factory=RetentionConfig)

    # Security
    # Encrypt sensitive fields at rest (requires ARES_DB_ENCRYPTION_KEY)
    encrypt_sensitive_fields: bool = False

    @property
    def is_enabled(self) -> bool:
        """Check if persistent store is enabled (has valid database URL)."""
        return bool(self.database_url)


_cached_config: PersistentStoreConfig | None = None


def get_persistent_store_config() -> PersistentStoreConfig:
    """Get persistent store configuration from environment variables.

    Environment Variables:
        ARES_DATABASE_URL: PostgreSQL connection URL
        ARES_DB_POOL_MIN_SIZE: Minimum pool size (default: 2)
        ARES_DB_POOL_MAX_SIZE: Maximum pool size (default: 10)
        ARES_DB_POOL_TIMEOUT: Pool timeout seconds (default: 30)
        ARES_DB_OFFLOAD_MODE: "sync", "async", or "disabled" (default: async)
        ARES_DB_OFFLOAD_INTERVAL: Async offload interval seconds (default: 30)
        ARES_DB_OFFLOAD_ON_COMPLETION: Enable completion offload (default: true)
        ARES_DB_ENCRYPT_SENSITIVE: Encrypt sensitive fields (default: false)
        ARES_DB_RETENTION_OPERATIONS_DAYS: Operation retention days (default: 365)
        ARES_DB_RETENTION_CREDENTIALS_ANONYMIZE_DAYS: Credential anonymization days (default: 90)

    Returns:
        PersistentStoreConfig with values from environment or defaults.
    """
    global _cached_config

    if _cached_config is not None:
        return _cached_config

    config = PersistentStoreConfig()

    # Connection settings
    if db_url := os.environ.get("ARES_DATABASE_URL"):
        config.database_url = db_url
        logger.debug("Persistent store enabled with database URL")

    if pool_min := os.environ.get("ARES_DB_POOL_MIN_SIZE"):
        try:
            config.pool_min_size = int(pool_min)
        except ValueError:
            pass

    if pool_max := os.environ.get("ARES_DB_POOL_MAX_SIZE"):
        try:
            config.pool_max_size = int(pool_max)
        except ValueError:
            pass

    if pool_timeout := os.environ.get("ARES_DB_POOL_TIMEOUT"):
        try:
            config.pool_timeout = float(pool_timeout)
        except ValueError:
            pass

    # Offload behavior
    offload_mode = os.environ.get("ARES_DB_OFFLOAD_MODE")
    if offload_mode and offload_mode.lower() in ("sync", "async", "disabled"):
        config.offload_mode = offload_mode.lower()  # type: ignore[assignment]

    if offload_interval := os.environ.get("ARES_DB_OFFLOAD_INTERVAL"):
        try:
            config.offload_interval = float(offload_interval)
        except ValueError:
            pass

    if offload_on_completion := os.environ.get("ARES_DB_OFFLOAD_ON_COMPLETION"):
        config.offload_on_completion = offload_on_completion.lower() in ("true", "1", "yes")

    # Security
    if encrypt := os.environ.get("ARES_DB_ENCRYPT_SENSITIVE"):
        config.encrypt_sensitive_fields = encrypt.lower() in ("true", "1", "yes")

    # Retention settings
    if ops_days := os.environ.get("ARES_DB_RETENTION_OPERATIONS_DAYS"):
        try:
            config.retention.operations_default_days = int(ops_days)
        except ValueError:
            pass

    if ops_da_days := os.environ.get("ARES_DB_RETENTION_OPERATIONS_DA_DAYS"):
        try:
            config.retention.operations_with_da_days = int(ops_da_days)
        except ValueError:
            pass

    if cred_anon_days := os.environ.get("ARES_DB_RETENTION_CREDENTIALS_ANONYMIZE_DAYS"):
        try:
            config.retention.credentials_anonymize_after_days = int(cred_anon_days)
        except ValueError:
            pass

    if cred_days := os.environ.get("ARES_DB_RETENTION_CREDENTIALS_DAYS"):
        try:
            config.retention.credentials_default_days = int(cred_days)
        except ValueError:
            pass

    if timeline_days := os.environ.get("ARES_DB_RETENTION_TIMELINE_DAYS"):
        try:
            config.retention.timeline_events_days = int(timeline_days)
        except ValueError:
            pass

    if artifact_days := os.environ.get("ARES_DB_RETENTION_ARTIFACTS_DAYS"):
        try:
            config.retention.artifacts_days = int(artifact_days)
        except ValueError:
            pass

    if artifact_max := os.environ.get("ARES_DB_RETENTION_ARTIFACTS_MAX_SIZE"):
        try:
            config.retention.artifacts_max_size_bytes = int(artifact_max)
        except ValueError:
            pass

    _cached_config = config
    return config


def clear_persistent_store_config_cache() -> None:
    """Clear the cached configuration (useful for testing)."""
    global _cached_config
    _cached_config = None


__all__ = [
    "PersistentStoreConfig",
    "RetentionConfig",
    "clear_persistent_store_config_cache",
    "get_persistent_store_config",
]
