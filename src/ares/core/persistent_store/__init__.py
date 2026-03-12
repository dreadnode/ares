"""Persistent data store for long-term operation data storage.

This module provides PostgreSQL-based persistent storage for operation data,
enabling historical analysis, cross-operation correlation, and investigation tracking.

Key components:
- PersistentStore: Main interface for offloading operation data to PostgreSQL
- HistoricalQueryService: Query service for historical data analysis
- Models: SQLAlchemy models for database schema

The persistent store complements Redis (used for hot/active operation state)
by providing durable, queryable long-term storage.
"""

from ares.core.persistent_store.config import (
    PersistentStoreConfig,
    get_persistent_store_config,
)
from ares.core.persistent_store.models import (
    ArtifactRecord,
    CredentialRecord,
    HashRecord,
    HostRecord,
    InvestigationRecord,
    OperationRecord,
    TimelineEventRecord,
    UserRecord,
    VulnerabilityRecord,
)
from ares.core.persistent_store.queries import HistoricalQueryService
from ares.core.persistent_store.store import PersistentStore

__all__ = [
    "ArtifactRecord",
    "CredentialRecord",
    "HashRecord",
    "HistoricalQueryService",
    "HostRecord",
    "InvestigationRecord",
    "OperationRecord",
    "PersistentStore",
    "PersistentStoreConfig",
    "TimelineEventRecord",
    "UserRecord",
    "VulnerabilityRecord",
    "get_persistent_store_config",
]
