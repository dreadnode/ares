"""Historical query service for persistent data store.

This module provides query methods for analyzing historical operation data,
cross-operation correlation, and investigation tracking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from loguru import logger

if TYPE_CHECKING:
    from uuid import UUID
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload

from ares.core.persistent_store.config import PersistentStoreConfig, get_persistent_store_config
from ares.core.persistent_store.models import (
    CredentialRecord,
    HashRecord,
    InvestigationRecord,
    OperationRecord,
    TimelineEventRecord,
)


@dataclass
class OperationSummary:
    """Summary of an operation for listing."""

    id: UUID
    operation_id: str
    target_domain: str | None
    target_ip: str | None
    started_at: datetime
    completed_at: datetime | None
    has_domain_admin: bool
    has_golden_ticket: bool
    credential_count: int
    hash_count: int
    host_count: int
    vulnerability_count: int
    exploited_vulnerability_count: int
    duration_seconds: float | None = None

    @property
    def duration_str(self) -> str:
        """Human-readable duration."""
        if self.duration_seconds is None:
            return "running"
        hours, remainder = divmod(int(self.duration_seconds), 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours:
            return f"{hours}h {minutes}m {seconds}s"
        if minutes:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"


@dataclass
class AttackChainNode:
    """Node in an attack chain."""

    id: str
    type: str  # "credential" or "hash"
    username: str
    domain: str | None
    source: str | None
    attack_step: int
    children: list[AttackChainNode] = field(default_factory=list)


@dataclass
class MITRECoverage:
    """MITRE ATT&CK technique coverage statistics."""

    technique_id: str
    technique_name: str | None
    occurrence_count: int
    operations: list[str]


class HistoricalQueryService:
    """Service for querying historical operation data.

    Provides methods for:
    - Listing and searching operations
    - Cross-operation credential/hash lookup
    - Attack chain reconstruction
    - MITRE technique coverage analysis
    - Investigation management
    """

    def __init__(self, config: PersistentStoreConfig | None = None) -> None:
        """Initialize the query service.

        Args:
            config: Configuration for the store. If None, loads from environment.
        """
        self._config = config or get_persistent_store_config()
        self._engine = None
        self._session_factory: async_sessionmaker[AsyncSession] | None = None
        self._initialized = False

    @property
    def is_enabled(self) -> bool:
        """Check if the service is enabled."""
        return self._config.is_enabled

    async def initialize(self) -> bool:
        """Initialize the database connection."""
        if not self.is_enabled:
            return False

        if self._initialized:
            return True

        try:
            db_url = self._config.database_url
            if db_url.startswith("postgres://"):
                db_url = db_url.replace("postgres://", "postgresql+asyncpg://", 1)
            elif db_url.startswith("postgresql://") and "+asyncpg" not in db_url:
                db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

            self._engine = create_async_engine(
                db_url,
                pool_size=self._config.pool_min_size,
                max_overflow=self._config.pool_max_size - self._config.pool_min_size,
            )

            self._session_factory = async_sessionmaker(
                self._engine,
                class_=AsyncSession,
                expire_on_commit=False,
            )

            self._initialized = True
            return True
        except Exception as e:
            logger.error(f"Failed to initialize query service: {e}")
            return False

    async def close(self) -> None:
        """Close the database connection."""
        if self._engine:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
            self._initialized = False

    # =========================================================================
    # Operation Queries
    # =========================================================================

    async def list_operations(
        self,
        *,
        domain: str | None = None,
        has_da: bool | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[OperationSummary]:
        """List operations with optional filters.

        Args:
            domain: Filter by target domain (partial match)
            has_da: Filter by domain admin achievement
            since: Operations started after this date
            until: Operations started before this date
            limit: Maximum results to return
            offset: Number of results to skip

        Returns:
            List of operation summaries
        """
        if not self._session_factory and not await self.initialize():
            return []

        if not self._session_factory:
            return []

        try:
            async with self._session_factory() as session:
                stmt = select(OperationRecord).order_by(OperationRecord.started_at.desc())

                if domain:
                    stmt = stmt.where(OperationRecord.target_domain.ilike(f"%{domain}%"))
                if has_da is not None:
                    stmt = stmt.where(OperationRecord.has_domain_admin == has_da)
                if since:
                    stmt = stmt.where(OperationRecord.started_at >= since)
                if until:
                    stmt = stmt.where(OperationRecord.started_at <= until)

                stmt = stmt.limit(limit).offset(offset)
                result = await session.execute(stmt)
                records = result.scalars().all()

                summaries = []
                for r in records:
                    duration = None
                    if r.completed_at and r.started_at:
                        duration = (r.completed_at - r.started_at).total_seconds()
                    elif r.started_at:
                        duration = (datetime.now(timezone.utc) - r.started_at).total_seconds()

                    summaries.append(
                        OperationSummary(
                            id=r.id,
                            operation_id=r.operation_id,
                            target_domain=r.target_domain,
                            target_ip=str(r.target_ip) if r.target_ip else None,
                            started_at=r.started_at,
                            completed_at=r.completed_at,
                            has_domain_admin=r.has_domain_admin,
                            has_golden_ticket=r.has_golden_ticket,
                            credential_count=r.credential_count or 0,
                            hash_count=r.hash_count or 0,
                            host_count=r.host_count or 0,
                            vulnerability_count=r.vulnerability_count or 0,
                            exploited_vulnerability_count=r.exploited_vulnerability_count or 0,
                            duration_seconds=duration,
                        )
                    )

                return summaries

        except Exception as e:
            logger.error(f"Failed to list operations: {e}")
            return []

    async def get_operation(self, operation_id: str) -> OperationRecord | None:
        """Get full operation record by operation_id.

        Args:
            operation_id: The operation ID string (e.g., "op-20260312-abc123")

        Returns:
            OperationRecord with all relationships loaded, or None
        """
        if not self._session_factory and not await self.initialize():
            return None

        if not self._session_factory:
            return None

        try:
            async with self._session_factory() as session:
                stmt = (
                    select(OperationRecord)
                    .where(OperationRecord.operation_id == operation_id)
                    .options(
                        selectinload(OperationRecord.credentials),
                        selectinload(OperationRecord.hashes),
                        selectinload(OperationRecord.hosts),
                        selectinload(OperationRecord.vulnerabilities),
                        selectinload(OperationRecord.timeline_events),
                    )
                )
                result = await session.execute(stmt)
                return result.scalar_one_or_none()
        except Exception as e:
            logger.error(f"Failed to get operation {operation_id}: {e}")
            return None

    async def get_operation_report(self, operation_id: str) -> str | None:
        """Get the final report for an operation.

        Args:
            operation_id: The operation ID string

        Returns:
            Markdown report content, or None
        """
        if not self._session_factory and not await self.initialize():
            return None

        if not self._session_factory:
            return None

        try:
            async with self._session_factory() as session:
                stmt = select(OperationRecord.final_report).where(
                    OperationRecord.operation_id == operation_id
                )
                result = await session.execute(stmt)
                return result.scalar_one_or_none()
        except Exception as e:
            logger.error(f"Failed to get report for {operation_id}: {e}")
            return None

    # =========================================================================
    # Credential/Hash Search
    # =========================================================================

    async def search_credentials(
        self,
        *,
        domain: str | None = None,
        username: str | None = None,
        is_admin: bool | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Search credentials across all operations.

        Args:
            domain: Filter by domain (exact match, case-insensitive)
            username: Filter by username (partial match)
            is_admin: Filter by admin status
            since: Only credentials discovered after this date
            limit: Maximum results

        Returns:
            List of credential dicts with operation context
        """
        if not self._session_factory and not await self.initialize():
            return []

        if not self._session_factory:
            return []

        try:
            async with self._session_factory() as session:
                stmt = (
                    select(CredentialRecord, OperationRecord.operation_id)
                    .join(OperationRecord)
                    .order_by(CredentialRecord.created_at.desc())
                )

                if domain:
                    stmt = stmt.where(func.lower(CredentialRecord.domain) == domain.lower())
                if username:
                    stmt = stmt.where(CredentialRecord.username.ilike(f"%{username}%"))
                if is_admin is not None:
                    stmt = stmt.where(CredentialRecord.is_admin == is_admin)
                if since:
                    stmt = stmt.where(CredentialRecord.discovered_at >= since)

                stmt = stmt.limit(limit)
                result = await session.execute(stmt)
                rows = result.all()

                return [
                    {
                        "id": str(cred.id),
                        "operation_id": op_id,
                        "username": cred.username,
                        "domain": cred.domain,
                        "is_admin": cred.is_admin,
                        "source": cred.source,
                        "attack_step": cred.attack_step,
                        "discovered_at": cred.discovered_at.isoformat()
                        if cred.discovered_at
                        else None,
                    }
                    for cred, op_id in rows
                ]
        except Exception as e:
            logger.error(f"Failed to search credentials: {e}")
            return []

    async def search_hashes(
        self,
        *,
        domain: str | None = None,
        username: str | None = None,
        hash_type: str | None = None,
        cracked_only: bool = False,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Search hashes across all operations.

        Args:
            domain: Filter by domain
            username: Filter by username (partial match)
            hash_type: Filter by hash type (ntlm, asrep, kerberoast)
            cracked_only: Only return cracked hashes
            limit: Maximum results

        Returns:
            List of hash dicts with operation context
        """
        if not self._session_factory and not await self.initialize():
            return []

        if not self._session_factory:
            return []

        try:
            async with self._session_factory() as session:
                stmt = (
                    select(HashRecord, OperationRecord.operation_id)
                    .join(OperationRecord)
                    .order_by(HashRecord.created_at.desc())
                )

                if domain:
                    stmt = stmt.where(func.lower(HashRecord.domain) == domain.lower())
                if username:
                    stmt = stmt.where(HashRecord.username.ilike(f"%{username}%"))
                if hash_type:
                    stmt = stmt.where(func.lower(HashRecord.hash_type) == hash_type.lower())
                if cracked_only:
                    stmt = stmt.where(HashRecord.cracked_password_hash.isnot(None))

                stmt = stmt.limit(limit)
                result = await session.execute(stmt)
                rows = result.all()

                return [
                    {
                        "id": str(h.id),
                        "operation_id": op_id,
                        "username": h.username,
                        "domain": h.domain,
                        "hash_type": h.hash_type,
                        "is_cracked": h.cracked_password_hash is not None,
                        "source": h.source,
                        "attack_step": h.attack_step,
                        "discovered_at": h.discovered_at.isoformat() if h.discovered_at else None,
                    }
                    for h, op_id in rows
                ]
        except Exception as e:
            logger.error(f"Failed to search hashes: {e}")
            return []

    # =========================================================================
    # Attack Chain Reconstruction
    # =========================================================================

    async def get_attack_chain(
        self, credential_id: str | None = None, hash_id: str | None = None
    ) -> AttackChainNode | None:
        """Reconstruct attack chain from parent_id relationships.

        Builds a tree starting from the specified credential or hash,
        following parent_id references to the root.

        Args:
            credential_id: UUID of credential to trace
            hash_id: UUID of hash to trace

        Returns:
            Root AttackChainNode with children populated, or None
        """
        if not self._session_factory and not await self.initialize():
            return None

        if not self._session_factory:
            return None

        # Requires recursive CTE queries to follow parent_id references
        logger.debug("Attack chain reconstruction not yet implemented")
        return None

    # =========================================================================
    # MITRE Coverage Analysis
    # =========================================================================

    async def get_mitre_coverage(
        self,
        *,
        operation_ids: list[str] | None = None,
        since: datetime | None = None,
    ) -> list[MITRECoverage]:
        """Get MITRE ATT&CK technique coverage across operations.

        Args:
            operation_ids: Filter to specific operations (None = all)
            since: Only operations started after this date

        Returns:
            List of technique coverage statistics
        """
        if not self._session_factory and not await self.initialize():
            return []

        if not self._session_factory:
            return []

        try:
            async with self._session_factory() as session:
                # Get all timeline events with MITRE techniques
                stmt = (
                    select(
                        TimelineEventRecord.mitre_techniques,
                        OperationRecord.operation_id,
                    )
                    .join(OperationRecord)
                    .where(TimelineEventRecord.mitre_techniques.isnot(None))
                )

                if operation_ids:
                    stmt = stmt.where(OperationRecord.operation_id.in_(operation_ids))
                if since:
                    stmt = stmt.where(OperationRecord.started_at >= since)

                result = await session.execute(stmt)
                rows = result.all()

                # Aggregate by technique
                technique_ops: dict[str, set[str]] = {}
                for techniques, op_id in rows:
                    if techniques:
                        for t in techniques:
                            if t not in technique_ops:
                                technique_ops[t] = set()
                            technique_ops[t].add(op_id)

                return [
                    MITRECoverage(
                        technique_id=t,
                        technique_name=None,  # Could be enriched from MITRE API
                        occurrence_count=len(ops),
                        operations=list(ops),
                    )
                    for t, ops in sorted(technique_ops.items(), key=lambda x: -len(x[1]))
                ]
        except Exception as e:
            logger.error(f"Failed to get MITRE coverage: {e}")
            return []

    # =========================================================================
    # Investigation Management
    # =========================================================================

    async def create_investigation(
        self,
        name: str,
        description: str | None = None,
        operation_ids: list[str] | None = None,
        created_by: str | None = None,
    ) -> InvestigationRecord | None:
        """Create a new investigation linking operations.

        Args:
            name: Investigation name
            description: Optional description
            operation_ids: List of operation IDs to include
            created_by: Creator identifier

        Returns:
            Created InvestigationRecord or None
        """
        if not self._session_factory and not await self.initialize():
            return None

        if not self._session_factory:
            return None

        try:
            async with self._session_factory() as session:
                # Resolve operation UUIDs
                op_uuids = None
                if operation_ids:
                    stmt = select(OperationRecord.id).where(
                        OperationRecord.operation_id.in_(operation_ids)
                    )
                    result = await session.execute(stmt)
                    op_uuids = list(result.scalars().all())

                investigation = InvestigationRecord(
                    name=name,
                    description=description,
                    operation_ids=op_uuids,
                    created_by=created_by,
                )

                session.add(investigation)
                await session.commit()
                await session.refresh(investigation)

                logger.info(f"Created investigation: {name}")
                return investigation
        except Exception as e:
            logger.error(f"Failed to create investigation: {e}")
            return None

    async def list_investigations(
        self,
        *,
        status: str | None = None,
        limit: int = 100,
    ) -> list[InvestigationRecord]:
        """List investigations with optional status filter.

        Args:
            status: Filter by status (active, closed, etc.)
            limit: Maximum results

        Returns:
            List of investigation records
        """
        if not self._session_factory and not await self.initialize():
            return []

        if not self._session_factory:
            return []

        try:
            async with self._session_factory() as session:
                stmt = select(InvestigationRecord).order_by(InvestigationRecord.updated_at.desc())

                if status:
                    stmt = stmt.where(InvestigationRecord.status == status)

                stmt = stmt.limit(limit)
                result = await session.execute(stmt)
                return list(result.scalars().all())
        except Exception as e:
            logger.error(f"Failed to list investigations: {e}")
            return []

    async def add_operations_to_investigation(
        self, investigation_id: UUID, operation_ids: list[str]
    ) -> bool:
        """Add operations to an existing investigation.

        Args:
            investigation_id: UUID of investigation
            operation_ids: Operation IDs to add

        Returns:
            True if successful
        """
        if not self._session_factory:
            return False

        try:
            async with self._session_factory() as session:
                # Get investigation
                stmt = select(InvestigationRecord).where(InvestigationRecord.id == investigation_id)
                result = await session.execute(stmt)
                investigation = result.scalar_one_or_none()

                if not investigation:
                    return False

                # Resolve operation UUIDs
                op_stmt = select(OperationRecord.id).where(
                    OperationRecord.operation_id.in_(operation_ids)
                )
                op_result = await session.execute(op_stmt)
                new_uuids = list(op_result.scalars().all())

                # Merge with existing
                existing = investigation.operation_ids or []
                investigation.operation_ids = list(set(existing + new_uuids))
                investigation.updated_at = datetime.now(timezone.utc)

                await session.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to add operations to investigation: {e}")
            return False

    # =========================================================================
    # Retention/Cleanup
    # =========================================================================

    async def apply_retention_policy(self) -> dict[str, int]:
        """Apply retention policies to delete old data.

        Returns:
            Dict of table_name -> deleted_count
        """
        if not self._session_factory and not await self.initialize():
            return {}

        if not self._session_factory:
            return {}

        retention = self._config.retention
        now = datetime.now(timezone.utc)
        deleted: dict[str, int] = {}

        try:
            async with self._session_factory() as session, session.begin():
                # Delete old operations (without DA)
                cutoff = now - timedelta(days=retention.operations_default_days)
                stmt = (
                    select(OperationRecord)
                    .where(OperationRecord.started_at < cutoff)
                    .where(OperationRecord.has_domain_admin == False)  # noqa: E712
                )
                result = await session.execute(stmt)
                old_ops = result.scalars().all()
                for op in old_ops:
                    await session.delete(op)
                deleted["operations"] = len(old_ops)

                # Delete old DA operations (longer retention)
                da_cutoff = now - timedelta(days=retention.operations_with_da_days)
                stmt = (
                    select(OperationRecord)
                    .where(OperationRecord.started_at < da_cutoff)
                    .where(OperationRecord.has_domain_admin == True)  # noqa: E712
                )
                result = await session.execute(stmt)
                old_da_ops = result.scalars().all()
                for op in old_da_ops:
                    await session.delete(op)
                deleted["operations_da"] = len(old_da_ops)

            logger.info(f"Applied retention policy: {deleted}")
            return deleted
        except Exception as e:
            logger.error(f"Failed to apply retention policy: {e}")
            return {}


__all__ = [
    "AttackChainNode",
    "HistoricalQueryService",
    "MITRECoverage",
    "OperationSummary",
]
