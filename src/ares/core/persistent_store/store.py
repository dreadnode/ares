"""Persistent store for offloading operation data to PostgreSQL.

This module provides the main interface for persisting operation data
from Redis (hot storage) to PostgreSQL (long-term storage).

Key features:
- Async offload on operation completion
- Incremental sync during operation (optional)
- Batch upsert for efficiency
- Attack chain preservation (parent_id relationships)
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from loguru import logger
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ares.core.persistent_store.config import PersistentStoreConfig, get_persistent_store_config
from ares.core.persistent_store.models import (
    ArtifactRecord,
    Base,
    CredentialRecord,
    HashRecord,
    HostRecord,
    OperationRecord,
    TimelineEventRecord,
    UserRecord,
    VulnerabilityRecord,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine

    from ares.core.models import (
        Credential,
        Hash,
        Host,
        SharedRedTeamState,
        User,
        VulnerabilityInfo,
    )


class PersistentStore:
    """Async PostgreSQL store for long-term operation data.

    This class provides methods to offload operation data from Redis
    to PostgreSQL for historical analysis and investigation.

    Thread Safety:
        Uses SQLAlchemy async sessions which are not thread-safe.
        Each coroutine should use its own session via the session factory.

    Example:
        ```python
        store = PersistentStore()
        await store.initialize()

        # Offload entire operation on completion
        await store.offload_operation(shared_state)

        # Or incremental sync during operation
        await store.offload_credentials(operation_id, credentials)

        await store.close()
        ```
    """

    def __init__(self, config: PersistentStoreConfig | None = None) -> None:
        """Initialize the persistent store.

        Args:
            config: Configuration for the store. If None, loads from environment.
        """
        self._config = config or get_persistent_store_config()
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[AsyncSession] | None = None
        self._initialized = False

    @property
    def is_enabled(self) -> bool:
        """Check if the persistent store is enabled."""
        return self._config.is_enabled

    async def initialize(self) -> bool:
        """Initialize the database connection pool.

        Returns:
            True if initialization successful, False if disabled or failed.
        """
        if not self.is_enabled:
            logger.debug("Persistent store disabled (no ARES_DATABASE_URL)")
            return False

        if self._initialized:
            return True

        try:
            # Convert postgres:// to postgresql+asyncpg:// for async driver
            db_url = self._config.database_url
            if db_url.startswith("postgres://"):
                db_url = db_url.replace("postgres://", "postgresql+asyncpg://", 1)
            elif db_url.startswith("postgresql://") and "+asyncpg" not in db_url:
                db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

            self._engine = create_async_engine(
                db_url,
                pool_size=self._config.pool_min_size,
                max_overflow=self._config.pool_max_size - self._config.pool_min_size,
                pool_timeout=self._config.pool_timeout,
                pool_pre_ping=True,  # Verify connections before use
            )

            self._session_factory = async_sessionmaker(
                self._engine,
                class_=AsyncSession,
                expire_on_commit=False,
            )

            # Verify connection
            async with self._engine.begin() as conn:
                await conn.run_sync(lambda _: None)

            self._initialized = True
            logger.info("Persistent store initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize persistent store: {e}")
            self._engine = None
            self._session_factory = None
            return False

    async def close(self) -> None:
        """Close the database connection pool."""
        if self._engine:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
            self._initialized = False
            logger.debug("Persistent store connection closed")

    async def create_tables(self) -> None:
        """Create database tables if they don't exist.

        This should typically be done via Alembic migrations in production,
        but this method is useful for development and testing.
        """
        if not self._engine:
            raise RuntimeError("Persistent store not initialized")

        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created")

    # =========================================================================
    # Full Operation Offload
    # =========================================================================

    async def offload_operation(self, state: SharedRedTeamState) -> bool:
        """Offload complete operation state to PostgreSQL.

        This is the main entry point for persisting an operation, typically
        called on operation completion.

        Args:
            state: SharedRedTeamState containing all operation data

        Returns:
            True if offload successful, False otherwise
        """
        if (not self._initialized or not self._session_factory) and not await self.initialize():
            return False

        if not self._session_factory:
            return False

        try:
            async with self._session_factory() as session, session.begin():
                # Upsert operation record
                op_record = await self._upsert_operation(session, state)

                # Batch upsert all collections
                await self._upsert_credentials(session, op_record.id, state.all_credentials)
                await self._upsert_hashes(session, op_record.id, state.all_hashes)
                await self._upsert_hosts(session, op_record.id, state.all_hosts)
                await self._upsert_users(session, op_record.id, state.all_users)
                await self._upsert_vulnerabilities(
                    session,
                    op_record.id,
                    state.discovered_vulnerabilities,
                    state.exploited_vulnerabilities,
                )
                await self._upsert_timeline_events(session, op_record.id, state.operation_timeline)
                await self._upsert_artifacts(session, op_record.id, state.downloaded_artifacts)

                # Update aggregated stats
                op_record.credential_count = len(state.all_credentials)
                op_record.hash_count = len(state.all_hashes)
                op_record.host_count = len(state.all_hosts)
                op_record.vulnerability_count = len(state.discovered_vulnerabilities)
                op_record.exploited_vulnerability_count = len(state.exploited_vulnerabilities)

            logger.info(
                f"Offloaded operation {state.operation_id} to persistent store: "
                f"{len(state.all_credentials)} creds, {len(state.all_hashes)} hashes, "
                f"{len(state.all_hosts)} hosts"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to offload operation {state.operation_id}: {e}")
            return False

    async def _upsert_operation(
        self, session: AsyncSession, state: SharedRedTeamState
    ) -> OperationRecord:
        """Upsert operation record."""
        target = state.target
        target_ip = target.ip if target else None
        target_domain = target.domain if target else None
        environment = target.environment if target else None

        stmt = pg_insert(OperationRecord).values(
            operation_id=state.operation_id,
            target_ip=target_ip,
            target_domain=target_domain,
            environment=environment,
            started_at=state.started_at,
            completed_at=state.completed_at,
            has_domain_admin=state.has_domain_admin,
            has_golden_ticket=state.has_golden_ticket,
            domain_admin_path=state.domain_admin_path,
            da_hash_id=state.da_hash_id,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["operation_id"],
            set_={
                "completed_at": stmt.excluded.completed_at,
                "has_domain_admin": stmt.excluded.has_domain_admin,
                "has_golden_ticket": stmt.excluded.has_golden_ticket,
                "domain_admin_path": stmt.excluded.domain_admin_path,
                "da_hash_id": stmt.excluded.da_hash_id,
            },
        ).returning(OperationRecord)

        result = await session.execute(stmt)
        return result.scalar_one()

    async def _upsert_credentials(
        self,
        session: AsyncSession,
        operation_uuid: Any,
        credentials: list[Credential],
    ) -> None:
        """Batch upsert credentials."""
        if not credentials:
            return

        values = []
        for cred in credentials:
            # Hash password for dedup (don't store plaintext)
            password_hash = None
            if cred.password:
                password_hash = hashlib.sha256(cred.password.encode()).hexdigest()[:16]

            values.append(
                {
                    "operation_id": operation_uuid,
                    "credential_id": cred.id,
                    "username": cred.username,
                    "domain": cred.domain,
                    "password_hash": password_hash,
                    "source": cred.source,
                    "attack_step": cred.attack_step,
                    "discovered_at": getattr(cred, "discovered_at", None),
                }
            )

        stmt = pg_insert(CredentialRecord).values(values)
        stmt = stmt.on_conflict_do_nothing(constraint="uq_cred")
        await session.execute(stmt)

    async def _upsert_hashes(
        self,
        session: AsyncSession,
        operation_uuid: Any,
        hashes: list[Hash],
    ) -> None:
        """Batch upsert hashes."""
        if not hashes:
            return

        values = []
        for h in hashes:
            hash_prefix = h.hash_value[:64] if h.hash_value else None
            cracked_hash = None
            if h.cracked_password:
                cracked_hash = hashlib.sha256(h.cracked_password.encode()).hexdigest()[:16]

            values.append(
                {
                    "operation_id": operation_uuid,
                    "hash_id": h.id,
                    "username": h.username,
                    "domain": h.domain,
                    "hash_type": h.hash_type,
                    "hash_value_prefix": hash_prefix,
                    "cracked_password_hash": cracked_hash,
                    "source": h.source,
                    "attack_step": h.attack_step,
                    "discovered_at": h.discovered_at,
                }
            )

        stmt = pg_insert(HashRecord).values(values)
        stmt = stmt.on_conflict_do_nothing(constraint="uq_hash")
        await session.execute(stmt)

    async def _upsert_hosts(
        self,
        session: AsyncSession,
        operation_uuid: Any,
        hosts: list[Host],
    ) -> None:
        """Batch upsert hosts."""
        if not hosts:
            return

        values = []
        for host in hosts:
            values.append(
                {
                    "operation_id": operation_uuid,
                    "ip": host.ip,
                    "hostname": host.hostname,
                    "os": host.os,
                    "is_dc": host.is_dc,
                    "is_owned": getattr(host, "owned", False),
                    "roles": host.roles or None,
                    "services": host.services or None,
                }
            )

        stmt = pg_insert(HostRecord).values(values)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_host",
            set_={
                "hostname": stmt.excluded.hostname,
                "os": stmt.excluded.os,
                "is_dc": stmt.excluded.is_dc,
                "is_owned": stmt.excluded.is_owned,
                "roles": stmt.excluded.roles,
                "services": stmt.excluded.services,
            },
        )
        await session.execute(stmt)

    async def _upsert_users(
        self,
        session: AsyncSession,
        operation_uuid: Any,
        users: list[User],
    ) -> None:
        """Batch upsert users."""
        if not users:
            return

        values = []
        for user in users:
            values.append(
                {
                    "operation_id": operation_uuid,
                    "username": user.username,
                    "domain": user.domain,
                    "description": getattr(user, "description", None),
                    "is_admin": getattr(user, "is_admin", False),
                    "source": user.source,
                }
            )

        stmt = pg_insert(UserRecord).values(values)
        stmt = stmt.on_conflict_do_nothing(constraint="uq_user")
        await session.execute(stmt)

    async def _upsert_vulnerabilities(
        self,
        session: AsyncSession,
        operation_uuid: Any,
        vulnerabilities: dict[str, VulnerabilityInfo],
        exploited: set[str],
    ) -> None:
        """Batch upsert vulnerabilities."""
        if not vulnerabilities:
            return

        values = []
        for vuln_id, vuln in vulnerabilities.items():
            exploited_at = datetime.now(timezone.utc) if vuln_id in exploited else None
            values.append(
                {
                    "operation_id": operation_uuid,
                    "vuln_id": vuln.vuln_id,
                    "vuln_type": vuln.vuln_type,
                    "target_ip": vuln.target if _is_ip(vuln.target) else None,
                    "target_hostname": vuln.target if not _is_ip(vuln.target) else None,
                    "priority": vuln.priority,
                    "discovered_by": vuln.discovered_by,
                    "discovered_at": vuln.discovered_at,
                    "exploited_at": exploited_at,
                    "details": vuln.details,
                }
            )

        stmt = pg_insert(VulnerabilityRecord).values(values)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_vuln",
            set_={
                "exploited_at": stmt.excluded.exploited_at,
                "details": stmt.excluded.details,
            },
        )
        await session.execute(stmt)

    async def _upsert_timeline_events(
        self,
        session: AsyncSession,
        operation_uuid: Any,
        events: list[Any],
    ) -> None:
        """Batch insert timeline events."""
        if not events:
            return

        values = []
        for event in events:
            # Handle both TimelineEvent objects and dicts
            if hasattr(event, "id"):
                values.append(
                    {
                        "operation_id": operation_uuid,
                        "event_id": event.id,
                        "timestamp": event.timestamp,
                        "description": event.description,
                        "mitre_techniques": event.mitre_techniques or None,
                        "confidence": event.confidence,
                        "source": getattr(event, "source", None),
                        "evidence_ids": event.evidence_ids or None,
                    }
                )
            elif isinstance(event, dict):
                values.append(
                    {
                        "operation_id": operation_uuid,
                        "event_id": event.get("id"),
                        "timestamp": event.get("timestamp", datetime.now(timezone.utc)),
                        "description": event.get("description"),
                        "mitre_techniques": event.get("mitre_techniques"),
                        "confidence": event.get("confidence"),
                        "source": event.get("source"),
                        "evidence_ids": event.get("evidence_ids"),
                    }
                )

        if values:
            stmt = pg_insert(TimelineEventRecord).values(values)
            stmt = stmt.on_conflict_do_nothing()
            await session.execute(stmt)

    async def _upsert_artifacts(
        self,
        session: AsyncSession,
        operation_uuid: Any,
        artifacts: dict[str, str],
    ) -> None:
        """Batch upsert artifacts."""
        if not artifacts:
            return

        max_size = self._config.retention.artifacts_max_size_bytes
        values = []
        for key, content_b64 in artifacts.items():
            # Estimate size (base64 is ~4/3 of original)
            estimated_size = len(content_b64) * 3 // 4
            if estimated_size > max_size:
                logger.debug(
                    f"Skipping artifact {key}: size {estimated_size} exceeds max {max_size}"
                )
                continue

            content_hash = hashlib.sha256(content_b64.encode()).hexdigest()
            values.append(
                {
                    "operation_id": operation_uuid,
                    "artifact_key": key,
                    "size_bytes": estimated_size,
                    "content_hash": content_hash,
                    "content_base64": content_b64,
                }
            )

        if values:
            stmt = pg_insert(ArtifactRecord).values(values)
            stmt = stmt.on_conflict_do_nothing(constraint="uq_artifact")
            await session.execute(stmt)

    # =========================================================================
    # Incremental Offload (for sync during operation)
    # =========================================================================

    async def offload_credentials(self, operation_id: str, credentials: list[Credential]) -> bool:
        """Incrementally offload credentials during operation.

        Args:
            operation_id: The operation ID string
            credentials: List of credentials to offload

        Returns:
            True if successful
        """
        if not self._initialized or not self._session_factory:
            return False

        try:
            async with self._session_factory() as session:
                # Get operation UUID
                stmt = select(OperationRecord.id).where(
                    OperationRecord.operation_id == operation_id
                )
                result = await session.execute(stmt)
                op_uuid = result.scalar_one_or_none()

                if not op_uuid:
                    logger.debug(f"Operation {operation_id} not found in persistent store")
                    return False

                async with session.begin():
                    await self._upsert_credentials(session, op_uuid, credentials)

            return True
        except Exception as e:
            logger.warning(f"Failed to offload credentials: {e}")
            return False

    async def offload_hashes(self, operation_id: str, hashes: list[Hash]) -> bool:
        """Incrementally offload hashes during operation."""
        if not self._initialized or not self._session_factory:
            return False

        try:
            async with self._session_factory() as session:
                stmt = select(OperationRecord.id).where(
                    OperationRecord.operation_id == operation_id
                )
                result = await session.execute(stmt)
                op_uuid = result.scalar_one_or_none()

                if not op_uuid:
                    return False

                async with session.begin():
                    await self._upsert_hashes(session, op_uuid, hashes)

            return True
        except Exception as e:
            logger.warning(f"Failed to offload hashes: {e}")
            return False

    # =========================================================================
    # Store Report
    # =========================================================================

    async def store_report(self, operation_id: str, report_markdown: str) -> bool:
        """Store the final operation report.

        Args:
            operation_id: The operation ID string
            report_markdown: The markdown report content

        Returns:
            True if successful
        """
        if not self._initialized or not self._session_factory:
            return False

        try:
            async with self._session_factory() as session, session.begin():
                stmt = select(OperationRecord).where(OperationRecord.operation_id == operation_id)
                result = await session.execute(stmt)
                op_record = result.scalar_one_or_none()

                if op_record:
                    op_record.final_report = report_markdown

            logger.debug(f"Stored report for operation {operation_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to store report: {e}")
            return False


def _is_ip(value: str) -> bool:
    """Check if a string looks like an IP address."""
    if not value:
        return False
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


__all__ = ["PersistentStore"]
