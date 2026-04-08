"""SQLAlchemy models for persistent data store.

These models define the PostgreSQL schema for long-term operation data storage.
All tables use UUID primary keys for consistency with Redis data.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utc_now() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(timezone.utc)


def new_uuid() -> uuid.UUID:
    """Generate a new UUID."""
    return uuid.uuid4()


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""


class OperationRecord(Base):
    """Record of a red team operation."""

    __tablename__ = "operations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    operation_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    target_ip: Mapped[str | None] = mapped_column(INET)
    target_domain: Mapped[str | None] = mapped_column(String(255), index=True)
    environment: Mapped[str | None] = mapped_column(String(50))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    has_domain_admin: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    has_golden_ticket: Mapped[bool] = mapped_column(Boolean, default=False)
    domain_admin_path: Mapped[str | None] = mapped_column(Text)
    da_hash_id: Mapped[str | None] = mapped_column(String(255))
    final_report: Mapped[str | None] = mapped_column(Text)
    config: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    # Aggregated stats (computed on offload)
    credential_count: Mapped[int | None] = mapped_column(Integer)
    hash_count: Mapped[int | None] = mapped_column(Integer)
    host_count: Mapped[int | None] = mapped_column(Integer)
    vulnerability_count: Mapped[int | None] = mapped_column(Integer)
    exploited_vulnerability_count: Mapped[int | None] = mapped_column(Integer)

    # Token usage / cost tracking (populated by offload-cost)
    total_input_tokens: Mapped[int | None] = mapped_column(BigInteger)
    total_output_tokens: Mapped[int | None] = mapped_column(BigInteger)
    total_cost: Mapped[float | None] = mapped_column(Float)
    model_usage: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    # Relationships
    credentials: Mapped[list[CredentialRecord]] = relationship(
        back_populates="operation", cascade="all, delete-orphan"
    )
    hashes: Mapped[list[HashRecord]] = relationship(
        back_populates="operation", cascade="all, delete-orphan"
    )
    hosts: Mapped[list[HostRecord]] = relationship(
        back_populates="operation", cascade="all, delete-orphan"
    )
    users: Mapped[list[UserRecord]] = relationship(
        back_populates="operation", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[list[VulnerabilityRecord]] = relationship(
        back_populates="operation", cascade="all, delete-orphan"
    )
    timeline_events: Mapped[list[TimelineEventRecord]] = relationship(
        back_populates="operation", cascade="all, delete-orphan"
    )
    artifacts: Mapped[list[ArtifactRecord]] = relationship(
        back_populates="operation", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("idx_operations_started_at", "started_at"),)


class CredentialRecord(Base):
    """Record of a discovered credential."""

    __tablename__ = "credentials"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    operation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operations.id", ondelete="CASCADE"), nullable=False
    )
    credential_id: Mapped[str | None] = mapped_column(String(255))
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    domain: Mapped[str | None] = mapped_column(String(255))
    # Store hash of password for dedup, not actual password (security)
    password_hash: Mapped[str | None] = mapped_column(String(64))
    # Actual password is encrypted if encrypt_sensitive_fields is enabled
    password_encrypted: Mapped[str | None] = mapped_column(Text)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str | None] = mapped_column(String(255))
    parent_credential_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("credentials.id", ondelete="SET NULL")
    )
    attack_step: Mapped[int] = mapped_column(Integer, default=0)
    discovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    # Relationships
    operation: Mapped[OperationRecord] = relationship(back_populates="credentials")
    parent_credential: Mapped[CredentialRecord | None] = relationship(
        remote_side=[id], foreign_keys=[parent_credential_id]
    )

    __table_args__ = (
        UniqueConstraint("operation_id", "domain", "username", "password_hash", name="uq_cred"),
        Index("idx_credentials_operation", "operation_id"),
        Index("idx_credentials_domain_user", "domain", "username"),
    )


class HashRecord(Base):
    """Record of a discovered password hash."""

    __tablename__ = "hashes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    operation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operations.id", ondelete="CASCADE"), nullable=False
    )
    hash_id: Mapped[str | None] = mapped_column(String(255))
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    domain: Mapped[str | None] = mapped_column(String(255))
    hash_type: Mapped[str | None] = mapped_column(String(50))
    # Store truncated hash for dedup (first 64 chars)
    hash_value_prefix: Mapped[str | None] = mapped_column(String(64))
    # Full hash value (encrypted if enabled)
    hash_value_encrypted: Mapped[str | None] = mapped_column(Text)
    # Cracked password hash (not the actual password)
    cracked_password_hash: Mapped[str | None] = mapped_column(String(64))
    source: Mapped[str | None] = mapped_column(String(255))
    parent_hash_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hashes.id", ondelete="SET NULL")
    )
    attack_step: Mapped[int] = mapped_column(Integer, default=0)
    discovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    # Relationships
    operation: Mapped[OperationRecord] = relationship(back_populates="hashes")
    parent_hash: Mapped[HashRecord | None] = relationship(
        remote_side=[id], foreign_keys=[parent_hash_id]
    )

    __table_args__ = (
        UniqueConstraint(
            "operation_id", "domain", "username", "hash_type", "hash_value_prefix", name="uq_hash"
        ),
        Index("idx_hashes_operation", "operation_id"),
        Index("idx_hashes_type", "hash_type"),
    )


class HostRecord(Base):
    """Record of a discovered host."""

    __tablename__ = "hosts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    operation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operations.id", ondelete="CASCADE"), nullable=False
    )
    ip: Mapped[str] = mapped_column(INET, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255))
    fqdn: Mapped[str | None] = mapped_column(String(255))
    os: Mapped[str | None] = mapped_column(String(255))
    is_dc: Mapped[bool] = mapped_column(Boolean, default=False)
    is_owned: Mapped[bool] = mapped_column(Boolean, default=False)
    roles: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    services: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    discovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    # Relationships
    operation: Mapped[OperationRecord] = relationship(back_populates="hosts")

    __table_args__ = (
        UniqueConstraint("operation_id", "ip", name="uq_host"),
        Index("idx_hosts_operation", "operation_id"),
        Index("idx_hosts_dc", "is_dc"),
    )


class UserRecord(Base):
    """Record of a discovered user account."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    operation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operations.id", ondelete="CASCADE"), nullable=False
    )
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    domain: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str | None] = mapped_column(String(255))
    discovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    # Relationships
    operation: Mapped[OperationRecord] = relationship(back_populates="users")

    __table_args__ = (
        UniqueConstraint("operation_id", "domain", "username", name="uq_user"),
        Index("idx_users_operation", "operation_id"),
    )


class VulnerabilityRecord(Base):
    """Record of a discovered vulnerability."""

    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    operation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operations.id", ondelete="CASCADE"), nullable=False
    )
    vuln_id: Mapped[str] = mapped_column(String(255), nullable=False)
    vuln_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    target_ip: Mapped[str | None] = mapped_column(INET)
    target_hostname: Mapped[str | None] = mapped_column(String(255))
    priority: Mapped[int | None] = mapped_column(Integer)
    discovered_by: Mapped[str | None] = mapped_column(String(100))
    discovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exploited_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exploitation_result: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    # Relationships
    operation: Mapped[OperationRecord] = relationship(back_populates="vulnerabilities")

    __table_args__ = (
        UniqueConstraint("operation_id", "vuln_id", name="uq_vuln"),
        Index("idx_vulns_operation", "operation_id"),
        Index("idx_vulns_type", "vuln_type"),
    )


class TimelineEventRecord(Base):
    """Record of a timeline event during operation."""

    __tablename__ = "timeline_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    operation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operations.id", ondelete="CASCADE"), nullable=False
    )
    event_id: Mapped[str | None] = mapped_column(String(255))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    mitre_techniques: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    confidence: Mapped[float | None] = mapped_column(Float)
    source: Mapped[str | None] = mapped_column(String(255))
    evidence_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    # Relationships
    operation: Mapped[OperationRecord] = relationship(back_populates="timeline_events")

    __table_args__ = (
        Index("idx_timeline_operation_time", "operation_id", "timestamp"),
        Index("idx_timeline_techniques", "mitre_techniques", postgresql_using="gin"),
    )


class ArtifactRecord(Base):
    """Record of an artifact (file) discovered during operation."""

    __tablename__ = "artifacts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    operation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operations.id", ondelete="CASCADE"), nullable=False
    )
    artifact_key: Mapped[str] = mapped_column(String(500), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(100))
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    content_hash: Mapped[str | None] = mapped_column(String(64))
    # For small artifacts, store inline; for large, use external storage path
    content_base64: Mapped[str | None] = mapped_column(Text)
    storage_path: Mapped[str | None] = mapped_column(Text)
    discovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    # Relationships
    operation: Mapped[OperationRecord] = relationship(back_populates="artifacts")

    __table_args__ = (
        UniqueConstraint("operation_id", "artifact_key", name="uq_artifact"),
        Index("idx_artifacts_operation", "operation_id"),
    )


class InvestigationRecord(Base):
    """Record of an investigation linking multiple operations."""

    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    operation_ids: Mapped[list[uuid.UUID] | None] = mapped_column(ARRAY(UUID(as_uuid=True)))
    status: Mapped[str] = mapped_column(String(50), default="active", index=True)
    findings: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )
    created_by: Mapped[str | None] = mapped_column(String(255))

    __table_args__ = (Index("idx_investigations_status", "status"),)


__all__ = [
    "ArtifactRecord",
    "Base",
    "CredentialRecord",
    "HashRecord",
    "HostRecord",
    "InvestigationRecord",
    "OperationRecord",
    "TimelineEventRecord",
    "UserRecord",
    "VulnerabilityRecord",
]
