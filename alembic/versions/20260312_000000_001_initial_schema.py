"""Initial schema for persistent data store.

Revision ID: 001
Revises:
Create Date: 2026-03-12 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create initial tables for persistent data store."""
    # Operations table
    op.create_table(
        "operations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("operation_id", sa.String(255), unique=True, nullable=False),
        sa.Column("target_ip", postgresql.INET),
        sa.Column("target_domain", sa.String(255)),
        sa.Column("environment", sa.String(50)),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("has_domain_admin", sa.Boolean, default=False),
        sa.Column("has_golden_ticket", sa.Boolean, default=False),
        sa.Column("domain_admin_path", sa.Text),
        sa.Column("da_hash_id", sa.String(255)),
        sa.Column("final_report", sa.Text),
        sa.Column("config", postgresql.JSONB),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("credential_count", sa.Integer),
        sa.Column("hash_count", sa.Integer),
        sa.Column("host_count", sa.Integer),
        sa.Column("vulnerability_count", sa.Integer),
        sa.Column("exploited_vulnerability_count", sa.Integer),
    )
    op.create_index("idx_operations_operation_id", "operations", ["operation_id"])
    op.create_index("idx_operations_target_domain", "operations", ["target_domain"])
    op.create_index("idx_operations_started_at", "operations", ["started_at"])
    op.create_index("idx_operations_has_da", "operations", ["has_domain_admin"])

    # Credentials table
    op.create_table(
        "credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "operation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("operations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("credential_id", sa.String(255)),
        sa.Column("username", sa.String(255), nullable=False),
        sa.Column("domain", sa.String(255)),
        sa.Column("password_hash", sa.String(64)),
        sa.Column("password_encrypted", sa.Text),
        sa.Column("is_admin", sa.Boolean, default=False),
        sa.Column("source", sa.String(255)),
        sa.Column(
            "parent_credential_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("credentials.id", ondelete="SET NULL"),
        ),
        sa.Column("attack_step", sa.Integer, default=0),
        sa.Column("discovered_at", sa.DateTime(timezone=True)),
        sa.Column("extra_data", postgresql.JSONB),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_unique_constraint(
        "uq_cred", "credentials", ["operation_id", "domain", "username", "password_hash"]
    )
    op.create_index("idx_credentials_operation", "credentials", ["operation_id"])
    op.create_index("idx_credentials_domain_user", "credentials", ["domain", "username"])

    # Hashes table
    op.create_table(
        "hashes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "operation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("operations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("hash_id", sa.String(255)),
        sa.Column("username", sa.String(255), nullable=False),
        sa.Column("domain", sa.String(255)),
        sa.Column("hash_type", sa.String(50)),
        sa.Column("hash_value_prefix", sa.String(64)),
        sa.Column("hash_value_encrypted", sa.Text),
        sa.Column("cracked_password_hash", sa.String(64)),
        sa.Column("source", sa.String(255)),
        sa.Column(
            "parent_hash_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("hashes.id", ondelete="SET NULL"),
        ),
        sa.Column("attack_step", sa.Integer, default=0),
        sa.Column("discovered_at", sa.DateTime(timezone=True)),
        sa.Column("extra_data", postgresql.JSONB),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_unique_constraint(
        "uq_hash",
        "hashes",
        ["operation_id", "domain", "username", "hash_type", "hash_value_prefix"],
    )
    op.create_index("idx_hashes_operation", "hashes", ["operation_id"])
    op.create_index("idx_hashes_type", "hashes", ["hash_type"])

    # Hosts table
    op.create_table(
        "hosts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "operation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("operations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ip", postgresql.INET, nullable=False),
        sa.Column("hostname", sa.String(255)),
        sa.Column("fqdn", sa.String(255)),
        sa.Column("os", sa.String(255)),
        sa.Column("is_dc", sa.Boolean, default=False),
        sa.Column("is_owned", sa.Boolean, default=False),
        sa.Column("roles", postgresql.ARRAY(sa.String)),
        sa.Column("services", postgresql.ARRAY(sa.String)),
        sa.Column("discovered_at", sa.DateTime(timezone=True)),
        sa.Column("extra_data", postgresql.JSONB),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_unique_constraint("uq_host", "hosts", ["operation_id", "ip"])
    op.create_index("idx_hosts_operation", "hosts", ["operation_id"])
    op.create_index("idx_hosts_dc", "hosts", ["is_dc"])

    # Users table
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "operation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("operations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("username", sa.String(255), nullable=False),
        sa.Column("domain", sa.String(255)),
        sa.Column("description", sa.Text),
        sa.Column("is_admin", sa.Boolean, default=False),
        sa.Column("source", sa.String(255)),
        sa.Column("discovered_at", sa.DateTime(timezone=True)),
        sa.Column("extra_data", postgresql.JSONB),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_unique_constraint("uq_user", "users", ["operation_id", "domain", "username"])
    op.create_index("idx_users_operation", "users", ["operation_id"])

    # Vulnerabilities table
    op.create_table(
        "vulnerabilities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "operation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("operations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("vuln_id", sa.String(255), nullable=False),
        sa.Column("vuln_type", sa.String(100), nullable=False),
        sa.Column("target_ip", postgresql.INET),
        sa.Column("target_hostname", sa.String(255)),
        sa.Column("priority", sa.Integer),
        sa.Column("discovered_by", sa.String(100)),
        sa.Column("discovered_at", sa.DateTime(timezone=True)),
        sa.Column("exploited_at", sa.DateTime(timezone=True)),
        sa.Column("exploitation_result", sa.Text),
        sa.Column("details", postgresql.JSONB),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_unique_constraint("uq_vuln", "vulnerabilities", ["operation_id", "vuln_id"])
    op.create_index("idx_vulns_operation", "vulnerabilities", ["operation_id"])
    op.create_index("idx_vulns_type", "vulnerabilities", ["vuln_type"])

    # Timeline events table
    op.create_table(
        "timeline_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "operation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("operations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_id", sa.String(255)),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("mitre_techniques", postgresql.ARRAY(sa.String)),
        sa.Column("confidence", sa.Float),
        sa.Column("source", sa.String(255)),
        sa.Column("evidence_ids", postgresql.ARRAY(sa.String)),
        sa.Column("extra_data", postgresql.JSONB),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("idx_timeline_operation_time", "timeline_events", ["operation_id", "timestamp"])
    op.create_index(
        "idx_timeline_techniques",
        "timeline_events",
        ["mitre_techniques"],
        postgresql_using="gin",
    )

    # Artifacts table
    op.create_table(
        "artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "operation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("operations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("artifact_key", sa.String(500), nullable=False),
        sa.Column("content_type", sa.String(100)),
        sa.Column("size_bytes", sa.Integer),
        sa.Column("content_hash", sa.String(64)),
        sa.Column("content_base64", sa.Text),
        sa.Column("storage_path", sa.Text),
        sa.Column("discovered_at", sa.DateTime(timezone=True)),
        sa.Column("extra_data", postgresql.JSONB),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_unique_constraint("uq_artifact", "artifacts", ["operation_id", "artifact_key"])
    op.create_index("idx_artifacts_operation", "artifacts", ["operation_id"])

    # Investigations table
    op.create_table(
        "investigations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("operation_ids", postgresql.ARRAY(postgresql.UUID(as_uuid=True))),
        sa.Column("status", sa.String(50), default="active"),
        sa.Column("findings", postgresql.JSONB),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("created_by", sa.String(255)),
    )
    op.create_index("idx_investigations_status", "investigations", ["status"])


def downgrade() -> None:
    """Drop all tables."""
    op.drop_table("investigations")
    op.drop_table("artifacts")
    op.drop_table("timeline_events")
    op.drop_table("vulnerabilities")
    op.drop_table("users")
    op.drop_table("hosts")
    op.drop_table("hashes")
    op.drop_table("credentials")
    op.drop_table("operations")
