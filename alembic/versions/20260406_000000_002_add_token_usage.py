"""Add token usage and cost columns to operations table.

Revision ID: 002
Revises: 001
Create Date: 2026-04-06 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: str = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add token usage tracking columns to operations table."""
    op.add_column("operations", sa.Column("total_input_tokens", sa.BigInteger, default=0))
    op.add_column("operations", sa.Column("total_output_tokens", sa.BigInteger, default=0))
    op.add_column("operations", sa.Column("total_cost", sa.Float))
    # Per-model breakdown stored as JSONB:
    # {"openai/gpt-4.1-mini": {"input_tokens": 1000, "output_tokens": 500, "cost": 0.12}, ...}
    op.add_column("operations", sa.Column("model_usage", postgresql.JSONB))


def downgrade() -> None:
    """Remove token usage columns."""
    op.drop_column("operations", "model_usage")
    op.drop_column("operations", "total_cost")
    op.drop_column("operations", "total_output_tokens")
    op.drop_column("operations", "total_input_tokens")
