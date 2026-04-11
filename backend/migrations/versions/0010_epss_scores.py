"""Add EPSS score and percentile columns to findings.

Revision: 0010
Created: 2026-04-11
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def _column_names(table: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {col["name"] for col in inspector.get_columns(table)}


def upgrade() -> None:
    cols = _column_names("findings")
    with op.batch_alter_table("findings") as batch_op:
        if "epss_score" not in cols:
            batch_op.add_column(sa.Column("epss_score", sa.Float(), nullable=True))
        if "epss_percentile" not in cols:
            batch_op.add_column(sa.Column("epss_percentile", sa.Float(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("epss_percentile")
        batch_op.drop_column("epss_score")
