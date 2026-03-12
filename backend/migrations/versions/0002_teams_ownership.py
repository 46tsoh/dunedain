"""Add teams, ownership_rules tables and scans.team_id column.

Revision ID: 0002
Revises: 0001
Create Date: 2026-03-12

Introduces team ownership for scans:
- ``teams`` table with SLA configuration per severity
- ``ownership_rules`` table with glob-pattern matching for auto-assignment
- ``scans.team_id`` FK linking scans to their owning team

Each operation is guarded by an existence check so the migration is
idempotent — safe to run against both fresh databases (where create_all
already added the tables/columns) and older databases.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_exists(name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return name in inspector.get_table_names()


def _column_names(table: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {col["name"] for col in inspector.get_columns(table)}


def upgrade() -> None:
    # --- teams table ---
    if not _table_exists("teams"):
        op.create_table(
            "teams",
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column("name", sa.String(), nullable=False, unique=True),
            sa.Column("description", sa.String(), nullable=True),
            sa.Column("contact_email", sa.String(), nullable=True),
            sa.Column("sla_critical_hours", sa.Integer(), nullable=True),
            sa.Column("sla_high_hours", sa.Integer(), nullable=True),
            sa.Column("sla_medium_hours", sa.Integer(), nullable=True),
            sa.Column("sla_low_hours", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )

    # --- ownership_rules table ---
    if not _table_exists("ownership_rules"):
        op.create_table(
            "ownership_rules",
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column("team_id", sa.String(), sa.ForeignKey("teams.id"), nullable=False),
            sa.Column("pattern", sa.String(), nullable=False),
            sa.Column("scan_type", sa.String(), nullable=True),
            sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("description", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )

    # --- scans.team_id ---
    scans_cols = _column_names("scans")
    if "team_id" not in scans_cols:
        op.add_column("scans", sa.Column("team_id", sa.String(), nullable=True))


def downgrade() -> None:
    raise NotImplementedError(
        "Downgrade not supported for this migration. "
        "Restore the database from a backup to revert schema changes."
    )
