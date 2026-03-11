"""Add columns introduced after initial schema creation.

Revision ID: 0001
Revises:
Create Date: 2026-03-09

Replaces the manual _apply_migrations() SQL in main.py.
Each operation is guarded by an existence check so the migration is
idempotent — safe to run against both fresh databases (where
create_all already added the columns) and older databases (where the
columns are genuinely missing).
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _column_names(table: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {col["name"] for col in inspector.get_columns(table)}


def upgrade() -> None:
    scans_cols = _column_names("scans")
    registries_cols = _column_names("registries")

    # scans: registry_id (FK to registries)
    if "registry_id" not in scans_cols:
        op.add_column("scans", sa.Column("registry_id", sa.String(), nullable=True))

    # registries: username / password
    if "username" not in registries_cols:
        op.add_column("registries", sa.Column("username", sa.String(), nullable=True))
    if "password" not in registries_cols:
        op.add_column("registries", sa.Column("password", sa.String(), nullable=True))

    # scans: drop legacy cached column (SQLite batch required for DROP)
    if "cached" in scans_cols:
        with op.batch_alter_table("scans") as batch_op:
            batch_op.drop_column("cached")

    # scans: scanner_override
    if "scanner_override" not in scans_cols:
        op.add_column("scans", sa.Column("scanner_override", sa.String(), nullable=True))

    # registries: auto_sync
    if "auto_sync" not in registries_cols:
        op.add_column(
            "registries",
            sa.Column("auto_sync", sa.Boolean(), nullable=False, server_default=sa.true()),
        )

    # scans: error_message
    if "error_message" not in scans_cols:
        op.add_column("scans", sa.Column("error_message", sa.String(), nullable=True))


def downgrade() -> None:
    raise NotImplementedError(
        "Downgrade not supported for this migration. "
        "Restore the database from a backup to revert schema changes."
    )
