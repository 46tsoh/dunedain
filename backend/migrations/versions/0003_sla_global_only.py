"""Remove per-team SLA columns — SLA is now global-only.

Revision ID: 0003
Revises: 0002
Create Date: 2026-03-12

Drops the four ``sla_*_hours`` columns from the ``teams`` table.  SLA
deadlines are now configured exclusively via the global ``app_settings``
table (keys ``sla_critical_hours``, ``sla_high_hours``, etc.).

Each operation is guarded by an existence check so the migration is
idempotent — safe to run against both fresh databases (where create_all
never added these columns) and older databases.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _column_names(table: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {col["name"] for col in inspector.get_columns(table)}


def upgrade() -> None:
    cols = _column_names("teams")
    drop_cols = [
        "sla_critical_hours",
        "sla_high_hours",
        "sla_medium_hours",
        "sla_low_hours",
    ]
    to_drop = [c for c in drop_cols if c in cols]
    if to_drop:
        with op.batch_alter_table("teams") as batch_op:
            for col in to_drop:
                batch_op.drop_column(col)


def downgrade() -> None:
    raise NotImplementedError(
        "Downgrade not supported for this migration. "
        "Restore the database from a backup to revert schema changes."
    )
