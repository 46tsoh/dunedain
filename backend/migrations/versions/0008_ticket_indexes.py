"""Add indexes to tickets.external_id and tickets.external_key for webhook lookup performance.

Revision ID: 0008
Revises: 0007
Create Date: 2026-04-10
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _index_exists(index_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    indexes = inspector.get_indexes("tickets")
    return any(idx["name"] == index_name for idx in indexes)


def upgrade() -> None:
    if not _index_exists("ix_tickets_external_id"):
        with op.batch_alter_table("tickets") as batch_op:
            batch_op.create_index("ix_tickets_external_id", ["external_id"])

    if not _index_exists("ix_tickets_external_key"):
        with op.batch_alter_table("tickets") as batch_op:
            batch_op.create_index("ix_tickets_external_key", ["external_key"])


def downgrade() -> None:
    if _index_exists("ix_tickets_external_id"):
        with op.batch_alter_table("tickets") as batch_op:
            batch_op.drop_index("ix_tickets_external_id")
    if _index_exists("ix_tickets_external_key"):
        with op.batch_alter_table("tickets") as batch_op:
            batch_op.drop_index("ix_tickets_external_key")
