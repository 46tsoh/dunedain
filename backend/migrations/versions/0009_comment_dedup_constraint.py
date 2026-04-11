"""Add unique constraint on ticket_comments(ticket_id, external_comment_id) for deduplication.

Revision ID: 0009
Revises: 0008
Create Date: 2026-04-10
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _constraint_exists(table: str, constraint_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    constraints = inspector.get_unique_constraints(table)
    return any(c["name"] == constraint_name for c in constraints)


def upgrade() -> None:
    # Remove duplicate (ticket_id, external_comment_id) rows before adding constraint.
    # Keeps the row with the smallest rowid / id for each duplicate group.
    bind = op.get_bind()
    bind.execute(sa.text("""
        DELETE FROM ticket_comments
        WHERE id NOT IN (
            SELECT MIN(id)
            FROM ticket_comments
            WHERE external_comment_id IS NOT NULL
            GROUP BY ticket_id, external_comment_id
        )
        AND external_comment_id IS NOT NULL
    """))

    if not _constraint_exists("ticket_comments", "uq_ticket_comment_external"):
        with op.batch_alter_table("ticket_comments") as batch_op:
            batch_op.create_unique_constraint(
                "uq_ticket_comment_external",
                ["ticket_id", "external_comment_id"],
            )


def downgrade() -> None:
    if _constraint_exists("ticket_comments", "uq_ticket_comment_external"):
        with op.batch_alter_table("ticket_comments") as batch_op:
            batch_op.drop_constraint("uq_ticket_comment_external", type_="unique")
