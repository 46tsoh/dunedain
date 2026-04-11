"""Add auto-ticketing columns to teams table.

Revision ID: 0006
Revises: 0005
Create Date: 2026-04-05
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _column_exists(table: str, column: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = [c["name"] for c in inspector.get_columns(table)]
    return column in columns


def upgrade() -> None:
    if not _column_exists("teams", "integration_id"):
        op.add_column("teams", sa.Column("integration_id", sa.String(), nullable=True))
        op.create_foreign_key(
            "fk_teams_integration_id", "teams", "integrations",
            ["integration_id"], ["id"], ondelete="SET NULL",
        )
    if not _column_exists("teams", "auto_create_tickets"):
        op.add_column(
            "teams",
            sa.Column("auto_create_tickets", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        )
    if not _column_exists("teams", "ticket_severity_threshold"):
        op.add_column(
            "teams",
            sa.Column("ticket_severity_threshold", sa.String(), nullable=False, server_default="HIGH"),
        )


def downgrade() -> None:
    if _column_exists("teams", "ticket_severity_threshold"):
        op.drop_column("teams", "ticket_severity_threshold")
    if _column_exists("teams", "auto_create_tickets"):
        op.drop_column("teams", "auto_create_tickets")
    if _column_exists("teams", "integration_id"):
        op.drop_constraint("fk_teams_integration_id", "teams", type_="foreignkey")
        op.drop_column("teams", "integration_id")
