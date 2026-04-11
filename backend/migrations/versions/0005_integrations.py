"""Add integrations, integration_field_mappings, and tickets tables.

Revision ID: 0005
Revises: 0004
Create Date: 2026-04-05
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_exists(table: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return table in inspector.get_table_names()


def upgrade() -> None:
    if not _table_exists("integrations"):
        op.create_table(
            "integrations",
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column(
                "provider",
                sa.Enum(
                    "jira", "servicenow", "linear", "github_issues",
                    name="integration_provider_enum",
                    create_type=False,
                    create_constraint=False,
                ),
                nullable=False,
            ),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
            sa.Column("base_url", sa.String(), nullable=False),
            sa.Column(
                "auth_method",
                sa.Enum(
                    "basic", "api_token", "oauth2", "pat",
                    name="integration_auth_enum",
                    create_type=False,
                    create_constraint=False,
                ),
                nullable=False,
                server_default="api_token",
            ),
            sa.Column("auth_username", sa.String(), nullable=True),
            sa.Column("auth_secret", sa.String(), nullable=True),
            sa.Column("provider_config", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )

    if not _table_exists("integration_field_mappings"):
        op.create_table(
            "integration_field_mappings",
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column("integration_id", sa.String(), sa.ForeignKey("integrations.id"), nullable=False),
            sa.Column("source", sa.String(), nullable=False),
            sa.Column("target_field", sa.String(), nullable=False),
            sa.Column("transform", sa.String(), nullable=True),
            sa.Column("template_value", sa.String(), nullable=True),
            sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
        )

    if not _table_exists("tickets"):
        op.create_table(
            "tickets",
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column("integration_id", sa.String(), sa.ForeignKey("integrations.id"), nullable=False),
            sa.Column("finding_id", sa.String(), sa.ForeignKey("findings.id", ondelete="SET NULL"), nullable=True),
            sa.Column("external_id", sa.String(), nullable=False),
            sa.Column("external_key", sa.String(), nullable=False),
            sa.Column("external_url", sa.String(), nullable=False),
            sa.Column("external_status", sa.String(), nullable=True),
            sa.Column("summary", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("synced_at", sa.DateTime(), nullable=True),
            sa.UniqueConstraint("integration_id", "finding_id", name="uq_integration_finding"),
        )


def downgrade() -> None:
    if _table_exists("tickets"):
        op.drop_table("tickets")
    if _table_exists("integration_field_mappings"):
        op.drop_table("integration_field_mappings")
    if _table_exists("integrations"):
        op.drop_table("integrations")
