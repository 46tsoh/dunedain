"""Add webhook events, automation rules, and supporting tables.

Revision ID: 0007
Revises: 0006
Create Date: 2026-04-10
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _column_exists(table: str, column: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = [c["name"] for c in inspector.get_columns(table)]
    return column in columns


def _table_exists(table: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return table in inspector.get_table_names()


def upgrade() -> None:
    if not _column_exists("integrations", "webhook_secret"):
        op.add_column("integrations", sa.Column("webhook_secret", sa.String(), nullable=True))

    if not _column_exists("findings", "risk_accepted"):
        op.add_column(
            "findings",
            sa.Column("risk_accepted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        )

    if not _column_exists("findings", "risk_accepted_at"):
        op.add_column("findings", sa.Column("risk_accepted_at", sa.DateTime(), nullable=True))

    if not _column_exists("tickets", "external_assignee"):
        op.add_column("tickets", sa.Column("external_assignee", sa.String(), nullable=True))

    if not _column_exists("tickets", "external_priority"):
        op.add_column("tickets", sa.Column("external_priority", sa.String(), nullable=True))

    if not _table_exists("webhook_events"):
        op.create_table(
            "webhook_events",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("integration_id", sa.String(), nullable=False),
            sa.Column("event_type", sa.String(), nullable=False),
            sa.Column("external_issue_id", sa.String(), nullable=True),
            sa.Column("external_issue_key", sa.String(), nullable=True),
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.Column("status", sa.String(), nullable=False, server_default="received"),
            sa.Column("error_message", sa.String(), nullable=True),
            sa.Column("received_at", sa.DateTime(), nullable=False, server_default=sa.text("(CURRENT_TIMESTAMP)")),
            sa.Column("processed_at", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(["integration_id"], ["integrations.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    if not _table_exists("webhook_registrations"):
        op.create_table(
            "webhook_registrations",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("integration_id", sa.String(), nullable=False),
            sa.Column("external_webhook_id", sa.String(), nullable=True),
            sa.Column("callback_url", sa.String(), nullable=False),
            sa.Column("jira_events", sa.JSON(), nullable=True, server_default="[]"),
            sa.Column("secret", sa.String(), nullable=True),
            sa.Column("is_cloud", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("(CURRENT_TIMESTAMP)")),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("(CURRENT_TIMESTAMP)")),
            sa.ForeignKeyConstraint(["integration_id"], ["integrations.id"]),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("integration_id"),
        )

    if not _table_exists("ticket_comments"):
        op.create_table(
            "ticket_comments",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("ticket_id", sa.String(), nullable=False),
            sa.Column("external_comment_id", sa.String(), nullable=True),
            sa.Column("author", sa.String(), nullable=True),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("direction", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("(CURRENT_TIMESTAMP)")),
            sa.ForeignKeyConstraint(["ticket_id"], ["tickets.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    if not _table_exists("automation_rules"):
        op.create_table(
            "automation_rules",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column("description", sa.String(), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("trigger", sa.String(), nullable=False),
            sa.Column("conditions", sa.JSON(), nullable=True, server_default="[]"),
            sa.Column("actions", sa.JSON(), nullable=True, server_default="[]"),
            sa.Column("integration_id", sa.String(), nullable=True),
            sa.Column("team_id", sa.String(), nullable=True),
            sa.Column("execution_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("last_executed_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("(CURRENT_TIMESTAMP)")),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("(CURRENT_TIMESTAMP)")),
            sa.ForeignKeyConstraint(["integration_id"], ["integrations.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )

    if not _table_exists("automation_rule_executions"):
        op.create_table(
            "automation_rule_executions",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("rule_id", sa.String(), nullable=False),
            sa.Column("trigger_event", sa.String(), nullable=False),
            sa.Column("trigger_context", sa.JSON(), nullable=True, server_default="{}"),
            sa.Column("conditions_matched", sa.Boolean(), nullable=False),
            sa.Column("actions_executed", sa.JSON(), nullable=True, server_default="[]"),
            sa.Column("status", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("(CURRENT_TIMESTAMP)")),
            sa.ForeignKeyConstraint(["rule_id"], ["automation_rules.id"]),
            sa.PrimaryKeyConstraint("id"),
        )


def downgrade() -> None:
    if _table_exists("automation_rule_executions"):
        op.drop_table("automation_rule_executions")
    if _table_exists("automation_rules"):
        op.drop_table("automation_rules")
    if _table_exists("ticket_comments"):
        op.drop_table("ticket_comments")
    if _table_exists("webhook_registrations"):
        op.drop_table("webhook_registrations")
    if _table_exists("webhook_events"):
        op.drop_table("webhook_events")

    if _column_exists("tickets", "external_priority"):
        op.drop_column("tickets", "external_priority")
    if _column_exists("tickets", "external_assignee"):
        op.drop_column("tickets", "external_assignee")
    if _column_exists("findings", "risk_accepted_at"):
        op.drop_column("findings", "risk_accepted_at")
    if _column_exists("findings", "risk_accepted"):
        op.drop_column("findings", "risk_accepted")
    if _column_exists("integrations", "webhook_secret"):
        op.drop_column("integrations", "webhook_secret")
