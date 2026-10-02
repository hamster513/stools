"""статусы находок: состояние, история, настройки платформы

Revision ID: a4b5c6d7e8f9
Revises: f3a4b5c6d7e8
Create Date: 2026-10-02 00:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "a4b5c6d7e8f9"
down_revision: str | Sequence[str] | None = "f3a4b5c6d7e8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "platform_finding_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("module", sa.String(16), nullable=False),
        sa.Column("scope_id", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("assignee", sa.String(255), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("risk_until", sa.Date(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("present", sa.Boolean(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("updated_by", sa.String(255), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("module", "scope_id", "key", name="uq_platform_finding_state_key"),
    )
    op.create_index("ix_platform_finding_state_status", "platform_finding_state", ["module", "scope_id", "status"])
    op.create_index("ix_platform_finding_state_assignee", "platform_finding_state", ["assignee"])
    op.create_index("ix_platform_finding_state_due_date", "platform_finding_state", ["due_date"])
    op.create_index("ix_platform_finding_state_risk_until", "platform_finding_state", ["risk_until"])

    op.create_table(
        "platform_finding_event",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "state_id", sa.Integer(), sa.ForeignKey("platform_finding_state.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("from_status", sa.String(16), nullable=True),
        sa.Column("to_status", sa.String(16), nullable=True),
        sa.Column("comment", sa.Text(), nullable=False),
        sa.Column("details", JSON, nullable=False),
    )
    op.create_index("ix_platform_finding_event_state_id", "platform_finding_event", ["state_id"])
    op.create_index("ix_platform_finding_event_at", "platform_finding_event", ["at"])

    op.create_table(
        "platform_finding_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("data", JSON, nullable=False),
        sa.Column("updated_by", sa.String(255), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("platform_finding_settings")
    op.drop_table("platform_finding_event")
    op.drop_table("platform_finding_state")
