"""роли, блокировка, активность сессий, журнал аудита

Revision ID: a1b2c3d4e5f6
Revises: d0f0317c82b8
Create Date: 2026-09-13 00:00:00.000000

"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: str | Sequence[str] | None = "d0f0317c82b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Все существующие пользователи становятся администраторами: до
    ролей любой вошедший мог всё, и после обновления кто-то должен
    иметь право раздать роли остальным."""
    with op.batch_alter_table("app_user") as batch:
        batch.add_column(sa.Column("role", sa.String(16), nullable=False, server_default="admin"))
        batch.add_column(sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()))
        batch.add_column(sa.Column("display_name", sa.String(255), nullable=True))
        batch.add_column(sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))
    with op.batch_alter_table("session") as batch:
        batch.add_column(
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now())
        )
    op.create_table(
        "audit_event",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("app_user.id", ondelete="SET NULL"), nullable=True),
        sa.Column("login", sa.String(255), nullable=False),
        sa.Column("role", sa.String(16), nullable=True),
        sa.Column("method", sa.String(8), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("status", sa.Integer(), nullable=False),
        sa.Column("ip", sa.String(64), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
    )
    op.create_index("ix_audit_event_at", "audit_event", ["at"])
    op.create_index("ix_audit_event_user_id", "audit_event", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_event_user_id", table_name="audit_event")
    op.drop_index("ix_audit_event_at", table_name="audit_event")
    op.drop_table("audit_event")
    with op.batch_alter_table("session") as batch:
        batch.drop_column("last_seen_at")
    with op.batch_alter_table("app_user") as batch:
        batch.drop_column("last_login_at")
        batch.drop_column("display_name")
        batch.drop_column("is_active")
        batch.drop_column("role")
