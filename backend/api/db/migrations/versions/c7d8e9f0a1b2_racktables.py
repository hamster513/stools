"""RackTables как источник Assets: подключения к JSON API, происхождение сети

Revision ID: c7d8e9f0a1b2
Revises: 3d4e5f6a7b8c
Create Date: 2026-10-13 00:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c7d8e9f0a1b2"
down_revision: str | Sequence[str] | None = "3d4e5f6a7b8c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "asset_racktables",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("title", sa.String(255), nullable=False, server_default=""),
        sa.Column("url", sa.String(512), nullable=False),
        sa.Column("username", sa.String(255), nullable=False, server_default=""),
        sa.Column("password", sa.Text(), nullable=False, server_default=""),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("rate_per_s", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("timeout_ms", sa.Integer(), nullable=False, server_default="30000"),
        sa.Column("schedule_id", sa.Integer(), sa.ForeignKey("platform_schedule.id", ondelete="SET NULL"), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column("network", sa.Column("origin", sa.String(32), nullable=False, server_default=""))
    op.add_column("network", sa.Column("origin_key", sa.String(64), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("network", "origin_key")
    op.drop_column("network", "origin")
    op.drop_table("asset_racktables")
