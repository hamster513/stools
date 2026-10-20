"""Assets: пользователи как активы — учётки, наблюдения AD/KSC, связи с хостами, группы AD

Revision ID: 2bd3112bc826
Revises: c4e8a2d6f1b3
Create Date: 2026-10-20 14:00:00.000000

Отдельные таблицы `asset_user*`: таблица `asset` не меняется, откат удаляет
только эти четыре таблицы.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "2bd3112bc826"
down_revision: str | Sequence[str] | None = "c4e8a2d6f1b3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "asset_user",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("sid", sa.String(255), nullable=False),
        sa.Column("name_key", sa.String(512), nullable=False),
        sa.Column("sam", sa.String(255), nullable=False),
        sa.Column("upn", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("local", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("privileged", sa.Boolean(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("merged_into", sa.Integer(), sa.ForeignKey("asset_user.id", ondelete="SET NULL"), nullable=True),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("tags", JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    for column in ("sid", "name_key"):
        op.create_index(f"ix_asset_user_{column}", "asset_user", [column])

    op.create_table(
        "asset_user_observation",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("asset_user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("source_key", sa.String(512), nullable=False),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("gone_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("data", JSON, nullable=False),
        sa.UniqueConstraint("source", "source_key", name="uq_asset_user_observation_source_key"),
    )
    op.create_index("ix_asset_user_observation_user_id", "asset_user_observation", ["user_id"])

    op.create_table(
        "asset_user_host",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("asset_user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("gone_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("user_id", "asset_id", "source", "kind", name="uq_asset_user_host_link"),
    )
    op.create_index("ix_asset_user_host_asset_id", "asset_user_host", ["asset_id"])

    op.create_table(
        "asset_user_group",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("asset_user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("group_sid", sa.String(255), nullable=False),
        sa.Column("group_name", sa.String(512), nullable=False),
        sa.Column("direct", sa.Boolean(), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.UniqueConstraint("user_id", "group_sid", name="uq_asset_user_group_sid"),
    )


def downgrade() -> None:
    op.drop_table("asset_user_group")
    op.drop_index("ix_asset_user_host_asset_id", table_name="asset_user_host")
    op.drop_table("asset_user_host")
    op.drop_index("ix_asset_user_observation_user_id", table_name="asset_user_observation")
    op.drop_table("asset_user_observation")
    for column in ("sid", "name_key"):
        op.drop_index(f"ix_asset_user_{column}", table_name="asset_user")
    op.drop_table("asset_user")
