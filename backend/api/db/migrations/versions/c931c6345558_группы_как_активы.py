"""Assets: группы как активы — доменные и локальные группы, их прямой состав, права по политике GPO

Revision ID: c931c6345558
Revises: d7a1c3e5b9f2
Create Date: 2026-10-23 12:00:00.000000

Отдельные таблицы `asset_group*`: таблицы `asset` и `asset_user*` не меняются, откат удаляет
только эти три таблицы.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "c931c6345558"
down_revision: str | Sequence[str] | None = "d7a1c3e5b9f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "asset_group",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("group_key", sa.String(800), nullable=False),
        sa.Column("sid", sa.String(255), nullable=False),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("local", sa.Boolean(), nullable=False),
        sa.Column("os_family", sa.String(8), nullable=False),
        sa.Column("host_asset_id", sa.Integer(), sa.ForeignKey("asset.id", ondelete="CASCADE"), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("sources", JSON, nullable=False),
        sa.Column("in_ad", sa.Boolean(), nullable=False),
        sa.Column("members_direct", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("gone_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("group_key", name="uq_asset_group_group_key"),
    )
    for column in ("sid", "host_asset_id"):
        op.create_index(f"ix_asset_group_{column}", "asset_group", [column])
    # Страница списка — по `lower(name)`.
    op.create_index("ix_asset_group_name_lower", "asset_group", [sa.text("lower(name)")])

    op.create_table(
        "asset_group_member",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("group_id", sa.Integer(), sa.ForeignKey("asset_group.id", ondelete="CASCADE"), nullable=False),
        sa.Column("member_kind", sa.String(16), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("asset_user.id", ondelete="SET NULL"), nullable=True),
        sa.Column("member_group_id", sa.Integer(), sa.ForeignKey("asset_group.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset.id", ondelete="SET NULL"), nullable=True),
        sa.Column("member_sid", sa.String(255), nullable=False),
        sa.Column("member_name", sa.String(512), nullable=False),
        sa.Column("member_domain", sa.String(255), nullable=False),
        sa.Column("primary", sa.Boolean(), nullable=False),
        sa.Column("source", sa.String(8), nullable=False),
        sa.UniqueConstraint("group_id", "source", "member_sid", "member_name", name="uq_asset_group_member"),
    )
    # По `group_id` — уникальный индекс (он ведущий); `user_id` и `asset_id` — для `SET NULL` при удалении.
    for column in ("member_group_id", "user_id", "asset_id"):
        op.create_index(f"ix_asset_group_member_{column}", "asset_group_member", [column])

    op.create_table(
        "asset_group_gpo",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("group_sid", sa.String(255), nullable=False),
        sa.Column("group_name", sa.String(512), nullable=False),
        sa.Column("local_group", sa.String(255), nullable=False),
        sa.Column("local_group_sid", sa.String(255), nullable=False),
        sa.Column("via", sa.String(32), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("gpo_name", sa.String(512), nullable=False),
        sa.Column("gpo_dn", sa.String(1024), nullable=False),
        sa.Column("filtered", sa.Boolean(), nullable=True),
        sa.Column("hosts", JSON, nullable=False),
        sa.Column("hosts_total", sa.Integer(), nullable=False),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
    )
    for column in ("domain", "group_sid"):
        op.create_index(f"ix_asset_group_gpo_{column}", "asset_group_gpo", [column])


def downgrade() -> None:
    for column in ("domain", "group_sid"):
        op.drop_index(f"ix_asset_group_gpo_{column}", table_name="asset_group_gpo")
    op.drop_table("asset_group_gpo")
    for column in ("member_group_id", "user_id", "asset_id"):
        op.drop_index(f"ix_asset_group_member_{column}", table_name="asset_group_member")
    op.drop_table("asset_group_member")
    op.drop_index("ix_asset_group_name_lower", table_name="asset_group")
    for column in ("sid", "host_asset_id"):
        op.drop_index(f"ix_asset_group_{column}", table_name="asset_group")
    op.drop_table("asset_group")
