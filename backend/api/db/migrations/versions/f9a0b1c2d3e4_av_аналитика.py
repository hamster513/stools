"""аналитика АВ: политики снапшота, их привязка к группам, профили, исключения, сетевые правила, изменения

Revision ID: f9a0b1c2d3e4
Revises: e8f9a0b1c2d3
Create Date: 2026-10-03 00:00:00.000000

Таблицы заполняются при импорте и пересчёте снапшота KSC. У строк `ksc_host`,
записанных до миграции, `group_id` пуст до пересчёта снапшота.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f9a0b1c2d3e4"
down_revision: str | Sequence[str] | None = "e8f9a0b1c2d3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _snapshot() -> sa.Column[int]:
    return sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("ksc_snapshot.id", ondelete="CASCADE"), nullable=False, index=True)


def upgrade() -> None:
    op.add_column("ksc_host", sa.Column("group_id", sa.Integer(), nullable=True))
    op.create_table(
        "ksc_policy",
        sa.Column("id", sa.Integer(), primary_key=True),
        _snapshot(),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False, server_default=""),
        sa.Column("product", sa.String(64), nullable=False, server_default=""),
        sa.Column("version", sa.String(64), nullable=False, server_default=""),
        sa.Column("group_id", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("group_path", sa.String(1024), nullable=False, server_default=""),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("accept_parent", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("has_contents", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("described", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("groups", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hosts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("profiles", sa.Integer(), nullable=True),
        sa.Column("exclusions", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("net_rules", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("settings_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("settings_known", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_table(
        "ksc_policy_scope",
        sa.Column("id", sa.Integer(), primary_key=True),
        _snapshot(),
        sa.Column("policy_id", sa.Integer(), nullable=False, index=True),
        sa.Column("group_id", sa.Integer(), nullable=False, index=True),
        sa.Column("group_path", sa.String(1024), nullable=False, server_default=""),
        sa.Column("own", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("hosts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_table(
        "ksc_profile",
        sa.Column("id", sa.Integer(), primary_key=True),
        _snapshot(),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False, server_default=""),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("condition_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("settings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("errors_json", sa.Text(), nullable=False, server_default="[]"),
    )
    op.create_table(
        "ksc_exclusion",
        sa.Column("id", sa.Integer(), primary_key=True),
        _snapshot(),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.Column("profile", sa.String(255), nullable=False, server_default=""),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("value", sa.Text(), nullable=False, server_default=""),
        sa.Column("components_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("comment", sa.Text(), nullable=False, server_default=""),
        sa.Column("risks_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("key", sa.String(64), nullable=False, index=True),
    )
    op.create_table(
        "ksc_net_rule",
        sa.Column("id", sa.Integer(), primary_key=True),
        _snapshot(),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.Column("profile", sa.String(255), nullable=False, server_default=""),
        sa.Column("layer", sa.String(16), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("name", sa.String(255), nullable=False, server_default=""),
        sa.Column("action", sa.String(16), nullable=False, server_default=""),
        sa.Column("direction", sa.String(16), nullable=False, server_default=""),
        sa.Column("protocol", sa.String(32), nullable=False, server_default=""),
        sa.Column("local_ports", sa.String(255), nullable=False, server_default=""),
        sa.Column("remote_ports", sa.String(255), nullable=False, server_default=""),
        sa.Column("addresses", sa.Text(), nullable=False, server_default=""),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("key", sa.String(64), nullable=False, index=True),
    )
    op.create_table(
        "ksc_change",
        sa.Column("id", sa.Integer(), primary_key=True),
        _snapshot(),
        sa.Column("prev_snapshot_id", sa.Integer(), nullable=True),
        sa.Column("kind", sa.String(16), nullable=False, index=True),
        sa.Column("action", sa.String(8), nullable=False),
        sa.Column("policy_id", sa.Integer(), nullable=True, index=True),
        sa.Column("policy_name", sa.String(255), nullable=False, server_default=""),
        sa.Column("profile", sa.String(255), nullable=False, server_default=""),
        sa.Column("section", sa.String(255), nullable=False, server_default=""),
        sa.Column("path", sa.Text(), nullable=False, server_default=""),
        sa.Column("before_json", sa.Text(), nullable=False, server_default="null"),
        sa.Column("after_json", sa.Text(), nullable=False, server_default="null"),
    )


def downgrade() -> None:
    for name in ("ksc_change", "ksc_net_rule", "ksc_exclusion", "ksc_profile", "ksc_policy_scope", "ksc_policy"):
        op.drop_table(name)
    op.drop_column("ksc_host", "group_id")
