"""KSC: структура адресов сетевых правил (`scope_json`), настройки сетевого экрана и HIPS (`ksc_policy_firewall`), версия таблиц политик снапшота

Revision ID: 4e7a9c1b3d5f
Revises: 8aacd2621120
Create Date: 2026-10-28 00:00:00.000000

Строки `ksc_net_rule`, записанные до миграции, получают `scope_json` NULL, снапшоты — `policy_store_version` 0; такие снапшоты
дозаполняются из файла выгрузки при первом чтении (`policy_store.ensure_policy_tables`: версия ниже текущей — таблицы политик
переписываются, вместе с `ksc_policy_firewall`); без файла остаются как были.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "4e7a9c1b3d5f"
down_revision: str | Sequence[str] | None = "8aacd2621120"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("ksc_snapshot", sa.Column("policy_store_version", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("ksc_net_rule", sa.Column("scope_json", sa.Text(), nullable=True))
    op.create_table(
        "ksc_policy_firewall",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("ksc_snapshot.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.Column("profile", sa.String(255), nullable=False, server_default=""),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("notify_only", sa.Boolean(), nullable=True),
        sa.Column("hips_enabled", sa.Boolean(), nullable=True),
        sa.Column("hips_notify_only", sa.Boolean(), nullable=True),
        sa.Column("zones_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("app_groups_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("locks_json", sa.Text(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_table("ksc_policy_firewall")
    op.drop_column("ksc_net_rule", "scope_json")
    op.drop_column("ksc_snapshot", "policy_store_version")
