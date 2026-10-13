"""наборы установки и статус установки правил из базы знаний по API; у снапшота — сервер и БД контента

Revision ID: c7d8e9f0a1b2
Revises: 3d4e5f6a7b8c
Create Date: 2026-10-13 12:00:00.000000

Снапшот, собранный из базы знаний по API, помнит, с какого сервера и из
какой БД контента он взят, и получает инвентарь: наборы установки со
статусами и для каждого правила — установлено ли оно в SIEM, в какой папке
лежит и в какие наборы входит. У снапшотов из файла всего этого нет.
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
    op.add_column("snapshot", sa.Column("kb_host", sa.String(255), nullable=True))
    op.add_column("snapshot", sa.Column("kb_database", sa.String(255), nullable=True))
    op.create_table(
        "siem_deployment_set",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("snapshot.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kb_id", sa.String(64), nullable=False),
        sa.Column("parent_kb_id", sa.String(64), nullable=True),
        sa.Column("name", sa.String(255), nullable=False, server_default=""),
        sa.Column("system_name", sa.String(255), nullable=False, server_default=""),
        sa.Column("general_status", sa.String(64), nullable=False, server_default=""),
        sa.Column("compilation_status", sa.String(64), nullable=False, server_default=""),
        sa.Column("deployment_statuses_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("rule_count", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint("snapshot_id", "kb_id", name="uq_siem_deployment_set"),
    )
    op.create_index("ix_siem_deployment_set_snapshot_id", "siem_deployment_set", ["snapshot_id"])
    op.create_table(
        "siem_rule_deployment",
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("snapshot.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("rule_uuid", sa.String(64), primary_key=True),
        sa.Column("installed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("folder_path", sa.String(1024), nullable=False, server_default=""),
        sa.Column("set_ids_json", sa.Text(), nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_table("siem_rule_deployment")
    op.drop_index("ix_siem_deployment_set_snapshot_id", table_name="siem_deployment_set")
    op.drop_table("siem_deployment_set")
    op.drop_column("snapshot", "kb_database")
    op.drop_column("snapshot", "kb_host")
