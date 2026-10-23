"""VM: локальные группы Windows и Linux из второго и третьего PDQL, отдельный снимок

Revision ID: 1c1f9acd03bb
Revises: c931c6345558
Create Date: 2026-10-23 15:00:00.000000

Новые таблицы `vm_host_group` и `vm_group_import`; прочие таблицы модуля не меняются,
откат удаляет только эти две.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "1c1f9acd03bb"
down_revision: str | Sequence[str] | None = "c931c6345558"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "vm_host_group",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("os_family", sa.String(8), nullable=False),
        sa.Column("fqdn", sa.String(255), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("ip", sa.String(64), nullable=False),
        sa.Column("group_name", sa.String(512), nullable=False),
        sa.Column("group_sid", sa.String(255), nullable=False),
        sa.Column("group_gid", sa.String(32), nullable=False),
        sa.Column("group_description", sa.Text(), nullable=False),
        sa.Column("member_name", sa.String(512), nullable=False),
        sa.Column("member_domain", sa.String(255), nullable=False),
        sa.Column("member_sid", sa.String(255), nullable=False),
        sa.Column("member_type", sa.String(16), nullable=False),
        sa.Column("member_local", sa.Boolean(), nullable=True),
        sa.Column("member_system", sa.Boolean(), nullable=True),
    )
    op.create_index("ix_vm_host_group_host", "vm_host_group", ["os_family", "fqdn", "hostname", "ip"])
    op.create_table(
        "vm_group_import",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hosts", sa.Integer(), nullable=False),
        sa.Column("rows", sa.Integer(), nullable=False),
        sa.Column("windows_ok", sa.Boolean(), nullable=False),
        sa.Column("linux_ok", sa.Boolean(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("vm_group_import")
    op.drop_index("ix_vm_host_group_host", table_name="vm_host_group")
    op.drop_table("vm_host_group")
