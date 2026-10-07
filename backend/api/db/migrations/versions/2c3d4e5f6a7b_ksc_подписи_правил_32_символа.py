"""KSC: действие и направление сетевого правила — до 32 символов (подписи «исходящий (поток)», «по правилам программ» обрезались до 16)

Revision ID: 2c3d4e5f6a7b
Revises: 1b2c3d4e5f6a
Create Date: 2026-10-07 00:00:00.000000

Строки `ksc_net_rule`, записанные до миграции, остаются обрезанными до пересчёта снапшота.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "2c3d4e5f6a7b"
down_revision: str | Sequence[str] | None = "1b2c3d4e5f6a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("ksc_net_rule", "action", type_=sa.String(32), existing_type=sa.String(16), existing_nullable=False)
    op.alter_column("ksc_net_rule", "direction", type_=sa.String(32), existing_type=sa.String(16), existing_nullable=False)


def downgrade() -> None:
    op.alter_column("ksc_net_rule", "direction", type_=sa.String(16), existing_type=sa.String(32), existing_nullable=False)
    op.alter_column("ksc_net_rule", "action", type_=sa.String(16), existing_type=sa.String(32), existing_nullable=False)
