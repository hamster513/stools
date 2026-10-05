"""KSC: признак «содержимое политики собрано не полностью» (часть секций не прочиталась)

Revision ID: 1b2c3d4e5f6a
Revises: 0a1b2c3d4e5f
Create Date: 2026-10-05 00:00:00.000000

Строки `ksc_policy`, записанные до миграции, получают False до пересчёта снапшота: признак берётся из `errors` записи
содержимого в файле выгрузки при импорте и пересчёте.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "1b2c3d4e5f6a"
down_revision: str | Sequence[str] | None = "0a1b2c3d4e5f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("ksc_policy", sa.Column("contents_partial", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    op.drop_column("ksc_policy", "contents_partial")
