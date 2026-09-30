"""непроверенные проверки снапшота AD: причина, по которой данных не было

Проверка без данных (SYSVOL не прочитан, дат входа нет, шаблонов нет) выглядела
на обзоре как «без находок». Снапшот хранит код проверки → причину; старые
снапшоты получают пустой словарь и заполняются при пересчёте.

Revision ID: b9c0d1e2f3a4
Revises: a8b9c0d1e2f3
Create Date: 2026-09-30 00:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b9c0d1e2f3a4"
down_revision: str | Sequence[str] | None = "a8b9c0d1e2f3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("ad_snapshot") as batch:
        batch.add_column(sa.Column("unchecked_json", sa.Text(), nullable=False, server_default="{}"))


def downgrade() -> None:
    with op.batch_alter_table("ad_snapshot") as batch:
        batch.drop_column("unchecked_json")
