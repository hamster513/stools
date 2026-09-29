"""сбор AD порциями: размер страницы LDAP и пауза между запросами

Онлайн-сбор большого домена без пауз перегружал контроллеры. Существующие
подключения получают умолчания: страница 500 объектов, пауза 500 мс.

Revision ID: a8b9c0d1e2f3
Revises: f7a8b9c0d1e2
Create Date: 2026-09-30 00:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a8b9c0d1e2f3"
down_revision: str | Sequence[str] | None = "f7a8b9c0d1e2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("ad_connection") as batch:
        batch.add_column(sa.Column("page_size", sa.Integer(), nullable=False, server_default="500"))
        batch.add_column(sa.Column("pause_ms", sa.Integer(), nullable=False, server_default="500"))


def downgrade() -> None:
    with op.batch_alter_table("ad_connection") as batch:
        batch.drop_column("pause_ms")
        batch.drop_column("page_size")
