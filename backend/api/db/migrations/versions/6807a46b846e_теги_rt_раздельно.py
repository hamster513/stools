"""Assets: теги RackTables раздельно — `network.implicit_tags` (унаследованные), `network.origin_seen_at`

Revision ID: 6807a46b846e
Revises: 70f2a4b2a076
Create Date: 2026-10-24 10:00:00.000000

`network.tags` остаются явными тегами; унаследованные из RackTables (`itags`) — в новом столбце,
у существующих сетей пусто. `origin_seen_at` — начало последнего импорта, давшего сеть (NULL у описанных
вручную). Номера тегов, записанные прежним разбором, перезапишет следующий импорт RackTables; данные
миграция не трогает. Откат удаляет оба столбца.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "6807a46b846e"
down_revision: str | Sequence[str] | None = "70f2a4b2a076"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("network", sa.Column("implicit_tags", JSON, nullable=False, server_default="[]"))
    op.add_column("network", sa.Column("origin_seen_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("network", "origin_seen_at")
    op.drop_column("network", "implicit_tags")
