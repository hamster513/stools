"""Threat Hunting: один прогон на дату — среди невытесненных

Revision ID: b8d4f2a6c1e7
Revises: a7c3e91d5b24
Create Date: 2026-10-19 18:00:00.000000

«Повторить за дату» оставляет прежний прогон строкой со статусом
`superseded`: на него ссылаются находки, по которым уже идёт работа, и его
история запросов. Простая уникальность `target_date` не пускала бы новый
прогон той же даты, поэтому она заменена частичным уникальным индексом —
одна дата, один невытесненный прогон.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b8d4f2a6c1e7"
down_revision: str | Sequence[str] | None = "a7c3e91d5b24"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("uq_th_run_target_date", "th_run", type_="unique")
    op.create_index(
        "uq_th_run_target_date_live", "th_run", ["target_date"], unique=True,
        postgresql_where=sa.text("status <> 'superseded'"),
    )


def downgrade() -> None:
    # Сужение: при заменённых прогонах (две строки на дату) ограничение не создастся и откат упадёт.
    op.drop_index("uq_th_run_target_date_live", table_name="th_run")
    op.create_unique_constraint("uq_th_run_target_date", "th_run", ["target_date"])
