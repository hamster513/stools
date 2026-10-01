"""темп скана сети: rate_per_s — пакетов в секунду на весь проход (10–5000, по умолчанию 500)

Revision ID: e2f3a4b5c6d7
Revises: d1e2f3a4b5c6
Create Date: 2026-10-01 12:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e2f3a4b5c6d7"
down_revision: str | Sequence[str] | None = "d1e2f3a4b5c6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("network", sa.Column("rate_per_s", sa.Integer(), nullable=False, server_default="500"))


def downgrade() -> None:
    op.drop_column("network", "rate_per_s")
