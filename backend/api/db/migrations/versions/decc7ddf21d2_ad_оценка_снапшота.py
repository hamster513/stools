"""AD: оценка домена в снапшоте

Revision ID: decc7ddf21d2
Revises: b3c4d5e6f7a8
Create Date: 2026-10-20 00:00:00.000000

Пустая строка у прежних снапшотов — оценка не посчитана, на графике точки нет.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "decc7ddf21d2"
down_revision: str | Sequence[str] | None = "b3c4d5e6f7a8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("ad_snapshot") as batch:
        batch.add_column(sa.Column("score_json", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    with op.batch_alter_table("ad_snapshot") as batch:
        batch.drop_column("score_json")
