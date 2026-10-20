"""AD: сводка домена в снапшоте

Revision ID: b3c4d5e6f7a8
Revises: 740444c0aff9
Create Date: 2026-10-19 00:00:00.000000

Пустая строка у прежних снапшотов — сводка не посчитана, API просит пересчитать.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b3c4d5e6f7a8"
down_revision: str | Sequence[str] | None = "740444c0aff9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("ad_snapshot") as batch:
        batch.add_column(sa.Column("summary_json", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    with op.batch_alter_table("ad_snapshot") as batch:
        batch.drop_column("summary_json")
