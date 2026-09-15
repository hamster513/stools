"""уведомление о замене матрицы поставкой

Revision ID: c5a2f8e31b47
Revises: b3e7c19d4a52
Create Date: 2026-08-26

Заказчик загружает матрицу руками. Если поставка её перекрыла — тем более
когда поставка оказалась старее, — он должен об этом узнать, а не гадать,
почему матрица вдруг другая.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c5a2f8e31b47"
down_revision: str | Sequence[str] | None = "b3e7c19d4a52"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "attack_bundle", sa.Column("replaced_version", sa.String(length=32), nullable=True)
    )
    op.add_column(
        "attack_bundle", sa.Column("replaced_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "attack_bundle",
        sa.Column("notice_dismissed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("attack_bundle", "notice_dismissed")
    op.drop_column("attack_bundle", "replaced_at")
    op.drop_column("attack_bundle", "replaced_version")
