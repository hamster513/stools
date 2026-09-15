"""бандл ATT&CK и его перевод в базе

Revision ID: b3e7c19d4a52
Revises: 9a1c4f2b7d10
Create Date: 2026-08-26

Матрица перестала жить только в образе: заказчик обновляет её сам, не
дожидаясь поставки. Перевод хранит отпечаток английского исходника —
без него устаревший перевод не отличить от актуального.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b3e7c19d4a52"
down_revision: str | Sequence[str] | None = "9a1c4f2b7d10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "attack_bundle",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=True),
        sa.Column("techniques_json", sa.Text(), nullable=False),
        sa.Column("tactics_json", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("builtin_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("loaded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("loaded_by", sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "attack_translation",
        sa.Column("technique_id", sa.String(length=32), nullable=False),
        sa.Column("name_ru", sa.Text(), nullable=False),
        sa.Column("description_ru", sa.Text(), nullable=False),
        sa.Column("source_hash", sa.String(length=64), nullable=False),
        sa.Column("origin", sa.String(length=16), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("technique_id"),
    )


def downgrade() -> None:
    op.drop_table("attack_translation")
    op.drop_table("attack_bundle")
