"""эталонная разметка из чужой таблицы

Revision ID: a4d9e13f7c62
Revises: f1a6d24c8b95
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a4d9e13f7c62"
down_revision: str | Sequence[str] | None = "f1a6d24c8b95"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "attack_reference",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("rule_uuid", sa.String(length=64), nullable=True),
        sa.Column("source_key", sa.String(length=255), nullable=False),
        sa.Column("techniques_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("original_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("source", sa.String(length=255), nullable=True),
        sa.Column("imported_by", sa.String(length=255), nullable=True),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_attack_reference_rule_uuid"), "attack_reference", ["rule_uuid"])
    op.create_index(op.f("ix_attack_reference_source_key"), "attack_reference", ["source_key"])


def downgrade() -> None:
    op.drop_index(op.f("ix_attack_reference_source_key"), table_name="attack_reference")
    op.drop_index(op.f("ix_attack_reference_rule_uuid"), table_name="attack_reference")
    op.drop_table("attack_reference")
