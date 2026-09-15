"""Применяемость техник в России: выгрузка процедур и её происхождение."""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c8b3d51a7f24"
down_revision: str | Sequence[str] | None = "a4d9e13f7c62"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "attack_ru_ttp",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("technique_id", sa.String(length=32), nullable=False),
        sa.Column("technique_name", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("procedure", sa.Text(), nullable=False, server_default=""),
        sa.Column("command_line", sa.Text(), nullable=False, server_default=""),
        sa.Column("actors_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("malware_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("tools_json", sa.Text(), nullable=False, server_default="[]"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_attack_ru_ttp_technique_id"), "attack_ru_ttp", ["technique_id"])
    op.create_table(
        "attack_ru_import",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("imported_by", sa.String(length=255), nullable=True),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attack_version", sa.String(length=32), nullable=True),
        sa.Column("row_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("technique_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unknown_json", sa.Text(), nullable=False, server_default="[]"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("attack_ru_import")
    op.drop_index(op.f("ix_attack_ru_ttp_technique_id"), table_name="attack_ru_ttp")
    op.drop_table("attack_ru_ttp")
