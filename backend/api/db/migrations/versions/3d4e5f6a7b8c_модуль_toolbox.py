"""модуль toolbox: задания очистки, находки, таблица соответствий, настройки

Revision ID: 3d4e5f6a7b8c
Revises: 2c3d4e5f6a7b
Create Date: 2026-10-08 00:00:00.000000

`toolbox_alias` и `toolbox_settings` (ключ HMAC) — в резервную копию: без них старые очищенные
файлы обратно не перевести.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "3d4e5f6a7b8c"
down_revision: str | Sequence[str] | None = "2c3d4e5f6a7b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "toolbox_job",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False, index=True),
        sa.Column("stage", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("status", sa.String(16), nullable=False, server_default="running", index=True),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("processed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total", sa.Integer(), nullable=True),
        sa.Column("message", sa.Text(), nullable=False, server_default=""),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_by", sa.String(255), nullable=False, server_default=""),
        sa.Column("input_name", sa.String(255), nullable=False, server_default=""),
        sa.Column("input_size", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("input_kind", sa.String(8), nullable=False, server_default="file"),
        sa.Column("files_deleted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("result_name", sa.String(255), nullable=False, server_default=""),
        sa.Column("stats", JSON, nullable=False),
        sa.Column("users_from_ad", sa.Boolean(), nullable=False, server_default=sa.false()),
    )

    op.create_table(
        "toolbox_alias",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("real_key", sa.String(512), nullable=False),
        sa.Column("real", sa.String(512), nullable=False),
        sa.Column("alias", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False, server_default=""),
        sa.Column("first_job_id", sa.Integer(), sa.ForeignKey("toolbox_job.id", ondelete="SET NULL"), nullable=True),
        sa.UniqueConstraint("kind", "real_key", name="uq_toolbox_alias_real"),
        sa.UniqueConstraint("kind", "alias", name="uq_toolbox_alias_alias"),
    )

    op.create_table(
        "toolbox_finding",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job_id", sa.Integer(), sa.ForeignKey("toolbox_job.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("value_key", sa.Text(), nullable=False),
        sa.Column("alias", sa.Text(), nullable=False),
        sa.Column("alias_id", sa.Integer(), sa.ForeignKey("toolbox_alias.id", ondelete="SET NULL"), nullable=True),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("contexts", JSON, nullable=False),
        sa.Column("first_file", sa.String(512), nullable=False, server_default=""),
        sa.Column("checked", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("auto", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_toolbox_finding_job_id", "toolbox_finding", ["job_id"])
    op.create_index(
        "uq_toolbox_finding_value", "toolbox_finding", ["job_id", "kind", sa.text("md5(value_key)")], unique=True,
    )

    op.create_table(
        "toolbox_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.LargeBinary(32), nullable=False),
        sa.Column("words", JSON, nullable=False),
        sa.Column("subnets", JSON, nullable=False),
        sa.Column("retention_days", sa.Integer(), nullable=False, server_default="7"),
    )


def downgrade() -> None:
    op.drop_table("toolbox_settings")
    op.drop_table("toolbox_finding")
    op.drop_table("toolbox_alias")
    op.drop_table("toolbox_job")
