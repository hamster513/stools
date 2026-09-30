"""данные центра сертификации AD: отдельная сущность домена и ссылка снапшота на них

Настройки и права ЦС, реестр контроллеров и веб-выдачу собирает PowerShell-сборщик
отдельным файлом `stools-ad-ca/1`. Загрузки хранятся с историей по домену; снапшот
помнит, по каким данным ЦС посчитан.

Revision ID: c0d1e2f3a4b5
Revises: b9c0d1e2f3a4
Create Date: 2026-09-30 00:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "c0d1e2f3a4b5"
down_revision: str | Sequence[str] | None = "b9c0d1e2f3a4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ad_ca_data",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain_id", sa.Integer(), sa.ForeignKey("ad_domain.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("uploaded_by", sa.String(255), nullable=False),
        sa.Column("sections_json", sa.Text(), nullable=False),
        sa.Column("data", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
    )
    op.create_index("ix_ad_ca_data_domain_id", "ad_ca_data", ["domain_id"])
    # Внешний ключ отдельной операцией: batch без пересоздания таблицы (Postgres)
    # не создаёт ограничения из ForeignKey внутри add_column.
    with op.batch_alter_table("ad_snapshot") as batch:
        batch.add_column(sa.Column("ca_data_id", sa.Integer(), nullable=True))
        batch.create_foreign_key("fk_ad_snapshot_ca_data_id", "ad_ca_data", ["ca_data_id"], ["id"], ondelete="SET NULL")


def downgrade() -> None:
    with op.batch_alter_table("ad_snapshot") as batch:
        batch.drop_constraint("fk_ad_snapshot_ca_data_id", type_="foreignkey")
        batch.drop_column("ca_data_id")
    op.drop_index("ix_ad_ca_data_domain_id", table_name="ad_ca_data")
    op.drop_table("ad_ca_data")
