"""разметка ATT&CK, кэш векторов и настройки сервиса

Revision ID: 9a1c4f2b7d10
Revises: 7278f78324b3
Create Date: 2026-08-26

Три таблицы, и все три намеренно вне снапшотов:

- `attack_markup` привязана к группе правил. Подтверждённая человеком
  разметка обязана пережить следующую выгрузку — это единственное
  в системе, что стоит человеко-часов.
- `technique_vector` кэширует векторы техник. Бандл ATT&CK меняется раз
  в квартал, разметка запускается на каждой выгрузке.
- `app_setting` хранит адрес модели. Настройка, которую меняют
  пересборкой контейнера, настройкой не является.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "9a1c4f2b7d10"
down_revision: str | Sequence[str] | None = "7278f78324b3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "app_setting",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value_json", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint("key"),
    )

    op.create_table(
        "attack_markup",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("group_name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("techniques_json", sa.Text(), nullable=False),
        sa.Column("candidates_json", sa.Text(), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("attack_version", sa.String(length=32), nullable=True),
        sa.Column("reviewed_by", sa.String(length=255), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_attack_markup_group_name"), "attack_markup", ["group_name"], unique=True
    )
    op.create_index(op.f("ix_attack_markup_status"), "attack_markup", ["status"])

    op.create_table(
        "technique_vector",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("technique_id", sa.String(length=32), nullable=False),
        sa.Column("embed_model", sa.String(length=128), nullable=False),
        sa.Column("attack_version", sa.String(length=32), nullable=True),
        sa.Column("vector_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("technique_id", "embed_model", name="uq_technique_vector_model"),
    )
    op.create_index(
        op.f("ix_technique_vector_technique_id"), "technique_vector", ["technique_id"]
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_technique_vector_technique_id"), table_name="technique_vector")
    op.drop_table("technique_vector")
    op.drop_index(op.f("ix_attack_markup_status"), table_name="attack_markup")
    op.drop_index(op.f("ix_attack_markup_group_name"), table_name="attack_markup")
    op.drop_table("attack_markup")
    op.drop_table("app_setting")
