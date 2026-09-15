"""описание правила из локализации

Revision ID: d7f4b0c92e18
Revises: c5a2f8e31b47
Create Date: 2026-08-26

Шаблон сообщения, которое правило выдаёт при срабатывании, — единственное
место в выгрузке, где словами написано, что правило обнаруживает. Раньше
из локализации брался только заголовок, а он часто содержит служебный код
вида type_id=JC-MNA-005-004 и о технике говорит меньше.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d7f4b0c92e18"
down_revision: str | Sequence[str] | None = "c5a2f8e31b47"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("rule", sa.Column("description_ru", sa.Text(), nullable=True))
    op.add_column("rule", sa.Column("description_en", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("rule", "description_en")
    op.drop_column("rule", "description_ru")
