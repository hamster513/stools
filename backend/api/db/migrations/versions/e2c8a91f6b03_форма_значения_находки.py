"""форма значения находки

Revision ID: e2c8a91f6b03
Revises: d7f4b0c92e18
Create Date: 2026-08-26

Классы находок взаимоисключающи, и «дублирует список» перекрывает
«IP / CIDR / FQDN»: продублированное значение — более тяжёлое замечание.
Из-за этого сетевые имена в классе становятся невидимы: на эталонной
выгрузке их 585, а в классе видно 371. Форма значения хранится отдельно
от класса и отвечает на другой вопрос.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e2c8a91f6b03"
down_revision: str | Sequence[str] | None = "d7f4b0c92e18"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("finding", sa.Column("shape", sa.String(length=8), nullable=True))
    op.create_index(op.f("ix_finding_shape"), "finding", ["shape"])


def downgrade() -> None:
    op.drop_index(op.f("ix_finding_shape"), table_name="finding")
    op.drop_column("finding", "shape")
