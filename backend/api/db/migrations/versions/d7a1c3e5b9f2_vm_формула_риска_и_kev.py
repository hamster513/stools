"""VM: новая формула риска (вероятность × тяжесть × ценность) и справочник CISA KEV

Revision ID: d7a1c3e5b9f2
Revises: 2bd3112bc826
Create Date: 2026-10-21 12:00:00.000000

Множители старой формулы (`vm_cve.cve_factor`, `vm_host.impact`) заменяются
членами новой (спека 2026-10-21 §9): у CVE — вероятность эксплуатации, CVSS ÷ 10,
класс вектора атаки и отметки KEV; у хоста — ценность и доступ из интернета.
Значения не переносятся: старые числа в новую шкалу не переводятся. Риск пар
до пересчёта остаётся прежним; API при старте сам ставит задачу `recalculate`,
если пары есть, а вероятности ещё не посчитаны (`scoring.ensure_rescored`).
Откат возвращает старые колонки нулями — нужен пересчёт старым кодом.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d7a1c3e5b9f2"
down_revision: str | Sequence[str] | None = "2bd3112bc826"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Колонки, которым умолчание базы нужно только для заполнения существующих строк:
#: значения новых строк ставит код (модель).
CVE_COLUMNS = (
    ("kev", sa.Boolean(), False, sa.false()),
    ("kev_added", sa.Date(), True, None),
    ("kev_ransomware", sa.Boolean(), False, sa.false()),
    ("kev_due", sa.Date(), True, None),
    ("likelihood", sa.Float(), False, sa.text("0")),
    ("cvss10", sa.Float(), True, None),
    ("av_class", sa.String(16), False, sa.text("'none'")),
)
HOST_COLUMNS = (
    ("value", sa.Float(), False, sa.text("0.6")),
    ("internet", sa.Boolean(), False, sa.false()),
)


def upgrade() -> None:
    op.create_table(
        "vm_ref_kev",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("date_added", sa.Date(), nullable=True),
        sa.Column("ransomware", sa.Boolean(), nullable=False),
        sa.Column("vendor", sa.Text(), nullable=False),
        sa.Column("product", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("due_date", sa.Date(), nullable=True),
    )
    for table, columns in (("vm_cve", CVE_COLUMNS), ("vm_host", HOST_COLUMNS)):
        for name, type_, nullable, default in columns:
            op.add_column(table, sa.Column(name, type_, nullable=nullable, server_default=default))
            if default is not None:
                op.alter_column(table, name, server_default=None)
    op.drop_column("vm_cve", "cve_factor")
    op.drop_column("vm_host", "impact")


def downgrade() -> None:
    op.add_column("vm_host", sa.Column("impact", sa.Float(), nullable=False, server_default=sa.text("0")))
    op.alter_column("vm_host", "impact", server_default=None)
    op.add_column("vm_cve", sa.Column("cve_factor", sa.Float(), nullable=False, server_default=sa.text("0")))
    op.alter_column("vm_cve", "cve_factor", server_default=None)
    for table, columns in (("vm_host", HOST_COLUMNS), ("vm_cve", CVE_COLUMNS)):
        for name, *_ in reversed(columns):
            op.drop_column(table, name)
    op.drop_table("vm_ref_kev")
