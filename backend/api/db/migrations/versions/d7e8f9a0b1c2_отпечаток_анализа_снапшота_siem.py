"""снапшот SIEM помнит версию разбора и отпечаток профиля; индекс ключа находки переименован

Revision ID: d7e8f9a0b1c2
Revises: c6d7e8f9a0b1
Create Date: 2026-10-02 20:00:00.000000

`parser_version` и `profile_hash` — чем посчитаны находки снапшота. Автоматика
статусов сравнивает соседние снапшоты, только если они посчитаны одинаково
(findings_adapter.reconcile). У старых снапшотов колонки пустые: первая
выгрузка после обновления с ними не сравнивается.

Индекс `finding (object_uuid, kind, field, value_hash)` назывался по таблице
вердиктов, которой больше нет; теперь он служит ключу статуса находки.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d7e8f9a0b1c2"
down_revision: str | Sequence[str] | None = "c6d7e8f9a0b1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("snapshot", sa.Column("parser_version", sa.String(32), nullable=True))
    op.add_column("snapshot", sa.Column("profile_hash", sa.String(64), nullable=True))
    # IF EXISTS: индекс могли уже переименовать (стенд прогнал раннюю редакцию миграции).
    op.execute("ALTER INDEX IF EXISTS ix_finding_verdict_key RENAME TO ix_finding_identity")


def downgrade() -> None:
    op.execute("ALTER INDEX IF EXISTS ix_finding_identity RENAME TO ix_finding_verdict_key")
    op.drop_column("snapshot", "profile_hash")
    op.drop_column("snapshot", "parser_version")
