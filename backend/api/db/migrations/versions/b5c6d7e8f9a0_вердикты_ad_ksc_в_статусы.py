"""вердикты AD и KSC → статусы находок; старые таблицы — в архив

Revision ID: b5c6d7e8f9a0
Revises: a4b5c6d7e8f9
Create Date: 2026-10-02 00:00:00.000000

Вердикт «принято как норма» становится статусом «Принят риск» с тем же
обоснованием, автором и датой и событием `migrated` в истории. Таблицы
вердиктов не удаляются, а переименовываются в `*_archive_20261002`;
`downgrade` возвращает их и убирает перенесённые строки.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b5c6d7e8f9a0"
down_revision: str | Sequence[str] | None = "a4b5c6d7e8f9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SUFFIX = "_archive_20261002"
#: модуль → (таблица вердиктов, колонка области)
SOURCES = {"ad": ("ad_verdict", "domain_id"), "ksc": ("ksc_verdict", "server_id")}


def upgrade() -> None:
    for module, (table, scope) in SOURCES.items():
        # Вердикт был одного вида — «accepted»; переносится каждая строка, чтобы числа сошлись.
        op.execute(sa.text(f"""
            INSERT INTO platform_finding_state
                (module, scope_id, key, status, reason, present, title, severity, updated_by, updated_at)
            SELECT '{module}', {scope}, key, 'risk_accepted', reason, true, '', '', decided_by, decided_at
            FROM {table}
        """))
        op.execute(sa.text(f"""
            INSERT INTO platform_finding_event (state_id, at, actor, kind, from_status, to_status, comment, details)
            SELECT s.id, v.decided_at, COALESCE(NULLIF(v.decided_by, ''), 'system'), 'migrated', NULL, 'risk_accepted',
                   v.reason, CAST(:details AS jsonb)
            FROM {table} v
            JOIN platform_finding_state s ON s.module = '{module}' AND s.scope_id = v.{scope} AND s.key = v.key
        """).bindparams(details=f'{{"from": "{table}"}}'))
        op.rename_table(table, table + SUFFIX)


def downgrade() -> None:
    for module, (table, _scope) in SOURCES.items():
        op.rename_table(table + SUFFIX, table)
        op.execute(sa.text(f"""
            DELETE FROM platform_finding_state
            WHERE module = '{module}'
              AND id IN (SELECT state_id FROM platform_finding_event WHERE kind = 'migrated')
        """))
