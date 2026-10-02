"""вердикты AD и KSC → статусы находок; старые таблицы — в архив

Revision ID: b5c6d7e8f9a0
Revises: a4b5c6d7e8f9
Create Date: 2026-10-02 00:00:00.000000

Вердикт «принято как норма» становится статусом «Принят риск» с тем же
обоснованием, автором и датой и событием `migrated` в истории. `present` —
есть ли ключ в последнем по времени сбора снапшоте области; подпись и
severity — из самого позднего снапшота, где ключ был (вердикт без находки ни
в одном снапшоте — пустые). Подпись — код проверки и объект: названия
проверок живут в коде модуля, и подписи находок в данных обновит ближайшая
сверка. Таблицы вердиктов не удаляются, а переименовываются в
`*_archive_20261002`; `downgrade` возвращает их и убирает перенесённые строки.

`downgrade` теряет данные: решения, принятые или изменённые после upgrade
(новый статус, исполнитель, срок, история), в таблицы вердиктов не
возвращаются, а строки с событием `migrated` удаляются целиком — вместе с
поздними правками этих находок.
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
#: модуль → (таблица вердиктов, колонка области, снапшоты, находки, колонка объекта для подписи)
SOURCES = {
    "ad": ("ad_verdict", "domain_id", "ad_snapshot", "ad_finding", "identity"),
    "ksc": ("ksc_verdict", "server_id", "ksc_snapshot", "ksc_finding", "host"),
}


def upgrade() -> None:
    for module, (table, scope, snapshots, findings, label) in SOURCES.items():
        # Вердикт был одного вида — «accepted»; переносится каждая строка, чтобы числа сошлись.
        # Строка, которая уже есть (повторный прогон), не трогается, и события ей не пишутся:
        # событие `migrated` — только строкам, вставленным здесь. Вердикт без автора — `system`.
        op.execute(sa.text(f"""
            WITH ins AS (
                INSERT INTO platform_finding_state
                    (module, scope_id, key, status, reason, present, title, severity, updated_by, updated_at)
                SELECT '{module}', v.{scope}, v.key, 'risk_accepted', v.reason,
                       EXISTS (
                           SELECT 1 FROM {findings} f
                           WHERE f.key = v.key AND f.snapshot_id = (
                               SELECT s.id FROM {snapshots} s WHERE s.{scope} = v.{scope}
                               ORDER BY s.collected_at DESC, s.id DESC LIMIT 1)
                       ),
                       COALESCE(k.title, ''), COALESCE(k.severity, ''),
                       COALESCE(NULLIF(v.decided_by, ''), 'system'), v.decided_at
                FROM {table} v
                LEFT JOIN LATERAL (
                    SELECT LEFT(f."check" || ': ' || COALESCE(NULLIF(f.{label}, ''), f.target), 512) AS title,
                           LEFT(f.severity, 16) AS severity
                    FROM {findings} f JOIN {snapshots} s ON s.id = f.snapshot_id
                    WHERE s.{scope} = v.{scope} AND f.key = v.key
                    ORDER BY s.collected_at DESC, s.id DESC
                    LIMIT 1
                ) k ON true
                ON CONFLICT (module, scope_id, key) DO NOTHING
                RETURNING id, scope_id, key
            )
            INSERT INTO platform_finding_event (state_id, at, actor, kind, from_status, to_status, comment, details)
            SELECT ins.id, v.decided_at, COALESCE(NULLIF(v.decided_by, ''), 'system'), 'migrated', NULL, 'risk_accepted',
                   v.reason, CAST(:details AS jsonb)
            FROM ins JOIN {table} v ON v.{scope} = ins.scope_id AND v.key = ins.key
        """).bindparams(details=f'{{"from": "{table}"}}'))
        op.rename_table(table, table + SUFFIX)


def downgrade() -> None:
    for module, (table, *_rest) in SOURCES.items():
        op.rename_table(table + SUFFIX, table)
        op.execute(sa.text(f"""
            DELETE FROM platform_finding_state
            WHERE module = '{module}'
              AND id IN (SELECT state_id FROM platform_finding_event WHERE kind = 'migrated')
        """))
