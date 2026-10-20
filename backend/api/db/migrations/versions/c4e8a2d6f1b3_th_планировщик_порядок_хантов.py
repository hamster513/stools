"""Threat Hunting: порядок хантов в очереди; пауза между хантами; окно от времени старта

Revision ID: c4e8a2d6f1b3
Revises: b8d4f2a6c1e7
Create Date: 2026-10-20 12:00:00.000000

Очередь ночного прогона шла по дате создания ханта; теперь порядок задаёт
человек (`th_hunt.position`). Существующие ханты получают места в прежнем
порядке — по `created_at`, затем `id`, — чтобы первая ночь после обновления
шла так же, как раньше.

В настройках раздела (`app_setting['siem_th']`) пауза между запросами
стала паузой между хантами (`query_pause_s` → `hunt_pause_s`, значение
сохраняется), а конец окна больше не хранится: он выводится из начала.
Та же правка JSON — `settings.migrate_legacy_json`; здесь своя копия в SQL,
чтобы миграция не зависела от кода, который потом будет меняться.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c4e8a2d6f1b3"
down_revision: str | Sequence[str] | None = "b8d4f2a6c1e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("th_hunt", sa.Column("position", sa.Integer(), nullable=False, server_default="0"))
    op.execute(
        "UPDATE th_hunt SET position = sub.rn - 1"
        " FROM (SELECT id, row_number() OVER (ORDER BY created_at, id) AS rn FROM th_hunt) sub"
        " WHERE th_hunt.id = sub.id"
    )
    # Умолчание базы нужно было только для заполнения: место нового ханта ставит код (в конец).
    op.alter_column("th_hunt", "position", server_default=None)
    # jsonb_strip_nulls убирает ключ, если старого значения не было: умолчание возьмёт модель.
    op.execute(
        "UPDATE app_setting SET value_json = ("
        " (value_json::jsonb - 'query_pause_s' - 'window_to')"
        " || jsonb_strip_nulls(jsonb_build_object('hunt_pause_s', value_json::jsonb -> 'query_pause_s'))"
        ")::text WHERE key = 'siem_th'"
    )


def downgrade() -> None:
    # Прежний конец окна не восстанавливается: ставится умолчание старой модели '02:00'.
    op.execute(
        "UPDATE app_setting SET value_json = ("
        " (value_json::jsonb - 'hunt_pause_s')"
        " || jsonb_strip_nulls(jsonb_build_object('query_pause_s', value_json::jsonb -> 'hunt_pause_s'))"
        " || '{\"window_to\": \"02:00\"}'::jsonb"
        ")::text WHERE key = 'siem_th'"
    )
    op.drop_column("th_hunt", "position")
