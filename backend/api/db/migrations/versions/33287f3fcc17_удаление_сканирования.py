"""Assets: сканирование удалено — наблюдения и активы скана, расписания и задачи скана, столбцы скана сети

Revision ID: 33287f3fcc17
Revises: 5e909f11ba53
Create Date: 2026-10-24 18:00:00.000000

Спека сетей §7, владелец 23.10: «Сканов и не было, это синтетика. Убираем». Удаляются активы, у которых
нет ни одного наблюдения, кроме `scan` (живого или пропавшего), — тем же путём, что удаление актива из
интерфейса (`services.assets.delete_assets` удаляет строку `asset`, остальное делают внешние ключи:
наблюдения, связи с пользователями и локальные группы хоста — CASCADE; ссылки участников групп и
`merged_into` — SET NULL). Активы, слитые в удаляемый (по цепочке тоже), без своих живых наблюдений
удаляются вместе с ним: иначе остались бы без наблюдений и без ссылки. Прочие слитые активы не трогаются.
Затем — наблюдения `scan` у оставшихся активов, расписания `assets/scan` в `platform_schedule`, задачи
`scan` в `asset_job` и столбцы скана у `network`. Откат возвращает столбцы с умолчаниями прежней модели;
данные не восстанавливаются — их и не было.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "33287f3fcc17"
down_revision: str | Sequence[str] | None = "5e909f11ba53"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(JSONB(), "postgresql")

#: Столбцы скана сети в порядке прежней модели; у NOT NULL — умолчание, с которым откат их возвращает.
NOT_NULL: tuple[tuple[str, sa.types.TypeEngine[Any], Any], ...] = (
    ("scan_enabled", sa.Boolean(), sa.false()),
    ("ports", JSON, "[22, 80, 135, 139, 443, 445, 3389]"),
    ("exclude", JSON, "[]"),
    ("concurrency", sa.Integer(), "64"),
    ("icmp_timeout_ms", sa.Integer(), "1000"),
    ("tcp_timeout_ms", sa.Integer(), "2000"),
    ("rate_per_s", sa.Integer(), "500"),
)
NULLABLE: tuple[tuple[str, sa.types.TypeEngine[Any]], ...] = (
    ("last_scan_at", sa.DateTime(timezone=True)),
    ("last_scan_alive", sa.Integer()),
    ("last_scan_icmp", sa.Boolean()),
)


def upgrade() -> None:
    op.execute(sa.text(
        "WITH RECURSIVE doomed(id) AS ("
        " SELECT a.id FROM asset a WHERE a.id IN (SELECT asset_id FROM asset_observation WHERE source = 'scan')"
        " AND NOT EXISTS (SELECT 1 FROM asset_observation o WHERE o.asset_id = a.id AND o.source <> 'scan')"
        " UNION"
        " SELECT a.id FROM asset a JOIN doomed d ON a.merged_into = d.id"
        " WHERE NOT EXISTS (SELECT 1 FROM asset_observation o WHERE o.asset_id = a.id AND o.source <> 'scan' AND o.gone_at IS NULL)"
        ") DELETE FROM asset WHERE id IN (SELECT id FROM doomed)"
    ))
    op.execute(sa.text("DELETE FROM asset_observation WHERE source = 'scan'"))
    op.execute(sa.text("DELETE FROM platform_schedule WHERE module = 'assets' AND kind = 'scan'"))
    op.execute(sa.text("DELETE FROM asset_job WHERE kind = 'scan'"))
    for name, _type, _default in NOT_NULL:
        op.drop_column("network", name)
    op.drop_column("network", "schedule_id")
    for name, _type in NULLABLE:
        op.drop_column("network", name)


def downgrade() -> None:
    for name, type_, default in NOT_NULL:
        op.add_column("network", sa.Column(name, type_, nullable=False, server_default=default))
    op.add_column(
        "network", sa.Column("schedule_id", sa.Integer(), sa.ForeignKey("platform_schedule.id", ondelete="SET NULL"), nullable=True),
    )
    for name, type_ in NULLABLE:
        op.add_column("network", sa.Column(name, type_, nullable=True))
    # Умолчание в базе было только у темпа (`e2f3a4b5c6d7`); остальные задавала модель.
    for name, _type, _default in NOT_NULL:
        if name != "rate_per_s":
            op.alter_column("network", name, server_default=None)
