"""AD: сохранённые настройки с прежними умолчаниями привилегированных групп — новые умолчания

Revision ID: 0a1b2c3d4e5f
Revises: f9a0b1c2d3e4
Create Date: 2026-10-03 00:00:00.000000

Список RID расширен с 7 до 13 групп, к именам добавлена `DnsAdmins`.
Настройки в `app_setting['ad']` хранятся целиком, поэтому без миграции
установка, однажды сохранившая настройки, осталась бы на 7 группах.
Заменяется только список, совпадающий с прежним умолчанием: изменённый
владельцем не трогается. `downgrade` ничего не делает — прежнее умолчание
от нового после правок владельца не отличить.
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0a1b2c3d4e5f"
down_revision: str | Sequence[str] | None = "f9a0b1c2d3e4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

AD_KEY = "ad"
OLD_PRIVILEGED_RIDS = frozenset({512, 519, 518, 544, 548, 551, 549})
NEW_PRIVILEGED_RIDS = [512, 519, 518, 544, 548, 551, 549, 550, 552, 517, 520, 526, 527]
# Копии умолчаний из core/config.py на момент миграции: миграция не зависит от будущих правок кода.
OLD_PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Администраторы домена",
    "Администраторы предприятия",
    "Администраторы схемы",
    "Администраторы",
    "Операторы учетных записей",
    "Операторы архива",
    "Операторы серверов",
]
DNS_ADMINS = "DnsAdmins"


def upgrade_settings(value: dict[str, Any]) -> dict[str, Any]:
    rids = value.get("privileged_rids")
    if isinstance(rids, list) and set(rids) == OLD_PRIVILEGED_RIDS:
        value["privileged_rids"] = list(NEW_PRIVILEGED_RIDS)
    groups = value.get("privileged_groups")
    if isinstance(groups, list) and groups == OLD_PRIVILEGED_GROUPS:
        value["privileged_groups"] = [*groups, DNS_ADMINS]
    return value


def upgrade() -> None:
    conn = op.get_bind()
    raw = conn.execute(sa.text("SELECT value_json FROM app_setting WHERE key = :k"), {"k": AD_KEY}).scalar_one_or_none()
    if not raw:
        return
    value = json.loads(raw)
    if not isinstance(value, dict):
        return
    new = upgrade_settings(dict(value))
    if new != value:
        conn.execute(sa.text("UPDATE app_setting SET value_json = :v WHERE key = :k"), {"k": AD_KEY, "v": json.dumps(new, ensure_ascii=False)})


def downgrade() -> None:
    pass
