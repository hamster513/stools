"""AD: в сохранённый прежний умолчательный список опасных прав GPO добавляется SeTrustedCredManAccessPrivilege

Revision ID: 740444c0aff9
Revises: f0a1b2c3d4e5
Create Date: 2026-10-19 00:00:00.000000

Умолчание `user_rights` дополнено правом SeTrustedCredManAccessPrivilege
(Medium). Настройки в `app_setting['ad']` хранятся целиком, поэтому без
миграции установка, однажды сохранившая настройки, его бы не получила.
Дополняется только список, совпадающий с прежним умолчанием (порядок не
важен): изменённый владельцем не трогается. `downgrade` ничего не делает —
как и в 0a1b2c3d4e5f.
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "740444c0aff9"
down_revision: str | Sequence[str] | None = "f0a1b2c3d4e5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

AD_KEY = "ad"
# Копия прежнего умолчания из core/config.py: миграция не зависит от будущих правок кода.
OLD_USER_RIGHTS = frozenset({
    ("SeEnableDelegationPrivilege", "High"),
    ("SeDebugPrivilege", "High"),
    ("SeTcbPrivilege", "High"),
    ("SeBackupPrivilege", "Medium"),
    ("SeRestorePrivilege", "Medium"),
})
TRUSTED_CRED_MAN = {"right": "SeTrustedCredManAccessPrivilege", "severity": "Medium"}


def _is_old_default(rights: Any) -> bool:
    if not isinstance(rights, list) or len(rights) != len(OLD_USER_RIGHTS) or not all(isinstance(r, dict) for r in rights):
        return False
    return frozenset((r.get("right"), r.get("severity")) for r in rights) == OLD_USER_RIGHTS


def upgrade_settings(value: dict[str, Any]) -> dict[str, Any]:
    if _is_old_default(value.get("user_rights")):
        value["user_rights"] = [*value["user_rights"], dict(TRUSTED_CRED_MAN)]
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
