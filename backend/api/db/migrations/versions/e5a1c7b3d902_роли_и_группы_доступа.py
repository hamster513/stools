"""Роли, группы и членство: доступ по матрицам «область × уровень»

Revision ID: e5a1c7b3d902
Revises: 8aacd2621120
Create Date: 2026-10-27 12:00:00.000000

Спека ролей §2 «Миграция», шаги 1–4: четыре таблицы; три встроенные роли и три локальные группы;
членство локальных учёток по `app_user.role` (учётки OIDC получают его при входе); OIDC `group_roles` из настроек становятся группами `source='oidc'`, а ключ
`group_roles` из JSON уходит. Колонку `app_user.role` эта миграция не трогает — её удаляет вторая
(миграция B), когда код перестанет её читать.

Откат возвращает `app_user.role` по максимуму из групп (`platform=admin` → admin, иначе `write` и выше
где-либо → analyst, иначе auditor; пользователь без групп сохраняет прежнюю роль) и собирает
`group_roles` обратно из OIDC-групп. Пользовательские роли и группы пропадают вместе с таблицами.
"""
from __future__ import annotations

import json
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e5a1c7b3d902"
down_revision: str | Sequence[str] | None = "8aacd2621120"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Состав справочников зафиксирован здесь, а не импортируется из приложения: миграция должна давать
# тот же результат и после того, как приложение изменит свои константы.
MODULES = ("attack", "siem", "vm", "ad", "ksc", "assets", "toolbox")
#: Старая роль → (встроенная роль, её уровень в модулях, уровень платформы).
BUILTIN = {
    "admin": ("Администратор", "admin", "admin"),
    "analyst": ("Аналитик", "write", "deny"),
    "auditor": ("Аудитор", "read", "deny"),
}
GROUPS = {"admin": "Администраторы", "analyst": "Аналитики", "auditor": "Аудиторы"}
#: Старшинство старых ролей: при повторе одной OIDC-группы в `group_roles` берётся широчайшая.
WIDTH = {"auditor": 0, "analyst": 1, "admin": 2}
OIDC_KEY = "oidc"


def upgrade() -> None:
    op.create_table(
        "access_role",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("builtin", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "access_role_level",
        sa.Column("role_id", sa.Integer, sa.ForeignKey("access_role.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("area", sa.String(16), primary_key=True),
        sa.Column("level", sa.String(8), nullable=False),
    )
    op.create_table(
        "access_group",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("source", sa.String(8), nullable=False, server_default="local"),
        sa.Column("external_name", sa.String(255), nullable=True, unique=True),
        sa.Column("role_id", sa.Integer, sa.ForeignKey("access_role.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "access_membership",
        sa.Column("user_id", sa.Integer, sa.ForeignKey("app_user.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("group_id", sa.Integer, sa.ForeignKey("access_group.id", ondelete="CASCADE"), primary_key=True),
    )

    conn = op.get_bind()
    role_ids: dict[str, int] = {}
    for old, (name, module_level, platform_level) in BUILTIN.items():
        role_id = conn.execute(
            sa.text("INSERT INTO access_role (name, builtin) VALUES (:n, true) RETURNING id"), {"n": name}
        ).scalar_one()
        role_ids[old] = int(role_id)
        for area in (*MODULES, "platform"):
            conn.execute(
                sa.text("INSERT INTO access_role_level (role_id, area, level) VALUES (:r, :a, :l)"),
                {"r": role_id, "a": area, "l": platform_level if area == "platform" else module_level},
            )
    for old, group_name in GROUPS.items():
        conn.execute(
            sa.text("INSERT INTO access_group (name, source, role_id) VALUES (:n, 'local', :r)"),
            {"n": group_name, "r": role_ids[old]},
        )
        # Только локальные учётки: локальную группу вход по OIDC не снимает, и учётка OIDC
        # сохранила бы права вопреки каталогу. Учётки OIDC получат членство при следующем входе.
        conn.execute(sa.text(
            "INSERT INTO access_membership (user_id, group_id) "
            "SELECT u.id, g.id FROM app_user u, access_group g "
            "WHERE u.role = :old AND u.auth_source = 'local' AND g.name = :n"
        ), {"old": old, "n": group_name})

    row = conn.execute(sa.text("SELECT value_json FROM app_setting WHERE key = :k"), {"k": OIDC_KEY}).first()
    if row is None:
        return
    settings = json.loads(row[0] or "{}")
    pairs = settings.pop("group_roles", None) or []
    widest: dict[str, str] = {}
    for pair in pairs:
        group, role = pair.get("group"), pair.get("role")
        if not group or role not in WIDTH:
            continue
        if group not in widest or WIDTH[role] > WIDTH[widest[group]]:
            widest[group] = role
    local_names = set(GROUPS.values())
    for group, role in widest.items():
        conn.execute(
            sa.text("INSERT INTO access_group (name, source, external_name, role_id) VALUES (:n, 'oidc', :e, :r)"),
            {"n": f"{group} (OIDC)" if group in local_names else group, "e": group, "r": role_ids[role]},
        )
    conn.execute(
        sa.text("UPDATE app_setting SET value_json = :v WHERE key = :k"),
        {"v": json.dumps(settings, ensure_ascii=False), "k": OIDC_KEY},
    )


def _old_role(levels: dict[str, str]) -> str:
    """Роль прежней схемы по матрице: platform=admin → admin, write и выше где-либо → analyst."""
    if levels.get("platform") == "admin":
        return "admin"
    if any(level in ("write", "admin") for level in levels.values()):
        return "analyst"
    return "auditor"


def downgrade() -> None:
    conn = op.get_bind()
    matrices: dict[int, dict[str, str]] = {}
    for role_id, area, level in conn.execute(sa.text("SELECT role_id, area, level FROM access_role_level")):
        matrices.setdefault(role_id, {})[area] = level
    # Пользователь в нескольких группах получает широчайшую из ролей.
    best: dict[int, str] = {}
    for user_id, role_id in conn.execute(sa.text(
        "SELECT m.user_id, g.role_id FROM access_membership m JOIN access_group g ON g.id = m.group_id"
    )):
        old = _old_role(matrices.get(role_id, {}))
        if user_id not in best or WIDTH[old] > WIDTH[best[user_id]]:
            best[user_id] = old
    for user_id, old in best.items():
        conn.execute(sa.text("UPDATE app_user SET role = :r WHERE id = :u"), {"r": old, "u": user_id})

    pairs = [
        {"group": external, "role": _old_role(matrices.get(role_id, {}))}
        for external, role_id in conn.execute(sa.text(
            "SELECT external_name, role_id FROM access_group WHERE source = 'oidc' AND external_name IS NOT NULL ORDER BY id"
        ))
    ]
    if pairs:
        row = conn.execute(sa.text("SELECT value_json FROM app_setting WHERE key = :k"), {"k": OIDC_KEY}).first()
        settings = json.loads(row[0] or "{}") if row else {}
        settings["group_roles"] = pairs
        value = json.dumps(settings, ensure_ascii=False)
        if row:
            conn.execute(sa.text("UPDATE app_setting SET value_json = :v WHERE key = :k"), {"v": value, "k": OIDC_KEY})
        else:
            conn.execute(
                sa.text("INSERT INTO app_setting (key, value_json, updated_at) VALUES (:k, :v, now())"),
                {"k": OIDC_KEY, "v": value},
            )

    op.drop_table("access_membership")
    op.drop_table("access_group")
    op.drop_table("access_role_level")
    op.drop_table("access_role")
