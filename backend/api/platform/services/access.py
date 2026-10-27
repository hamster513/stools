"""Права доступа: роли как матрицы «область × уровень», назначенные группам.

Эффективный уровень пользователя в области — максимум по всем его группам.
Кэша между запросами нет: смена роли или группы действует со следующего
запроса (спека ролей §2).
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.models import (
    AREAS,
    LEVELS,
    MODULE_IDS,
    AccessGroup,
    AccessMembership,
    AccessRole,
    AccessRoleLevel,
)

#: Область → уровень; присутствуют все AREAS.
Access = dict[str, str]


def _matrix(module_level: str, platform_level: str) -> dict[str, str]:
    return {**dict.fromkeys(MODULE_IDS, module_level), "platform": platform_level}


#: Встроенные роли. «Администратор» не редактируется — ensure_builtin
#: возвращает ему полную матрицу (в том числе по модулям, добавленным позже);
#: «Аналитик» и «Аудитор» после создания принадлежат владельцу системы.
BUILTIN_ROLES: dict[str, dict[str, str]] = {
    "Администратор": _matrix("admin", "admin"),
    "Аналитик": _matrix("write", "deny"),
    "Аудитор": _matrix("read", "deny"),
}
#: Группа → роль, которая ей назначена при создании.
BUILTIN_GROUPS: dict[str, str] = {
    "Администраторы": "Администратор",
    "Аналитики": "Аналитик",
    "Аудиторы": "Аудитор",
}
_ADMIN_ROLE = "Администратор"


def rank(level: str) -> int:
    return LEVELS.index(level)


def allows(access: Access, area: str, level: str) -> bool:
    """Хватает ли у пользователя в области `area` уровня не ниже `level`."""
    return rank(access.get(area, "deny")) >= rank(level)


def access_for(db: Session, user_id: int) -> Access:
    """Максимум по группам пользователя; нет групп — везде `deny`."""
    access: Access = dict.fromkeys(AREAS, "deny")
    rows = db.execute(
        select(AccessRoleLevel.area, AccessRoleLevel.level)
        .join(AccessGroup, AccessGroup.role_id == AccessRoleLevel.role_id)
        .join(AccessMembership, AccessMembership.group_id == AccessGroup.id)
        .where(AccessMembership.user_id == user_id)
    )
    for area, level in rows:
        if area in access and rank(level) > rank(access[area]):
            access[area] = level
    return access


def ensure_builtin(db: Session) -> None:
    """Три встроенные роли и три группы — идемпотентно, при каждом старте API.

    Существующие роли не перезаписываются, кроме «Администратора»: его
    матрица всегда полная. Существующие группы не трогаются (владелец мог
    назначить им другую роль)."""
    roles = {r.name: r for r in db.scalars(select(AccessRole).where(AccessRole.name.in_(BUILTIN_ROLES)))}
    for name, matrix in BUILTIN_ROLES.items():
        role = roles.get(name)
        if role is None:
            role = roles[name] = AccessRole(name=name, description="", builtin=True)
            role.levels = [AccessRoleLevel(area=a, level=lv) for a, lv in matrix.items()]
            db.add(role)
        elif name == _ADMIN_ROLE:
            have = {lv.area: lv for lv in role.levels}
            for area, level in matrix.items():
                if area in have:
                    have[area].level = level
                else:
                    role.levels.append(AccessRoleLevel(area=area, level=level))
    db.flush()
    existing = set(db.scalars(select(AccessGroup.name).where(AccessGroup.name.in_(BUILTIN_GROUPS))))
    for group_name, role_name in BUILTIN_GROUPS.items():
        if group_name not in existing:
            db.add(AccessGroup(name=group_name, source="local", role_id=roles[role_name].id))
    db.commit()
