"""Права доступа: роли как матрицы «область × уровень», назначенные группам.

Эффективный уровень пользователя в области — максимум по всем его группам.
Кэша между запросами нет: смена роли или группы действует со следующего
запроса (спека ролей §2).
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Literal

from fastapi import HTTPException, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import delete, func, select
from sqlalchemy.orm import InstrumentedAttribute, Session

from api.db.models import (
    AREAS,
    LEVELS,
    MODULE_IDS,
    AccessGroup,
    AccessMembership,
    AccessRole,
    AccessRoleLevel,
    AppUser,
)

logger = logging.getLogger(__name__)

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


def groups_of(db: Session, user_id: int) -> list[AccessGroup]:
    """Группы пользователя по имени."""
    return list(db.scalars(
        select(AccessGroup)
        .join(AccessMembership, AccessMembership.group_id == AccessGroup.id)
        .where(AccessMembership.user_id == user_id)
        .order_by(AccessGroup.name)
    ))


def ensure_builtin(db: Session) -> None:
    """Три встроенные роли — при каждом старте API; три встроенные группы — только вместе с ролью.

    Роли ищутся по имени среди `builtin`; существующие не перезаписываются,
    кроме «Администратора»: его матрица всегда полная. Группа сеется лишь
    для только что созданной роли (чистая схема) и никогда не возвращается:
    владелец мог удалить, переименовать её или назначить другую роль.
    Обычная роль с именем встроенной не присваивается — запись об этом в
    лог, встроенная роль не создаётся (имя уникально)."""
    roles = {
        r.name: r
        for r in db.scalars(select(AccessRole).where(AccessRole.name.in_(BUILTIN_ROLES), AccessRole.builtin.is_(True)))
    }
    taken = set(db.scalars(select(AccessRole.name).where(AccessRole.name.in_(BUILTIN_ROLES)))) - roles.keys()
    created: set[str] = set()
    for name, matrix in BUILTIN_ROLES.items():
        role = roles.get(name)
        if role is None and name in taken:
            logger.error("роль «%s» уже занята обычной ролью — встроенная не создана", name)
        elif role is None:
            role = roles[name] = AccessRole(name=name, description="", builtin=True)
            role.levels = [AccessRoleLevel(area=a, level=lv) for a, lv in matrix.items()]
            db.add(role)
            created.add(name)
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
        if role_name in created and group_name not in existing:
            db.add(AccessGroup(name=group_name, source="local", role_id=roles[role_name].id))
    db.commit()


# --- защита от самоблокировки --------------------------------------------------------

LAST_ADMIN = "нельзя оставить систему без администратора"
SELF_LOCKOUT = "нельзя снять права с себя"
BUILTIN_RENAME = "встроенную роль нельзя переименовать"


def _conflict(detail: str) -> HTTPException:
    return HTTPException(status.HTTP_409_CONFLICT, detail=detail)


def _active_platform_admins(db: Session) -> int:
    """Активные пользователи, у которых хоть одна группа даёт `platform = admin`."""
    return db.scalar(
        select(func.count(func.distinct(AppUser.id)))
        .join(AccessMembership, AccessMembership.user_id == AppUser.id)
        .join(AccessGroup, AccessGroup.id == AccessMembership.group_id)
        .join(AccessRoleLevel, AccessRoleLevel.role_id == AccessGroup.role_id)
        .where(AppUser.is_active.is_(True), AccessRoleLevel.area == "platform", AccessRoleLevel.level == "admin")
    ) or 0


def guard_last_admin(db: Session, actor_id: int, *, after: Callable[[], None]) -> None:
    """Выполняет `after()` и проверяет, что система не осталась без администратора.

    Правки идут в той же транзакции и сбрасываются на сервер (flush), но не
    фиксируются: не прошла проверка — rollback и 409, иначе коммит за
    вызывающим. Две проверки: в системе остался хоть один активный
    пользователь с `platform = admin`, и сам актор не опустил себя ниже него
    (даже когда другие администраторы есть). Любая другая ошибка тоже
    откатывает транзакцию."""
    try:
        after()
        db.flush()
        if _active_platform_admins(db) == 0:
            raise _conflict(LAST_ADMIN)
        if not allows(access_for(db, actor_id), "platform", "admin"):
            raise _conflict(SELF_LOCKOUT)
    except Exception:
        db.rollback()
        #: Откат сбрасывает все загруженные объекты, в том числе актора, а журнал действий
        #: читает его логин уже после закрытия сессии запроса.
        db.get(AppUser, actor_id)
        raise


# --- роли ---------------------------------------------------------------------------


class RoleIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str = ""
    #: область → уровень; отсутствующая область — `deny`.
    levels: dict[str, str]

    @field_validator("levels")
    @classmethod
    def _levels(cls, value: dict[str, str]) -> dict[str, str]:
        for area, level in value.items():
            if area not in AREAS:
                raise ValueError(f"неизвестная область: {area}")
            if level not in LEVELS:
                raise ValueError(f"неизвестный уровень: {level}")
        if value.get("platform") == "write":
            raise ValueError("для платформы уровень write не используется")
        return value


class RoleView(RoleIn):
    id: int
    builtin: bool
    groups: int


def _role(db: Session, role_id: int) -> AccessRole:
    role = db.get(AccessRole, role_id)
    if role is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="роль не найдена")
    return role


def _role_view(role: AccessRole, groups: int) -> RoleView:
    levels = dict.fromkeys(AREAS, "deny") | {lv.area: lv.level for lv in role.levels}
    return RoleView(
        id=role.id, name=role.name, description=role.description, builtin=role.builtin, levels=levels, groups=groups,
    )


def _group_counts(db: Session) -> dict[int, int]:
    """Роль → число групп, которым она назначена."""
    return dict(db.execute(select(AccessGroup.role_id, func.count()).group_by(AccessGroup.role_id)).tuples().all())


def _check_role_name(db: Session, name: str, *, exclude_id: int | None = None) -> None:
    query = select(AccessRole.id).where(AccessRole.name == name)
    if exclude_id is not None:
        query = query.where(AccessRole.id != exclude_id)
    if db.scalar(query) is not None:
        raise _conflict("роль с таким именем уже есть")


def _apply_levels(role: AccessRole, levels: dict[str, str]) -> None:
    """Приводит строки роли к матрице: хранятся только не-`deny` (нет строки = запрет).

    Строки правятся на месте, а не пересоздаются: пересозданная строка с тем же
    ключом (role_id, area) конфликтовала бы с удаляемой в одном flush."""
    wanted = {a: lv for a, lv in levels.items() if lv != "deny"}
    for row in list(role.levels):
        if row.area in wanted:
            row.level = wanted.pop(row.area)
        else:
            role.levels.remove(row)
    role.levels.extend(AccessRoleLevel(area=a, level=lv) for a, lv in wanted.items())


def list_roles(db: Session) -> list[RoleView]:
    counts = _group_counts(db)
    return [_role_view(r, counts.get(r.id, 0)) for r in db.scalars(select(AccessRole).order_by(AccessRole.name))]


def create_role(db: Session, actor: AppUser, payload: RoleIn) -> RoleView:
    _check_role_name(db, payload.name)
    role = AccessRole(name=payload.name, description=payload.description, builtin=False)
    _apply_levels(role, payload.levels)
    db.add(role)
    db.commit()
    return _role_view(role, 0)


def update_role(db: Session, actor: AppUser, role_id: int, payload: RoleIn) -> RoleView:
    role = _role(db, role_id)
    if role.builtin and role.name == _ADMIN_ROLE:
        raise _conflict("встроенную роль «Администратор» нельзя изменить")
    if role.builtin and payload.name != role.name:
        raise _conflict(BUILTIN_RENAME)
    _check_role_name(db, payload.name, exclude_id=role.id)

    def apply() -> None:
        role.name = payload.name
        role.description = payload.description
        _apply_levels(role, payload.levels)

    guard_last_admin(db, actor.id, after=apply)
    db.commit()
    return _role_view(role, _group_counts(db).get(role.id, 0))


def delete_role(db: Session, actor: AppUser, role_id: int) -> None:
    role = _role(db, role_id)
    if role.builtin:
        raise _conflict("встроенную роль нельзя удалить")
    if _group_counts(db).get(role.id):
        raise _conflict("роль назначена группе — сначала смените роль группы")
    guard_last_admin(db, actor.id, after=lambda: db.delete(role))
    db.commit()


# --- группы -------------------------------------------------------------------------


def _check_external(source: str, external_name: str | None) -> None:
    if source == "oidc" and not external_name:
        raise ValueError("у группы из OIDC нужно имя группы в claim")
    if source == "local" and external_name is not None:
        raise ValueError("имя группы в claim задаётся только у группы из OIDC")


class GroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    source: Literal["local", "oidc"]
    #: Значение claim провайдера; только у oidc-группы, и там обязательно.
    external_name: str | None = Field(default=None, max_length=255)
    role_id: int

    @model_validator(mode="after")
    def _external(self) -> GroupIn:
        _check_external(self.source, self.external_name)
        return self


class GroupPatch(BaseModel):
    """Источник группы не меняется: `external_name` сверяется в сервисе с сохранённым источником."""

    name: str = Field(min_length=1, max_length=64)
    external_name: str | None = Field(default=None, max_length=255)
    role_id: int


class GroupView(BaseModel):
    id: int
    name: str
    source: str
    external_name: str | None
    role_id: int
    role_name: str
    members: int


class MemberView(BaseModel):
    user_id: int
    login: str
    display_name: str | None
    auth_source: str


def _group(db: Session, group_id: int) -> AccessGroup:
    group = db.get(AccessGroup, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="группа не найдена")
    return group


def _member_counts(db: Session) -> dict[int, int]:
    return dict(db.execute(select(AccessMembership.group_id, func.count()).group_by(AccessMembership.group_id)).tuples().all())


def _group_view(group: AccessGroup, members: int) -> GroupView:
    return GroupView(
        id=group.id, name=group.name, source=group.source, external_name=group.external_name,
        role_id=group.role_id, role_name=group.role.name, members=members,
    )


def _require_role(db: Session, role_id: int) -> None:
    if db.get(AccessRole, role_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="роль не найдена")


def _check_group_names(db: Session, name: str, external_name: str | None, *, exclude_id: int | None = None) -> None:
    def taken(column: InstrumentedAttribute[str | None], value: str) -> bool:
        query = select(AccessGroup.id).where(column == value)
        if exclude_id is not None:
            query = query.where(AccessGroup.id != exclude_id)
        return db.scalar(query) is not None

    if taken(AccessGroup.name, name):
        raise _conflict("группа с таким именем уже есть")
    if external_name is not None and taken(AccessGroup.external_name, external_name):
        raise _conflict("группа с таким именем в claim уже есть")


def list_groups(db: Session) -> list[GroupView]:
    counts = _member_counts(db)
    return [_group_view(g, counts.get(g.id, 0)) for g in db.scalars(select(AccessGroup).order_by(AccessGroup.name))]


def create_group(db: Session, actor: AppUser, payload: GroupIn) -> GroupView:
    _require_role(db, payload.role_id)
    _check_group_names(db, payload.name, payload.external_name)
    group = AccessGroup(
        name=payload.name, source=payload.source, external_name=payload.external_name, role_id=payload.role_id,
    )
    db.add(group)
    db.commit()
    return _group_view(group, 0)


def update_group(db: Session, actor: AppUser, group_id: int, payload: GroupPatch) -> GroupView:
    group = _group(db, group_id)
    try:
        _check_external(group.source, payload.external_name)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    _require_role(db, payload.role_id)
    _check_group_names(db, payload.name, payload.external_name, exclude_id=group.id)

    def apply() -> None:
        group.name = payload.name
        group.external_name = payload.external_name
        group.role = _role(db, payload.role_id)

    guard_last_admin(db, actor.id, after=apply)
    db.commit()
    return _group_view(group, _member_counts(db).get(group.id, 0))


def delete_group(db: Session, actor: AppUser, group_id: int) -> None:
    group = _group(db, group_id)
    guard_last_admin(db, actor.id, after=lambda: db.delete(group))
    db.commit()


# --- членство -----------------------------------------------------------------------


def list_members(db: Session, group_id: int) -> list[MemberView]:
    _group(db, group_id)
    users = db.scalars(
        select(AppUser)
        .join(AccessMembership, AccessMembership.user_id == AppUser.id)
        .where(AccessMembership.group_id == group_id)
        .order_by(AppUser.login)
    )
    return [
        MemberView(user_id=u.id, login=u.login, display_name=u.display_name, auth_source=u.auth_source) for u in users
    ]


def set_members(db: Session, actor: AppUser, group_id: int, user_ids: list[int]) -> list[MemberView]:
    """Полная замена членов локальной группы. Членство в oidc-группе выдаёт вход."""
    group = _group(db, group_id)
    if group.source == "oidc":
        raise _conflict("членов группы из OIDC назначает провайдер при входе")
    wanted = set(user_ids)
    if wanted - set(db.scalars(select(AppUser.id).where(AppUser.id.in_(wanted)))):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="пользователь не найден")

    def apply() -> None:
        have = set(db.scalars(select(AccessMembership.user_id).where(AccessMembership.group_id == group_id)))
        if have - wanted:
            db.execute(delete(AccessMembership).where(
                AccessMembership.group_id == group_id, AccessMembership.user_id.in_(have - wanted),
            ))
        db.add_all(AccessMembership(user_id=uid, group_id=group_id) for uid in wanted - have)

    guard_last_admin(db, actor.id, after=apply)
    db.commit()
    return list_members(db, group_id)


def set_user_groups(db: Session, actor: AppUser, user_id: int, group_ids: list[int]) -> None:
    """Полная замена локального членства пользователя; членство в OIDC-группах не трогается."""
    if db.get(AppUser, user_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="пользователь не найден")
    wanted = set(group_ids)
    found = list(db.scalars(select(AccessGroup).where(AccessGroup.id.in_(wanted))))
    if len(found) != len(wanted):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="группа не найдена")
    if any(g.source != "local" for g in found):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="членство в группе из OIDC назначает провайдер")

    def apply() -> None:
        have = set(db.scalars(
            select(AccessMembership.group_id)
            .join(AccessGroup, AccessGroup.id == AccessMembership.group_id)
            .where(AccessMembership.user_id == user_id, AccessGroup.source == "local")
        ))
        if have - wanted:
            db.execute(delete(AccessMembership).where(
                AccessMembership.user_id == user_id, AccessMembership.group_id.in_(have - wanted),
            ))
        db.add_all(AccessMembership(user_id=user_id, group_id=gid) for gid in wanted - have)

    guard_last_admin(db, actor.id, after=apply)
    db.commit()
