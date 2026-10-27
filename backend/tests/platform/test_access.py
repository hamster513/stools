"""Права доступа: максимум по группам и встроенные роли (спека ролей §1–§2)."""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select

from api.db.models import (
    AREAS,
    AccessGroup,
    AccessMembership,
    AccessRole,
    AccessRoleLevel,
    AppUser,
)
from api.platform.services.access import (
    BUILTIN_GROUPS,
    BUILTIN_ROLES,
    access_for,
    allows,
    ensure_builtin,
    rank,
)


def _user(db: Any, login: str = "u1") -> AppUser:
    user = AppUser(login=login, password_hash="x")
    db.add(user)
    db.commit()
    return user


def _role(db: Any, name: str, levels: dict[str, str]) -> AccessRole:
    role = AccessRole(name=name, description="", builtin=False)
    role.levels = [AccessRoleLevel(area=area, level=level) for area, level in levels.items()]
    db.add(role)
    db.commit()
    return role


def _group(db: Any, name: str, role: AccessRole, user: AppUser) -> None:
    group = AccessGroup(name=name, source="local", role_id=role.id)
    db.add(group)
    db.flush()
    db.add(AccessMembership(user_id=user.id, group_id=group.id))
    db.commit()


def test_access_is_max_over_groups(db_session: Any) -> None:
    user = _user(db_session)
    _group(db_session, "A", _role(db_session, "ра", {"siem": "write", "vm": "read"}), user)
    _group(db_session, "B", _role(db_session, "рб", {"siem": "read", "vm": "admin", "platform": "read"}), user)
    access = access_for(db_session, user.id)
    assert access == {
        "attack": "deny", "siem": "write", "vm": "admin", "ad": "deny", "ksc": "deny",
        "assets": "deny", "toolbox": "deny", "platform": "read",
    }
    assert set(access) == set(AREAS)


def test_no_groups_is_all_deny(db_session: Any) -> None:
    user = _user(db_session)
    assert set(access_for(db_session, user.id).values()) == {"deny"}


def test_other_users_groups_do_not_leak(db_session: Any) -> None:
    mine, other = _user(db_session, "mine"), _user(db_session, "other")
    _group(db_session, "G", _role(db_session, "р", {"vm": "admin"}), other)
    assert access_for(db_session, mine.id)["vm"] == "deny"


def test_rank_and_allows() -> None:
    assert [rank(x) for x in ("deny", "read", "write", "admin")] == [0, 1, 2, 3]
    access = {area: "deny" for area in AREAS} | {"siem": "write"}
    assert allows(access, "siem", "read") and allows(access, "siem", "write")
    assert not allows(access, "siem", "admin")
    assert not allows(access, "vm", "read")


def test_ensure_builtin_is_idempotent(db_session: Any) -> None:
    ensure_builtin(db_session)
    ensure_builtin(db_session)
    assert db_session.scalar(select(func.count()).select_from(AccessRole)) == 3
    assert {g.name for g in db_session.scalars(select(AccessGroup))} == {"Администраторы", "Аналитики", "Аудиторы"}
    assert all(r.builtin for r in db_session.scalars(select(AccessRole)))
    for group_name, role_name in BUILTIN_GROUPS.items():
        group = db_session.scalar(select(AccessGroup).where(AccessGroup.name == group_name))
        assert group.role.name == role_name and group.source == "local" and group.external_name is None


def test_builtin_levels(db_session: Any) -> None:
    ensure_builtin(db_session)
    assert set(BUILTIN_ROLES) == {"Администратор", "Аналитик", "Аудитор"}
    levels = {
        role.name: {lv.area: lv.level for lv in role.levels}
        for role in db_session.scalars(select(AccessRole))
    }
    for name, module_level, platform_level in (
        ("Администратор", "admin", "admin"), ("Аналитик", "write", "deny"), ("Аудитор", "read", "deny"),
    ):
        assert set(levels[name]) == set(AREAS)
        assert {a: lv for a, lv in levels[name].items() if a != "platform"} == {
            a: module_level for a in AREAS if a != "platform"
        }
        assert levels[name]["platform"] == platform_level


def test_ensure_builtin_keeps_edits_to_analyst_but_restores_admin(db_session: Any) -> None:
    ensure_builtin(db_session)
    roles = {r.name: r for r in db_session.scalars(select(AccessRole))}
    next(lv for lv in roles["Аналитик"].levels if lv.area == "vm").level = "admin"
    next(lv for lv in roles["Администратор"].levels if lv.area == "ksc").level = "deny"
    db_session.commit()
    ensure_builtin(db_session)
    db_session.expire_all()
    roles = {r.name: r for r in db_session.scalars(select(AccessRole))}
    assert {lv.area: lv.level for lv in roles["Аналитик"].levels}["vm"] == "admin"
    assert {lv.area: lv.level for lv in roles["Администратор"].levels}["ksc"] == "admin"


def test_ensure_builtin_does_not_resurrect_deleted_groups(db_session: Any) -> None:
    ensure_builtin(db_session)
    for name in ("Аудиторы", "Администраторы"):
        db_session.delete(db_session.scalar(select(AccessGroup).where(AccessGroup.name == name)))
    db_session.commit()
    ensure_builtin(db_session)
    assert {g.name for g in db_session.scalars(select(AccessGroup))} == {"Аналитики"}
    assert db_session.scalar(select(func.count()).select_from(AccessRole)) == 3


def test_ensure_builtin_does_not_adopt_custom_role_with_builtin_name(db_session: Any) -> None:
    custom = AccessRole(name="Аналитик", description="своя", builtin=False)
    db_session.add(custom)
    db_session.commit()
    ensure_builtin(db_session)
    db_session.expire_all()
    roles = {r.name: r.builtin for r in db_session.scalars(select(AccessRole))}
    assert roles == {"Аналитик": False, "Администратор": True, "Аудитор": True}
    assert db_session.get(AccessRole, custom.id).levels == []
    # Группа сеется только вместе со своей ролью: для занятого имени её нет.
    assert {g.name for g in db_session.scalars(select(AccessGroup))} == {"Администраторы", "Аудиторы"}
