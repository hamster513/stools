"""Роли, группы и членство: ручки /api/settings/roles и /api/settings/groups.

Защита от самоблокировки (спека ролей §2) проверяется через HTTP: актор —
`tester` из встроенной группы «Администраторы» (фикстура auth_client)."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.models import AccessGroup, AccessMembership, AccessRole, AppUser
from api.platform.services import access as svc

ADMINS = "Администраторы"
LAST_ADMIN = "нельзя оставить систему без администратора"
SELF_LOCKOUT = "нельзя снять права с себя"


def _role_id(client: TestClient, name: str) -> int:
    return next(r["id"] for r in client.get("/api/settings/roles").json() if r["name"] == name)


def _group(client: TestClient, name: str) -> dict[str, Any]:
    return next(g for g in client.get("/api/settings/groups").json() if g["name"] == name)


def _member_ids(client: TestClient, group_id: int) -> list[int]:
    return [m["user_id"] for m in client.get(f"/api/settings/groups/{group_id}/members").json()]


def _put_members(client: TestClient, group_id: int, user_ids: list[int]) -> Any:
    return client.put(f"/api/settings/groups/{group_id}/members", json={"user_ids": user_ids})


def _put_group(client: TestClient, group: dict[str, Any], role_id: int) -> Any:
    return client.put(
        f"/api/settings/groups/{group['id']}",
        json={"name": group["name"], "external_name": group["external_name"], "role_id": role_id},
    )


# --- роли ---------------------------------------------------------------------------


def test_builtin_roles_listed(auth_client: TestClient) -> None:
    roles = {r["name"]: r for r in auth_client.get("/api/settings/roles").json()}
    assert set(roles) == {"Администратор", "Аналитик", "Аудитор"}
    admin = roles["Администратор"]
    assert admin["builtin"] is True and admin["groups"] == 1
    assert set(admin["levels"]) == {"attack", "siem", "vm", "ad", "ksc", "assets", "toolbox", "irp", "platform"}
    assert set(admin["levels"].values()) == {"admin"}


def test_role_crud_with_matrix(auth_client: TestClient) -> None:
    created = auth_client.post(
        "/api/settings/roles",
        json={"name": "Охотник", "description": "SIEM", "levels": {"siem": "write", "vm": "read", "ad": "deny"}},
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["builtin"] is False and body["groups"] == 0 and body["description"] == "SIEM"
    # Недостающие области — deny: матрица в ответе всегда полная.
    assert body["levels"]["siem"] == "write" and body["levels"]["vm"] == "read"
    assert body["levels"]["ad"] == "deny" and body["levels"]["platform"] == "deny"
    assert len(body["levels"]) == 9

    changed = auth_client.put(
        f"/api/settings/roles/{body['id']}",
        json={"name": "Охотник 2", "description": "", "levels": {"siem": "admin", "platform": "read"}},
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["name"] == "Охотник 2"
    assert changed.json()["levels"]["siem"] == "admin" and changed.json()["levels"]["vm"] == "deny"
    assert changed.json()["levels"]["platform"] == "read"

    assert auth_client.delete(f"/api/settings/roles/{body['id']}").status_code == 204
    assert all(r["name"] != "Охотник 2" for r in auth_client.get("/api/settings/roles").json())


def test_role_stores_only_non_deny_rows(auth_client: TestClient, db_session: Session) -> None:
    created = auth_client.post("/api/settings/roles", json={"name": "Узкая", "levels": {"siem": "read", "vm": "deny"}})
    role = db_session.get(AccessRole, created.json()["id"])
    assert role is not None and {(lv.area, lv.level) for lv in role.levels} == {("siem", "read")}


@pytest.mark.parametrize("levels", [
    {"platform": "write"},
    {"nonexistent": "read"},
    {"siem": "superuser"},
])
def test_role_rejects_bad_matrix(auth_client: TestClient, levels: dict[str, str]) -> None:
    assert auth_client.post("/api/settings/roles", json={"name": "Плохая", "levels": levels}).status_code == 422
    good = auth_client.post("/api/settings/roles", json={"name": "Хорошая", "levels": {"siem": "read"}}).json()
    assert auth_client.put(
        f"/api/settings/roles/{good['id']}", json={"name": "Хорошая", "levels": levels},
    ).status_code == 422


def test_role_name_must_be_unique_and_nonempty(auth_client: TestClient) -> None:
    assert auth_client.post("/api/settings/roles", json={"name": "Аудитор", "levels": {}}).status_code == 409
    assert auth_client.post("/api/settings/roles", json={"name": "", "levels": {}}).status_code == 422
    other = auth_client.post("/api/settings/roles", json={"name": "Другая", "levels": {}}).json()
    renamed = auth_client.put(f"/api/settings/roles/{other['id']}", json={"name": "Аналитик", "levels": {}})
    assert renamed.status_code == 409


def test_builtin_admin_role_is_frozen(auth_client: TestClient) -> None:
    admin_id = _role_id(auth_client, "Администратор")
    edit = auth_client.put(f"/api/settings/roles/{admin_id}", json={"name": "Администратор", "levels": {"siem": "read"}})
    assert edit.status_code == 409
    assert auth_client.delete(f"/api/settings/roles/{admin_id}").status_code == 409
    admin = next(r for r in auth_client.get("/api/settings/roles").json() if r["id"] == admin_id)
    assert set(admin["levels"].values()) == {"admin"}


def test_other_builtin_roles_editable_but_not_deletable(auth_client: TestClient) -> None:
    auditor = _role_id(auth_client, "Аудитор")
    edit = auth_client.put(f"/api/settings/roles/{auditor}", json={"name": "Аудитор", "levels": {"siem": "write"}})
    assert edit.status_code == 200 and edit.json()["levels"]["siem"] == "write"
    assert auth_client.delete(f"/api/settings/roles/{auditor}").status_code == 409


def test_builtin_role_cannot_be_renamed_but_custom_can(auth_client: TestClient) -> None:
    analyst = _role_id(auth_client, "Аналитик")
    renamed = auth_client.put(f"/api/settings/roles/{analyst}", json={"name": "Аналитик 2", "levels": {"siem": "read"}})
    assert renamed.status_code == 409 and renamed.json()["detail"] == svc.BUILTIN_RENAME
    assert next(r for r in auth_client.get("/api/settings/roles").json() if r["id"] == analyst)["name"] == "Аналитик"
    renamed_admin = auth_client.put(f"/api/settings/roles/{_role_id(auth_client, 'Администратор')}", json={"name": "Админ", "levels": {}})
    assert renamed_admin.status_code == 409
    custom = auth_client.post("/api/settings/roles", json={"name": "Своя", "levels": {}}).json()
    ok = auth_client.put(f"/api/settings/roles/{custom['id']}", json={"name": "Своя 2", "levels": {}})
    assert ok.status_code == 200 and ok.json()["name"] == "Своя 2"


def test_role_assigned_to_group_is_not_deletable(auth_client: TestClient) -> None:
    role = auth_client.post("/api/settings/roles", json={"name": "Занятая", "levels": {"siem": "read"}}).json()
    group = auth_client.post("/api/settings/groups", json={"name": "Г", "source": "local", "role_id": role["id"]})
    assert group.status_code == 201
    denied = auth_client.delete(f"/api/settings/roles/{role['id']}")
    assert denied.status_code == 409
    assert next(r for r in auth_client.get("/api/settings/roles").json() if r["id"] == role["id"])["groups"] == 1


def test_delete_role_without_groups(auth_client: TestClient) -> None:
    role = auth_client.post("/api/settings/roles", json={"name": "Одинокая", "levels": {}}).json()
    assert auth_client.delete(f"/api/settings/roles/{role['id']}").status_code == 204


def test_missing_role_is_404(auth_client: TestClient) -> None:
    assert auth_client.put("/api/settings/roles/9999", json={"name": "x", "levels": {}}).status_code == 404
    assert auth_client.delete("/api/settings/roles/9999").status_code == 404


# --- группы -------------------------------------------------------------------------


def test_group_crud_and_members(auth_client: TestClient, make_user: Callable[..., AppUser]) -> None:
    anna, boris = make_user("anna", {"siem": "read"}), make_user("boris", {})
    role_id = _role_id(auth_client, "Аналитик")
    created = auth_client.post("/api/settings/groups", json={"name": "Охотники", "source": "local", "role_id": role_id})
    assert created.status_code == 201, created.text
    group = created.json()
    assert group["role_name"] == "Аналитик" and group["members"] == 0
    assert group["source"] == "local" and group["external_name"] is None

    put = _put_members(auth_client, group["id"], [anna.id, boris.id])
    assert put.status_code == 200, put.text
    assert sorted(m["login"] for m in put.json()) == ["anna", "boris"]
    members = auth_client.get(f"/api/settings/groups/{group['id']}/members").json()
    assert sorted(m["user_id"] for m in members) == sorted([anna.id, boris.id])
    assert set(members[0]) == {"user_id", "login", "display_name", "auth_source"}
    assert _group(auth_client, "Охотники")["members"] == 2

    # Полная замена, а не добавление.
    _put_members(auth_client, group["id"], [boris.id])
    assert _member_ids(auth_client, group["id"]) == [boris.id]

    changed = auth_client.put(
        f"/api/settings/groups/{group['id']}",
        json={"name": "Охотники 2", "external_name": None, "role_id": _role_id(auth_client, "Аудитор")},
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["name"] == "Охотники 2" and changed.json()["role_name"] == "Аудитор"
    assert changed.json()["source"] == "local" and changed.json()["members"] == 1

    assert auth_client.delete(f"/api/settings/groups/{group['id']}").status_code == 204
    assert all(g["name"] != "Охотники 2" for g in auth_client.get("/api/settings/groups").json())


def test_group_validation(auth_client: TestClient) -> None:
    role_id = _role_id(auth_client, "Аналитик")
    post = auth_client.post
    assert post("/api/settings/groups", json={"name": "О", "source": "oidc", "role_id": role_id}).status_code == 422
    local_with_ext = {"name": "Л", "source": "local", "external_name": "x", "role_id": role_id}
    assert post("/api/settings/groups", json=local_with_ext).status_code == 422
    assert post("/api/settings/groups", json={"name": "Н", "source": "ldap", "role_id": role_id}).status_code == 422
    assert post("/api/settings/groups", json={"name": "Р", "source": "local", "role_id": 9999}).status_code == 422
    assert post("/api/settings/groups", json={"name": ADMINS, "source": "local", "role_id": role_id}).status_code == 409
    first = post("/api/settings/groups", json={"name": "F1", "source": "oidc", "external_name": "stools-x", "role_id": role_id})
    assert first.status_code == 201
    dup = post("/api/settings/groups", json={"name": "F2", "source": "oidc", "external_name": "stools-x", "role_id": role_id})
    assert dup.status_code == 409
    # source не меняется: у local-группы external_name задавать нельзя, у oidc-группы — обязателен.
    local = _group(auth_client, "Аналитики")
    bad_local = auth_client.put(
        f"/api/settings/groups/{local['id']}", json={"name": "Аналитики", "external_name": "z", "role_id": role_id},
    )
    assert bad_local.status_code == 422
    bad_oidc = auth_client.put(
        f"/api/settings/groups/{first.json()['id']}", json={"name": "F1", "external_name": None, "role_id": role_id},
    )
    assert bad_oidc.status_code == 422
    clash = auth_client.put(f"/api/settings/groups/{local['id']}", json={"name": ADMINS, "external_name": None, "role_id": role_id})
    assert clash.status_code == 409


def test_group_name_fits_the_column(auth_client: TestClient) -> None:
    """Имя группы — до 255 символов, как столбец: перенесённые из OIDC длинные имена можно править."""
    role_id = _role_id(auth_client, "Аналитик")
    long_name = "г" * 255
    created = auth_client.post("/api/settings/groups", json={"name": long_name, "source": "local", "role_id": role_id})
    assert created.status_code == 201, created.text
    renamed = auth_client.put(
        f"/api/settings/groups/{created.json()['id']}", json={"name": "д" * 255, "external_name": None, "role_id": role_id},
    )
    assert renamed.status_code == 200, renamed.text
    too_long = {"name": "г" * 256, "source": "local", "role_id": role_id}
    assert auth_client.post("/api/settings/groups", json=too_long).status_code == 422


def test_oidc_group_members_are_not_editable(auth_client: TestClient, test_user: AppUser) -> None:
    role_id = _role_id(auth_client, "Аналитик")
    group = auth_client.post(
        "/api/settings/groups", json={"name": "FAM", "source": "oidc", "external_name": "stools-a", "role_id": role_id},
    ).json()
    assert _put_members(auth_client, group["id"], [test_user.id]).status_code == 409
    assert _member_ids(auth_client, group["id"]) == []


def test_members_reject_unknown_user_and_group(auth_client: TestClient) -> None:
    analysts = _group(auth_client, "Аналитики")
    assert _put_members(auth_client, analysts["id"], [9999]).status_code == 422
    assert _put_members(auth_client, 9999, []).status_code == 404
    assert auth_client.get("/api/settings/groups/9999/members").status_code == 404
    assert auth_client.put("/api/settings/groups/9999", json={"name": "x", "role_id": 1}).status_code == 404
    assert auth_client.delete("/api/settings/groups/9999").status_code == 404


def test_delete_empty_group_ok(auth_client: TestClient) -> None:
    auditors = _group(auth_client, "Аудиторы")
    assert auth_client.delete(f"/api/settings/groups/{auditors['id']}").status_code == 204


# --- самоблокировка -----------------------------------------------------------------


def test_cannot_delete_group_of_last_admin(auth_client: TestClient, test_user: AppUser) -> None:
    admins = _group(auth_client, ADMINS)
    denied = auth_client.delete(f"/api/settings/groups/{admins['id']}")
    assert denied.status_code == 409 and denied.json()["detail"] == LAST_ADMIN
    # Откат: группа и её член на месте.
    assert _member_ids(auth_client, admins["id"]) == [test_user.id]


def test_cannot_empty_group_of_last_admin(auth_client: TestClient, test_user: AppUser) -> None:
    admins = _group(auth_client, ADMINS)
    denied = _put_members(auth_client, admins["id"], [])
    assert denied.status_code == 409 and denied.json()["detail"] == LAST_ADMIN
    assert _member_ids(auth_client, admins["id"]) == [test_user.id]


def test_cannot_demote_role_of_last_admin_group(auth_client: TestClient) -> None:
    admins = _group(auth_client, ADMINS)
    denied = _put_group(auth_client, admins, _role_id(auth_client, "Аудитор"))
    assert denied.status_code == 409 and denied.json()["detail"] == LAST_ADMIN
    assert _group(auth_client, ADMINS)["role_name"] == "Администратор"


def test_cannot_strip_own_admin_even_if_others_remain(
    auth_client: TestClient, make_user: Callable[..., AppUser], test_user: AppUser,
) -> None:
    make_user("boss", {"platform": "admin"})  # другой администратор через свою группу и роль
    admins = _group(auth_client, ADMINS)

    removed = _put_members(auth_client, admins["id"], [])
    assert removed.status_code == 409 and removed.json()["detail"] == SELF_LOCKOUT
    assert _member_ids(auth_client, admins["id"]) == [test_user.id]

    demoted = _put_group(auth_client, admins, _role_id(auth_client, "Аудитор"))
    assert demoted.status_code == 409 and demoted.json()["detail"] == SELF_LOCKOUT

    deleted = auth_client.delete(f"/api/settings/groups/{admins['id']}")
    assert deleted.status_code == 409 and deleted.json()["detail"] == SELF_LOCKOUT
    assert _group(auth_client, ADMINS)["members"] == 1


def _owner_role(client: TestClient, member_ids: list[int]) -> dict[str, Any]:
    """Роль «Хозяин» (platform=admin), назначенная группе «Хозяева» с участниками; возвращает роль."""
    role = client.post("/api/settings/roles", json={"name": "Хозяин", "levels": {"platform": "admin"}}).json()
    group = client.post("/api/settings/groups", json={"name": "Хозяева", "source": "local", "role_id": role["id"]}).json()
    assert _put_members(client, group["id"], member_ids).status_code == 200
    return role


def test_cannot_lower_own_platform_via_role_edit(
    auth_client: TestClient, make_user: Callable[..., AppUser], test_user: AppUser,
) -> None:
    make_user("boss", {"platform": "admin"})
    role = _owner_role(auth_client, [test_user.id])
    # Из встроенной группы актор выходит спокойно: «Хозяева» держат его администратором.
    assert _put_members(auth_client, _group(auth_client, ADMINS)["id"], []).status_code == 200
    denied = auth_client.put(f"/api/settings/roles/{role['id']}", json={"name": "Хозяин", "levels": {"platform": "read"}})
    assert denied.status_code == 409 and denied.json()["detail"] == SELF_LOCKOUT
    assert next(r for r in auth_client.get("/api/settings/roles").json() if r["id"] == role["id"])["levels"]["platform"] == "admin"


def test_cannot_lower_role_of_last_admin(auth_client: TestClient, test_user: AppUser) -> None:
    role = _owner_role(auth_client, [test_user.id])
    assert _put_members(auth_client, _group(auth_client, ADMINS)["id"], []).status_code == 200
    denied = auth_client.put(f"/api/settings/roles/{role['id']}", json={"name": "Хозяин", "levels": {"platform": "read"}})
    assert denied.status_code == 409 and denied.json()["detail"] == LAST_ADMIN


def test_inactive_admin_does_not_count(
    auth_client: TestClient, make_user: Callable[..., AppUser], db_session: Session,
) -> None:
    boss = make_user("boss", {"platform": "admin"})
    boss.is_active = False
    db_session.commit()
    admins = _group(auth_client, ADMINS)
    # Заблокированный «администратор» не в счёт: актор по-прежнему единственный.
    denied = auth_client.delete(f"/api/settings/groups/{admins['id']}")
    assert denied.status_code == 409 and denied.json()["detail"] == LAST_ADMIN


# --- set_user_groups ----------------------------------------------------------------


def test_set_user_groups_replaces_only_local(
    auth_client: TestClient, db_session: Session, make_user: Callable[..., AppUser], test_user: AppUser,
) -> None:
    user = make_user("anna", {})
    local_a = _group(auth_client, "Аналитики")["id"]
    local_b = _group(auth_client, "Аудиторы")["id"]
    role_id = _role_id(auth_client, "Аналитик")
    fam = auth_client.post(
        "/api/settings/groups", json={"name": "FAM", "source": "oidc", "external_name": "stools-a", "role_id": role_id},
    ).json()["id"]
    db_session.add(AccessMembership(user_id=user.id, group_id=fam))
    db_session.commit()

    def own() -> set[int]:
        db_session.expire_all()
        return set(db_session.scalars(select(AccessMembership.group_id).where(AccessMembership.user_id == user.id)))

    own_before = own()
    assert fam in own_before
    svc.set_user_groups(db_session, test_user, user.id, [local_a, local_b, local_a])
    assert own() == {local_a, local_b, fam}
    svc.set_user_groups(db_session, test_user, user.id, [local_b])
    assert own() == {local_b, fam}
    svc.set_user_groups(db_session, test_user, user.id, [])
    assert own() == {fam}


def test_set_user_groups_rejects_oidc_and_unknown(
    auth_client: TestClient, db_session: Session, test_user: AppUser,
) -> None:
    role_id = _role_id(auth_client, "Аналитик")
    fam = auth_client.post(
        "/api/settings/groups", json={"name": "FAM", "source": "oidc", "external_name": "stools-a", "role_id": role_id},
    ).json()["id"]
    for bad in ([fam], [9999]):
        with pytest.raises(HTTPException) as exc:
            svc.set_user_groups(db_session, test_user, test_user.id, bad)
        assert exc.value.status_code == 422
    with pytest.raises(HTTPException) as exc:
        svc.set_user_groups(db_session, test_user, 9999, [])
    assert exc.value.status_code == 404


def test_set_user_groups_guards_last_admin_and_self(
    auth_client: TestClient, db_session: Session, make_user: Callable[..., AppUser], test_user: AppUser,
) -> None:
    with pytest.raises(HTTPException) as exc:
        svc.set_user_groups(db_session, test_user, test_user.id, [])
    assert (exc.value.status_code, exc.value.detail) == (409, LAST_ADMIN)
    boss = make_user("boss", {"platform": "admin"})
    with pytest.raises(HTTPException) as exc:
        svc.set_user_groups(db_session, test_user, test_user.id, [])
    assert (exc.value.status_code, exc.value.detail) == (409, SELF_LOCKOUT)
    # Откат: членство актора на месте. Другого администратора снять можно — актор остаётся.
    admins = db_session.scalars(select(AccessGroup).where(AccessGroup.name == ADMINS)).one()
    assert db_session.get(AccessMembership, (test_user.id, admins.id)) is not None
    svc.set_user_groups(db_session, test_user, boss.id, [])
    assert db_session.scalars(select(AccessMembership).where(AccessMembership.user_id == boss.id)).all() == []


# --- границы прав -------------------------------------------------------------------


def test_platform_read_can_list_but_not_write(client_as: Callable[..., TestClient]) -> None:
    reader = client_as({"platform": "read"})
    assert reader.get("/api/settings/roles").status_code == 200
    assert reader.get("/api/settings/groups").status_code == 200
    assert reader.post("/api/settings/roles", json={"name": "x", "levels": {}}).status_code == 403
    assert reader.post("/api/settings/groups", json={"name": "x", "source": "local", "role_id": 1}).status_code == 403
    assert _put_members(reader, 1, []).status_code == 403
    assert reader.delete("/api/settings/groups/1").status_code == 403
