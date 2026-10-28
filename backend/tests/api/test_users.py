"""Пользователи: роли, блокировка, защита себя и последнего администратора."""
from __future__ import annotations

import csv
import io
from collections.abc import Callable
from typing import Any

from fastapi.testclient import TestClient

from api.crypto import hash_token
from api.db.models import AREAS, SessionRow
from tests.api.conftest import TEST_LOGIN


def _group_id(client: TestClient, name: str) -> int:
    return next(g["id"] for g in client.get("/api/settings/groups").json() if g["name"] == name)


def _create(client: TestClient, login: str, group: str = "Аналитики") -> dict[str, Any]:
    response = client.post(
        "/api/settings/users",
        json={
            "login": login, "display_name": login.title(), "password": "pw123456",
            "group_ids": [_group_id(client, group)] if group else [],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_me_has_access_groups_and_name(auth_client: TestClient) -> None:
    body = auth_client.get("/api/auth/me").json()
    assert [(g["name"], g["source"]) for g in body.pop("groups")] == [("Администраторы", "local")]
    assert body == {
        "login": TEST_LOGIN,
        "display_name": None,
        "access": dict.fromkeys(AREAS, "admin"),
        "theme": "dark",
        "auth_source": "local",
    }


def test_create_list_patch_delete(auth_client: TestClient) -> None:
    created = _create(auth_client, "ann")
    assert "role" not in created
    assert [(g["name"], g["source"]) for g in created["groups"]] == [("Аналитики", "local")]
    assert created["access"]["siem"] == "write" and created["access"]["platform"] == "deny"
    assert created["is_active"] is True
    listed = {u["login"]: u for u in auth_client.get("/api/settings/users").json()}
    assert set(listed) == {TEST_LOGIN, "ann"}
    assert listed["ann"]["access"] == created["access"]
    assert [g["name"] for g in listed[TEST_LOGIN]["groups"]] == ["Администраторы"]
    assert listed[TEST_LOGIN]["access"] == dict.fromkeys(AREAS, "admin")
    patched = auth_client.patch(
        f"/api/settings/users/{created['id']}",
        json={"group_ids": [_group_id(auth_client, "Аудиторы")], "display_name": "Анна"},
    ).json()
    assert [g["name"] for g in patched["groups"]] == ["Аудиторы"]
    assert patched["access"]["siem"] == "read" and patched["display_name"] == "Анна"
    assert auth_client.delete(f"/api/settings/users/{created['id']}").status_code == 204
    assert [u["login"] for u in auth_client.get("/api/settings/users").json()] == [TEST_LOGIN]


def test_patch_without_group_ids_keeps_groups(auth_client: TestClient) -> None:
    created = _create(auth_client, "ann")
    patched = auth_client.patch(f"/api/settings/users/{created['id']}", json={"display_name": "Анна"}).json()
    assert [g["name"] for g in patched["groups"]] == ["Аналитики"]
    cleared = auth_client.patch(f"/api/settings/users/{created['id']}", json={"group_ids": []}).json()
    assert cleared["groups"] == [] and cleared["access"] == dict.fromkeys(AREAS, "deny")


def test_duplicate_login_and_bad_groups_are_refused(auth_client: TestClient, db_session: Any) -> None:
    from api.db.models import AppUser

    _create(auth_client, "ann")
    assert auth_client.post("/api/settings/users", json={"login": "ann", "password": "pw123456"}).status_code == 409
    # Неизвестная группа: 422, а пользователь не остаётся созданным.
    assert auth_client.post(
        "/api/settings/users", json={"login": "bob", "password": "pw123456", "group_ids": [999999]},
    ).status_code == 422
    db_session.expire_all()
    assert db_session.query(AppUser).filter_by(login="bob").one_or_none() is None


def test_oidc_group_cannot_be_assigned_by_hand(auth_client: TestClient) -> None:
    role = next(r for r in auth_client.get("/api/settings/roles").json() if r["name"] == "Аудитор")
    external = auth_client.post(
        "/api/settings/groups", json={"name": "FAM", "source": "oidc", "external_name": "fam", "role_id": role["id"]},
    ).json()
    refused = auth_client.post(
        "/api/settings/users", json={"login": "bob", "password": "pw123456", "group_ids": [external["id"]]},
    )
    assert refused.status_code == 422
    ann = _create(auth_client, "ann")
    assert auth_client.patch(f"/api/settings/users/{ann['id']}", json={"group_ids": [external["id"]]}).status_code == 422


def test_blocking_drops_sessions(auth_client: TestClient, client_as: Callable[[str], TestClient], db_session: Any) -> None:
    analyst = client_as("analyst")
    token = analyst.cookies["stools_session"]
    uid = next(u["id"] for u in auth_client.get("/api/settings/users").json() if u["login"] == "user-analyst")
    assert auth_client.patch(f"/api/settings/users/{uid}", json={"is_active": False}).json()["is_active"] is False
    assert db_session.get(SessionRow, hash_token(token)) is None
    assert analyst.get("/api/auth/me").status_code == 401


def test_cannot_block_delete_or_demote_self(auth_client: TestClient) -> None:
    me = next(u for u in auth_client.get("/api/settings/users").json() if u["login"] == TEST_LOGIN)
    assert auth_client.patch(f"/api/settings/users/{me['id']}", json={"is_active": False}).status_code == 409
    assert auth_client.delete(f"/api/settings/users/{me['id']}").status_code == 409
    demote = auth_client.patch(f"/api/settings/users/{me['id']}", json={"group_ids": [_group_id(auth_client, "Аналитики")]})
    assert demote.status_code == 409
    assert auth_client.get("/api/auth/me").json()["access"]["platform"] == "admin"


def test_last_admin_is_protected(auth_client: TestClient) -> None:
    other = _create(auth_client, "root2", group="Администраторы")
    analysts = [_group_id(auth_client, "Аналитики")]
    # Пока есть второй администратор, его можно понизить.
    assert auth_client.patch(f"/api/settings/users/{other['id']}", json={"group_ids": analysts}).status_code == 200
    # Один администратор остался (я сам): себя заблокировать нельзя.
    me = next(u for u in auth_client.get("/api/settings/users").json() if u["login"] == TEST_LOGIN)
    assert auth_client.patch(f"/api/settings/users/{me['id']}", json={"is_active": False}).status_code == 409


def test_demoting_self_is_refused_even_with_another_admin(auth_client: TestClient) -> None:
    _create(auth_client, "root2", group="Администраторы")
    me = next(u for u in auth_client.get("/api/settings/users").json() if u["login"] == TEST_LOGIN)
    refused = auth_client.patch(f"/api/settings/users/{me['id']}", json={"group_ids": []})
    assert refused.status_code == 409 and "с себя" in refused.json()["detail"]
    assert auth_client.get("/api/auth/me").json()["access"]["platform"] == "admin"


def test_deleting_and_blocking_other_admin_keeps_one(auth_client: TestClient) -> None:
    other = _create(auth_client, "root2", group="Администраторы")
    assert auth_client.patch(f"/api/settings/users/{other['id']}", json={"is_active": False}).status_code == 200
    assert auth_client.delete(f"/api/settings/users/{other['id']}").status_code == 204


def test_users_export_has_groups_column(auth_client: TestClient) -> None:
    ann = _create(auth_client, "ann")
    auth_client.patch(
        f"/api/settings/users/{ann['id']}",
        json={"group_ids": [_group_id(auth_client, "Аналитики"), _group_id(auth_client, "Аудиторы")]},
    )
    text = auth_client.get("/api/settings/users/export?format=csv").content.decode("utf-8-sig")
    header, *rows = csv.reader(io.StringIO(text), delimiter=";")
    assert "Группы" in header and "Роль" not in header
    by_login = {r[header.index("Логин")]: r[header.index("Группы")] for r in rows}
    assert by_login == {TEST_LOGIN: "Администраторы", "ann": "Аналитики, Аудиторы"}


def test_admin_resets_password_and_user_changes_own(auth_client: TestClient, client: TestClient) -> None:
    created = _create(auth_client, "ann")
    assert auth_client.post(f"/api/settings/users/{created['id']}/password", json={"password": "newpass1"}).status_code == 204
    ann = TestClient(client.app)
    assert ann.post("/api/auth/login", json={"login": "ann", "password": "newpass1"}).status_code == 204
    assert ann.post("/api/auth/password", json={"current": "wrong", "new": "x1234567"}).status_code == 400
    assert ann.post("/api/auth/password", json={"current": "newpass1", "new": "x1234567"}).status_code == 204
    assert ann.patch("/api/auth/me", json={"display_name": "Анна"}).status_code == 204
    assert ann.get("/api/auth/me").json()["display_name"] == "Анна"
    again = TestClient(client.app)
    assert again.post("/api/auth/login", json={"login": "ann", "password": "x1234567"}).status_code == 204


def test_patch_me_without_fields_keeps_the_name(auth_client: TestClient) -> None:
    """Пустое тело — «ничего не менять», явный null — «стереть имя».
    Без этого различия любой PATCH без поля затирал бы имя."""
    assert auth_client.patch("/api/auth/me", json={"display_name": "Иван"}).status_code == 204
    assert auth_client.patch("/api/auth/me", json={}).status_code == 204
    assert auth_client.get("/api/auth/me").json()["display_name"] == "Иван"
    assert auth_client.patch("/api/auth/me", json={"display_name": None}).status_code == 204
    assert auth_client.get("/api/auth/me").json()["display_name"] is None


def test_theme_defaults_to_dark_and_switches(auth_client: TestClient) -> None:
    """Тема — часть своего профиля: по умолчанию тёмная, светлую выбирают
    сами. Неизвестное значение не сохраняется вовсе."""
    assert auth_client.get("/api/auth/me").json()["theme"] == "dark"
    assert auth_client.patch("/api/auth/me", json={"theme": "light"}).status_code == 204
    assert auth_client.get("/api/auth/me").json()["theme"] == "light"
    assert auth_client.patch("/api/auth/me", json={"display_name": "Иван"}).status_code == 204
    assert auth_client.get("/api/auth/me").json()["theme"] == "light"
    assert auth_client.patch("/api/auth/me", json={"theme": "blue"}).status_code == 422
    assert auth_client.get("/api/auth/me").json()["theme"] == "light"


def test_user_view_and_me_carry_auth_source(auth_client: TestClient) -> None:
    assert auth_client.get("/api/auth/me").json()["auth_source"] == "local"
    assert auth_client.get("/api/settings/users").json()[0]["auth_source"] == "local"


def test_oidc_user_cannot_get_a_password(auth_client: TestClient, db_session: Any) -> None:
    from api.db.models import AppUser

    user = AppUser(login="fam-ann", auth_source="oidc", oidc_subject="sub-1", password_hash=None)
    db_session.add(user)
    db_session.commit()
    response = auth_client.post(f"/api/settings/users/{user.id}/password", json={"password": "newpass12"})
    assert response.status_code == 409
    assert "провайдер" in response.json()["detail"]
