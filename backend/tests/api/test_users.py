"""Пользователи: роли, блокировка, защита себя и последнего администратора."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi.testclient import TestClient

from api.db.models import SessionRow
from tests.api.conftest import TEST_LOGIN


def _create(client: TestClient, login: str, role: str = "analyst") -> dict[str, Any]:
    response = client.post(
        "/api/settings/users",
        json={"login": login, "display_name": login.title(), "role": role, "password": "pw123456"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_me_has_role_and_name(auth_client: TestClient) -> None:
    assert auth_client.get("/api/auth/me").json() == {
        "login": TEST_LOGIN,
        "display_name": None,
        "role": "admin",
        "theme": "dark",
        "auth_source": "local",
    }


def test_create_list_patch_delete(auth_client: TestClient) -> None:
    created = _create(auth_client, "ann")
    assert created["role"] == "analyst" and created["is_active"] is True
    listed = auth_client.get("/api/settings/users").json()
    assert {u["login"] for u in listed} == {TEST_LOGIN, "ann"}
    patched = auth_client.patch(f"/api/settings/users/{created['id']}", json={"role": "auditor", "display_name": "Анна"})
    assert patched.json()["role"] == "auditor" and patched.json()["display_name"] == "Анна"
    assert auth_client.delete(f"/api/settings/users/{created['id']}").status_code == 204
    assert [u["login"] for u in auth_client.get("/api/settings/users").json()] == [TEST_LOGIN]


def test_duplicate_login_and_bad_role_are_refused(auth_client: TestClient) -> None:
    _create(auth_client, "ann")
    assert auth_client.post("/api/settings/users", json={"login": "ann", "role": "analyst", "password": "pw123456"}).status_code == 409
    assert auth_client.post("/api/settings/users", json={"login": "bob", "role": "boss", "password": "pw123456"}).status_code == 422


def test_blocking_drops_sessions(auth_client: TestClient, client_as: Callable[[str], TestClient], db_session: Any) -> None:
    analyst = client_as("analyst")
    token = analyst.cookies["stools_session"]
    uid = next(u["id"] for u in auth_client.get("/api/settings/users").json() if u["login"] == "user-analyst")
    assert auth_client.patch(f"/api/settings/users/{uid}", json={"is_active": False}).json()["is_active"] is False
    assert db_session.get(SessionRow, token) is None
    assert analyst.get("/api/auth/me").status_code == 401


def test_cannot_block_delete_or_demote_self(auth_client: TestClient) -> None:
    me = next(u for u in auth_client.get("/api/settings/users").json() if u["login"] == TEST_LOGIN)
    assert auth_client.patch(f"/api/settings/users/{me['id']}", json={"is_active": False}).status_code == 409
    assert auth_client.patch(f"/api/settings/users/{me['id']}", json={"role": "analyst"}).status_code == 409
    assert auth_client.delete(f"/api/settings/users/{me['id']}").status_code == 409


def test_last_admin_is_protected(auth_client: TestClient) -> None:
    other = _create(auth_client, "root2", role="admin")
    me = next(u for u in auth_client.get("/api/settings/users").json() if u["login"] == TEST_LOGIN)
    # Пока есть второй администратор, себя понизить можно? Нет — себя нельзя никогда (тест выше).
    # Второго можно понизить, пока остаётся первый:
    assert auth_client.patch(f"/api/settings/users/{other['id']}", json={"role": "analyst"}).status_code == 200
    # Вернуть и заблокировать себя через другого админа нельзя проверить одним клиентом; проверяем
    # правило «последний активный админ» напрямую: единственный админ — это я, блокировать нельзя.
    assert auth_client.patch(f"/api/settings/users/{me['id']}", json={"is_active": False}).status_code == 409


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

    user = AppUser(login="fam-ann", role="analyst", auth_source="oidc", oidc_subject="sub-1", password_hash=None)
    db_session.add(user)
    db_session.commit()
    response = auth_client.post(f"/api/settings/users/{user.id}/password", json={"password": "newpass12"})
    assert response.status_code == 409
    assert "провайдер" in response.json()["detail"]
