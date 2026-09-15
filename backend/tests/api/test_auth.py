from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from tests.api.conftest import TEST_LOGIN, TEST_PASSWORD


def test_login_sets_cookie_and_allows_me(client: TestClient, test_user: Any) -> None:
    response = client.post("/api/auth/login", json={"login": TEST_LOGIN, "password": TEST_PASSWORD})
    assert response.status_code == 204
    assert "stools_session" in response.cookies

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json() == {
        "login": TEST_LOGIN,
        "display_name": None,
        "role": "admin",
        "theme": "dark",
        "auth_source": "local",
    }


def test_login_rejects_wrong_password(client: TestClient, test_user: Any) -> None:
    response = client.post("/api/auth/login", json={"login": TEST_LOGIN, "password": "неверно"})
    assert response.status_code == 401
    assert "stools_session" not in response.cookies


def test_login_rejects_unknown_user(client: TestClient) -> None:
    response = client.post("/api/auth/login", json={"login": "ghost", "password": "x"})
    assert response.status_code == 401


def test_me_without_session_is_401(client: TestClient) -> None:
    assert client.get("/api/auth/me").status_code == 401


def test_logout_invalidates_session(auth_client: TestClient) -> None:
    assert auth_client.get("/api/auth/me").status_code == 200
    logout = auth_client.post("/api/auth/logout")
    assert logout.status_code == 204
    assert auth_client.get("/api/auth/me").status_code == 401
