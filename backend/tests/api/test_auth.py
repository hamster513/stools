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


def test_session_is_stored_as_hash_of_the_cookie_token(auth_client: TestClient, db_session: Any) -> None:
    """В базе лежит SHA-256 токена: дамп таблицы session не даёт войти."""
    from sqlalchemy import select

    from api.crypto import hash_token
    from api.db.models import SessionRow

    token = auth_client.cookies["stools_session"]
    stored = db_session.execute(select(SessionRow.token)).scalars().all()
    assert stored == [hash_token(token)] and token not in stored
    #: Значение из базы, подставленное в cookie, сессией не является.
    forged = TestClient(auth_client.app)
    forged.cookies.set("stools_session", stored[0])
    assert forged.get("/api/auth/me").status_code == 401
    assert auth_client.get("/api/auth/me").status_code == 200
    assert auth_client.post("/api/auth/logout").status_code == 204
    db_session.expire_all()
    assert db_session.execute(select(SessionRow.token)).scalars().all() == []


def test_password_change_keeps_only_the_current_session(auth_client: TestClient, db_session: Any) -> None:
    from sqlalchemy import select

    from api.crypto import hash_token
    from api.db.models import SessionRow

    other = TestClient(auth_client.app)
    assert other.post("/api/auth/login", json={"login": TEST_LOGIN, "password": TEST_PASSWORD}).status_code == 204
    r = auth_client.post("/api/auth/password", json={"current": TEST_PASSWORD, "new": "another-password-1"})
    assert r.status_code == 204
    db_session.expire_all()
    assert db_session.execute(select(SessionRow.token)).scalars().all() == [hash_token(auth_client.cookies["stools_session"])]
    assert auth_client.get("/api/auth/me").status_code == 200
    assert other.get("/api/auth/me").status_code == 401


def test_changing_the_key_ends_sessions(auth_client: TestClient, monkeypatch: Any) -> None:
    assert auth_client.get("/api/auth/me").status_code == 200
    monkeypatch.setenv("STOOLS_SESSION_SECRET", "another-test-only-key")
    assert auth_client.get("/api/auth/me").status_code == 401


def test_hash_migration_ends_all_sessions() -> None:
    """Миграция на хеши удаляет старые строки: сырой токен в базе больше не ищется."""
    from pathlib import Path

    versions = Path(__file__).resolve().parents[2] / "api" / "db" / "migrations" / "versions"
    source = next(versions.glob("*_секреты_и_хеш_сессий.py")).read_text(encoding="utf-8")
    assert 'down_revision: str | Sequence[str] | None = "d5e6f7a8b9c0"' in source
    assert 'op.execute("DELETE FROM session")' in source


def test_cookie_name_from_settings_is_honoured(client: TestClient, test_user: Any, monkeypatch: Any) -> None:
    """`session_cookie_name` не зашит в `Cookie(...)` — login/me/logout читают
    и ставят cookie по имени из настроек (deps.py, routers/auth.py)."""
    monkeypatch.setenv("STOOLS_SESSION_COOKIE_NAME", "other")

    login = client.post("/api/auth/login", json={"login": TEST_LOGIN, "password": TEST_PASSWORD})
    assert login.status_code == 204
    assert "other" in login.cookies
    assert "stools_session" not in login.cookies

    assert client.get("/api/auth/me").status_code == 200

    logout = client.post("/api/auth/logout")
    assert logout.status_code == 204
    assert client.get("/api/auth/me").status_code == 401
