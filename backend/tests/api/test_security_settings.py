"""Срок сессии и таймаут бездействия задаются в общих настройках."""
from __future__ import annotations

import datetime as dt
from typing import Any

from fastapi.testclient import TestClient

from api.db.models import AppUser, SessionRow
from tests.api.conftest import TEST_LOGIN, TEST_PASSWORD


def test_defaults(auth_client: TestClient) -> None:
    assert auth_client.get("/api/settings/security").json() == {
        "session_ttl_hours": 12,
        "idle_timeout_minutes": 0,
        "audit_retention_days": 90,
    }


def test_ttl_from_settings_applies_at_login(client: TestClient, auth_client: TestClient, db_session: Any) -> None:
    assert auth_client.put("/api/settings/security", json={"session_ttl_hours": 2}).status_code == 204
    fresh = TestClient(client.app)
    assert fresh.post("/api/auth/login", json={"login": TEST_LOGIN, "password": TEST_PASSWORD}).status_code == 204
    token = fresh.cookies["stools_session"]
    row = db_session.get(SessionRow, token)
    db_session.refresh(row)
    lifetime = row.expires_at.replace(tzinfo=dt.UTC) - row.created_at.replace(tzinfo=dt.UTC)
    assert dt.timedelta(hours=1, minutes=59) < lifetime <= dt.timedelta(hours=2)


def test_idle_timeout_ends_session(auth_client: TestClient, db_session: Any) -> None:
    assert auth_client.put("/api/settings/security", json={"idle_timeout_minutes": 15}).status_code == 204
    token = auth_client.cookies["stools_session"]
    row = db_session.get(SessionRow, token)
    row.last_seen_at = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=16)
    db_session.commit()
    response = auth_client.get("/api/auth/me")
    assert response.status_code == 401
    assert "бездейств" in response.json()["detail"]
    # Удаление сессии сделал другой Session (внутри запроса) — expire_all,
    # иначе идентичная карта db_session отдаст закэшированный объект
    # (expire_on_commit=False, см. api/db/base.py; тот же приём — в
    # tests/vm/test_attack_layer.py и других).
    db_session.expire_all()
    assert db_session.get(SessionRow, token) is None


def test_last_seen_is_refreshed_at_most_once_a_minute(auth_client: TestClient, db_session: Any) -> None:
    token = auth_client.cookies["stools_session"]
    row = db_session.get(SessionRow, token)
    stale = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=5)
    row.last_seen_at = stale
    db_session.commit()
    auth_client.get("/api/auth/me")
    db_session.refresh(row)
    assert row.last_seen_at.replace(tzinfo=dt.UTC) > stale + dt.timedelta(minutes=4)

    # Свежий last_seen_at (моложе минуты) запрос не трогает — иначе
    # каждый GET писал бы в БД.
    recent = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=10)
    row.last_seen_at = recent
    db_session.commit()
    auth_client.get("/api/auth/me")
    db_session.refresh(row)
    assert row.last_seen_at.replace(tzinfo=dt.UTC) < dt.datetime.now(dt.UTC) - dt.timedelta(seconds=5)


def test_blocked_user_cannot_log_in_and_loses_sessions(auth_client: TestClient, db_session: Any, test_user: AppUser) -> None:
    token = auth_client.cookies["stools_session"]
    test_user.is_active = False
    db_session.commit()
    assert auth_client.get("/api/auth/me").status_code == 401
    fresh = TestClient(auth_client.app)
    assert fresh.post("/api/auth/login", json={"login": TEST_LOGIN, "password": TEST_PASSWORD}).status_code == 401
    assert db_session.get(SessionRow, token) is None


def test_validation(auth_client: TestClient) -> None:
    assert auth_client.put("/api/settings/security", json={"session_ttl_hours": 0}).status_code == 422
    assert auth_client.put("/api/settings/security", json={"audit_retention_days": 4000}).status_code == 422


def test_short_idle_timeout_does_not_log_out_an_active_user(auth_client: TestClient, db_session: Any) -> None:
    """При минутном таймауте порог обновления last_seen_at — полминуты:
    иначе работающего человека выгоняло бы собственное «не чаще раза в
    минуту» — запись не обновлялась, а таймаут по ней уже истекал."""
    assert auth_client.put("/api/settings/security", json={"idle_timeout_minutes": 1}).status_code == 204
    token = auth_client.cookies["stools_session"]
    row = db_session.get(SessionRow, token)
    stale = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=40)
    row.last_seen_at = stale
    db_session.commit()

    assert auth_client.get("/api/auth/me").status_code == 200
    db_session.refresh(row)
    assert row.last_seen_at.replace(tzinfo=dt.UTC) > stale + dt.timedelta(seconds=20)
