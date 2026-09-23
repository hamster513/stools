"""Вход: троттлинг по журналу, одинаковое время ответа, лимит длины пароля (аудит M1)."""
from __future__ import annotations

import datetime as dt
import statistics
import threading
import time
from typing import Any

import pytest
from fastapi.testclient import TestClient

import api.routers.auth as auth_module
from api.db.models import AuditEvent
from tests.api.conftest import TEST_LOGIN, TEST_PASSWORD

LOGIN = "/api/auth/login"
#: Адрес клиента, который TestClient подставляет в scope.
TESTCLIENT_IP = "testclient"


def _failures(db: Any, *, login: str, ip: str, count: int, minutes_ago: int = 1) -> None:
    at = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=minutes_ago)
    db.add_all(
        AuditEvent(at=at, login=login, method="POST", path=LOGIN, status=401, ip=ip) for _ in range(count)
    )
    db.commit()


def test_eleventh_attempt_is_throttled_even_with_the_right_password(
    client: TestClient, test_user: Any, db_session: Any
) -> None:
    for _ in range(10):
        assert client.post(LOGIN, json={"login": TEST_LOGIN, "password": "wrong"}).status_code == 401
    response = client.post(LOGIN, json={"login": TEST_LOGIN, "password": TEST_PASSWORD})
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "900"
    assert response.json() == {"detail": "слишком много попыток входа, подождите"}
    db_session.expire_all()
    last = db_session.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    assert (last.path, last.status, last.login) == (LOGIN, 429, TEST_LOGIN)


def test_throttle_by_login_from_other_addresses(client: TestClient, test_user: Any, db_session: Any) -> None:
    _failures(db_session, login=TEST_LOGIN, ip="10.0.0.5", count=10)
    assert client.post(LOGIN, json={"login": TEST_LOGIN, "password": TEST_PASSWORD}).status_code == 429


def test_throttle_by_address_across_logins(client: TestClient, test_user: Any, db_session: Any) -> None:
    """Порог по IP — 50: за общим адресом (NAT, терминатор TLS) сидят многие."""
    for i in range(50):
        _failures(db_session, login=f"user{i}", ip=TESTCLIENT_IP, count=1)
    assert client.post(LOGIN, json={"login": TEST_LOGIN, "password": TEST_PASSWORD}).status_code == 429


def test_shared_address_does_not_lock_after_ten(client: TestClient, test_user: Any, db_session: Any) -> None:
    """11 неудач с одного адреса на разных логинах не запирают свежий логин
    (раньше порог по IP был тем же, что по логину, — 10)."""
    for i in range(11):
        _failures(db_session, login=f"user{i}", ip=TESTCLIENT_IP, count=1)
    assert client.post(LOGIN, json={"login": TEST_LOGIN, "password": TEST_PASSWORD}).status_code == 204


def test_address_below_fifty_is_not_throttled(client: TestClient, test_user: Any, db_session: Any) -> None:
    for i in range(49):
        _failures(db_session, login=f"user{i}", ip=TESTCLIENT_IP, count=1)
    assert client.post(LOGIN, json={"login": TEST_LOGIN, "password": TEST_PASSWORD}).status_code == 204


def test_other_login_from_other_address_is_not_throttled(
    client: TestClient, test_user: Any, db_session: Any
) -> None:
    _failures(db_session, login="someone", ip="10.0.0.5", count=10)
    assert client.post(LOGIN, json={"login": TEST_LOGIN, "password": TEST_PASSWORD}).status_code == 204


def test_failures_older_than_window_do_not_count(client: TestClient, test_user: Any, db_session: Any) -> None:
    _failures(db_session, login=TEST_LOGIN, ip=TESTCLIENT_IP, count=10, minutes_ago=16)
    assert client.post(LOGIN, json={"login": TEST_LOGIN, "password": TEST_PASSWORD}).status_code == 204


def test_login_after_nine_failures_works(client: TestClient, test_user: Any) -> None:
    for _ in range(9):
        assert client.post(LOGIN, json={"login": TEST_LOGIN, "password": "wrong"}).status_code == 401
    assert client.post(LOGIN, json={"login": TEST_LOGIN, "password": TEST_PASSWORD}).status_code == 204


def test_password_longer_than_1024_is_422(client: TestClient, test_user: Any) -> None:
    assert client.post(LOGIN, json={"login": TEST_LOGIN, "password": "x" * 1025}).status_code == 422
    assert client.post(LOGIN, json={"login": TEST_LOGIN, "password": "x" * 1024}).status_code == 401


@pytest.mark.parametrize(("login", "password", "after"), [
    (TEST_LOGIN, TEST_PASSWORD, 204),
    (TEST_LOGIN, "wrong", 401),
    ("nobody", "wrong", 401),
])
def test_concurrent_password_checks_are_capped(
    client: TestClient, test_user: Any, db_session: Any, monkeypatch: pytest.MonkeyPatch,
    login: str, password: str, after: int,
) -> None:
    """Счётчик по журналу не видит попыток, которые ещё идут, — поэтому
    одновременных проверок пароля не больше потолка, лишние сразу 429."""
    gate = threading.BoundedSemaphore(1)
    monkeypatch.setattr(auth_module, "_PASSWORD_CHECKS", gate)
    gate.acquire()
    response = client.post(LOGIN, json={"login": login, "password": password})
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "5"
    assert response.json() == {"detail": "слишком много одновременных попыток входа"}
    db_session.expire_all()
    last = db_session.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    assert (last.path, last.status) == (LOGIN, 429)
    gate.release()
    assert client.post(LOGIN, json={"login": login, "password": password}).status_code == after
    #: Семафор отпущен и после неудачи, и после успеха.
    assert gate.acquire(blocking=False)


def test_unknown_login_takes_as_long_as_wrong_password(
    client: TestClient, test_user: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Несуществующий логин тоже проходит Argon2 (фиктивный хеш): по времени
    ответа нельзя узнать, есть ли локальная учётка. Замеры чередуются, чтобы
    дрейф машины ложился на обе серии поровну; троттлинг отключён — иначе
    после десятой неудачи ответы шли бы 429 без хеширования."""
    monkeypatch.setattr(auth_module, "LOGIN_MAX_FAILURES", 10**6)

    def timed(login: str) -> float:
        start = time.perf_counter()
        response = client.post(LOGIN, json={"login": login, "password": "wrong"})
        elapsed = time.perf_counter() - start
        assert response.status_code == 401
        return elapsed

    timed(TEST_LOGIN)
    timed("nobody")  # прогрев
    existing: list[float] = []
    unknown: list[float] = []
    for _ in range(20):
        existing.append(timed(TEST_LOGIN))
        unknown.append(timed("nobody"))
    m_existing, m_unknown = statistics.median(existing), statistics.median(unknown)
    assert abs(m_existing - m_unknown) / max(m_existing, m_unknown) < 0.30, (m_existing, m_unknown)
