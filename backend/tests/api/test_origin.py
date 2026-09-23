"""Проверка источника запросов с изменением состояния (аудит M6).

Без Origin, Sec-Fetch-Site и Referer запрос пропускается: это curl и
скрипты стенда, браузер хотя бы один из заголовков шлёт всегда. Защита —
от чужой страницы в браузере пользователя, а не от клиента с cookie на руках.
"""
from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.db.models import AuditEvent
from tests.api.conftest import TEST_LOGIN, TEST_PASSWORD

SECURITY = "/api/settings/security"
BODY = {"session_ttl_hours": 3}
DENIED = {"detail": "запрос с другого сайта"}


def _ttl(auth_client: TestClient) -> int:
    return int(auth_client.get(SECURITY).json()["session_ttl_hours"])


def test_foreign_origin_is_refused_and_audited(auth_client: TestClient, db_session: Any) -> None:
    response = auth_client.put(SECURITY, json=BODY, headers={"Origin": "https://evil.example"})
    assert response.status_code == 403
    assert response.json() == DENIED
    assert _ttl(auth_client) == 12
    db_session.expire_all()
    last = db_session.query(AuditEvent).filter_by(path=SECURITY).order_by(AuditEvent.id.desc()).first()
    assert (last.method, last.status) == ("PUT", 403)
    assert "evil.example" in (last.summary or "")


def test_anonymous_refusal_is_not_audited(client: TestClient, db_session: Any) -> None:
    """Отказ по источнику без cookie сессии в журнал не пишется: иначе любой
    снаружи заполнял бы журнал анонимными строками (финальное ревью)."""
    response = client.put(SECURITY, json=BODY, headers={"Origin": "https://evil.example"})
    assert response.status_code == 403 and response.json() == DENIED
    db_session.expire_all()
    assert db_session.query(AuditEvent).filter_by(path=SECURITY).count() == 0


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
def test_foreign_fetch_site_is_refused(auth_client: TestClient, site: str) -> None:
    response = auth_client.put(SECURITY, json=BODY, headers={"Sec-Fetch-Site": site})
    assert response.status_code == 403
    assert response.json() == DENIED


@pytest.mark.parametrize("site", ["same-origin", "none"])
def test_own_fetch_site_passes(auth_client: TestClient, site: str) -> None:
    #: Sec-Fetch-Site главнее Origin: его браузер ставит сам, подделать нельзя.
    headers = {"Sec-Fetch-Site": site, "Origin": "https://evil.example"}
    assert auth_client.put(SECURITY, json=BODY, headers=headers).status_code == 204


def test_same_origin_passes(auth_client: TestClient) -> None:
    assert auth_client.put(SECURITY, json=BODY, headers={"Origin": "http://testserver"}).status_code == 204


def test_no_source_headers_passes(auth_client: TestClient) -> None:
    assert auth_client.put(SECURITY, json=BODY).status_code == 204


def test_null_origin_is_refused(auth_client: TestClient) -> None:
    assert auth_client.put(SECURITY, json=BODY, headers={"Origin": "null"}).status_code == 403


def test_referer_is_checked_when_origin_is_absent(auth_client: TestClient) -> None:
    evil = auth_client.put(SECURITY, json=BODY, headers={"Referer": "https://evil.example/page"})
    assert evil.status_code == 403
    own = auth_client.put(SECURITY, json=BODY, headers={"Referer": "http://testserver/settings"})
    assert own.status_code == 204


def test_forwarded_host_and_proto_from_the_proxy(auth_client: TestClient) -> None:
    """За Caddy: хост и схему браузера несут X-Forwarded-Host/-Proto."""
    proxy = {"X-Forwarded-Host": "stools.corp.local", "X-Forwarded-Proto": "https"}
    ok = auth_client.put(SECURITY, json=BODY, headers={**proxy, "Origin": "https://stools.corp.local"})
    assert ok.status_code == 204
    downgraded = auth_client.put(SECURITY, json=BODY, headers={**proxy, "Origin": "http://stools.corp.local"})
    assert downgraded.status_code == 403
    other_host = auth_client.put(SECURITY, json=BODY, headers={**proxy, "Origin": "https://testserver"})
    assert other_host.status_code == 403


def test_reads_are_not_checked(auth_client: TestClient) -> None:
    assert auth_client.get(SECURITY, headers={"Origin": "https://evil.example"}).status_code == 200


def test_login_from_foreign_site_is_refused(client: TestClient, test_user: Any) -> None:
    response = client.post(
        "/api/auth/login",
        json={"login": TEST_LOGIN, "password": TEST_PASSWORD},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert "stools_session" not in client.cookies


def test_oidc_paths_are_exempt(client: TestClient) -> None:
    """Возврат от провайдера — переход с чужого сайта по определению."""
    response = client.post("/api/auth/oidc/callback", headers={"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 405
