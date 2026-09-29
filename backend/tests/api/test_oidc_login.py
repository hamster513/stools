"""Вход через провайдера: автозаведение, роль из групп, отказы без сессии."""
from __future__ import annotations

import datetime as dt
import logging
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from api.db.models import AppUser, AuditEvent, OidcLoginState
from api.main import app
from tests.api.fake_oidc import FakeProvider


def _start(client: TestClient) -> dict[str, str]:
    response = client.get("/api/auth/oidc/start", follow_redirects=False)
    assert response.status_code == 302, response.text
    query = parse_qs(urlparse(response.headers["location"]).query)
    return {k: v[0] for k, v in query.items()}


def _login(
    client: TestClient, fam: FakeProvider, sub: str, login: str, groups: list[str], **kw: Any
) -> Any:
    params = _start(client)
    code = fam.issue_code(
        sub,
        login,
        kw.get("name", login.title()),
        groups,
        nonce=params["nonce"],
        groups_in_id_token=kw.get("in_id_token", True),
        code_challenge=params["code_challenge"],
    )
    return client.get(
        "/api/auth/oidc/callback",
        params={"code": code, "state": params["state"]},
        follow_redirects=False,
    )


def test_status_is_public_and_reflects_settings(
    client: TestClient, oidc_enabled: FakeProvider
) -> None:
    assert client.get("/api/auth/oidc/status").json() == {"enabled": True, "display_name": "FAM"}


def test_start_is_404_when_disabled(client: TestClient, fam: FakeProvider) -> None:
    assert client.get("/api/auth/oidc/start", follow_redirects=False).status_code == 404


def test_start_redirects_with_pkce_and_stores_state(
    client: TestClient, oidc_enabled: FakeProvider, db_session: Any
) -> None:
    params = _start(client)
    assert params["response_type"] == "code" and params["code_challenge_method"] == "S256"
    assert params["redirect_uri"] == "https://testserver/api/auth/oidc/callback"
    assert db_session.get(OidcLoginState, params["state"]) is not None


def test_first_login_creates_user_with_mapped_role(
    client: TestClient, oidc_enabled: FakeProvider, db_session: Any
) -> None:
    fresh = TestClient(app)
    response = _login(fresh, oidc_enabled, "sub-1", "ann", ["stools-analysts", "other"])
    assert response.status_code == 302 and response.headers["location"] == "/attack"
    assert "stools_session" in fresh.cookies
    me = fresh.get("/api/auth/me").json()
    assert me == {
        "login": "ann",
        "display_name": "Ann",
        "role": "analyst",
        "theme": "dark",
        "auth_source": "oidc",
    }
    db_session.expire_all()
    user = db_session.query(AppUser).filter_by(login="ann").one()
    assert user.oidc_subject == "sub-1" and user.password_hash is None
    #: Успешный вход попадает в журнал, но код авторизации и state — нет.
    last = db_session.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    assert last.path == "/api/auth/oidc/callback" and last.login == "ann"
    assert "code=" not in (last.summary or "") and "state=" not in (last.summary or "")


def test_widest_role_wins_and_role_is_recomputed_each_login(
    client: TestClient, oidc_enabled: FakeProvider
) -> None:
    first = TestClient(app)
    _login(first, oidc_enabled, "sub-1", "ann", ["stools-auditors", "stools-admins"])
    assert first.get("/api/auth/me").json()["role"] == "admin"
    second = TestClient(app)
    _login(second, oidc_enabled, "sub-1", "ann", ["stools-auditors"])
    assert second.get("/api/auth/me").json()["role"] == "auditor"


def test_no_mapped_group_is_refused_without_creating_user(
    client: TestClient, oidc_enabled: FakeProvider, db_session: Any
) -> None:
    fresh = TestClient(app)
    response = _login(fresh, oidc_enabled, "sub-9", "bob", ["unrelated"])
    assert response.headers["location"] == "/login?error=oidc_no_role"
    assert "stools_session" not in fresh.cookies
    assert db_session.query(AppUser).filter_by(login="bob").one_or_none() is None
    db_session.expire_all()
    last = db_session.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    assert last.path == "/api/auth/oidc/callback"
    assert last.login == "bob" and last.summary == "oidc_no_role"


def test_renamed_login_keeps_the_same_account(
    client: TestClient, oidc_enabled: FakeProvider, db_session: Any
) -> None:
    _login(TestClient(app), oidc_enabled, "sub-1", "ann", ["stools-analysts"])
    _login(TestClient(app), oidc_enabled, "sub-1", "anna", ["stools-analysts"])
    db_session.expire_all()
    assert db_session.query(AppUser).filter(AppUser.oidc_subject == "sub-1").count() == 1
    assert db_session.query(AppUser).filter_by(login="anna").one().oidc_subject == "sub-1"


def test_local_login_collision_is_refused(
    client: TestClient, oidc_enabled: FakeProvider, make_user: Any
) -> None:
    make_user("ann", "analyst")
    response = _login(TestClient(app), oidc_enabled, "sub-1", "ann", ["stools-analysts"])
    assert response.headers["location"] == "/login?error=oidc_login_taken"


def test_blocked_user_is_refused(
    client: TestClient, oidc_enabled: FakeProvider, db_session: Any
) -> None:
    _login(TestClient(app), oidc_enabled, "sub-1", "ann", ["stools-analysts"])
    db_session.expire_all()
    user = db_session.query(AppUser).filter_by(login="ann").one()
    user.is_active = False
    db_session.commit()
    response = _login(TestClient(app), oidc_enabled, "sub-1", "ann", ["stools-analysts"])
    assert response.headers["location"] == "/login?error=blocked"


def test_groups_from_userinfo_when_absent_in_id_token(
    client: TestClient, oidc_enabled: FakeProvider
) -> None:
    fresh = TestClient(app)
    _login(fresh, oidc_enabled, "sub-1", "ann", ["stools-analysts"], in_id_token=False)
    assert fresh.get("/api/auth/me").json()["role"] == "analyst"
    assert any(path.endswith("/userinfo") for path in oidc_enabled.calls)


def test_empty_groups_in_id_token_do_not_ask_userinfo(
    client: TestClient, oidc_enabled: FakeProvider
) -> None:
    """Пустой список групп — это ответ «групп нет», а не «их тут не отдают»:
    второй раз спрашивать провайдера незачем."""
    fresh = TestClient(app)
    response = _login(fresh, oidc_enabled, "sub-1", "ann", [])
    assert response.headers["location"] == "/login?error=oidc_no_role"
    assert not [path for path in oidc_enabled.calls if path.endswith("/userinfo")]


def test_userinfo_with_another_sub_is_refused(
    client: TestClient, oidc_enabled: FakeProvider
) -> None:
    """userinfo про другого человека решал бы роль этого — вход отклоняется."""
    fresh = TestClient(app)
    params = _start(fresh)
    code = oidc_enabled.issue_code(
        "sub-1", "ann", "Ann", ["stools-admins"],
        nonce=params["nonce"], groups_in_id_token=False,
        code_challenge=params["code_challenge"], userinfo_sub="sub-чужой",
    )
    response = fresh.get(
        "/api/auth/oidc/callback",
        params={"code": code, "state": params["state"]},
        follow_redirects=False,
    )
    assert response.headers["location"] == "/login?error=oidc_token"
    assert "stools_session" not in fresh.cookies


def test_oversized_jwks_is_refused(client: TestClient, oidc_enabled: FakeProvider) -> None:
    """Ответ провайдера длиной в мегабайты не разбирается вовсе."""
    oidc_enabled.oversized.add("certs")
    response = _login(TestClient(app), oidc_enabled, "sub-1", "ann", ["stools-analysts"])
    assert response.headers["location"] == "/login?error=oidc_unavailable"


def test_bad_state_expired_state_and_provider_error(
    client: TestClient, oidc_enabled: FakeProvider, db_session: Any
) -> None:
    fresh = TestClient(app)
    bad = fresh.get(
        "/api/auth/oidc/callback", params={"code": "x", "state": "nope"}, follow_redirects=False
    )
    assert bad.headers["location"] == "/login?error=oidc_state"
    params = _start(fresh)
    row = db_session.get(OidcLoginState, params["state"])
    row.created_at = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=11)
    db_session.commit()
    expired = fresh.get(
        "/api/auth/oidc/callback",
        params={"code": "x", "state": params["state"]},
        follow_redirects=False,
    )
    assert expired.headers["location"] == "/login?error=oidc_state"
    params = _start(fresh)
    denied = fresh.get(
        "/api/auth/oidc/callback",
        params={"error": "access_denied", "state": params["state"]},
        follow_redirects=False,
    )
    assert denied.headers["location"] == "/login?error=oidc_denied"
    params = _start(fresh)
    refused = fresh.get(
        "/api/auth/oidc/callback",
        params={"code": "no-such", "state": params["state"]},
        follow_redirects=False,
    )
    assert refused.headers["location"] == "/login?error=oidc_token"
    assert "stools_session" not in fresh.cookies


def test_wrong_code_verifier_is_rejected(
    client: TestClient, oidc_enabled: FakeProvider, db_session: Any
) -> None:
    """PKCE проверяется по-настоящему: с чужим verifier обмен не проходит."""
    fresh = TestClient(app)
    params = _start(fresh)
    db_session.expire_all()
    row = db_session.get(OidcLoginState, params["state"])
    row.code_verifier = "подменённый-verifier"
    db_session.commit()
    code = oidc_enabled.issue_code(
        "sub-1", "ann", "Ann", ["stools-analysts"],
        nonce=params["nonce"], code_challenge=params["code_challenge"],
    )
    response = fresh.get(
        "/api/auth/oidc/callback",
        params={"code": code, "state": params["state"]},
        follow_redirects=False,
    )
    assert response.headers["location"] == "/login?error=oidc_token"
    assert "stools_session" not in fresh.cookies


def test_callback_without_the_state_cookie_is_refused(
    client: TestClient, oidc_enabled: FakeProvider
) -> None:
    """state привязан к браузеру: без своей cookie callback не принимается,
    даже если state в базе живой (чужой браузер, подсунутая ссылка)."""
    browser = TestClient(app)
    params = _start(browser)
    code = oidc_enabled.issue_code(
        "sub-1", "ann", "Ann", ["stools-analysts"],
        nonce=params["nonce"], code_challenge=params["code_challenge"],
    )
    stranger = TestClient(app)
    response = stranger.get(
        "/api/auth/oidc/callback",
        params={"code": code, "state": params["state"]},
        follow_redirects=False,
    )
    assert response.headers["location"] == "/login?error=oidc_state"
    assert "stools_session" not in stranger.cookies


def test_callback_with_a_mismatching_state_cookie_is_refused(
    client: TestClient, oidc_enabled: FakeProvider
) -> None:
    browser = TestClient(app)
    params = _start(browser)
    assert browser.cookies["stools_oidc_state"] == params["state"]
    stranger = TestClient(app)
    stranger.cookies.set("stools_oidc_state", "not-the-right-state")
    response = stranger.get(
        "/api/auth/oidc/callback",
        params={"code": "x", "state": params["state"]},
        follow_redirects=False,
    )
    assert response.headers["location"] == "/login?error=oidc_state"
    #: state приходит снаружи и бывает каким угодно — сравнение не должно
    #: спотыкаться о не-ASCII (compare_digest на таких строках падает).
    weird = stranger.get(
        "/api/auth/oidc/callback",
        params={"code": "x", "state": "чужое-состояние"},
        follow_redirects=False,
    )
    assert weird.headers["location"] == "/login?error=oidc_state"


def test_callback_when_disabled_is_404_without_code_in_the_journal(
    client: TestClient, fam: FakeProvider, db_session: Any
) -> None:
    """Выключенный OIDC отвечает 404, но запрос всё равно проходит журнал —
    строка запроса с кодом авторизации туда попасть не должна."""
    response = client.get(
        "/api/auth/oidc/callback",
        params={"code": "секретный-код", "state": "s"},
        follow_redirects=False,
    )
    assert response.status_code == 404
    db_session.expire_all()
    last = db_session.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    assert last.path == "/api/auth/oidc/callback" and last.status == 404
    assert not last.summary


def test_provider_down_at_start(client: TestClient, oidc_enabled: FakeProvider) -> None:
    from api.oidc import provider

    provider.invalidate_cache()
    oidc_enabled.down = True
    response = client.get("/api/auth/oidc/start", follow_redirects=False)
    assert response.headers["location"] == "/login?error=oidc_unavailable"


def test_oidc_user_cannot_use_the_password_form(
    client: TestClient, oidc_enabled: FakeProvider
) -> None:
    _login(TestClient(app), oidc_enabled, "sub-1", "ann", ["stools-analysts"])
    response = client.post("/api/auth/login", json={"login": "ann", "password": "anything"})
    assert response.status_code == 401


def test_oidc_user_cannot_change_the_password(
    client: TestClient, oidc_enabled: FakeProvider
) -> None:
    """Пароля у учётки провайдера нет: форма смены отвечает отказом, а не 400."""
    fresh = TestClient(app)
    _login(fresh, oidc_enabled, "sub-1", "ann", ["stools-analysts"])
    response = fresh.post("/api/auth/password", json={"current": "x", "new": "y" * 8})
    assert response.status_code == 409
    assert "провайдер" in response.json()["detail"]


def test_successful_start_is_not_written_to_the_journal(
    client: TestClient, oidc_enabled: FakeProvider, db_session: Any
) -> None:
    """Начатый вход — не действие: журнал не должен пухнуть от редиректов
    к провайдеру. Отказ — другое дело, у него есть сводка."""
    before = db_session.query(AuditEvent).count()
    _start(client)
    db_session.expire_all()
    assert db_session.query(AuditEvent).count() == before

    from api.oidc import provider

    provider.invalidate_cache()
    oidc_enabled.down = True
    refused = client.get("/api/auth/oidc/start", follow_redirects=False)
    assert refused.headers["location"] == "/login?error=oidc_unavailable"
    db_session.expire_all()
    last = db_session.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    assert last.path == "/api/auth/oidc/start" and last.summary == "oidc_unavailable"


def test_state_table_is_capped(
    client: TestClient, oidc_enabled: FakeProvider, db_session: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Брошенные попытки входа моложе десяти минут тоже не копятся без конца."""
    from api.oidc import login as oidc_login

    monkeypatch.setattr(oidc_login, "STATE_MAX", 3)
    states = [_start(client)["state"] for _ in range(5)]
    db_session.expire_all()
    kept = {row.state for row in db_session.query(OidcLoginState).all()}
    assert len(kept) <= 3
    assert states[-1] in kept and states[0] not in kept


def test_legacy_plaintext_client_secret_still_logs_in_and_is_reencrypted(
    client: TestClient, oidc_enabled: FakeProvider, auth_client: TestClient
) -> None:
    """Секрет, сохранённый до шифрования, продолжает работать и шифруется
    при следующем сохранении настроек."""
    import json

    from api.db.base import get_sessionmaker
    from api.db.models import AppSetting

    with get_sessionmaker()() as db:
        row = db.get(AppSetting, "oidc")
        value = json.loads(row.value_json)
        value["client_secret"] = oidc_enabled.client_secret
        row.value_json = json.dumps(value)
        db.commit()

    fresh = TestClient(app)
    response = _login(fresh, oidc_enabled, "sub-9", "zoe", ["stools-analysts"])
    assert response.status_code == 302 and response.headers["location"] == "/attack"

    body = {k: v for k, v in auth_client.get("/api/settings/oidc").json().items() if k not in ("has_secret", "redirect_uri")}
    assert auth_client.put("/api/settings/oidc", json=body).status_code == 204
    with get_sessionmaker()() as db:
        stored = json.loads(db.get(AppSetting, "oidc").value_json)["client_secret"]
    assert stored.startswith("enc:v1:")
    again = TestClient(app)
    assert _login(again, oidc_enabled, "sub-9", "zoe", ["stools-analysts"]).status_code == 302
    assert again.get("/api/auth/me").status_code == 200


def test_provider_refusal_reason_is_logged(
    client: TestClient, oidc_enabled: FakeProvider, caplog: pytest.LogCaptureFixture
) -> None:
    """Человек видит общий текст, а в логе API — какая проверка не прошла."""
    fresh = TestClient(app)
    params = _start(fresh)
    code = oidc_enabled.issue_code(
        "sub-1", "ann", "Ann", ["stools-admins"],
        nonce=params["nonce"], groups_in_id_token=False,
        code_challenge=params["code_challenge"], userinfo_sub="sub-чужой",
    )
    with caplog.at_level(logging.WARNING, logger="stools.oidc"):
        fresh.get("/api/auth/oidc/callback", params={"code": code, "state": params["state"]}, follow_redirects=False)
    messages = [r.getMessage() for r in caplog.records if r.name == "stools.oidc"]
    assert any("oidc_token" in m and "userinfo вернул другой sub" in m for m in messages)


def test_no_role_refusal_logs_received_groups(
    client: TestClient, oidc_enabled: FakeProvider, caplog: pytest.LogCaptureFixture
) -> None:
    fresh = TestClient(app)
    with caplog.at_level(logging.WARNING, logger="stools.oidc"):
        _login(fresh, oidc_enabled, "sub-9", "bob", ["unrelated", "other"])
    messages = [r.getMessage() for r in caplog.records if r.name == "stools.oidc"]
    assert any("oidc_no_role" in m and "bob" in m and "unrelated" in m and "other" in m for m in messages)
