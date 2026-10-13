"""api.cli create-user: пароль только через getpass, никогда как аргумент."""
from __future__ import annotations

from typing import Any

import pytest
from typer.testing import CliRunner

from api.cli import app
from api.db.base import get_sessionmaker
from api.db.models import AppUser
from api.security import verify_password

runner = CliRunner()


def _create(login: str, *extra_args: str, monkeypatch: pytest.MonkeyPatch) -> Any:
    answers = iter(["pw1234", "pw1234"])
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: next(answers))
    return runner.invoke(app, ["create-user", login, *extra_args])


def test_create_user_prompts_for_password_twice(
    app_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    answers = iter(["s3cret-pass", "s3cret-pass"])
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: next(answers))

    result = runner.invoke(app, ["create-user", "alice"])
    assert result.exit_code == 0, result.output

    session = get_sessionmaker()()
    try:
        user = session.query(AppUser).filter_by(login="alice").one()
        assert verify_password("s3cret-pass", user.password_hash)
    finally:
        session.close()


def test_create_user_rejects_mismatched_passwords(
    app_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    answers = iter(["one", "two"])
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: next(answers))

    result = runner.invoke(app, ["create-user", "bob"])
    assert result.exit_code != 0

    session = get_sessionmaker()()
    try:
        assert session.query(AppUser).filter_by(login="bob").one_or_none() is None
    finally:
        session.close()


def test_first_user_is_admin_and_next_is_analyst(
    app_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Первый пользователь — администратор (иначе некому управлять),
    следующие — аналитики, если роль не задана явно."""
    result = _create("root", monkeypatch=monkeypatch)
    assert result.exit_code == 0, result.output
    result = _create("ann", monkeypatch=monkeypatch)
    assert result.exit_code == 0, result.output
    result = _create("aud", "--role", "auditor", monkeypatch=monkeypatch)
    assert result.exit_code == 0, result.output

    session = get_sessionmaker()()
    try:
        roles = {u.login: u.role for u in session.query(AppUser)}
    finally:
        session.close()
    assert roles == {"root": "admin", "ann": "analyst", "aud": "auditor"}


def test_unknown_role_is_refused(app_settings: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    result = _create("x", "--role", "boss", monkeypatch=monkeypatch)
    assert result.exit_code != 0


def test_reseal_secrets_encrypts_plaintext_in_place(app_settings: Any, db_session: Any) -> None:
    """Открытые секреты из старой базы шифруются одной командой; значения
    в вывод не попадают."""
    import json

    from api.crypto import decrypt
    from api.db.models import AppSetting
    from api.modules.ad.models import AdConnection
    from api.modules.ksc.models import KscConnection

    db_session.add_all([
        AdConnection(host="dc01.corp.local", username="CORP\\auditor", password="ad-plain"),
        KscConnection(host="ksc01.corp.local", username="svc", password="ksc-plain"),
        AppSetting(key="vm", value_json=json.dumps({"connection": {"host": "vm.local", "username": "u", "password": "vm-plain", "client_secret": "vm-sec"}})),
        AppSetting(key="oidc", value_json=json.dumps({"client_id": "stools", "client_secret": "oidc-plain"})),
        AppSetting(key="siem_kb", value_json=json.dumps({"host": "mp.local", "username": "u", "password": "kb-plain", "client_secret": "kb-sec"})),
    ])
    db_session.commit()

    result = runner.invoke(app, ["reseal-secrets"])
    assert result.exit_code == 0, result.output
    assert "ad: 1" in result.output and "ksc: 1" in result.output
    assert "vm: 2" in result.output and "oidc: 1" in result.output
    assert "siem_kb: 2" in result.output and "kb-plain" not in result.output
    assert "plain" not in result.output and "vm-sec" not in result.output

    db_session.expire_all()
    ad = db_session.query(AdConnection).one().password
    ksc = db_session.query(KscConnection).one().password
    vm = json.loads(db_session.get(AppSetting, "vm").value_json)["connection"]
    oidc = json.loads(db_session.get(AppSetting, "oidc").value_json)
    kb = json.loads(db_session.get(AppSetting, "siem_kb").value_json)
    sealed = [ad, ksc, vm["password"], vm["client_secret"], oidc["client_secret"], kb["password"], kb["client_secret"]]
    assert all(v.startswith("enc:v1:") for v in sealed)
    assert [decrypt(v) for v in sealed] == ["ad-plain", "ksc-plain", "vm-plain", "vm-sec", "oidc-plain", "kb-plain", "kb-sec"]
    assert oidc["client_id"] == "stools" and vm["host"] == "vm.local"

    again = runner.invoke(app, ["reseal-secrets"])
    assert again.exit_code == 0 and "ad: 0" in again.output and "vm: 0" in again.output


def test_reseal_secrets_refuses_without_key(app_settings: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STOOLS_SESSION_SECRET", "")
    result = runner.invoke(app, ["reseal-secrets"])
    assert result.exit_code == 1 and "STOOLS_SESSION_SECRET" in result.output


# ---- unlock-login: снять блокировку входа ----------------------------------


def _login_failures(db: Any, *, login: str, ip: str, count: int, minutes_ago: int = 1) -> None:
    import datetime as dt

    from api.db.models import AuditEvent

    at = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=minutes_ago)
    db.add_all(
        AuditEvent(at=at, login=login, method="POST", path="/api/auth/login", status=401, ip=ip)
        for _ in range(count)
    )
    db.commit()


def _audit(db: Any) -> list[tuple[str, str | None, int]]:
    from api.db.models import AuditEvent

    db.expire_all()
    return sorted((e.login, e.ip, e.status) for e in db.query(AuditEvent))


def test_unlock_login_clears_the_login_lock(client: Any, test_user: Any, db_session: Any) -> None:
    from tests.api.conftest import TEST_LOGIN, TEST_PASSWORD

    _login_failures(db_session, login=TEST_LOGIN, ip="10.0.0.5", count=10)
    _login_failures(db_session, login="other", ip="10.0.0.5", count=3)
    body = {"login": TEST_LOGIN, "password": TEST_PASSWORD}
    assert client.post("/api/auth/login", json=body).status_code == 429
    result = runner.invoke(app, ["unlock-login", TEST_LOGIN])
    assert result.exit_code == 0, result.output
    assert "10" in result.output
    # Неудачи других логинов не тронуты.
    assert [row for row in _audit(db_session) if row[2] == 401] == [("other", "10.0.0.5", 401)] * 3
    assert client.post("/api/auth/login", json=body).status_code == 204


def test_unlock_login_by_ip_clears_the_address_lock(client: Any, test_user: Any, db_session: Any) -> None:
    from tests.api.conftest import TEST_LOGIN, TEST_PASSWORD

    for i in range(50):
        _login_failures(db_session, login=f"user{i}", ip="testclient", count=1)
    _login_failures(db_session, login="user0", ip="10.0.0.9", count=2)
    body = {"login": TEST_LOGIN, "password": TEST_PASSWORD}
    assert client.post("/api/auth/login", json=body).status_code == 429
    result = runner.invoke(app, ["unlock-login", "--ip", "testclient"])
    assert result.exit_code == 0, result.output
    assert [row for row in _audit(db_session) if row[2] == 401] == [("user0", "10.0.0.9", 401)] * 2
    assert client.post("/api/auth/login", json=body).status_code == 204


def test_unlock_login_keeps_failures_outside_the_window(app_settings: Any, db_session: Any) -> None:
    """Удаляются только неудачи, которые считает троттлинг (окно 15 минут):
    история журнала старше окна остаётся."""
    _login_failures(db_session, login="u", ip="10.0.0.5", count=2, minutes_ago=30)
    _login_failures(db_session, login="u", ip="10.0.0.5", count=4)
    result = runner.invoke(app, ["unlock-login", "u"])
    assert result.exit_code == 0 and "4" in result.output
    assert len(_audit(db_session)) == 2


def test_unlock_login_needs_login_or_ip(app_settings: Any) -> None:
    result = runner.invoke(app, ["unlock-login"])
    assert result.exit_code == 1
