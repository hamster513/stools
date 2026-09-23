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
    ])
    db_session.commit()

    result = runner.invoke(app, ["reseal-secrets"])
    assert result.exit_code == 0, result.output
    assert "ad: 1" in result.output and "ksc: 1" in result.output
    assert "vm: 2" in result.output and "oidc: 1" in result.output
    assert "plain" not in result.output and "vm-sec" not in result.output

    db_session.expire_all()
    ad = db_session.query(AdConnection).one().password
    ksc = db_session.query(KscConnection).one().password
    vm = json.loads(db_session.get(AppSetting, "vm").value_json)["connection"]
    oidc = json.loads(db_session.get(AppSetting, "oidc").value_json)
    sealed = [ad, ksc, vm["password"], vm["client_secret"], oidc["client_secret"]]
    assert all(v.startswith("enc:v1:") for v in sealed)
    assert [decrypt(v) for v in sealed] == ["ad-plain", "ksc-plain", "vm-plain", "vm-sec", "oidc-plain"]
    assert oidc["client_id"] == "stools" and vm["host"] == "vm.local"

    again = runner.invoke(app, ["reseal-secrets"])
    assert again.exit_code == 0 and "ad: 0" in again.output and "vm: 0" in again.output


def test_reseal_secrets_refuses_without_key(app_settings: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STOOLS_SESSION_SECRET", "")
    result = runner.invoke(app, ["reseal-secrets"])
    assert result.exit_code == 1 and "STOOLS_SESSION_SECRET" in result.output
