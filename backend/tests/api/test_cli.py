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
