"""Шифрование секретов подключений и хеш токена сессии (api/crypto.py)."""
from __future__ import annotations

import hashlib
import logging

import pytest

from api.crypto import PREFIX, check_session_secret, decrypt, encrypt, hash_token
from api.settings import Settings

KEY = "unit-test-key-one"
OTHER_KEY = "unit-test-key-two"


def test_round_trip_under_the_same_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STOOLS_SESSION_SECRET", KEY)
    sealed = encrypt("p@ss")
    assert sealed.startswith(PREFIX) and "p@ss" not in sealed
    assert decrypt(sealed) == "p@ss"
    #: Случайный вектор: одинаковые пароли в базе не совпадают.
    assert encrypt("p@ss") != sealed
    assert encrypt("") == ""


def test_plaintext_passes_through(monkeypatch: pytest.MonkeyPatch) -> None:
    """Старое значение без префикса читается как есть — обратная совместимость."""
    monkeypatch.setenv("STOOLS_SESSION_SECRET", KEY)
    assert decrypt("legacy-password") == "legacy-password"
    assert decrypt("") == ""


def test_other_key_gives_a_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STOOLS_SESSION_SECRET", KEY)
    sealed = encrypt("p@ss")
    monkeypatch.setenv("STOOLS_SESSION_SECRET", OTHER_KEY)
    with pytest.raises(ValueError, match="другим ключом — введите его заново"):
        decrypt(sealed)
    monkeypatch.setenv("STOOLS_SESSION_SECRET", "")
    with pytest.raises(ValueError, match="другим ключом"):
        decrypt(sealed)


def test_without_key_values_stay_plaintext(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STOOLS_SESSION_SECRET", "")
    assert encrypt("p@ss") == "p@ss"


def test_hash_token_depends_on_the_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Хеш сессии — HMAC с ключом из STOOLS_SESSION_SECRET: смена ключа
    завершает сессии, а дамп базы без ключа не даёт подобрать токен."""
    monkeypatch.setenv("STOOLS_SESSION_SECRET", KEY)
    one = hash_token("abc")
    assert len(one) == 64 and one != "abc" and one != hashlib.sha256(b"abc").hexdigest()
    assert hash_token("abc") == one
    monkeypatch.setenv("STOOLS_SESSION_SECRET", OTHER_KEY)
    assert hash_token("abc") != one


def test_hash_token_without_key_is_plain_sha256(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STOOLS_SESSION_SECRET", "")
    assert hash_token("abc") == hashlib.sha256(b"abc").hexdigest()


def test_startup_refuses_production_without_key(caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    #: fileConfig из alembic/env.py (миграции тестовой базы) выключает уже
    #: созданные логгеры; в проде миграции идут отдельным процессом.
    monkeypatch.setattr(logging.getLogger("api.crypto"), "disabled", False)
    with pytest.raises(RuntimeError, match="STOOLS_SESSION_SECRET"):
        check_session_secret(Settings(session_secret="", session_cookie_secure=True))

    with caplog.at_level(logging.WARNING, logger="api.crypto"):
        check_session_secret(Settings(session_secret="", session_cookie_secure=False))
    assert "не шифруются" in caplog.text

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="api.crypto"):
        check_session_secret(Settings(session_secret=KEY, session_cookie_secure=True))
    assert caplog.text == ""
