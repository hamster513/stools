"""Умолчания настроек не должны нести секретов и адресов баз."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.settings import Settings


def test_database_url_has_no_default(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ни пароля в коде, ни подключения без пароля: адрес базы приходит
    # только из окружения, иначе приложение не стартует.
    monkeypatch.delenv("STOOLS_DATABASE_URL", raising=False)
    with pytest.raises(ValidationError, match="database_url"):
        Settings(_env_file=None)


def test_database_url_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STOOLS_DATABASE_URL", "postgresql+psycopg://u:p@db:5432/x")
    assert Settings(_env_file=None).database_url == "postgresql+psycopg://u:p@db:5432/x"
