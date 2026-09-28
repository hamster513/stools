"""Умолчания настроек не должны нести секретов."""
from __future__ import annotations

from sqlalchemy.engine import make_url

from api.settings import Settings


def test_database_url_default_has_no_password() -> None:
    default = Settings.model_fields["database_url"].default
    url = make_url(default)
    assert url.password is None
    assert (url.host, url.database) == ("localhost", "kbaudit")
