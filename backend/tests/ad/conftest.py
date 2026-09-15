"""Фикстуры модуля AD поверх инфраструктуры tests/api/conftest.py."""
from __future__ import annotations

from tests.api.conftest import (  # noqa: F401 — реэкспорт фикстур
    _reset_db_singletons,
    app_settings,
    auth_client,
    client,
    db_session,
    test_user,
)
