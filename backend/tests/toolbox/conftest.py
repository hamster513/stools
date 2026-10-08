"""Фикстуры ToolBox поверх инфраструктуры tests/api/conftest.py (Postgres, клиенты по ролям)."""
from __future__ import annotations

from tests.api.conftest import (  # noqa: F401 — реэкспорт фикстур
    _reset_db_singletons,
    app_settings,
    auth_client,
    client,
    client_as,
    db_session,
    make_user,
    test_user,
)
