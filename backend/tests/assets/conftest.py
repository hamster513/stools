"""Фикстуры модуля Assets поверх инфраструктуры tests/api/conftest.py."""
from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

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


@pytest.fixture
def assets_admin(client_as: Callable[..., TestClient]) -> TestClient:  # noqa: F811 — фикстура из реэкспорта выше
    """Администратор модуля Assets: сети, группы сетей, DNS, RackTables, расписания и settings — настройка модуля."""
    return client_as({"assets": "admin"})
