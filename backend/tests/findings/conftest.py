"""Фикстуры статусов находок поверх инфраструктуры tests/api/conftest.py.

Модуль `test` — поддельный адаптер: свежие ключи области задаёт сам тест,
так автоматика проверяется без импорта настоящих выгрузок.
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Iterable, Iterator
from typing import Any

import pytest

from api.db.models import AppUser
from api.platform.findings import adapters
from api.platform.findings.adapters import CurrentFinding
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


class FakeAdapter:
    module = "test"

    def __init__(self) -> None:
        self.keys: dict[int, list[CurrentFinding]] = {}
        self.first: dict[str, dt.datetime] = {}
        self.fail = False

    def set_keys(self, scope_id: int, *keys: str) -> None:
        self.keys[scope_id] = [CurrentFinding(key=k, title=f"находка {k}", severity="High") for k in keys]

    def scopes(self, db: Any) -> Iterable[int]:
        return list(self.keys)

    def current(self, db: Any, scope_id: int) -> Iterable[CurrentFinding]:
        if self.fail:
            raise RuntimeError("адаптер сломан")
        return list(self.keys.get(scope_id, []))

    def first_seen(self, db: Any, scope_id: int, key: str) -> dt.datetime | None:
        return self.first.get(key)

    def link(self, scope_id: int, key: str) -> str:
        return f"/test/{scope_id}/{key}"


@pytest.fixture
def adapter() -> Iterator[FakeAdapter]:
    fake = FakeAdapter()
    adapters.register_adapter(fake)
    yield fake
    adapters._ADAPTERS.pop("test", None)


@pytest.fixture
def users(make_user: Callable[[str, str], AppUser], db_session: Any) -> dict[str, AppUser]:  # noqa: F811
    """Синтетические учётки: двое аналитиков, администратор, аудитор и заблокированный аналитик."""
    made = {
        "analyst1": make_user("analyst1", "analyst"),
        "analyst2": make_user("analyst2", "analyst"),
        "admin1": make_user("admin1", "admin"),
        "auditor1": make_user("auditor1", "auditor"),
        "blocked1": make_user("blocked1", "analyst"),
    }
    made["blocked1"].is_active = False
    made["analyst1"].display_name = "Аналитик Один"
    db_session.commit()
    return made
