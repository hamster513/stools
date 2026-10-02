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
        #: Области, о которых адаптер знает; данные есть только у тех, кому заданы ключи.
        self.scope_ids: set[int] = {1, 2}
        #: Сколько раз платформа спросила возраст находок (`first_seen_many`, в том числе через `first_seen`).
        self.first_seen_calls = 0

    def set_keys(self, scope_id: int, *keys: str) -> None:
        self.scope_ids.add(scope_id)
        self.keys[scope_id] = [CurrentFinding(key=k, title=f"находка {k}", severity="High") for k in keys]

    def scopes(self, db: Any) -> Iterable[int]:
        return sorted(self.scope_ids)

    def has_scope(self, db: Any, scope_id: int) -> bool:
        return scope_id in self.scope_ids

    def current(self, db: Any, scope_id: int) -> Iterable[CurrentFinding] | None:
        if self.fail:
            raise RuntimeError("адаптер сломан")
        found = self.keys.get(scope_id)
        return None if found is None else list(found)

    def first_seen_many(self, db: Any, scope_id: int, keys: Iterable[str]) -> dict[str, dt.datetime]:
        self.first_seen_calls += 1
        return {k: self.first[k] for k in keys if k in self.first}

    def first_seen(self, db: Any, scope_id: int, key: str) -> dt.datetime | None:
        return self.first_seen_many(db, scope_id, [key]).get(key)

    def link(self, scope_id: int, key: str) -> str:
        return f"/test/{scope_id}/{key}"


@pytest.fixture
def today() -> dt.date:
    """«Сегодня» платформы — на момент теста, а не импорта модуля тестов."""
    from api.platform.findings import service

    return service.today()


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
