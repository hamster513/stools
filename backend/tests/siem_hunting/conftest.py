"""Фикстуры Threat Hunting поверх инфраструктуры tests/api/conftest.py."""
from __future__ import annotations

from typing import Any

import pytest

from api.modules.siem.services.kb_settings import KbConnectionIn, save_connection
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
from tests.siem_hunting.fake_events import TOKEN, FakeEvents


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch, db_session: Any) -> FakeEvents:  # noqa: F811 — фикстура из реэкспорта
    """Поддельный API событий для ночного прогона и большого ханта, подключение настроено.
    В test_nightly.py — своя одноимённая фикстура (только ночной прогон)."""
    fake = FakeEvents()
    monkeypatch.setattr("api.modules.siem.hunting.deep.make_client", fake.http_factory)
    monkeypatch.setattr("api.modules.siem.hunting.nightly.make_client", fake.http_factory)
    save_connection(db_session, KbConnectionIn(host="mp.corp.local", api_token=TOKEN), "t")
    return fake
