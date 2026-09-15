"""Фикстуры модуля attack поверх инфраструктуры tests/api/conftest.py."""
from __future__ import annotations

import pytest

from api.modules.attack import layers as layers_module
from tests.api.conftest import (  # noqa: F401 — реэкспорт фикстур
    _reset_db_singletons,
    app_settings,
    auth_client,
    client,
    db_session,
    test_user,
)


@pytest.fixture
def clean_layers(monkeypatch: pytest.MonkeyPatch) -> dict[str, layers_module.Layer]:
    """Реестр без слоёв модулей: тесты регистрируют свои."""
    fresh: dict[str, layers_module.Layer] = {}
    monkeypatch.setattr(layers_module, "LAYERS", fresh)
    return fresh
