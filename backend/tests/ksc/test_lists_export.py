"""Выгрузка списков KSC (спека фильтров и экспорта §2.2): находки, хосты, исключения, сетевые правила, политики,
задачи, журнал изменений — с фильтрами списка, подписи колонок — как на экране, аудитору — тоже."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.modules.ksc.core.policy_model import EXTRACTORS
from api.modules.ksc.models import KscChange
from api.modules.ksc.routers.changes import _where
from tests.export_check import check_export, csv_rows
from tests.ksc.synthetic import build_export
from tests.ksc.test_api import upload
from tests.ksc.test_changes_api import _setup as changes_setup
from tests.ksc.test_policy_objects_api import _fake

FINDINGS = ["Серьёзность", "Проверка", "Хост", "Цель", "Статус", "Возраст (дней)", "Назначено", "Впервые"]
HOSTS = ["Хост", "Группа", "Теги", "ОС", "Агент", "Защита", "Базы", "Полный поиск", "Угрозы", "AD", "Находок"]
EXCLUSIONS = ["Значение", "Риск", "Вид", "Политика/профиль", "Компоненты", "Включено", "Комментарий", "Политик", "Перекрыто"]
NET_RULES = ["Название", "№", "Действие", "Направление", "Протокол", "Локальные порты", "Удалённые порты", "Адреса", "Включено",
             "Политика/профиль"]
POLICIES = ["Политика", "Продукт", "Группа", "Активна", "Групп", "Хостов", "Оценка", "Замки", "Профилей", "Исключений", "Находок"]
TASKS = ["Тип", "Название", "Продукт", "Группа", "Расписание", "Последний запуск", "Успех", "Предупр.", "Провал"]
CHANGES = ["Сбор", "Вид", "Действие", "Политика/профиль", "Где", "Значение"]


@pytest.fixture
def snap(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setitem(EXTRACTORS, "KES", _fake)
    assert upload(auth_client, build_export())["status"] == "done"
    return int(auth_client.get("/api/ksc/snapshots").json()[0]["id"])


def _first_facet(client: TestClient, url: str, facet: str, **params: Any) -> str:
    """Значение фасета, которое отбирает не всё: иначе «сужение» нечем проверить."""
    body = client.get(url, params=params).json()
    total = body["total"] if "total" in body else len(body["items"])
    counts = body["facets"][facet]
    return next(str(k) for k, n in sorted(counts.items()) if 0 < n < total)


@pytest.mark.parametrize(("path", "titles", "facet"), [
    ("findings", FINDINGS, "severity"),
    ("hosts", HOSTS, "group"),
    ("exclusions", EXCLUSIONS, "kind"),
    ("net-rules", NET_RULES, "action"),
    ("policy-list", POLICIES, "product"),
    ("tasks", TASKS, "type"),
])
def test_snapshot_lists(auth_client: TestClient, client_as: Callable[[str], TestClient], snap: int, path: str,
                        titles: list[str], facet: str) -> None:
    url = f"/api/ksc/snapshots/{snap}/{path}"
    value = _first_facet(auth_client, url, facet)
    rows = check_export(auth_client, f"{url}/export", titles, narrow={facet: value})
    body = auth_client.get(url, params={"limit": 1000} if path not in ("policy-list", "tasks") else {}).json()
    assert len(rows) - 1 == len(body["items"])
    assert client_as("auditor").get(f"{url}/export").status_code == 200


def test_hosts_cells_mirror_screen(auth_client: TestClient, snap: int) -> None:
    rows = csv_rows(auth_client, f"/api/ksc/snapshots/{snap}/hosts/export")
    agents = {r[4].split(" · ")[0] for r in rows[1:]}
    assert agents <= {"нет агента", "молчит", "на связи"} and agents
    assert all(" · " in r[6] for r in rows[1:])  # базы: дата · свежесть


def test_changes_where_without_exclusion_kind() -> None:
    """Вид исключения не записан — пусто, а не «None»."""
    change = KscChange(kind="exclusion", section="", path="")
    assert _where(change, None, {"value": "C:\\tmp\\a.exe"}) == ": C:\\tmp\\a.exe"


def test_changes(auth_client: TestClient, client_as: Callable[[str], TestClient]) -> None:
    server, ids = changes_setup(auth_client)
    url = f"/api/ksc/servers/{server}/changes/export"
    rows = check_export(auth_client, url, CHANGES, narrow={"snapshot_id": str(ids["2026-09-16"])})
    assert len(rows) - 1 == 4
    newest = rows[1]
    assert newest[1:4] == ["политика", "изменено", "KES workstations 3 / сама политика"]
    assert newest[4] == "название" and newest[5] == "KES workstations 2 → KES workstations 3"
    assert newest[0].startswith("2026-09-16T12:00:00")
    assert client_as("auditor").get(url).status_code == 200
