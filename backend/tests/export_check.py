"""Общая проверка ручки выгрузки списка (спека фильтров и экспорта §2.2): заголовок CSV — подписи колонок,
фильтр списка сужает выгрузку, XLSX читается обратно и совпадает с CSV по числу строк."""
from __future__ import annotations

import csv
import io
from typing import Any

from fastapi.testclient import TestClient

from kbaudit.attack.reference import rows_from_xlsx


def csv_rows(client: TestClient, url: str, **params: Any) -> list[list[str]]:
    r = client.get(url, params={**params, "format": "csv"})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/csv")
    return list(csv.reader(io.StringIO(r.content.decode("utf-8-sig")), delimiter=";"))


def check_export(client: TestClient, url: str, titles: list[str], *, narrow: dict[str, Any] | None = None,
                 **params: Any) -> list[list[str]]:
    """Полная выгрузка (с `params`) — CSV и XLSX; `narrow` — одно значение фильтра: строк меньше, но не ноль.
    Возвращает строки полного CSV."""
    full = csv_rows(client, url, **params)
    assert full[0] == titles
    assert len(full) > 1, "пустая выгрузка ничего не проверяет"
    if narrow is not None:
        part = csv_rows(client, url, **params, **narrow)
        assert part[0] == titles
        assert 1 < len(part) < len(full), (narrow, len(part), len(full))
    r = client.get(url, params={**params, "format": "xlsx"})
    assert r.status_code == 200, r.text
    table = rows_from_xlsx(r.content)
    assert table[0] == titles and len(table) == len(full)
    return full
