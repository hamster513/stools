"""Выгрузка находок AD (спека фильтров и экспорта §2.2): те же фильтры, что у списка, подписи — как на экране."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable

from fastapi.testclient import TestClient

from tests.ad.test_findings_multi import _snapshot
from tests.export_check import check_export, csv_rows

TITLES = ["Серьёзность", "Проверка", "Identity", "Цель", "Право/детали", "Статус", "Возраст (дней)", "Назначено", "Впервые"]


def test_export_follows_list_filters(auth_client: TestClient, client_as: Callable[[str], TestClient]) -> None:
    snap = _snapshot(auth_client)
    url = f"/api/ad/snapshots/{snap}/findings/export"
    rows = check_export(auth_client, url, TITLES, narrow={"check": "DCSync"})
    listed = auth_client.get(f"/api/ad/snapshots/{snap}/findings", params={"limit": 1000}).json()
    assert len(rows) - 1 == listed["total"]
    # Порядок — как у списка; серьёзность и статус — подписями экрана, дата — ISO.
    assert [r[3] for r in rows[1:]] == [i["target"] for i in listed["items"]]
    assigned = next(r for r in rows[1:] if r[7])
    assert assigned[5] == "В работе" and assigned[0] in {"критический", "высокий", "средний", "низкий", "справочно"}
    assert dt.datetime.fromisoformat(assigned[8]) and assigned[6].isdigit()
    # Многозначный фасет — повтором ключа, как у списка.
    both = csv_rows(auth_client, url, check=["DCSync", "Kerberoast"])
    assert len(both) - 1 == auth_client.get(f"/api/ad/snapshots/{snap}/findings",
                                            params={"check": ["DCSync", "Kerberoast"]}).json()["total"]
    # Аудитор читает список — и выгружает его.
    assert client_as("auditor").get(url).status_code == 200
