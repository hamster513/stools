"""Выгрузка реестра активов и сетей (спека фильтров и экспорта §2.2): фильтры — как у списка, подписи — как на экране."""
from __future__ import annotations

from collections.abc import Callable

from fastapi.testclient import TestClient

from tests.assets.test_assets_api import analyst  # noqa: F401 — фикстура синтетики трёх источников
from tests.export_check import check_export

ASSETS = ["Имя", "IP", "Сеть", "Зона", "ОС", "Источники", "Виден", "Расхождения"]
NETWORKS = ["CIDR", "Название", "Зона", "Площадка", "Активов"]


def test_assets(analyst: TestClient, client_as: Callable[[str], TestClient]) -> None:  # noqa: F811
    rows = check_export(analyst, "/api/assets/assets/export", ASSETS, narrow={"source_missing": "ksc"})
    listed = analyst.get("/api/assets/assets").json()
    assert [r[0] for r in rows[1:]] == [i["name"] for i in listed["items"]]
    msk1 = next(r for r in rows[1:] if r[0].lower() == "msk1")
    assert msk1[1] == "192.168.2.23" and set(msk1[5].split(", ")) == {"VM", "KSC"}
    assert client_as("auditor").get("/api/assets/assets/export").status_code == 200


def test_networks(analyst: TestClient, client_as: Callable[[str], TestClient]) -> None:  # noqa: F811
    assert analyst.post("/api/assets/networks", json={"cidr": "10.91.0.0/24", "title": "Офис"}).status_code == 201
    assert analyst.post("/api/assets/networks", json={"cidr": "10.92.0.0/24"}).status_code == 201
    rows = check_export(analyst, "/api/assets/networks/export", NETWORKS)
    assert [r[0] for r in rows[1:]] == ["10.91.0.0/24", "10.92.0.0/24"]
    assert rows[1][1] == "Офис" and rows[2][4] == "0"
    assert client_as("auditor").get("/api/assets/networks/export").status_code == 200
