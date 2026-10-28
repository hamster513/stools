"""Многозначные фасеты реестра активов: внутри фасета — «ИЛИ». У фасетов с одним значением на актив
(критичность, зона, сеть) два значения дают сумму итогов порознь; у источников и кодов расхождений
актив может подходить под оба — там итог равен объединению выбранных по каждому порознь."""
from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.assets.test_assets_api import (  # noqa: F401 — фикстура синтетики трёх источников
    analyst,
    by_name,
)

URL = "/api/assets/assets"


def _ids(c: TestClient, **params: Any) -> set[int]:
    r = c.get(URL, params=params)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == len(body["items"])
    return {i["id"] for i in body["items"]}


def _with_networks(c: TestClient, admin: TestClient) -> tuple[int, int]:
    """Две сети в разных зонах (их заводит администратор модуля); msk1 — в первой, ws01 и srv01 — во второй."""
    for zone in ("DMZ", "Office"):
        assert admin.post("/api/assets/zones", json={"name": zone}).status_code in (200, 201, 409)
    nets = []
    for cidr, zone in (("10.91.0.0/24", "DMZ"), ("10.92.0.0/24", "Office")):
        r = admin.post("/api/assets/networks", json={"cidr": cidr, "zone": zone})
        assert r.status_code in (200, 201), r.text
        nets.append(int(r.json()["id"]))
    for name, net in (("msk1", nets[0]), ("ws01", nets[1]), ("srv01", nets[1])):
        r = c.patch(f"{URL}/{by_name(c, name)['id']}", json={"network_id": net, "network_manual": True})
        assert r.status_code == 200, r.text
    return nets[0], nets[1]


@pytest.mark.parametrize(("param", "a", "b"), [
    ("criticality", "High", "none"),
    ("zone", "DMZ", "Office"),
    ("network_id", None, None),
    ("assignee", "me", "none"),
])
def test_single_valued_facets_sum_up(analyst: TestClient, assets_admin: TestClient, param: str, a: str | None, b: str | None) -> None:  # noqa: F811
    net1, net2 = _with_networks(analyst, assets_admin)
    assert analyst.patch(f"{URL}/{by_name(analyst, 'old01')['id']}", json={"criticality": "High"}).status_code == 200
    if param == "network_id":
        a, b = str(net1), str(net2)
    if param == "assignee":  # исполнитель — у расхождений: фасет без кода не отбирает активы без них
        both = _ids(analyst, assignee=[a, b], code="any")
        assert both == _ids(analyst, assignee=a, code="any") | _ids(analyst, assignee=b, code="any") and both
        return
    one, two = _ids(analyst, **{param: a}), _ids(analyst, **{param: b})
    assert one and two and not one & two
    assert _ids(analyst, **{param: [a, b]}) == one | two


@pytest.mark.parametrize(("param", "a", "b"), [
    ("source_has", "vm", "ksc"),
    ("source_missing", "ksc", "ad"),
    ("code", "conflict", "no_av"),
])
def test_multi_valued_facets_union(analyst: TestClient, param: str, a: str, b: str) -> None:  # noqa: F811
    one, two = _ids(analyst, **{param: a}), _ids(analyst, **{param: b})
    assert one and two
    assert _ids(analyst, **{param: [a, b]}) == one | two


def test_all_and_bad_values(analyst: TestClient) -> None:  # noqa: F811
    full = _ids(analyst)
    assert _ids(analyst, source_has="all", criticality="all", zone="all", code="all") == full
    assert analyst.get(URL, params={"network_id": ["1", "x"]}).status_code == 422
    assert analyst.get(URL, params={"code": ["conflict", "nope"]}).status_code == 422
    assert analyst.get(URL, params={"code": "conflict,no_av"}).status_code == 422  # запятая — не разделитель
    assert analyst.get("/api/assets/assets/ids", params={"source_has": ["vm", "ksc"]}).json()["total"] == len(
        _ids(analyst, source_has=["vm", "ksc"]))
    assert _ids(analyst, disc_status=",") == full


def test_empty_disc_status_does_not_switch_the_filter_on() -> None:
    """Включает фильтр по расхождениям разобранный статус, а не сырая строка (`disc_status=,`)."""
    from api.modules.assets.services.assets import disc_filter

    counted = frozenset({"new"})
    assert not disc_filter(counted, disc_status=[","]).active and not disc_filter(counted, disc_status=[""]).active
    assert disc_filter(counted, disc_status=["new"]).active and disc_filter(counted, disc_status=["all"]).active


def test_dash_is_the_empty_value(analyst: TestClient, assets_admin: TestClient) -> None:  # noqa: F811
    """`-` — «не задано»: критичность не задана (как `none`), зона не задана (вне сетей с зоной)."""
    _with_networks(analyst, assets_admin)
    assert analyst.patch(f"{URL}/{by_name(analyst, 'old01')['id']}", json={"criticality": "High"}).status_code == 200
    assert _ids(analyst, criticality="-") == _ids(analyst, criticality="none") and _ids(analyst, criticality="-")
    assert _ids(analyst, criticality=["High", "-"]) == _ids(analyst)
    no_zone = _ids(analyst, zone="-")
    assert no_zone == _ids(analyst) - _ids(analyst, zone=["DMZ", "Office"]) and no_zone


def test_zone_with_comma_is_one_value(analyst: TestClient, assets_admin: TestClient) -> None:  # noqa: F811
    """Свободное значение с запятой (зона «Офис, этаж 2») не рвётся на части."""
    zone = "Офис, этаж 2"
    assert assets_admin.post("/api/assets/zones", json={"name": zone}).status_code in (200, 201)
    r = assets_admin.post("/api/assets/networks", json={"cidr": "10.93.0.0/24", "zone": zone})
    assert r.status_code in (200, 201), r.text
    msk1 = by_name(analyst, "msk1")["id"]
    assert analyst.patch(f"{URL}/{msk1}", json={"network_id": r.json()["id"], "network_manual": True}).status_code == 200
    assert _ids(analyst, zone=zone) == {msk1}
    assert _ids(analyst, zone=[zone, "Офис"]) == {msk1}
