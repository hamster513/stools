"""Многозначные фасеты находок SIEM: значения — повтором ключа, внутри фасета «ИЛИ», два значения
дают сумму итогов по каждому порознь; `all` — фильтра нет."""
from __future__ import annotations

import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from tests.api.conftest import META, TEST_LOGIN, _build_kb_zip, upload_and_wait

URL = "/api/siem/findings"
#: Фильтр с отрицанием адреса — третья находка: у синтетики иначе одна полярность и один вид объекта.
FILTER_UUID = "333ffb49-bb9e-4ee4-9262-6754b7ee28d5"


@pytest.fixture
def snap(auth_client: TestClient) -> int:
    buf = io.BytesIO(_build_kb_zip())
    with zipfile.ZipFile(buf, "a") as zf:
        zf.writestr(f"filters/{FILTER_UUID}/metainfo.yaml", META)
        zf.writestr(f"filters/{FILTER_UUID}/DEMO_Not_Gateway.flt", 'filter { dst.ip != "10.20.30.41" }\n')
    return int(upload_and_wait(auth_client, buf.getvalue())["snapshot_id"])


def _total(client: TestClient, snap: int, **params: object) -> int:
    r = client.get(URL, params={"snapshot_id": snap, **params})
    assert r.status_code == 200, r.text
    return int(r.json()["total"])


def _assign_one(client: TestClient, snap: int) -> None:
    key = client.get(URL, params={"snapshot_id": snap}).json()["items"][0]["key"]
    r = client.put("/api/findings/state", json={"module": "siem", "scope_id": 0, "key": key,
                                                "status": "in_work", "assignee": TEST_LOGIN})
    assert r.status_code == 200, r.text


@pytest.mark.parametrize(("facet", "a", "b"), [
    ("kind", "1", "2"),
    ("object_type", "correlation", "filter"),
    ("polarity", "assertion", "negation"),
    ("shape", "ip", "plain"),
    ("field", "subject.account.name", "dst.ip"),
    ("assignee", "me", "none"),
])
def test_two_values_sum_up(auth_client: TestClient, snap: int, facet: str, a: str, b: str) -> None:
    _assign_one(auth_client, snap)
    one, two = _total(auth_client, snap, **{facet: a}), _total(auth_client, snap, **{facet: b})
    assert one > 0 and two > 0
    assert _total(auth_client, snap, **{facet: [a, b]}) == one + two


def test_kind_list_and_all(auth_client: TestClient, snap: int) -> None:
    full = _total(auth_client, snap)
    assert full == 3
    assert _total(auth_client, snap, kind=["1", "2"]) == 3
    # `all` — у строковых фасетов; id и классы — числа, как и до мультивыбора.
    assert _total(auth_client, snap, polarity="all", object_type="all") == full
    assert auth_client.get(URL, params={"snapshot_id": snap, "kind": ["1", "x"]}).status_code == 422
