"""Слой покрытия SIEM совпадает с прежним состоянием по техникам."""
from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from api.modules.attack.layers import LAYERS
from tests.api.test_attack_markup import _grouped_zip, upload_and_wait


def test_siem_layer_reflects_confirmed_markup(
    auth_client: TestClient, db_session: Any
) -> None:
    snapshot_id = int(upload_and_wait(auth_client, _grouped_zip())["snapshot_id"])
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    group = groups["items"][0]["group"]
    response = auth_client.post(
        "/api/siem/attack/confirm",
        json={"snapshot_id": snapshot_id, "group": group, "techniques": ["T1003.001"]},
    )
    assert response.status_code == 204, response.text

    result = LAYERS["siem"].build(db_session)
    assert result.available and "T1003.001" in result.technique_ids
    cell = result.cells["T1003"]
    assert cell.status == "confirmed" and cell.count >= 1
    # Ключ группы — `автор/тип/подтип`: в ссылке он обязан быть закодирован,
    # иначе слэш из имени читается как часть адреса и уводит не туда.
    href = cell.items[0].href
    assert "/" in group, "в выгрузке ключ группы составной — иначе проверка пустая"
    query = href.split("?group=", 1)[1]
    assert "%2F" in query and "/" not in query
    assert urlparse(href).path == f"/siem/snapshots/{snapshot_id}/rules"
    assert parse_qs(urlparse(href).query)["group"] == [group]


def test_siem_layer_without_snapshot(db_session: Any) -> None:
    result = LAYERS["siem"].build(db_session)
    assert result.available is False and result.cells == {} and result.note
