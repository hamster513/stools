"""Журнал действий: `user_id` — id пользователей повтором ключа, внутри фильтра «ИЛИ»."""
from __future__ import annotations

from collections.abc import Callable

from fastapi.testclient import TestClient

URL = "/api/settings/audit"


def _total(client: TestClient, **params: object) -> int:
    r = client.get(URL, params={"page_size": "500", **params})
    assert r.status_code == 200, r.text
    return int(r.json()["total"])


def test_two_users_sum_up(auth_client: TestClient, client_as: Callable[[str], TestClient], test_user: object) -> None:
    other = client_as("analyst")
    other.put("/api/findings/state", json={"module": "x", "scope_id": 0, "key": "k"})  # отказ или ошибка — тоже событие
    auth_client.put("/api/settings/security", json={"session_ttl_hours": 3})
    ids = sorted({i["user_id"] for i in auth_client.get(URL, params={"page_size": "500"}).json()["items"] if i["user_id"]})
    assert len(ids) >= 2, ids
    a, b = str(ids[0]), str(ids[1])
    one, two = _total(auth_client, user_id=a), _total(auth_client, user_id=b)
    assert one > 0 and two > 0
    assert _total(auth_client, user_id=[a, b]) == one + two
    assert auth_client.get(URL, params={"user_id": ["1", "x"]}).status_code == 422
    assert auth_client.get(f"{URL}/export", params={"user_id": [a, b]}).status_code == 200
