from __future__ import annotations

from fastapi.testclient import TestClient


def test_defaults_and_secrets_hidden(auth_client: TestClient) -> None:
    r = auth_client.get("/api/vm/settings")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["threshold"] == 70
    assert body["weights"]["exploitdb"]["remote"] == 1.3
    assert body["connection"]["password_set"] is False
    assert "password" not in body["connection"]
    assert body["defaults"]["threshold"] == 70


def test_put_keeps_secrets_when_empty(auth_client: TestClient) -> None:
    first = {
        "connection": {"host": "vm.local", "username": "u", "password": "p1", "client_secret": "s1"},
        "weights": {},
        "threshold": 60,
    }
    r = auth_client.put("/api/vm/settings", json=first)
    assert r.status_code == 200, r.text
    assert r.json()["connection"]["password_set"] is True
    assert r.json()["threshold"] == 60

    second = {"connection": {"host": "vm2.local", "username": "u", "password": "", "client_secret": ""}, "weights": {}, "threshold": 60}
    r = auth_client.put("/api/vm/settings", json=second)
    assert r.json()["connection"]["host"] == "vm2.local"
    assert r.json()["connection"]["password_set"] is True
    assert r.json()["connection"]["client_secret_set"] is True

    from api.db.base import get_sessionmaker
    from api.modules.vm.services.settings import load_settings

    with get_sessionmaker()() as db:
        s = load_settings(db)
        assert s.connection.password == "p1" and s.connection.client_secret == "s1"


def test_put_keeps_attack_threshold_when_absent(auth_client: TestClient) -> None:
    """Формы подключения и весов порога матрицы не присылают — и не трогают его."""
    assert auth_client.put("/api/vm/settings", json={"attack_min_risk": 0}).json()["attack_min_risk"] == 0

    connection_only = {"connection": {"host": "vm.local", "username": "u", "password": "p1"}, "weights": {}, "threshold": 60}
    r = auth_client.put("/api/vm/settings", json=connection_only)
    assert r.status_code == 200, r.text
    assert r.json()["attack_min_risk"] == 0
    assert auth_client.get("/api/vm/settings").json()["attack_min_risk"] == 0

    # Присланный порог по-прежнему сохраняется, в том числе умолчание.
    assert auth_client.put("/api/vm/settings", json={"attack_min_risk": 40}).json()["attack_min_risk"] == 40
    assert auth_client.get("/api/vm/settings").json()["attack_min_risk"] == 40


def test_zones_roundtrip(auth_client: TestClient) -> None:
    assert auth_client.get("/api/vm/zones").json() == []
    r = auth_client.put(
        "/api/vm/zones",
        json=[{"name": "DMZ", "internet_access": True, "confidential_data": False}],
    )
    assert r.status_code == 204
    zones = auth_client.get("/api/vm/zones").json()
    assert zones == [
        {"name": "DMZ", "internet_access": True, "confidential_data": False, "marked": True, "hosts": 0}
    ]
