"""Ручка «Сервер KSC»: 2FA, администраторы, сертификаты, иерархия, точки распространения."""
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from tests.ksc.synthetic import build_export
from tests.ksc.test_api import upload


def test_server_endpoint(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    body = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/server").json()

    assert body["two_factor_required_for_all"] is False

    # account — то же значение, что target находки: UPN, если он есть
    accounts = {a["account"] for a in body["admins"]}
    assert accounts == {"kladmin", "ivanov@corp.local"}
    kladmin = next(a for a in body["admins"] if a["account"] == "kladmin")
    assert kladmin["internal"] is True and kladmin["role"] == "Main Administrator" and kladmin["group"] == "Managed devices"
    ivanov = next(a for a in body["admins"] if a["account"] == "ivanov@corp.local")
    assert ivanov["internal"] is False
    assert "internal_users" not in body  # список внутренних учёток на экране не показывается

    role_targets = {f["target"] for f in body["findings"] if f["check"] in ("KSC_ADMINS", "KSC_INTERNAL_ADMIN")}
    assert role_targets == accounts  # находки пристают к строкам таблицы

    assert len(body["certs"]) == 1
    assert body["certs"][0]["function"] == "1" and body["certs"][0]["days_left"] == 30

    assert len(body["secondary_servers"]) == 1
    assert body["secondary_servers"][0]["name"] == "ksc02" and body["secondary_servers"][0]["address"] == "ksc02.corp.local"

    assert body["update_agents"] == [{"host": "WS01", "group": "Managed devices/Workstations"}]

    assert body["warnings"] == []

    assert {f["check"] for f in body["findings"]} == {
        "KSC_2FA_OFF", "KSC_INTERNAL_ADMIN", "KSC_ADMINS", "SERVER_CERT", "SECONDARY_SERVER_STALE",
    }

    assert auth_client.get("/api/ksc/snapshots/999/server").status_code == 404


def test_server_endpoint_old_file_without_sections(auth_client: TestClient) -> None:
    """Файл без новых секций (старый сборщик) — пустые списки и `null`, без падения и без находок."""
    raw: dict[str, Any] = build_export()
    for key in ("role_assignments", "internal_users", "security", "server_certs", "secondary_servers", "update_agents"):
        del raw[key]
    assert upload(auth_client, raw)["status"] == "done"
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    body = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/server").json()
    assert body == {
        "two_factor_required_for_all": None,
        "admins": [],
        "certs": [],
        "secondary_servers": [],
        "update_agents": [],
        "warnings": [],
        "findings": [],
    }
