"""Импорт через API: замена атомарна, зоны заводятся, риск считается."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.modules.vm.models import VmHost, VmHostCve, VmJob, VmZone

FIXTURES = Path(__file__).parent / "fixtures"


def _upload(client: TestClient, name: str, content: bytes | None = None) -> dict[str, Any]:
    data = content if content is not None else (FIXTURES / name).read_bytes()
    r = client.post("/api/vm/import/file", files={"file": (name, data, "application/octet-stream")})
    assert r.status_code == 202, r.text
    job = client.get(f"/api/vm/jobs/{r.json()['job_id']}").json()
    return job


def test_csv_import_creates_hosts_pairs_zones(auth_client: TestClient, db_session: Any) -> None:
    job = _upload(auth_client, "hosts.csv")
    assert job["status"] == "done", job
    state = auth_client.get("/api/vm/import").json()
    assert state["active"] is None
    last = state["last"]
    assert (last["hosts"], last["pairs"], last["cves"], last["new_zones"]) == (3, 4, 4, 2)
    assert last["source"] == "file" and last["filename"] == "hosts.csv"

    hosts = {h.hostname: h for h in db_session.execute(select(VmHost)).scalars()}
    assert set(hosts) == {"srv01.corp.local", "ws02.corp.local", "srv03.corp.local"}
    assert hosts["srv01.corp.local"].groups == "Servers,Prod"
    zones = {z.name: z for z in db_session.execute(select(VmZone)).scalars()}
    assert set(zones) == {"DMZ", "Internal"} and not zones["DMZ"].marked
    pairs = db_session.execute(select(VmHostCve)).scalars().all()
    assert len(pairs) == 4
    # Нет справочников: баллы EPSS 8, CVSS 12.5, неизвестного вектора 12;
    # значимость High 12, зона неизвестна. Старый кэш ценности хранится для совместимости.
    srv01 = next(p for p in pairs if p.host_id == hosts["srv01.corp.local"].id)
    assert srv01.risk == 45 and srv01.risk_raw == pytest.approx((8 + 12.5 + 12 + 12) / 100)
    assert hosts["srv01.corp.local"].value == pytest.approx(0.8)


def test_reimport_replaces_and_dedupes(auth_client: TestClient, db_session: Any) -> None:
    assert _upload(auth_client, "hosts.csv")["status"] == "done"
    job = _upload(auth_client, "hosts.json")
    assert job["status"] == "done", job
    last = auth_client.get("/api/vm/import").json()["last"]
    assert (last["hosts"], last["pairs"]) == (2, 3)
    names = sorted(db_session.execute(select(VmHost.hostname)).scalars())
    assert names == ["srv01.corp.local", "srv02.corp.local"]
    # Зоны прошлого импорта остаются: разметка — труд человека.
    assert {z for z in db_session.execute(select(VmZone.name)).scalars()} == {"DMZ", "Internal", "AppDMZ"}


def test_broken_file_keeps_previous_data(auth_client: TestClient, db_session: Any) -> None:
    assert _upload(auth_client, "hosts.csv")["status"] == "done"
    job = _upload(auth_client, "broken.json", b"{not json")
    assert job["status"] == "failed" and job["error"]
    assert db_session.execute(select(VmHost)).scalars().all().__len__() == 3


def test_second_import_rejected_while_running(auth_client: TestClient, db_session: Any) -> None:
    db_session.add(VmJob(kind="import_vm", stage="parsing", status="running", started_by="x"))
    db_session.commit()
    r = auth_client.post("/api/vm/import/file", files={"file": ("h.csv", b"@Host\n", "text/csv")})
    assert r.status_code == 409 and "уже идёт" in r.json()["detail"]


def test_vm_import_requires_connection(auth_client: TestClient) -> None:
    r = auth_client.post("/api/vm/import/vm")
    assert r.status_code == 400
