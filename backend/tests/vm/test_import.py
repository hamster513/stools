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


@pytest.mark.parametrize("body", [
    b'@Host;Host.@Vulners.CVEs\nnew;CVE-2026-12345\n"unfinished;CVE-2026-12346',
    b"@Host;Host.@Vulners.CVEs\nnew;CVE-2026-12345\nmissing-column\n",
    b"@Host;Host.@Vulners.CVEs\nnew;CVE-2026-12345;unexpected-column\n",
])
def test_incomplete_csv_preserves_previous_snapshot(
    auth_client: TestClient, db_session: Any, body: bytes, monkeypatch: Any,
) -> None:
    from api.modules.vm.services import importer

    assert _upload(auth_client, "hosts.csv")["status"] == "done"
    old_ids = list(db_session.scalars(select(VmHost.id).order_by(VmHost.id).limit(10)))
    monkeypatch.setattr(importer, "PAIR_BATCH", 1)  # At least one staging commit before the broken row.
    job = _upload(auth_client, "partial.csv", body)
    assert job["status"] == "failed"
    assert list(db_session.scalars(select(VmHost.id).order_by(VmHost.id).limit(10))) == old_ids


@pytest.mark.parametrize("failure", ["truncated", "timeout", "invalid_json", "download_http", "download_timeout"])
def test_api_unverified_export_preserves_previous_snapshot(
    auth_client: TestClient, db_session: Any, tmp_path: Path, monkeypatch: Any, failure: str,
) -> None:
    import httpx

    from api.modules.vm.core.mpvm import MpVmError
    from tests.vm.test_groups_import import FakeVm, _run_vm

    class UnverifiedVm(FakeVm):
        def handler(self, request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/export") and request.url.params["pdqlToken"] == "main":
                if failure == "download_timeout":
                    raise httpx.ReadTimeout("test timeout", request=request)
                if failure == "download_http":
                    return httpx.Response(503)
            if request.url.path.endswith("/row_count") and request.url.params["pdqlToken"] == "main":
                if failure == "timeout":
                    raise httpx.ReadTimeout("test timeout", request=request)
                if failure == "invalid_json":
                    return httpx.Response(200, content=b"<html>not JSON</html>")
                if failure == "truncated":
                    return httpx.Response(200, json={"rowCount": 999})
            return super().handler(request)

    assert _upload(auth_client, "hosts.csv")["status"] == "done"
    before = list(db_session.scalars(select(VmHost.id).order_by(VmHost.id).limit(10)))
    with pytest.raises(MpVmError, match="полнот|экспорт"):
        _run_vm(db_session, tmp_path, monkeypatch, UnverifiedVm())
    assert list(db_session.scalars(select(VmHost.id).order_by(VmHost.id).limit(10))) == before


def test_second_import_rejected_while_running(auth_client: TestClient, db_session: Any) -> None:
    db_session.add(VmJob(kind="import_vm", stage="parsing", status="running", started_by="x"))
    db_session.commit()
    r = auth_client.post("/api/vm/import/file", files={"file": ("h.csv", b"@Host\n", "text/csv")})
    assert r.status_code == 409 and "уже идёт" in r.json()["detail"]


def test_vm_import_requires_connection(auth_client: TestClient) -> None:
    r = auth_client.post("/api/vm/import/vm")
    assert r.status_code == 400
