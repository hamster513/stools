"""Файл выгрузки KSC на диске — так же, как у AD: загрузка переносится без повторного
сжатия, сбор пишется в gzip потоком, sha256 прежний, временных файлов не остаётся."""
from __future__ import annotations

import gzip
import hashlib
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.modules.ksc.core import client as client_mod
from api.modules.ksc.models import KscSnapshot
from api.modules.ksc.services import connections as svc
from api.modules.ksc.services import snapshots as snapshots_mod
from api.modules.ksc.services.snapshots import snapshot_path
from tests.ksc.fake_ksc import PASSWORD, USER, FakeKsc, http_factory_for
from tests.ksc.synthetic import export_bytes


@pytest.fixture
def fake(monkeypatch: Any) -> FakeKsc:
    f = FakeKsc()
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(f))
    return f


def _upload(client: TestClient, name: str, body: bytes) -> dict[str, Any]:
    r = client.post("/api/ksc/snapshots/file", files={"file": (name, body, "application/octet-stream")})
    assert r.status_code == 202, r.text
    return client.get(f"/api/ksc/jobs/{r.json()['job_id']}").json()


def _last_snapshot(db_session: Any) -> KscSnapshot:
    db_session.expire_all()
    snap = db_session.execute(select(KscSnapshot).order_by(KscSnapshot.id.desc())).scalars().first()
    assert snap is not None
    return snap


def _files(app_settings: Any) -> list[str]:
    folder = app_settings.data_dir / "ksc"
    return sorted(p.name for p in folder.glob("*")) if folder.exists() else []


@pytest.mark.parametrize("packed", [True, False], ids=["gzip", "plain"])
def test_upload_is_stored_and_hashed_as_before(auth_client: TestClient, db_session: Any, app_settings: Any, packed: bool) -> None:
    text = export_bytes()
    body = gzip.compress(text) if packed else text
    assert _upload(auth_client, "ksc.json.gz" if packed else "ksc.json", body)["status"] == "done"
    snap = _last_snapshot(db_session)
    path = snapshot_path(app_settings.data_dir, snap.id)
    assert (path.read_bytes() == body) if packed else (gzip.decompress(path.read_bytes()) == text)
    assert snap.sha256 == hashlib.sha256(body).hexdigest()
    assert _files(app_settings) == [path.name]


def test_collect_stores_the_collected_text(auth_client: TestClient, db_session: Any, app_settings: Any, fake: FakeKsc, monkeypatch: Any) -> None:
    texts: list[bytes] = []
    real = svc.collect

    def collect(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raw = real(*args, **kwargs)
        texts.append(json.dumps(raw, ensure_ascii=False).encode("utf-8"))
        return raw

    monkeypatch.setattr(svc, "collect", collect)
    cid = auth_client.post("/api/ksc/connections", json={"host": "ksc01.corp.local", "username": USER, "password": PASSWORD}).json()["id"]
    r = auth_client.post(f"/api/ksc/connections/{cid}/collect")
    assert auth_client.get(f"/api/ksc/jobs/{r.json()['job_id']}").json()["status"] == "done"
    snap = _last_snapshot(db_session)
    path = snapshot_path(app_settings.data_dir, snap.id)
    assert gzip.decompress(path.read_bytes()) == texts[0]
    assert snap.sha256 == hashlib.sha256(texts[0]).hexdigest()
    assert _files(app_settings) == [path.name]


def test_collect_failure_after_collection_leaves_no_file(auth_client: TestClient, app_settings: Any, fake: FakeKsc, monkeypatch: Any) -> None:
    def boom(*args: Any) -> Any:
        raise RuntimeError("сбой анализа")

    monkeypatch.setattr(snapshots_mod, "analyze", boom)
    cid = auth_client.post("/api/ksc/connections", json={"host": "ksc01.corp.local", "username": USER, "password": PASSWORD}).json()["id"]
    r = auth_client.post(f"/api/ksc/connections/{cid}/collect")
    job = auth_client.get(f"/api/ksc/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "failed" and job["error"] == "сбой анализа"
    assert _files(app_settings) == []


def test_online_above_upload_limit_can_be_read_compared_and_reanalyzed(auth_client, db_session, app_settings, fake, monkeypatch):
    from api.modules.ksc.core import export
    from api.modules.ksc.services.changes import summary_view

    monkeypatch.setattr(export, "MAX_UNPACKED", 1024)
    original = svc.collect
    dates = iter(("2026-11-18T01:00:00Z", "2026-11-19T01:00:00Z"))

    def collect(*args, **kwargs):
        raw = original(*args, **kwargs)
        raw["server"]["collected_at"] = next(dates)
        return raw

    monkeypatch.setattr(svc, "collect", collect)
    cid = auth_client.post("/api/ksc/connections", json={"host": "ksc01", "username": USER, "password": PASSWORD}).json()["id"]
    snapshots = []
    for _ in range(2):
        response = auth_client.post(f"/api/ksc/connections/{cid}/collect")
        job = auth_client.get(f"/api/ksc/jobs/{response.json()['job_id']}").json()
        assert job["status"] == "done", job
        snap = _last_snapshot(db_session)
        snapshots.append(snap.id)
        body = snapshot_path(app_settings.data_dir, snap.id).read_bytes()
        assert len(gzip.decompress(body)) > export.MAX_UNPACKED
        software = auth_client.get(f"/api/ksc/snapshots/{snap.id}/hosts/h-ws01/software")
        assert software.status_code == 200, software.text
        assert software.json()["software"]["total"] == 1
    summary = summary_view(_last_snapshot(db_session))
    assert summary["prev"] == snapshots[0] and summary["reason"] is None
    response = auth_client.post(f"/api/ksc/snapshots/{snapshots[1]}/reanalyze")
    job = auth_client.get(f"/api/ksc/jobs/{response.json()['job_id']}").json()
    assert job["status"] == "done", job
    # A saved online archive is still untrusted when uploaded through the public endpoint.
    job = _upload(auth_client, "copied-online.json.gz", body)
    assert job["status"] == "failed" and "распакованный размер больше лимита" in job["error"]
    assert len(auth_client.get("/api/ksc/snapshots").json()) == 2
