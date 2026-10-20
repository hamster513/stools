"""Файл выгрузки AD на диске: загрузка переносится в хранилище без повторного сжатия,
сбор пишется в gzip потоком; sha256 — по исходным байтам загрузки или тексту сбора,
как раньше; временных файлов не остаётся ни после успеха, ни после сбоя."""
from __future__ import annotations

import gzip
import hashlib
import json
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select

from api.modules.ad.core.findings import Finding
from api.modules.ad.models import AdSnapshot
from api.modules.ad.services import connections as svc
from api.modules.ad.services import snapshots as snapshots_mod
from api.modules.ad.services.snapshots import snapshot_path
from tests.ad.synthetic import export_bytes
from tests.ad.test_connections import _FakeConn


def _upload(client: TestClient, name: str, body: bytes) -> dict[str, Any]:
    r = client.post("/api/ad/snapshots/file", files={"file": (name, body, "application/octet-stream")})
    assert r.status_code == 202, r.text
    return client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()


def _last_snapshot(db_session: Any) -> AdSnapshot:
    db_session.expire_all()
    snap = db_session.execute(select(AdSnapshot).order_by(AdSnapshot.id.desc())).scalars().first()
    assert snap is not None
    return snap


def _files(app_settings: Any) -> list[str]:
    folder = app_settings.data_dir / "ad"
    return sorted(p.name for p in folder.glob("*")) if folder.exists() else []


def test_gzip_upload_is_stored_as_uploaded(auth_client: TestClient, db_session: Any, app_settings: Any) -> None:
    body = gzip.compress(export_bytes())
    assert _upload(auth_client, "ad.json.gz", body)["status"] == "done"
    snap = _last_snapshot(db_session)
    path = snapshot_path(app_settings.data_dir, snap.id)
    assert path.read_bytes() == body
    assert snap.sha256 == hashlib.sha256(body).hexdigest()
    assert _files(app_settings) == [path.name]


def test_plain_upload_is_stored_gzipped(auth_client: TestClient, db_session: Any, app_settings: Any) -> None:
    body = export_bytes()
    assert _upload(auth_client, "ad.json", body)["status"] == "done"
    snap = _last_snapshot(db_session)
    path = snapshot_path(app_settings.data_dir, snap.id)
    assert gzip.decompress(path.read_bytes()) == body
    assert snap.sha256 == hashlib.sha256(body).hexdigest()
    assert _files(app_settings) == [path.name]


def _fake_ldap(auth_client: TestClient, monkeypatch: Any) -> int:
    fake_conn = _FakeConn()
    monkeypatch.setattr(svc, "ldap3_connection", lambda conn: fake_conn)
    monkeypatch.setattr(svc, "ldap3_searcher", lambda c, **kw: fake_conn.fake.search)
    monkeypatch.setattr(svc, "smb_access", lambda host, u, p, **kw: (fake_conn.fake.smb, fake_conn.fake.ls))
    r = auth_client.post("/api/ad/connections", json={"host": "dc01.corp.local", "username": "CORP\\auditor", "password": "secret"})
    return int(r.json()["id"])


def test_collect_stores_the_collected_text(auth_client: TestClient, db_session: Any, app_settings: Any, monkeypatch: Any) -> None:
    cid = _fake_ldap(auth_client, monkeypatch)
    texts: list[bytes] = []
    real = svc.LdapCollector.collect

    def collect(self: Any) -> dict[str, Any]:
        raw = real(self)
        texts.append(json.dumps(raw, ensure_ascii=False).encode("utf-8"))
        return raw

    monkeypatch.setattr(svc.LdapCollector, "collect", collect)
    r = auth_client.post(f"/api/ad/connections/{cid}/collect")
    assert auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()["status"] == "done"
    snap = _last_snapshot(db_session)
    path = snapshot_path(app_settings.data_dir, snap.id)
    assert gzip.decompress(path.read_bytes()) == texts[0]
    assert snap.sha256 == hashlib.sha256(texts[0]).hexdigest()
    assert _files(app_settings) == [path.name]


def test_collect_failure_leaves_no_file(auth_client: TestClient, app_settings: Any, monkeypatch: Any) -> None:
    cid = _fake_ldap(auth_client, monkeypatch)

    def boom(*args: Any) -> list[Finding]:
        raise RuntimeError("сбой анализа")

    monkeypatch.setattr(snapshots_mod, "analyze", boom)
    r = auth_client.post(f"/api/ad/connections/{cid}/collect")
    job = auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "failed" and job["error"] == "сбой анализа"
    assert auth_client.get("/api/ad/snapshots").json() == []
    assert _files(app_settings) == []


def test_finding_has_no_instance_dict() -> None:
    """Сотни тысяч находок крупного домена: без __dict__ у каждой."""
    f = Finding(check="SensitiveAcl", severity="High")
    assert not hasattr(f, "__dict__")
    assert f.severity_original == "High" and f.details == {} and Finding(check="x", severity="Low").details is not f.details
