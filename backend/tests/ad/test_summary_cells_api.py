"""Ручка «кто в ячейке сводки» и кэш составов по снапшоту на синтетическом домене."""
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex, load_export_path
from api.modules.ad.core.summary_cells import cell_count, summary_cells
from api.modules.ad.models import AdSnapshot
from api.modules.ad.services import summary_cells as svc
from api.modules.ad.services.settings import save_config
from api.modules.ad.services.snapshots import snapshot_path
from tests.ad.synthetic import build_export, rid

INACTIVE = "accounts:users:inactive"
#: Domain Admins — участники-пользователи и, через вложенность, возможно компьютеры.
ADMINS_MEMBERS = f"groups:members:{rid(512)}"


@pytest.fixture(autouse=True)
def _clear_cache() -> Iterator[None]:
    """Номера снапшотов между тестами повторяются (TRUNCATE … RESTART IDENTITY)."""
    svc.clear_cache()
    yield
    svc.clear_cache()


def _snapshot(client: TestClient) -> int:
    r = client.post("/api/ad/snapshots/file", files={"file": ("ad.json", json.dumps(build_export()).encode(), "application/json")})
    assert r.status_code == 202, r.text
    job = client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "done", job
    snap_id: int = client.get("/api/ad/snapshots").json()[0]["id"]
    return snap_id


def _summary(client: TestClient, snap_id: int) -> dict[str, Any]:
    body: dict[str, Any] = client.get(f"/api/ad/snapshots/{snap_id}/summary").json()
    return body


def _set_summary(db: Session, snap_id: int, summary: dict[str, Any]) -> None:
    snap = db.get(AdSnapshot, snap_id)
    assert snap is not None
    snap.summary_json = json.dumps(summary)
    db.commit()


def _cells_by(data_dir: Path, snap_id: int, cfg: AdConfig) -> dict[str, Any]:
    return dict(summary_cells(ExportIndex(load_export_path(snapshot_path(data_dir, snap_id))), cfg))


def test_summary_cell_ok(auth_client: TestClient) -> None:
    snap_id = _snapshot(auth_client)
    snap = auth_client.get(f"/api/ad/snapshots/{snap_id}").json()
    summary = _summary(auth_client, snap_id)
    url = f"/api/ad/snapshots/{snap_id}/summary-cell"
    r = auth_client.get(url, params={"cell": INACTIVE})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body == {"snapshot_id": snap_id, "collected_at": snap["collected_at"], "domain": "corp.local",
                    "cell": INACTIVE, "label": "Пользователи: неактивно",
                    "users": cell_count(summary, INACTIVE), "computers": 0}
    assert body["users"] > 0
    r = auth_client.get(url, params={"cell": ADMINS_MEMBERS})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["label"] == "Группа «Domain Admins»: участники"
    assert body["users"] + body["computers"] == cell_count(summary, ADMINS_MEMBERS)


def test_summary_cell_unknown_cell_404(auth_client: TestClient) -> None:
    snap_id = _snapshot(auth_client)
    for cell in ("accounts:users:nope", f"groups:members:{rid(9999)}", "garbage"):
        r = auth_client.get(f"/api/ad/snapshots/{snap_id}/summary-cell", params={"cell": cell})
        assert r.status_code == 404 and r.json()["detail"] == "ячейки сводки нет", (cell, r.text)


def test_summary_cell_unknown_snapshot_404(auth_client: TestClient) -> None:
    r = auth_client.get("/api/ad/snapshots/999999/summary-cell", params={"cell": INACTIVE})
    assert r.status_code == 404 and r.json()["detail"]


def test_summary_cell_missing_export_409(auth_client: TestClient, app_settings: Any) -> None:
    snap_id = _snapshot(auth_client)
    snapshot_path(app_settings.data_dir, snap_id).unlink()
    r = auth_client.get(f"/api/ad/snapshots/{snap_id}/summary-cell", params={"cell": INACTIVE})
    assert r.status_code == 409 and r.json()["detail"] == "файл выгрузки снапшота недоступен"


def test_summary_cell_requires_login_401(client: TestClient) -> None:
    assert client.get("/api/ad/snapshots/1/summary-cell", params={"cell": INACTIVE}).status_code == 401


def test_cell_info_cached(auth_client: TestClient, app_settings: Any, db_session: Session,
                          monkeypatch: pytest.MonkeyPatch) -> None:
    snap_id = _snapshot(auth_client)
    reads: list[Path] = []

    def counting(path: Path) -> Any:
        reads.append(path)
        return load_export_path(path)

    monkeypatch.setattr(svc, "load_export_path", counting)
    first = svc.cell_info(db_session, app_settings.data_dir, snap_id, INACTIVE)
    second = svc.cell_info(db_session, app_settings.data_dir, snap_id, ADMINS_MEMBERS)
    assert len(reads) == 1
    assert first.users and first.label == "Пользователи: неактивно"
    assert second.user_sams is first.user_sams  # один словарь на снапшот
    assert first.domain == "corp.local" and first.snapshot_id == snap_id
    assert first.user_sams[rid(1101)] == "admin1"
    with pytest.raises(svc.CellNotFound):
        svc.cell_info(db_session, app_settings.data_dir, snap_id, "accounts:users:nope")
    with pytest.raises(svc.CellNotFound):
        svc.cell_info(db_session, app_settings.data_dir, 999999, INACTIVE)
    assert len(reads) == 1


def test_cell_info_missing_export_unavailable(auth_client: TestClient, app_settings: Any, db_session: Session) -> None:
    snap_id = _snapshot(auth_client)
    snapshot_path(app_settings.data_dir, snap_id).unlink()
    with pytest.raises(svc.CellUnavailable):
        svc.cell_info(db_session, app_settings.data_dir, snap_id, INACTIVE)


def test_cell_info_uses_build_params(auth_client: TestClient, app_settings: Any, db_session: Session) -> None:
    """Настройки поменяли после построения — состав по параметрам сводки, число совпадает со сводкой."""
    snap_id = _snapshot(auth_client)
    summary = _summary(auth_client, snap_id)
    save_config(db_session, AdConfig(user_inactivity_days=365), "tester")
    info = svc.cell_info(db_session, app_settings.data_dir, snap_id, INACTIVE)
    assert len(info.users) == cell_count(summary, INACTIVE)


def test_cell_info_v1_summary_uses_current_config(auth_client: TestClient, app_settings: Any, db_session: Session) -> None:
    snap_id = _snapshot(auth_client)
    summary = _summary(auth_client, snap_id)
    current = AdConfig(user_inactivity_days=365)
    save_config(db_session, current, "tester")
    expected = _cells_by(app_settings.data_dir, snap_id, current)[INACTIVE].users
    assert len(expected) != cell_count(summary, INACTIVE)  # иначе тест не различает настройки
    v1 = {k: v for k, v in summary.items() if k != "params"} | {"version": 1}
    _set_summary(db_session, snap_id, v1)
    assert svc.cell_info(db_session, app_settings.data_dir, snap_id, INACTIVE).users == expected


@pytest.mark.parametrize("summary_json", ["", "bad-params"])
def test_cell_info_no_or_invalid_params_uses_current_config(
    auth_client: TestClient, app_settings: Any, db_session: Session, summary_json: str
) -> None:
    """Сводки нет (снапшот до её появления) или её параметры уже не проходят проверку — текущие настройки."""
    snap_id = _snapshot(auth_client)
    current = AdConfig(user_inactivity_days=365)
    save_config(db_session, current, "tester")
    expected = _cells_by(app_settings.data_dir, snap_id, current)[INACTIVE].users
    snap = db_session.get(AdSnapshot, snap_id)
    assert snap is not None
    if summary_json:
        summary = json.loads(snap.summary_json)
        summary["params"] = {"user_inactivity_days": "не число"}
        snap.summary_json = json.dumps(summary)
    else:
        snap.summary_json = ""
    db_session.commit()
    assert svc.cell_info(db_session, app_settings.data_dir, snap_id, INACTIVE).users == expected


def test_cell_info_lru_keeps_four_snapshots(auth_client: TestClient, app_settings: Any, db_session: Session,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
    ids = [_snapshot(auth_client) for _ in range(5)]
    reads: list[Path] = []

    def counting(path: Path) -> Any:
        reads.append(path)
        return load_export_path(path)

    monkeypatch.setattr(svc, "load_export_path", counting)
    for snap_id in ids:
        svc.cell_info(db_session, app_settings.data_dir, snap_id, INACTIVE)
    assert len(reads) == 5
    for snap_id in ids[1:]:
        svc.cell_info(db_session, app_settings.data_dir, snap_id, INACTIVE)
    assert len(reads) == 5  # последние четыре в кэше
    svc.cell_info(db_session, app_settings.data_dir, ids[0], INACTIVE)
    assert len(reads) == 6  # первый вытеснен
