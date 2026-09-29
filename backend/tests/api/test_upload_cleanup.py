"""Загруженный файл убирается, даже если задачу сняли до старта потока; пустая загрузка закрывает задачу."""
from __future__ import annotations

import importlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.jobs import cancel_job
from api.modules.ad.models import AdJob
from api.modules.vm.models import VmJob

vm_import = importlib.import_module("api.modules.vm.routers.import_")
vm_refs = importlib.import_module("api.modules.vm.routers.refs")
collector_routes = importlib.import_module("api.collector_routes")


def _cancel_before_start(monkeypatch: Any, module: Any, db_session: Any, model: type[Any], *, vm_style: bool) -> None:
    """Снятие успевает раньше потока: задачу никто не ведёт, её закрывают как осиротевшую."""
    real = module.run_job

    def run_job(*args: Any) -> None:
        job_id = args[0] if vm_style else args[1]
        cancel_job(db_session, model, job_id)
        real(*args)

    monkeypatch.setattr(module, "run_job", run_job)


def _job(db_session: Any, model: type[Any]) -> Any:
    db_session.expire_all()
    return db_session.execute(select(model).order_by(model.id.desc())).scalars().first()


def _leftovers(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.glob("*")) if folder.exists() else []


def test_cancelled_vm_file_import_removes_upload(auth_client: TestClient, db_session: Any, app_settings: Any, monkeypatch: Any) -> None:
    _cancel_before_start(monkeypatch, vm_import, db_session, VmJob, vm_style=True)
    r = auth_client.post("/api/vm/import/file", files={"file": ("h.csv", b"@Host\nx\n", "text/csv")})
    assert r.status_code == 202, r.text
    assert _job(db_session, VmJob).status == "cancelled"
    assert _leftovers(app_settings.data_dir / "vm") == []


def test_cancelled_vm_ref_upload_removes_every_file(auth_client: TestClient, db_session: Any, app_settings: Any, monkeypatch: Any) -> None:
    _cancel_before_start(monkeypatch, vm_refs, db_session, VmJob, vm_style=True)
    files = [("files", ("a.csv", b"cve,epss\n", "text/csv")), ("files", ("b.csv", b"cve,epss\n", "text/csv"))]
    r = auth_client.post("/api/vm/refs/epss/upload", files=files)
    assert r.status_code == 202, r.text
    assert _job(db_session, VmJob).status == "cancelled"
    assert _leftovers(app_settings.data_dir / "vm") == []


def test_cancelled_ad_snapshot_upload_removes_file(auth_client: TestClient, db_session: Any, app_settings: Any, monkeypatch: Any) -> None:
    _cancel_before_start(monkeypatch, collector_routes, db_session, AdJob, vm_style=False)
    r = auth_client.post("/api/ad/snapshots/file", files={"file": ("e.json", b"{}", "application/json")})
    assert r.status_code == 202, r.text
    assert _job(db_session, AdJob).status == "cancelled"
    assert _leftovers(app_settings.data_dir / "ad") == []


@pytest.mark.parametrize(
    ("url", "files"),
    [
        ("/api/vm/import/file", lambda: {"file": ("h.csv", b"", "text/csv")}),
        ("/api/vm/refs/epss/upload", lambda: [("files", ("a.csv", b"", "text/csv"))]),
    ],
    ids=["import", "refs"],
)
def test_empty_upload_fails_the_job(
    auth_client: TestClient, db_session: Any, url: str, files: Callable[[], Any],
) -> None:
    r = auth_client.post(url, files=files())
    assert r.status_code == 422
    job = _job(db_session, VmJob)
    assert job.status == "failed" and job.error == "пустой файл" and job.finished_at is not None
    # Следующая загрузка не упирается в «импорт уже идёт».
    ok = auth_client.post("/api/vm/import/file", files={"file": ("h.csv", b"@Host\n", "text/csv")})
    assert ok.status_code == 202, ok.text
