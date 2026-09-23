"""Онлайн-загрузка бандла: скачать, показать разницу, применить по подтверждению."""
from __future__ import annotations

import base64
import json
import zlib
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from api.db.models import AppSetting, AttackBundleRow
from api.jobs import JobHandle, start_job
from api.modules.attack.models import AttackJob
from api.modules.attack.services import download_job
from tests.api.test_attack_bundle import _replace_by_shipped, bundle_file


def _http(payload: bytes, status: int = 200) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(status, content=payload))
    )


def _job(db: Any) -> JobHandle:
    job = AttackJob(kind="download", started_by="t")
    db.add(job)
    db.commit()
    return JobHandle(db, job)


def test_download_stores_pending_with_diff(auth_client: TestClient, db_session: Any) -> None:
    incoming = bundle_file(
        [{"id": "T1059", "name": "Command and Scripting Interpreter"}], version="21.0"
    )
    download_job.run_download(db_session, _job(db_session), http_factory=lambda: _http(incoming))
    pending = download_job.pending(db_session)
    assert pending is not None and pending.version == "21.0"
    assert "T1059" in pending.diff.added or "T1059" in pending.diff.changed
    assert db_session.get(AttackBundleRow, 1).version != "21.0"  # ещё не применено


def test_network_failure_leaves_nothing_behind(auth_client: TestClient, db_session: Any) -> None:
    with pytest.raises(ValueError):
        download_job.run_download(
            db_session, _job(db_session), http_factory=lambda: _http(b"", status=503)
        )
    assert download_job.pending(db_session) is None


def test_garbage_is_refused(auth_client: TestClient, db_session: Any) -> None:
    """Скачалось не то — задача падает, действующая матрица цела."""
    with pytest.raises(json.JSONDecodeError):
        download_job.run_download(
            db_session, _job(db_session), http_factory=lambda: _http(b"not json")
        )
    assert download_job.pending(db_session) is None


def test_apply_and_discard_via_api(auth_client: TestClient, db_session: Any) -> None:
    incoming = bundle_file([{"id": "T1059", "name": "X"}], version="21.0")
    download_job.run_download(db_session, _job(db_session), http_factory=lambda: _http(incoming))
    shown = auth_client.get("/api/settings/attack/pending").json()
    assert shown["version"] == "21.0" and "diff" in shown
    assert auth_client.post("/api/settings/attack/pending/apply").status_code == 200
    state = auth_client.get("/api/settings/attack").json()
    assert state["version"] == "21.0"
    # Происхождение записано: скачанное и принесённое файлом — разные вещи.
    assert state["source"] == "online"
    assert auth_client.get("/api/settings/attack/pending").json() is None
    download_job.run_download(db_session, _job(db_session), http_factory=lambda: _http(incoming))
    assert auth_client.delete("/api/settings/attack/pending").status_code == 204
    assert auth_client.get("/api/settings/attack/pending").json() is None


def test_download_endpoint_starts_job_once(
    auth_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(download_job, "run_download", lambda db, handle, http_factory=None: None)
    first = auth_client.post("/api/settings/attack/download")
    assert first.status_code == 202 and "job_id" in first.json()


def test_shipped_bundle_replaces_the_downloaded_one_and_says_so(
    auth_client: TestClient, db_session: Any
) -> None:
    """Скачанную матрицу человек выбрал так же, как принесённую файлом.
    Подмена её поставкой молча оставила бы его гадать, откуда взялась
    другая версия."""
    incoming = bundle_file([{"id": "T1059", "name": "X"}], version="21.0")
    download_job.run_download(db_session, _job(db_session), http_factory=lambda: _http(incoming))
    assert auth_client.post("/api/settings/attack/pending/apply").status_code == 200
    assert auth_client.get("/api/settings/attack").json()["source"] == "online"

    _replace_by_shipped(db_session)

    state = auth_client.get("/api/settings/attack").json()
    assert state["version"] == "19.2" and state["source"] == "builtin"
    notice = state["replacement"]
    assert notice is not None
    assert notice["replaced_version"] == "21.0"
    assert notice["downgraded"] is True


def test_broken_pending_row_is_treated_as_absent(
    auth_client: TestClient, db_session: Any
) -> None:
    """Строку пишет только код загрузки; нечитаемая — повод сказать
    «ничего не ждёт», а не отдавать пятисотку на каждый заход в настройки."""
    db_session.add(
        AppSetting(key=download_job.PENDING_KEY, value_json='{"version": "21.0"}')
    )
    db_session.commit()
    assert auth_client.get("/api/settings/attack/pending").json() is None
    assert auth_client.delete("/api/settings/attack/pending").status_code == 204


def test_download_stops_at_the_size_cap(db_session: Any, tmp_path: Path) -> None:
    """Сорвавшийся адрес может отдавать бесконечный поток: качать его до
    конца — значит забить диск стенда. Обрыв по счётчику, а не по вере
    в content-length, который сервер может и не прислать."""
    with pytest.raises(ValueError, match="бандл больше"):
        download_job.download(
            "http://mitre.example/enterprise-attack.json",
            tmp_path / "bundle.json",
            _job(db_session),
            _http(b"x" * (3 * 1024 * 1024)),
            max_bytes=1024 * 1024,
        )


def test_oversized_download_fails_the_job_and_leaves_nothing(
    db_session: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Предел тот же, что у загрузки файлом: разбор идёт в памяти процесса."""
    monkeypatch.setattr(download_job, "MAX_BUNDLE_BYTES", 1024 * 1024)
    with pytest.raises(ValueError, match="бандл больше 1 МБ"):
        download_job.run_download(
            db_session, _job(db_session), http_factory=lambda: _http(b"x" * (3 * 1024 * 1024))
        )
    assert download_job.pending(db_session) is None


def test_pending_is_stored_compressed_and_read_without_decoding(
    auth_client: TestClient, db_session: Any
) -> None:
    """Выжимка лежит сжатой, а карточка «ждёт подтверждения» читает только
    шапку: разворачивать мегабайты техник на каждый заход в настройки незачем."""
    incoming = bundle_file([{"id": "T1059", "name": "X"}], version="21.0")
    download_job.run_download(db_session, _job(db_session), http_factory=lambda: _http(incoming))

    stored = json.loads(db_session.get(AppSetting, download_job.PENDING_KEY).value_json)
    assert set(stored) == {"meta", "bundle_z"}
    meta = download_job.pending(db_session)
    assert meta is not None and meta.version == "21.0"
    assert not hasattr(meta, "bundle")

    book = download_job.pending_bundle(db_session)
    assert book is not None and [t.technique_id for t in book.techniques] == ["T1059"]
    download_job.apply_pending(db_session, "tester")
    assert db_session.get(AttackBundleRow, 1).version == "21.0"


def test_pending_written_by_the_previous_shape_still_applies(
    auth_client: TestClient, db_session: Any
) -> None:
    """Строку от прежней версии (бандл рядом с шапкой, без сжатия) читаем
    по-старому: обновление продукта не должно терять уже скачанное."""
    incoming = bundle_file([{"id": "T1059", "name": "X"}], version="21.0")
    download_job.run_download(db_session, _job(db_session), http_factory=lambda: _http(incoming))
    row = db_session.get(AppSetting, download_job.PENDING_KEY)
    stored = json.loads(row.value_json)
    flat = dict(stored["meta"])
    flat["bundle"] = json.loads(zlib.decompress(base64.b64decode(stored["bundle_z"])))
    row.value_json = json.dumps(flat)
    db_session.commit()

    meta = download_job.pending(db_session)
    assert meta is not None and meta.version == "21.0"
    assert auth_client.post("/api/settings/attack/pending/apply").status_code == 200
    assert auth_client.get("/api/settings/attack").json()["version"] == "21.0"


def test_second_download_is_refused_while_the_first_runs(
    auth_client: TestClient, db_session: Any
) -> None:
    """Загрузка идёт одна: две задачи писали бы в один ожидающий бандл,
    и человек увидел бы разницу не от того файла, который применит."""
    start_job(db_session, AttackJob, "download", "tester")
    response = auth_client.post("/api/settings/attack/download")
    assert response.status_code == 409
    assert response.json()["detail"] == "загрузка уже идёт"


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/api/attack/bundle"),
        ("POST", "/api/attack/translate"),
        ("GET", "/api/attack/translation/gaps"),
    ],
)
def test_module_paths_of_the_matrix_are_gone(auth_client: TestClient, method: str, path: str) -> None:
    """Матрица переехала в общие настройки (/api/settings/attack): старые
    адреса модуля не должны отвечать даже администратору."""
    assert auth_client.request(method, path).status_code == 404


def test_attack_job_cancel_is_an_admin_setting(auth_client: TestClient, client_as: Any, db_session: Any) -> None:
    """Аудит L3: задания ATT&CK запускает только администратор (общие настройки), он же их и
    отменяет — под /api/settings/attack. Ход заданий по-прежнему видят все."""
    job_id = start_job(db_session, AttackJob, "translate", "tester")
    analyst = client_as("analyst")
    assert analyst.get("/api/attack/jobs").status_code == 200
    assert analyst.get(f"/api/attack/jobs/{job_id}").status_code == 200
    assert analyst.post(f"/api/settings/attack/jobs/{job_id}/cancel").status_code == 403
    assert auth_client.post(f"/api/attack/jobs/{job_id}/cancel").status_code == 404  # старого адреса нет
    assert auth_client.post(f"/api/settings/attack/jobs/{job_id}/cancel").status_code == 204
    assert auth_client.get(f"/api/attack/jobs/{job_id}").json()["cancel_requested"] is True
    assert auth_client.post("/api/settings/attack/jobs/999999/cancel").status_code == 404
