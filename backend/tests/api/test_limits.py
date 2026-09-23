"""Лимиты тела запроса и загрузок (аудит H2).

Тело режется до маршрутизации и до проверки сессии: без входа нельзя залить
многогигабайтный запрос. Лимиты в тестах подменяются на мегабайт, чтобы
не гонять сотни мегабайт через тестовый клиент.
"""
from __future__ import annotations

import asyncio
import io
import json
import zipfile
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import JSONResponse

from api import limits
from api.limits import MB, BodyLimitMiddleware, limit_for
from kbaudit import safe_io
from tests.ksc.synthetic import build_export


def test_limit_for_uses_path_prefixes() -> None:
    assert limit_for("/api/siem/snapshots") == 300 * MB
    assert limit_for("/api/vm/import/file") == 500 * MB
    assert limit_for("/api/vm/refs/nvd/upload") == 500 * MB
    assert limit_for("/api/ad/snapshots/file") == 200 * MB
    assert limit_for("/api/ksc/snapshots/file") == 200 * MB
    assert limit_for("/api/settings/attack/preview") == 100 * MB
    assert limit_for("/api/attack/ru-ttp") == 20 * MB
    # Префикс — по границе сегмента пути, а не по началу строки.
    assert limit_for("/api/siem/snapshots-x") == 2 * MB
    assert limit_for("/api/auth/login") == 2 * MB
    assert limit_for("/api/siem/attack/reference") == 50 * MB
    assert limit_for("/api/siem/attack/run") == 2 * MB


# ---- Сама обёртка, без приложения ------------------------------------------


def _call(
    headers: list[tuple[bytes, bytes]], chunks: list[bytes], path: str = "/api/auth/login"
) -> tuple[int, dict[str, Any], dict[str, int]]:
    """Прогнать запрос через обёртку над приложением, читающим тело целиком."""
    seen = {"receive": 0, "app": 0}

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        seen["app"] += 1
        body = await Request(scope, receive).body()
        await JSONResponse({"len": len(body)})(scope, receive, send)

    pending = list(chunks)

    async def receive() -> dict[str, Any]:
        seen["receive"] += 1
        chunk = pending.pop(0)
        return {"type": "http.request", "body": chunk, "more_body": bool(pending)}

    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": path, "headers": headers}
    asyncio.run(BodyLimitMiddleware(inner)(scope, receive, send))
    status = sent[0]["status"]
    body = json.loads(b"".join(m.get("body", b"") for m in sent[1:]))
    return status, body, seen


def test_declared_length_over_limit_rejected_before_reading() -> None:
    status, body, seen = _call([(b"content-length", str(2 * MB + 1).encode())], [b"x"])
    assert status == 413
    assert body == {"detail": "тело запроса больше лимита (2 МБ)"}
    # Ни байта тела не прочитано, приложение не вызывалось.
    assert seen == {"receive": 0, "app": 0}


def test_body_within_limit_passes_through() -> None:
    status, body, _seen = _call([(b"content-length", b"6")], [b"abc", b"def"])
    assert status == 200 and body == {"len": 6}


def test_chunked_body_is_cut_by_counter() -> None:
    """Без Content-Length тело считается по мере чтения: на куске, который
    перешёл лимит, чтение обрывается, остальные куски не запрашиваются."""
    chunks = [b"x" * MB] * 5
    status, body, seen = _call([], chunks)
    assert status == 413 and body == {"detail": "тело запроса больше лимита (2 МБ)"}
    assert seen["receive"] == 3


# ---- Через приложение ------------------------------------------------------


@pytest.fixture
def small_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(limits, "BODY_LIMITS", [("/api/ksc/snapshots/file", MB)])
    monkeypatch.setattr(limits, "DEFAULT_LIMIT", MB)


def test_oversized_upload_without_session_gets_413_not_401(client: TestClient, small_limits: None) -> None:
    r = client.post("/api/ksc/snapshots/file", files={"file": ("k.json", b"x" * (MB + 1), "application/json")})
    assert r.status_code == 413
    assert r.json() == {"detail": "тело запроса больше лимита (1 МБ)"}
    # Тело в лимите доходит до проверки сессии, как раньше.
    r = client.post("/api/ksc/snapshots/file", files={"file": ("k.json", b"x" * 100, "application/json")})
    assert r.status_code == 401


def test_oversized_json_body_gets_413(client: TestClient, small_limits: None) -> None:
    r = client.post("/api/auth/login", content=b"x" * (MB + 1), headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_multipart_within_limit_passes(auth_client: TestClient, small_limits: None) -> None:
    raw = json.dumps(build_export()).encode()
    assert len(raw) < MB
    r = auth_client.post("/api/ksc/snapshots/file", files={"file": ("k.json", raw, "application/json")})
    assert r.status_code == 202, r.text


def _chunks(total: int) -> Iterator[bytes]:
    sent = 0
    while sent < total:
        piece = min(256 * 1024, total - sent)
        sent += piece
        yield b"x" * piece


def test_chunked_body_without_length_is_cut(client: TestClient, small_limits: None) -> None:
    """Chunked-тело без Content-Length: режет счётчик в `receive`. Сквозь
    журнал действий и FastAPI ошибка доходит как 400, обёртка заменяет её на 413."""
    r = client.post(
        "/api/auth/login", content=_chunks(MB + 1), headers={"content-type": "application/json"}
    )
    assert r.status_code == 413
    assert r.json() == {"detail": "тело запроса больше лимита (1 МБ)"}


# ---- Проверка размера в ручках ---------------------------------------------


def test_siem_upload_checks_size_after_reading(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.modules.siem.routers import snapshots as router

    monkeypatch.setattr(router, "SIEM_UPLOAD", 100)
    r = auth_client.post("/api/siem/snapshots", files={"file": ("kb.zip", b"x" * 101, "application/zip")})
    assert r.status_code == 413 and "МБ" in r.json()["detail"]


def test_vm_file_import_over_limit_fails_job_and_drops_file(
    auth_client: TestClient, monkeypatch: pytest.MonkeyPatch, app_settings: Any
) -> None:
    from api.modules.vm.routers import import_ as router

    monkeypatch.setattr(router, "VM_UPLOAD", 100)
    r = auth_client.post("/api/vm/import/file", files={"file": ("e.csv", b"x" * 101, "text/csv")})
    assert r.status_code == 413 and "МБ" in r.json()["detail"]
    jobs = auth_client.get("/api/vm/jobs").json()
    # Задача не висит «в работе» и не блокирует следующий импорт.
    assert jobs and jobs[0]["status"] == "failed" and "МБ" in jobs[0]["error"]
    assert not list((app_settings.data_dir / "vm").glob("upload-*"))


def test_vm_ref_upload_over_limit_fails_job_and_drops_files(
    auth_client: TestClient, monkeypatch: pytest.MonkeyPatch, app_settings: Any
) -> None:
    from api.modules.vm.routers import refs as router

    monkeypatch.setattr(router, "VM_UPLOAD", 100)
    files = [("files", ("a.json", b"x" * 60, "application/json")), ("files", ("b.json", b"x" * 60, "application/json"))]
    r = auth_client.post("/api/vm/refs/epss/upload", files=files)
    assert r.status_code == 413 and "МБ" in r.json()["detail"]
    jobs = auth_client.get("/api/vm/jobs").json()
    assert jobs and jobs[0]["status"] == "failed"
    assert not list((app_settings.data_dir / "vm").glob("ref-*"))


def test_ru_ttp_upload_checks_size(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.modules.attack.routers import ru_ttp as router

    monkeypatch.setattr(router, "RU_TTP_UPLOAD", 100)
    r = auth_client.post("/api/attack/ru-ttp", files={"file": ("t.csv", b"x" * 101, "text/csv")})
    assert r.status_code == 413 and "МБ" in r.json()["detail"]


def test_attack_bundle_upload_checks_size(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.platform.routers import attack as router

    monkeypatch.setattr(router, "ATTACK_BUNDLE_UPLOAD", 100)
    for path in ("/api/settings/attack/preview", "/api/settings/attack"):
        r = auth_client.post(path, files={"file": ("b.json", b"x" * 101, "application/json")})
        assert r.status_code == 413 and "МБ" in r.json()["detail"], path


def test_siem_reference_upload_checks_size(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.modules.siem.routers import attack as router

    monkeypatch.setattr(router, "SIEM_REFERENCE_UPLOAD", 100)
    r = auth_client.post(
        "/api/siem/attack/reference?snapshot_id=1", files={"file": ("r.csv", b"x" * 101, "text/csv")}
    )
    assert r.status_code == 413 and "МБ" in r.json()["detail"]


def test_siem_reference_above_default_limit_passes(auth_client: TestClient) -> None:
    """Таблица эталона больше 2 МБ по умолчанию доходит до разбора: 422 за
    содержимое (нет колонок), а не 413 за размер."""
    body = b"a;b\n" * (MB // 2 + 1024)
    assert len(body) > 2 * MB
    r = auth_client.post(
        "/api/siem/attack/reference?snapshot_id=1", files={"file": ("r.csv", body, "text/csv")}
    )
    assert r.status_code == 422, r.text


# ---- Распаковка xlsx в ручках ----------------------------------------------


def _xlsx_with_big_member(size: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("xl/sharedStrings.xml", b" " * size)
        zf.writestr("xl/worksheets/sheet1.xml", b"<worksheet/>")
    return buf.getvalue()


@pytest.mark.parametrize("path", ["/api/attack/ru-ttp", "/api/siem/attack/reference?snapshot_id=1"])
def test_xlsx_bomb_is_a_parse_error(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    monkeypatch.setattr(safe_io, "ZIP_MEMBER_LIMIT", MB)
    data = _xlsx_with_big_member(2 * MB)
    assert len(data) < 100 * 1024
    r = auth_client.post(path, files={"file": ("t.xlsx", data, "application/octet-stream")})
    assert r.status_code == 422
    assert "распакованный размер больше лимита" in r.json()["detail"]
