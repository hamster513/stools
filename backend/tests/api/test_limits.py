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
from api.limits import MB, VM_UPLOAD, BodyLimitMiddleware, limit_for
from kbaudit import safe_io
from tests.ksc.synthetic import build_export


def test_limit_for_matches_exact_upload_routes() -> None:
    """Большой лимит — только у ручек загрузки файлов (метод и путь целиком);
    JSON-ручки рядом с ними получают 2 МБ по умолчанию."""
    assert limit_for("POST", "/api/siem/snapshots") == 300 * MB
    assert limit_for("POST", "/api/siem/hunting/intel/import") == 65 * MB
    assert limit_for("POST", "/api/vm/import/file") == 500 * MB
    assert limit_for("POST", "/api/vm/refs/nvd/upload") == 500 * MB
    # Архив справочников — отдельный маршрут, но лимит тела тот же шаблон `{name}`.
    assert limit_for("POST", "/api/vm/refs/bundle/upload") == VM_UPLOAD
    assert limit_for("POST", "/api/ad/snapshots/file") == 200 * MB
    assert limit_for("POST", "/api/ksc/snapshots/file") == 200 * MB
    assert limit_for("POST", "/api/settings/attack") == 100 * MB
    assert limit_for("POST", "/api/settings/attack/preview") == 100 * MB
    assert limit_for("POST", "/api/attack/ru-ttp") == 20 * MB
    assert limit_for("POST", "/api/siem/attack/reference") == 50 * MB
    # JSON-ручки под теми же префиксами и другие методы — 2 МБ.
    for method, path in [
        ("POST", "/api/vm/refs/nvd/download"),
        ("POST", "/api/vm/import/vm"),
        ("POST", "/api/siem/attack/reference/apply"),
        ("POST", "/api/settings/attack/download"),
        ("POST", "/api/settings/attack/pending/apply"),
        ("POST", "/api/siem/snapshots/1/reparse"),
        ("PUT", "/api/siem/snapshots"),
        ("POST", "/api/vm/refs/a/b/upload"),
        ("POST", "/api/vm/refs//upload"),
        ("POST", "/api/siem/snapshots-x"),
        ("POST", "/api/auth/login"),
        ("GET", "/api/siem/hunting/intel/import"),
        ("POST", "/api/siem/hunting/intel/import/extra"),
        ("POST", "/api/siem/attack/run"),
    ]:
        assert limit_for(method, path) == 2 * MB, (method, path)


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


def test_upload_without_session_rejected_before_reading() -> None:
    """Лимит выше умолчания — только с живой сессией: без cookie 401 до
    чтения тела, приложение не вызывается."""
    status, body, seen = _call(
        [(b"content-length", str(3 * MB).encode())], [b"x"], path="/api/vm/import/file"
    )
    assert status == 401 and body == {"detail": "нет сессии"}
    assert seen == {"receive": 0, "app": 0}


def test_upload_with_unknown_session_rejected_before_reading(monkeypatch: pytest.MonkeyPatch) -> None:
    looked_up: list[str] = []

    def fake_refusal(token: str | None) -> str | None:
        looked_up.append(token or "")
        return "сессия не найдена"

    monkeypatch.setattr(limits, "session_refusal", fake_refusal)
    status, body, seen = _call(
        [(b"content-length", str(3 * MB).encode()), (b"cookie", b"stools_session=abc")],
        [b"x"],
        path="/api/vm/import/file",
    )
    assert status == 401 and body == {"detail": "сессия не найдена"}
    assert seen == {"receive": 0, "app": 0}
    assert looked_up == ["abc"]


def test_default_limit_needs_no_session() -> None:
    """В пределах 2 МБ сессия здесь не проверяется: это делает `require_access`."""
    for path in ("/api/auth/login", "/api/vm/refs/nvd/download"):
        status, body, _seen = _call([(b"content-length", b"3")], [b"abc"], path=path)
        assert status == 200 and body == {"len": 3}, path


# ---- Через приложение ------------------------------------------------------


@pytest.fixture
def small_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(limits, "BODY_LIMITS", [("POST", "/api/ksc/snapshots/file", MB)])
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


def test_anonymous_big_json_to_json_route_gets_413(client: TestClient) -> None:
    """JSON-ручка под путём справочников VM больше не наследует лимит загрузки:
    3 МБ без входа — 413, тело не разбирается (не 422 и не 401 после разбора)."""
    body = b'{"x": "' + b"a" * (3 * MB) + b'"}'
    for path in ("/api/vm/refs/x/download", "/api/siem/attack/reference/apply?snapshot_id=1"):
        r = client.post(path, content=body, headers={"content-type": "application/json"})
        assert r.status_code == 413, (path, r.status_code)
        assert r.json() == {"detail": "тело запроса больше лимита (2 МБ)"}


@pytest.fixture
def form_parses(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Сколько раз приложение разбирало multipart (разбор и есть спул на диск)."""
    from starlette.formparsers import MultiPartParser

    calls: list[bool] = []
    original = MultiPartParser.parse

    async def parse(self: Any) -> Any:
        calls.append(True)
        return await original(self)

    monkeypatch.setattr(MultiPartParser, "parse", parse)
    return calls


def test_anonymous_big_upload_gets_401_before_endpoint(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, app_settings: Any, form_parses: list[bool]
) -> None:
    from api.modules.vm.routers import import_ as router

    reached: list[bool] = []
    monkeypatch.setattr(router, "_reject_if_running", lambda db: reached.append(True))
    files = {"file": ("e.csv", b"x" * (3 * MB), "text/csv")}
    r = client.post("/api/vm/import/file", files=files)
    assert r.status_code == 401 and r.json() == {"detail": "нет сессии"}
    client.cookies.set(app_settings.session_cookie_name, "not-a-session")
    r = client.post("/api/vm/import/file", files=files)
    assert r.status_code == 401 and r.json() == {"detail": "сессия не найдена"}
    assert reached == []
    assert form_parses == []


def test_expired_session_big_upload_gets_401(
    auth_client: TestClient, db_session: Any, form_parses: list[bool]
) -> None:
    import datetime as dt

    from api.db.models import SessionRow

    db_session.query(SessionRow).update({"expires_at": dt.datetime(2000, 1, 1, tzinfo=dt.UTC)})
    db_session.commit()
    files = {"file": ("e.csv", b"x" * (3 * MB), "text/csv")}
    r = auth_client.post("/api/vm/import/file", files=files)
    assert r.status_code == 401 and r.json() == {"detail": "сессия истекла"}
    assert form_parses == []


def test_signed_in_analyst_upload_above_default_passes(client_as: Any, form_parses: list[bool]) -> None:
    analyst = client_as("analyst")
    body = b"cve,host\n" + b"x" * (3 * MB)
    r = analyst.post("/api/vm/import/file", files={"file": ("e.csv", body, "text/csv")})
    assert r.status_code == 202, r.text
    assert form_parses == [True]


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
