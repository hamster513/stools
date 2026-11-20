"""Лимиты тела запроса — до маршрутизации и до проверки сессии (аудит H2).

FastAPI читает тело (multipart — целиком, со спулом на диск) раньше, чем
отрабатывают зависимости, в том числе `require_access`: без этого слоя кто
угодно без входа мог залить многогигабайтный запрос. Поэтому лимит —
ASGI-обёртка снаружи всего приложения, и тело она не буферизует.

- Есть `Content-Length` больше лимита — 413 сразу, приложение не вызывается
  и ни байта тела не читается.
- Тело без длины (chunked) — обёртка над `receive` считает байты. На куске,
  который перешёл лимит, `receive` бросает `BodyTooLarge`, и дальше тело не
  читается. До обёртки это исключение доходит не всегда в чистом виде:
  `BaseHTTPMiddleware` (журнал действий) заворачивает его в группу, а FastAPI
  превращает ошибку чтения тела в 400. Поэтому обёртка не полагается на тип
  исключения: после переполнения всё, что приложение отправляет или бросает,
  отбрасывается, и клиент получает 413 тем же текстом. Если ответ уже начат
  до переполнения (в приложении таких ручек нет), исключение уходит серверу,
  и тот рвёт соединение: иначе прервать идущий ответ в ASGI нельзя.

Лимит выше 2 МБ — только у ручек загрузки файлов, по методу и пути целиком
(`{name}` — один сегмент). По префиксу нельзя: JSON-ручки рядом с загрузками
(`/api/vm/refs/{name}/download`, `/api/siem/attack/reference/apply`) получали
бы лимит загрузки, а JSON разбирается в память до проверки сессии (финальное
ревью, C1). Остальное — 2 МБ.

Запрос, которому положен лимит выше умолчания, пропускается дальше только
с живой сессией: cookie из настроек находит по хешу строку сессии со сроком
в будущем (`api.deps.find_session`, один поиск по первичному ключу). Иначе
401 до чтения хотя бы байта тела: FastAPI разбирает multipart (со спулом на
диск) раньше `require_access`. Для обычных загрузок роль проверяет
`require_access`; пачки VM дополнительно требуют VM admin до чтения большого тела.

Ручки загрузки дополнительно проверяют размер файла после чтения
(`check_upload_size`) — на случай, если карта ручек разойдётся с роутерами.
"""
from __future__ import annotations

import httpx
from fastapi import HTTPException, status
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from api.db.base import get_sessionmaker
from api.deps import find_session, session_expired
from api.settings import get_settings

MB = 1024 * 1024

SIEM_UPLOAD = 300 * MB
VM_UPLOAD = 500 * MB
VM_ARCHIVE_BATCH_UPLOAD = 2049 * MB  # 2 GiB files + bounded multipart framing
AD_UPLOAD = 200 * MB
KSC_UPLOAD = 200 * MB
TOOLBOX_UPLOAD = 200 * MB
ATTACK_BUNDLE_UPLOAD = 100 * MB
RU_TTP_UPLOAD = 20 * MB
#: Эталонная разметка ATT&CK (xlsx/csv): реальные таблицы больше 2 МБ.
SIEM_REFERENCE_UPLOAD = 50 * MB
#: Файл библиотеки хантов (YAML): текст запросов, поэтому 2 МБ с запасом; совпадает с умолчанием,
#: в `BODY_LIMITS` не нужен, но ручка проверяет размер явно.
TH_YAML_UPLOAD = 2 * MB
TH_INTEL_UPLOAD = 65 * MB  # 64 MiB ZIP + multipart framing
DIAGNOSTIC_UPLOAD = 21 * MB  # 20 MiB ZIP + bounded multipart framing
DEFAULT_LIMIT = 2 * MB

#: (метод, путь ручки загрузки, лимит тела в байтах). Путь сравнивается целиком,
#: `{name}` — любой непустой сегмент. Всё, чего здесь нет, — DEFAULT_LIMIT.
BODY_LIMITS: list[tuple[str, str, int]] = [
    ("POST", "/api/siem/snapshots", SIEM_UPLOAD),
    ("POST", "/api/siem/hunting/intel/import", TH_INTEL_UPLOAD),
    ("POST", "/api/vm/trends/news-archive", TH_INTEL_UPLOAD),
    ("POST", "/api/vm/import/file", VM_UPLOAD),
    ("POST", "/api/vm/refs/{name}/upload", VM_UPLOAD),
    ("POST", "/api/vm/refs/batches", VM_ARCHIVE_BATCH_UPLOAD),
    ("POST", "/api/ad/snapshots/file", AD_UPLOAD),
    ("POST", "/api/ksc/snapshots/file", KSC_UPLOAD),
    ("POST", "/api/toolbox/scrub/jobs", TOOLBOX_UPLOAD),
    ("POST", "/api/settings/diagnostics/imports", DIAGNOSTIC_UPLOAD),
    ("POST", "/api/settings/attack", ATTACK_BUNDLE_UPLOAD),
    ("POST", "/api/settings/attack/preview", ATTACK_BUNDLE_UPLOAD),
    ("POST", "/api/attack/ru-ttp", RU_TTP_UPLOAD),
    ("POST", "/api/siem/attack/reference", SIEM_REFERENCE_UPLOAD),
]


def _path_matches(pattern: str, path: str) -> bool:
    want, got = pattern.split("/"), path.split("/")
    return len(want) == len(got) and all(
        w == g or (w.startswith("{") and w.endswith("}") and g != "") for w, g in zip(want, got, strict=True)
    )


def limit_for(method: str, path: str) -> int:
    for route_method, pattern, limit in BODY_LIMITS:
        if method == route_method and _path_matches(pattern, path):
            return limit
    return DEFAULT_LIMIT


def session_refusal(token: str | None) -> str | None:
    """Почему нет входа (текст 401 как у `get_current_user`) или None."""
    if not token:
        return "нет сессии"
    with get_sessionmaker()() as db:
        row = find_session(db, token)
        if row is None:
            return "сессия не найдена"
        if session_expired(row):
            return "сессия истекла"
    return None


def batch_upload_allowed(token: str | None) -> bool:
    """The larger batch body is spooled only for an active VM administrator."""
    from api.db.models import AppUser
    from api.platform.services.access import access_for, allows

    if not token:
        return False
    with get_sessionmaker()() as db:
        row = find_session(db, token)
        user = db.get(AppUser, row.user_id) if row is not None and not session_expired(row) else None
        return bool(user and user.is_active and allows(access_for(db, user.id), "vm", "admin"))


def _detail(limit: int) -> str:
    return f"тело запроса больше лимита ({limit // MB} МБ)"


class BodyTooLarge(Exception):
    """Тело перешло лимит посреди чтения."""


#: Потолок ответа внешнего API, который читается в память целиком (KSC Open API, MaxPatrol VM;
#: аудит L6): ответ «сервера» больше — не данные, а поломка или подмена.
MAX_API_RESPONSE = 64 * MB


class ResponseTooLarge(ValueError):
    """Ответ внешнего API больше лимита."""


def read_limited(resp: httpx.Response, limit: int) -> bytes:
    """Тело потокового ответа (`client.stream(...)`), но не больше `limit` байт: заявленный
    `Content-Length` больше — отказ до чтения, иначе счётчик по мере чтения (распакованные байты)."""
    too_large = ResponseTooLarge(f"ответ больше лимита ({limit // MB} МБ)")
    declared = resp.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise too_large
    chunks: list[bytes] = []
    total = 0
    for chunk in resp.iter_bytes():
        total += len(chunk)
        if total > limit:
            raise too_large
        chunks.append(chunk)
    return b"".join(chunks)


def check_upload_size(size: int, limit: int) -> None:
    """413, если файл больше лимита; для проверки в ручке после чтения."""
    if size > limit:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, detail=f"файл больше {limit // MB} МБ")


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = limit_for(scope["method"], scope["path"])
        too_large = JSONResponse({"detail": _detail(limit)}, status_code=status.HTTP_413_CONTENT_TOO_LARGE)
        declared = Headers(scope=scope).get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            await too_large(scope, receive, send)
            return
        if limit > DEFAULT_LIMIT:
            token = HTTPConnection(scope).cookies.get(get_settings().session_cookie_name)
            refusal = await run_in_threadpool(session_refusal, token)
            if refusal is not None:
                await JSONResponse({"detail": refusal}, status_code=status.HTTP_401_UNAUTHORIZED)(scope, receive, send)
                return

            if scope["path"] == "/api/vm/refs/batches" and not await run_in_threadpool(batch_upload_allowed, token):
                await JSONResponse({"detail": "Нужны права администратора VM"}, status_code=403)(scope, receive, send)
                return

        received = 0
        overflowed = False
        started = False

        async def limited_receive() -> Message:
            nonlocal received, overflowed
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    overflowed = True
                    raise BodyTooLarge
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal started
            if overflowed and not started:
                return  # ответ приложения на оборванное тело заменяется на 413
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except Exception:
            if not overflowed or started:
                raise
        if overflowed and not started:
            await too_large(scope, receive, send)
