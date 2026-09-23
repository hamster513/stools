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

Лимит выбирается по префиксу пути (по границе сегмента); остальное — 2 МБ.
Ручки загрузки дополнительно проверяют размер файла после чтения
(`check_upload_size`) — на случай, если карта префиксов разойдётся с роутерами.
"""
from __future__ import annotations

from fastapi import HTTPException, status
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MB = 1024 * 1024

SIEM_UPLOAD = 300 * MB
VM_UPLOAD = 500 * MB
AD_UPLOAD = 200 * MB
KSC_UPLOAD = 200 * MB
ATTACK_BUNDLE_UPLOAD = 100 * MB
RU_TTP_UPLOAD = 20 * MB
#: Эталонная разметка ATT&CK (xlsx/csv): реальные таблицы больше 2 МБ.
SIEM_REFERENCE_UPLOAD = 50 * MB
DEFAULT_LIMIT = 2 * MB

#: (префикс пути, лимит тела в байтах). Первое совпадение выигрывает.
BODY_LIMITS: list[tuple[str, int]] = [
    ("/api/siem/snapshots", SIEM_UPLOAD),
    ("/api/vm/import", VM_UPLOAD),
    ("/api/vm/refs", VM_UPLOAD),
    ("/api/ad/snapshots/file", AD_UPLOAD),
    ("/api/ksc/snapshots/file", KSC_UPLOAD),
    ("/api/settings/attack", ATTACK_BUNDLE_UPLOAD),
    ("/api/attack/ru-ttp", RU_TTP_UPLOAD),
    ("/api/siem/attack/reference", SIEM_REFERENCE_UPLOAD),
]


def limit_for(path: str) -> int:
    for prefix, limit in BODY_LIMITS:
        if path == prefix or path.startswith(prefix + "/"):
            return limit
    return DEFAULT_LIMIT


def _detail(limit: int) -> str:
    return f"тело запроса больше лимита ({limit // MB} МБ)"


class BodyTooLarge(Exception):
    """Тело перешло лимит посреди чтения."""


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
        limit = limit_for(scope["path"])
        too_large = JSONResponse({"detail": _detail(limit)}, status_code=status.HTTP_413_CONTENT_TOO_LARGE)
        declared = Headers(scope=scope).get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            await too_large(scope, receive, send)
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
