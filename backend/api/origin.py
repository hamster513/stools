"""Проверка источника запросов с изменением состояния (аудит M6).

SameSite=Strict не спасает от соседнего поддомена того же сайта, поэтому
POST/PUT/PATCH/DELETE под `/api/` пропускаются, только если браузер
подтверждает, что запрос пришёл со страницы самого STools:

- есть `Sec-Fetch-Site` — он должен быть `same-origin` или `none`
  (заголовок ставит сам браузер, страница его подделать не может);
- иначе есть `Origin` — схема и хост как у запроса;
- иначе есть `Referer` — то же правило.

Хост запроса — `X-Forwarded-Host`, а без него `Host`; схема —
`X-Forwarded-Proto`. Оба ставит Caddy, к API напрямую не пройти (порт не
публикуется). Без `X-Forwarded-Proto` схема неизвестна и сравнивается
только хост.

Нет ни одного из трёх заголовков — запрос пропускается. Это осознанное
решение: браузер хотя бы один из них шлёт всегда, а без них приходят curl
и скрипты проверки стенда. Защита — от чужой страницы в браузере
пользователя, а не от клиента, у которого cookie и так на руках.

Вход через провайдера (`/api/auth/oidc/`) не проверяется: возврат от
провайдера — переход с чужого сайта по определению.

Middleware стоит внутри журнала действий: отказ пишется в журнал как 403,
без пользователя (до проверки сессии дело не доходит) и со сводкой.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import status
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from api.audit import OIDC_PREFIX, WRITE_METHODS

DETAIL = "запрос с другого сайта"
OWN_FETCH_SITES = frozenset({"same-origin", "none"})


def _first(value: str) -> str:
    return value.split(",")[0].strip().lower()


def _same_origin(url: str, headers: Headers) -> bool:
    parts = urlsplit(url.strip())
    host = _first(headers.get("x-forwarded-host") or headers.get("host") or "")
    if not parts.netloc or parts.netloc.lower() != host:
        return False
    proto = headers.get("x-forwarded-proto")
    return proto is None or parts.scheme.lower() == _first(proto)


def refusal(headers: Headers) -> str | None:
    """Почему запрос отклонён (для сводки журнала) или None, если пропустить."""
    fetch_site = headers.get("sec-fetch-site")
    if fetch_site is not None:
        return None if fetch_site.strip().lower() in OWN_FETCH_SITES else f"Sec-Fetch-Site: {fetch_site}"
    for name in ("Origin", "Referer"):
        value = headers.get(name)
        if value is not None:
            return None if _same_origin(value, headers) else f"{name}: {value}"
    return None


class OriginMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if (
            scope["type"] == "http"
            and scope["method"] in WRITE_METHODS
            and path.startswith("/api/")
            and not path.startswith(OIDC_PREFIX)
        ):
            reason = refusal(Headers(scope=scope))
            if reason is not None:
                state = scope.setdefault("state", {})
                state["audit_anonymous"] = True
                state["audit_summary"] = f"{DETAIL}; {reason}"
                await JSONResponse({"detail": DETAIL}, status_code=status.HTTP_403_FORBIDDEN)(scope, receive, send)
                return
        await self.app(scope, receive, send)
