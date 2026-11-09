"""Клиент событий MaxPatrol SIEM (`POST /api/events/v3/events`), только чтение.

Запрос и ответ повторяют скрипт владельца: тело `{filter, groupValues,
timeFrom, timeTo}`, Bearer-токен, ответ `{"events": [...]}`. API
событий живёт на хосте ядра на стандартном порту HTTPS, а не на порту
базы знаний. Повтор после 500 и таймаута решает вызывающий (ночной
прогон ждёт по графику), поэтому клиент читает страницы до заданного лимита и различает
классы отказа. offset/limit/noCount передаются в URL согласно API v3.
Классы отказа: токен не принят, можно повторить, остальное. Адрес, токен и
тело ответа в тексты ошибок не попадают — наружу уходит класс причины
(`public_error`).
"""
from __future__ import annotations

import datetime as dt
import json
from typing import Any, Protocol

import httpx

from api.hosts import (
    LOGIN_REJECTED,
    NO_LINK,
    NO_RIGHTS,
    TLS_FAILED,
    is_tls_error,
    server_error,
    url_host,
)
from api.limits import MAX_API_RESPONSE, ResponseTooLarge, read_limited

EVENTS_PATH = "/api/events/v3/events"


class ConnectionLike(Protocol):
    host: str
    api_token: str
    verify_tls: bool


class EventsError(Exception):
    """`status` — код HTTP-ответа, если отказ пришёл с ним."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class EventsAuthError(EventsError):
    """Токен не принят (401): повтор не поможет, прогон прерывается."""


class EventsRetryable(EventsError):
    """500 и таймаут: сервер занят, запрос можно повторить позже."""


class EventsShapeError(EventsError):
    """Ответ не той формы или больше лимита. Текст — для человека, без данных ответа."""


def make_client(conn: ConnectionLike, timeout: float = 60.0) -> httpx.Client:
    return httpx.Client(verify=conn.verify_tls, timeout=timeout)


class EventsClient:
    def __init__(self, conn: ConnectionLike, http: httpx.Client) -> None:
        self.conn = conn
        self.http = http

    @property
    def url(self) -> str:
        host = self.conn.host.strip().rstrip("/").removeprefix("https://").removeprefix("http://")
        return f"https://{url_host(host)}{EVENTS_PATH}"

    def _token(self) -> str:
        token = self.conn.api_token.strip()
        if not token:
            raise EventsAuthError("API-токен не задан", 401)
        return token

    def search(self, pdql: str, time_from: dt.datetime, time_to: dt.datetime, limit: int) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        offset, token = 0, None
        while len(events) < limit:
            size = min(1000, limit - len(events))
            page, token = self._page(pdql, time_from, time_to, offset, size, token)
            events.extend(page[:limit - len(events)])
            if len(page) < size:
                break
            offset += len(page)
        return events

    def _page(self, pdql: str, time_from: dt.datetime, time_to: dt.datetime,
              offset: int, limit: int, token: str | None) -> tuple[list[dict[str, Any]], str | None]:
        body = {
            "filter": pdql, "groupValues": [],
            "timeFrom": int(time_from.timestamp()), "timeTo": int(time_to.timestamp()),
        }
        params = {"offset": str(offset), "limit": str(limit), "noCount": "true"}
        if token:
            params["token"] = token
        headers = {"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json"}
        try:
            with self.http.stream("POST", self.url, headers=headers, json=body, params=params) as r:
                if r.status_code == 401:
                    raise EventsAuthError("события: HTTP 401", 401)
                if r.status_code == 500:
                    raise EventsRetryable("события: HTTP 500", 500)
                if r.status_code != 200:
                    raise EventsError(f"события: HTTP {r.status_code}", r.status_code)
                raw = read_limited(r, MAX_API_RESPONSE)
        except httpx.TimeoutException as exc:
            raise EventsRetryable("запрос событий не прошёл — таймаут") from exc
        except httpx.HTTPError as exc:
            raise EventsError(f"запрос событий не прошёл — {exc.__class__.__name__}") from exc
        except ResponseTooLarge as exc:
            raise EventsShapeError(f"события: {exc}") from exc
        try:
            data = json.loads(raw)
            events = data.get("events")
        except (ValueError, AttributeError) as exc:  # не JSON (страница входа) или не объект
            raise EventsShapeError("ответ без events") from exc
        if not isinstance(events, list):
            raise EventsShapeError("ответ без events")
        if any(not isinstance(event, dict) for event in events):
            raise EventsShapeError("ответ содержит некорректные события")
        next_token = data.get("token")
        return events, next_token if isinstance(next_token, str) else token


def public_error(exc: BaseException) -> str:
    """Класс причины отказа для человека: без адреса, токена и текста ответа."""
    if isinstance(exc, EventsShapeError):
        return str(exc)
    if isinstance(exc.__cause__, httpx.HTTPError) or isinstance(exc, httpx.HTTPError):
        return TLS_FAILED if is_tls_error(exc) else NO_LINK
    if isinstance(exc, EventsAuthError):
        return LOGIN_REJECTED
    code = exc.status if isinstance(exc, EventsError) else None
    if code == 401:
        return LOGIN_REJECTED
    if code == 403:
        return NO_RIGHTS
    return server_error(code)
