"""Opt-in request diagnostics; never record SQL, URLs, credentials or payloads."""
from __future__ import annotations

import logging
from contextvars import ContextVar
from dataclasses import dataclass
from time import perf_counter
from uuid import uuid4

from sqlalchemy import event
from sqlalchemy.engine import Engine
from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = logging.getLogger("api.request_timing")


@dataclass
class _Timing:
    sql_count: int = 0
    sql_seconds: float = 0
    active: bool = True


_current: ContextVar[_Timing | None] = ContextVar("request_timing", default=None)


def instrument_engine(engine: Engine) -> None:
    """Shared object follows the request into sync workers; cursors stay isolated."""
    @event.listens_for(engine, "before_cursor_execute")
    def before(conn, cursor, statement, parameters, context, executemany):
        timing = _current.get()
        if timing is not None and timing.active:
            timing.sql_count += 1
            context._stools_timing = (timing, perf_counter())

    def finish(context):
        token = getattr(context, "_stools_timing", None)
        if token is not None:
            timing, started = token
            if timing.active:
                timing.sql_seconds += perf_counter() - started
            context._stools_timing = None

    @event.listens_for(engine, "after_cursor_execute")
    def after(conn, cursor, statement, parameters, context, executemany):
        finish(context)

    @event.listens_for(engine, "handle_error")
    def error(exception_context):
        finish(exception_context.execution_context)


class RequestTimingMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app
        log.setLevel(logging.INFO)
        if not log.handlers and not logging.getLogger().handlers:
            log.addHandler(logging.StreamHandler())

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        timing = _Timing()
        token = _current.set(timing)
        started = perf_counter()
        request_id = uuid4().hex
        status, response_bytes = 500, 0
        finished = None
        response_started = False

        async def timed_send(message: Message) -> None:
            nonlocal status, response_bytes, finished, response_started
            if message["type"] == "http.response.start":
                response_started = True
                status = message["status"]
                # Header measures time to response headers; log measures the full body.
                header = (f'app;dur={(perf_counter() - started) * 1000:.2f}, '
                          f'sql;dur={timing.sql_seconds * 1000:.2f}, '
                          f'sql_count;desc="{timing.sql_count}"')
                message = {**message, "headers": [*message.get("headers", []),
                    (b"server-timing", header.encode("ascii")),
                    (b"x-request-id", request_id.encode("ascii"))]}
            elif message["type"] == "http.response.body":
                response_bytes += len(message.get("body", b""))
            await send(message)
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                finished = perf_counter()
                timing.active = False  # Exclude BackgroundTasks from request SQL/time.

        try:
            await self.app(scope, receive, timed_send)
        finally:
            timing.active = False
            _current.reset(token)
            route = getattr(scope.get("route"), "path", "<unmatched>")
            method = scope.get("method", "OTHER")
            if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
                method = "OTHER"
            fields = dict(request_id=request_id, route=route, method=method, status=status,
                          duration_ms=round(((finished or perf_counter()) - started) * 1000, 2),
                          sql_ms=round(timing.sql_seconds * 1000, 2), sql_count=timing.sql_count,
                          response_bytes=response_bytes if response_started else None)
            log.info("request_timing id=%s method=%s route=%s status=%s duration_ms=%s sql_ms=%s sql_count=%s response_bytes=%s",
                     *fields.values(), extra=fields)
