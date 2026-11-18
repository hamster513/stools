"""Opt-in diagnostics: real SQL execution, request isolation, no payload logging."""
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text
from starlette.responses import StreamingResponse

from api.db.base import make_engine
from api.platform.request_timing import RequestTimingMiddleware
from api.settings import Settings


def timed_app(postgres_url, enabled=True):
    settings = Settings(database_url=postgres_url, request_timing_enabled=enabled)
    engine = make_engine(settings)
    app = FastAPI()
    if settings.request_timing_enabled:
        app.add_middleware(RequestTimingMiddleware)

    @app.get('/items/{count}')
    def items(count: int):
        with engine.connect() as conn:
            for _ in range(count):
                conn.execute(text("SELECT 'private-sql-value'"))
        return {'value': 'private-response'}

    return app, engine


def timing_records(caplog):
    return [r for r in caplog.records if r.name == 'api.request_timing']


def test_disabled_by_default(postgres_url, caplog):
    assert Settings(database_url=postgres_url).request_timing_enabled is False
    app, engine = timed_app(postgres_url, False)
    with TestClient(app) as client, caplog.at_level(logging.INFO):
        response = client.get('/items/1')
    assert response.status_code == 200
    assert 'server-timing' not in response.headers
    assert not timing_records(caplog)
    engine.dispose()


def test_concurrent_sql_counts_are_isolated_and_safe(postgres_url, caplog):
    app, engine = timed_app(postgres_url)
    with TestClient(app) as client, caplog.at_level(logging.INFO, logger='api.request_timing'):
        def request(count):
            return client.get(f'/items/{count}?secret=private-query', headers={'X-Request-ID': 'private-header'})
        with ThreadPoolExecutor(max_workers=5) as pool:
            responses = list(pool.map(request, [1, 2, 3, 4, 5]))
        unknown = client.get('/private-path')
    for count, response in enumerate(responses, 1):
        assert response.json() == {'value': 'private-response'}
        assert f'sql_count;desc="{count}"' in response.headers['server-timing']
        assert response.headers['x-request-id'] != 'private-header'
    assert len({r.headers['x-request-id'] for r in responses}) == 5
    records = timing_records(caplog)
    assert sorted(r.sql_count for r in records) == [0, 1, 2, 3, 4, 5]
    assert {r.route for r in records} == {'/items/{count}', '<unmatched>'}
    assert all(r.response_bytes > 0 and r.duration_ms >= r.sql_ms >= 0 for r in records)
    assert all('private-' not in r.getMessage() for r in records)
    assert unknown.status_code == 404
    engine.dispose()


def test_failed_sql_is_counted_and_next_request_is_clean(postgres_url, caplog):
    app, engine = timed_app(postgres_url)

    @app.get('/failure')
    def failure():
        with engine.connect() as conn:
            conn.execute(text('SELECT * FROM definitely_missing_timing_table'))

    with TestClient(app, raise_server_exceptions=False) as client, caplog.at_level(logging.INFO, logger='api.request_timing'):
        assert client.get('/failure').status_code == 500
        assert client.get('/items/0').status_code == 200
    failed, clean = timing_records(caplog)
    assert (failed.status, failed.sql_count) == (500, 1)
    assert failed.response_bytes is None  # Starlette renders this 500 outside user middleware.
    assert clean.sql_count == 0
    assert 'definitely_missing' not in failed.getMessage()
    engine.dispose()


def test_stream_is_not_buffered_and_background_work_is_excluded(caplog):
    app = FastAPI()
    chunks = []

    @app.get('/stream')
    def stream():
        async def body():
            yield b'first'
            await asyncio.sleep(0)
            yield b'second'
        return StreamingResponse(body())

    wrapped = RequestTimingMiddleware(app)

    async def run():
        async def send(message):
            if message['type'] == 'http.response.body':
                chunks.append(message.get('body', b''))
        async def receive():
            await asyncio.Event().wait()
        await wrapped({'type': 'http', 'asgi': {'version': '3.0', 'spec_version': '2.4'}, 'method': 'GET', 'path': '/stream', 'raw_path': b'/stream', 'query_string': b'', 'headers': [], 'scheme': 'http', 'server': ('test', 80)}, receive, send)

    with caplog.at_level(logging.INFO, logger='api.request_timing'):
        asyncio.run(run())
    assert chunks == [b'first', b'second', b'']
    assert timing_records(caplog)[0].response_bytes == 11


def test_background_sql_does_not_enter_response_metrics(postgres_url, caplog):
    from starlette.background import BackgroundTask
    from starlette.responses import JSONResponse
    app, engine = timed_app(postgres_url)
    completed = []

    def background():
        with engine.connect() as conn:
            conn.execute(text("SELECT 'background-private'"))
        completed.append(True)

    @app.get('/background')
    def endpoint():
        return JSONResponse({'ok': True}, background=BackgroundTask(background))

    with TestClient(app) as client, caplog.at_level(logging.INFO, logger='api.request_timing'):
        response = client.get('/background')
    assert response.json() == {'ok': True}
    assert completed == [True]
    assert timing_records(caplog)[0].sql_count == 0
    assert 'sql_count;desc="0"' in response.headers['server-timing']
    engine.dispose()
