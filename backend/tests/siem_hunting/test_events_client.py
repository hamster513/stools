"""PDQL и клиент событий MaxPatrol: запрос как в скрипте владельца, классы ошибок, ни адреса, ни токена в текстах."""
from __future__ import annotations

import datetime as dt
import json
from types import SimpleNamespace

import httpx
import pytest

from api.hosts import LOGIN_REJECTED, NO_LINK, NO_RIGHTS, TLS_FAILED
from api.modules.siem.hunting.events_client import (
    EventsAuthError,
    EventsClient,
    EventsError,
    EventsRetryable,
    EventsShapeError,
    public_error,
)
from api.modules.siem.hunting.pdql import align_labels, build_pdql, split_fields
from tests.siem_hunting.fake_events import PATH, TOKEN, FakeEvents

CONN = SimpleNamespace(host="mp.corp.local", api_token=TOKEN, verify_tls=False)
T_FROM = dt.datetime(2026, 10, 18, 22, 0, tzinfo=dt.UTC)
T_TO = dt.datetime(2026, 10, 19, 22, 0, tzinfo=dt.UTC)
QUERY = 'event_src.host == "ws-01" and msgid == "4624"'
PDQL = f"filter({QUERY}) | select(time, event_src.host) | sort(time desc)"


def client(fake: FakeEvents) -> EventsClient:
    return EventsClient(CONN, fake.http_factory(CONN))


def test_build_pdql_matches_script() -> None:
    fields = split_fields(" time, event_src.host ,, ")
    assert fields == ["time", "event_src.host"]
    assert build_pdql(QUERY, fields) == PDQL


def test_labels_aligned() -> None:
    fields = ["time", "event_src.host", "msgid"]
    assert align_labels(fields, "Время, Хост") == ["Время", "Хост", "msgid"]
    assert align_labels(fields, "а, б, в, г, д") == ["а", "б", "в"]
    assert align_labels(fields, "") == fields


def test_search_sends_bearer_and_window() -> None:
    fake = FakeEvents({"ws-01": [{"time": "2026-10-19T01:00:00Z", "event_src.host": "ws-01"}]})
    events = client(fake).search(PDQL, T_FROM, T_TO, 500)
    assert events == [{"time": "2026-10-19T01:00:00Z", "event_src.host": "ws-01"}]
    (request,) = fake.calls
    assert request.url.host == "mp.corp.local" and request.url.scheme == "https"
    assert request.headers["Authorization"] == "Bearer pat_test_token"
    assert request.headers["Content-Type"] == "application/json"
    body = json.loads(request.content)
    assert body == {
        "filter": PDQL, "groupValues": [], "timeFrom": int(T_FROM.timestamp()), "timeTo": int(T_TO.timestamp()),
    }
    assert body["timeFrom"] < body["timeTo"]
    assert dict(request.url.params) == {"offset": "0", "limit": "500", "noCount": "true"}
    assert request.url.path == PATH


def test_401_is_auth_error() -> None:
    fake = FakeEvents()
    fake.status_once["ws-01"] = [401]
    with pytest.raises(EventsAuthError) as exc:
        client(fake).search(PDQL, T_FROM, T_TO, 10)
    assert exc.value.status == 401


def test_empty_token_is_auth_error_without_request() -> None:
    fake = FakeEvents()
    conn = SimpleNamespace(host="mp.corp.local", api_token="  ", verify_tls=False)
    with pytest.raises(EventsAuthError):
        EventsClient(conn, fake.http_factory(conn)).search(PDQL, T_FROM, T_TO, 10)
    assert fake.calls == []


def test_500_and_timeout_are_retryable() -> None:
    fake = FakeEvents()
    fake.status_once["ws-01"] = [500]
    with pytest.raises(EventsRetryable) as exc:
        client(fake).search(PDQL, T_FROM, T_TO, 10)
    assert exc.value.status == 500
    fake.timeouts = 1
    with pytest.raises(EventsRetryable) as exc:
        client(fake).search(PDQL, T_FROM, T_TO, 10)
    assert exc.value.status is None and isinstance(exc.value.__cause__, httpx.TimeoutException)


def test_other_status_is_plain_error() -> None:
    fake = FakeEvents()
    fake.status_once["ws-01"] = [400]
    with pytest.raises(EventsError) as exc:
        client(fake).search(PDQL, T_FROM, T_TO, 10)
    assert exc.value.status == 400 and not isinstance(exc.value, EventsRetryable | EventsAuthError)


@pytest.mark.parametrize("response", [
    httpx.Response(200, content=b"<html>login</html>"),
    httpx.Response(200, json={"count": 3}),
    httpx.Response(200, json=[1, 2]),
    httpx.Response(200, json={"events": "много"}),
])
def test_non_json_is_clear_error(response: httpx.Response) -> None:
    http = httpx.Client(transport=httpx.MockTransport(lambda request: response))
    with pytest.raises(EventsError, match="ответ без events"):
        EventsClient(CONN, http).search(PDQL, T_FROM, T_TO, 10)


def test_oversized_response_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("api.modules.siem.hunting.events_client.MAX_API_RESPONSE", 10)
    fake = FakeEvents({"ws-01": [{"time": "2026-10-19T01:00:00Z"}]})
    with pytest.raises(EventsError, match="лимита") as exc:
        client(fake).search(PDQL, T_FROM, T_TO, 10)
    assert public_error(exc.value).startswith("события: ответ больше лимита")


def test_public_error_classes() -> None:
    assert public_error(EventsAuthError("x", 401)) == LOGIN_REJECTED
    assert public_error(EventsError("x", 403)) == NO_RIGHTS
    assert public_error(EventsRetryable("x", 500)) == "ошибка сервера (HTTP 500)"
    assert public_error(EventsShapeError("ответ без events")) == "ответ без events"
    try:
        raise EventsRetryable("запрос не прошёл") from httpx.ReadTimeout("t")
    except EventsRetryable as exc:
        assert public_error(exc) == NO_LINK
    try:
        raise EventsError("запрос не прошёл") from httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] mp.corp.local")
    except EventsError as exc:
        assert public_error(exc) == TLS_FAILED
    for text in (public_error(EventsError("HTTP 502 mp.corp.local pat_test_token", 502)), public_error(RuntimeError("mp.corp.local"))):
        assert "mp.corp.local" not in text and TOKEN not in text


@pytest.mark.parametrize(("available", "limit", "expected", "pages"), [
    (2600, 2500, 2500, [(0, 1000), (1000, 1000), (2000, 500)]),
    (2300, 5000, 2300, [(0, 1000), (1000, 1000), (2000, 1000)]),
    (2000, 5000, 2000, [(0, 1000), (1000, 1000), (2000, 1000)]),
])
def test_event_limit_is_applied_across_url_pages(available, limit, expected, pages):
    calls = []
    def handle(request):
        offset = int(request.url.params.get("offset", 0))
        size = int(request.url.params.get("limit", 1000))
        calls.append((offset, size))
        assert request.url.params.get("noCount") == "true"
        if offset:
            assert request.url.params["token"] == "query-token"
        return httpx.Response(200, json={"events": [{"id": i} for i in range(offset, min(offset + size, available))], "token": "query-token"})
    with httpx.Client(transport=httpx.MockTransport(handle)) as http:
        events = EventsClient(CONN, http).search(PDQL, T_FROM, T_TO, limit)
    assert len(events) == expected
    assert [e["id"] for e in events] == list(range(expected))
    assert calls == pages


def test_second_page_error_does_not_return_partial_success():
    def handle(request):
        if request.url.params.get("offset", "0") != "0":
            return httpx.Response(500)
        return httpx.Response(200, json={"events": [{"id": i} for i in range(1000)]})
    with (httpx.Client(transport=httpx.MockTransport(handle)) as http,
          pytest.raises(EventsRetryable)):
        EventsClient(CONN, http).search(PDQL, T_FROM, T_TO, 2000)
