from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from api.modules.vm.core import mpvm as mpvm_mod
from api.modules.vm.core.docker_inventory import build_docker_pdql
from api.modules.vm.core.mpvm import MpVmClient, MpVmError, build_groups_pdql, build_pdql
from api.modules.vm.services.settings import Connection

CONN = Connection(host="vm.corp", api_token="pat-test", os_exclude=["Windows 10", "O'Reilly OS"], pdql_extra="Host.UF_Zone = 'DMZ'", limit=5)


def test_build_pdql() -> None:
    pdql = build_pdql(CONN)
    assert pdql.startswith("select(@Host, Host.OsName, Host.@Groups, Host.@Vulners.CVEs, Host.UF_Criticality, Host.UF_Zone) | filter(Host.OsName != null and Host.OsName != 'Windows 10' and Host.OsName != 'O\\'Reilly OS' and (Host.UF_Zone = 'DMZ'))")
    assert pdql.endswith("| limit(5)")
    assert build_pdql(Connection(host="h", limit=0)).endswith("| limit(0)")
    assert build_pdql(CONN, limit=1).endswith("| limit(1)")


def _transport(calls: list[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert request.headers["Authorization"] == "Bearer pat-test"
        if request.url.path.endswith("/assets_grid"):
            body = json.loads(request.content)
            assert body["pdql"].startswith("select(") and body["includeNestedGroups"] is False
            return httpx.Response(200, json={"token": "exp/ort+token"})
        if request.url.path.endswith("/assets_grid/export"):
            assert request.url.params["pdqlToken"] == "exp/ort+token"
            return httpx.Response(200, content=b"@Host;Host.OsName\n\"a (1.1.1.1)\";\"Linux\"\n")
        if request.url.path.endswith("/assets_grid/row_count"):
            assert request.url.params["pdqlToken"] == "exp/ort+token"
            return httpx.Response(200, json={"rowCount": 1})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_export_csv_to_file(tmp_path: Path) -> None:
    calls: list[httpx.Request] = []
    client = MpVmClient(CONN, httpx.Client(timeout=60.0, transport=_transport(calls)))
    out = tmp_path / "vm.csv"
    size = client.export_csv(build_pdql(CONN), out)
    assert size == out.stat().st_size > 0
    assert [c.url.path.rsplit("/", 1)[-1] for c in calls] == ["assets_grid", "row_count", "export"]
    # Computing the result count can run the same expensive query as the export.
    assert calls[2].extensions["timeout"] == calls[1].extensions["timeout"]
    assert calls[2].extensions["timeout"]["read"] > calls[0].extensions["timeout"]["read"]
    assert client.probe().startswith("@Host")
    assert all(c.extensions["timeout"]["read"] == 60.0 for c in calls[3:])


def test_export_counts_logical_rows_with_bom_commas_and_embedded_newlines(tmp_path: Path) -> None:
    body = '\ufeff"@Host","Host.OsName"\r\n"a","Linux,\nserver"\r\n"b","Linux"\r\n'.encode()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"token": "snapshot"})
        if request.url.path.endswith("/export"):
            return httpx.Response(200, content=body)
        assert request.url.path.endswith("/row_count")
        return httpx.Response(200, json={"rowCount": 2})

    client = MpVmClient(CONN, httpx.Client(transport=httpx.MockTransport(handler)))
    assert client.export_csv(build_pdql(CONN), tmp_path / "multiline.csv") == len(body)


def test_missing_or_rejected_token_is_a_clear_error() -> None:
    with pytest.raises(MpVmError, match="не задан"):
        MpVmClient(Connection(host="vm.corp"), httpx.Client()).token()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_token"})

    client = MpVmClient(CONN, httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(MpVmError, match="HTTP 401") as exc:
        client.export_token("select(@Host)")
    assert exc.value.status == 401


def test_oversized_response_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Аудит L6: ответ API больше лимита (64 МБ) в память не читается — по Content-Length сразу,
    без длины — счётчиком при чтении."""
    monkeypatch.setattr(mpvm_mod, "MAX_API_RESPONSE", 1000)
    big = json.dumps({"token": "t" * 2000}).encode()
    client = MpVmClient(CONN, httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=big))))
    with pytest.raises(MpVmError, match="больше лимита"):
        client.export_token("select(@Host)")

    def chunked(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=iter([b'{"token": "' + b"x" * 900, b"x" * 900 + b'"}']))

    client = MpVmClient(CONN, httpx.Client(transport=httpx.MockTransport(chunked)))
    with pytest.raises(MpVmError, match="больше лимита"):
        client.export_token("select(@Host)")


def test_all_full_inventory_queries_have_explicit_unlimited_rows() -> None:
    connection = Connection(host="vm.corp", limit=0)
    assert build_groups_pdql(connection, "windows").endswith("| limit(0)")
    assert build_groups_pdql(connection, "linux").endswith("| limit(0)")
    assert build_docker_pdql("images").endswith("| limit(0)")
    assert build_docker_pdql("containers").endswith("| limit(0)")


@pytest.mark.parametrize("rows,expected", [(2, 3), (3, 2), (0, 1)])
def test_export_rejects_row_count_mismatch(tmp_path: Path, rows: int, expected: int) -> None:
    body = b"@Host;Host.OsName\n" + b"host;Linux\n" * rows

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"token": "same-snapshot"})
        if request.url.path.endswith("/export"):
            return httpx.Response(200, content=body)
        assert request.url.path.endswith("/row_count")
        assert request.url.params["pdqlToken"] == "same-snapshot"
        return httpx.Response(200, json={"rowCount": expected})

    client = MpVmClient(CONN, httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(MpVmError, match="полнот|количеств"):
        client.export_csv(build_pdql(CONN), tmp_path / "bad.csv")


@pytest.mark.parametrize("rows", [0, 50_000, 50_001])
def test_complete_export_uses_saved_count_when_query_expires_after_download(tmp_path: Path, rows: int) -> None:
    body = b"@Host;Host.OsName\n" + b"host;Linux\n" * rows
    calls = []
    query_expired = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal query_expired
        calls.append(request.url.path.rsplit("/", 1)[-1])
        if request.method == "POST":
            return httpx.Response(200, json={"token": "snapshot"})
        if request.url.path.endswith("/export"):
            query_expired = True
            return httpx.Response(200, content=body)
        if request.url.path.endswith("/row_count") and not query_expired:
            assert request.url.params["pdqlToken"] == "snapshot"
            return httpx.Response(200, json={"rowCount": rows})
        return httpx.Response(404)

    client = MpVmClient(CONN, httpx.Client(transport=httpx.MockTransport(handler)))
    assert client.export_csv(build_pdql(CONN), tmp_path / "complete.csv") == len(body)
    assert calls == ["assets_grid", "row_count", "export"]


@pytest.mark.parametrize("body", [b'@Host;Host.OsName\n"host;Linux', b"@Host;Host.OsName\nhost\n"])
def test_export_rejects_broken_csv_before_import(tmp_path: Path, body: bytes) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"token": "snapshot"})
        if request.url.path.endswith("/row_count"):
            return httpx.Response(200, json={"rowCount": 1})
        return httpx.Response(200, content=body)

    client = MpVmClient(CONN, httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(MpVmError, match="CSV"):
        client.export_csv(build_pdql(CONN), tmp_path / "broken.csv")


@pytest.mark.parametrize("status,payload", [
    (503, {}), (200, {}), (200, {"rowCount": None}), (200, {"rowCount": True}),
    (200, {"rowCount": -1}), (200, {"rowCount": "1"}), (200, {"rowCount": 1.0}),
    (200, {"count": 1}), (200, [1]),
])
def test_export_fails_closed_when_completeness_check_fails(tmp_path: Path, status: int, payload: object) -> None:
    calls = []
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path.rsplit("/", 1)[-1])
        if request.method == "POST":
            return httpx.Response(200, json={"token": "snapshot"})
        if request.url.path.endswith("/export"):
            return httpx.Response(200, content=b"@Host;Host.OsName\nhost;Linux\n")
        return httpx.Response(status, json=payload)

    client = MpVmClient(CONN, httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(MpVmError, match="полнот"):
        client.export_csv(build_pdql(CONN), tmp_path / "unverified.csv")
    assert calls == ["assets_grid", "row_count"]
    assert not (tmp_path / "unverified.csv").exists()


@pytest.mark.parametrize("error_type,label", [
    (httpx.ReadTimeout, "тайм-аут"),
    (httpx.ConnectTimeout, "тайм-аут"),
    (httpx.ConnectError, "ошибка HTTP"),
    (httpx.DecodingError, "ошибка HTTP"),
])
def test_export_verification_reports_safe_transport_cause(
    tmp_path: Path, error_type: type[httpx.HTTPError], label: str,
) -> None:
    transport = _transport([])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/row_count"):
            raise error_type(f"{request.url} {CONN.api_token}", request=request)
        return transport.handle_request(request)

    client = MpVmClient(CONN, httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(MpVmError, match=label) as caught:
        client.export_csv(build_pdql(CONN), tmp_path / "failed.csv")
    assert error_type.__name__ in str(caught.value)
    assert isinstance(caught.value.__cause__, error_type)
    for secret in (CONN.host, CONN.api_token, "exp/ort+token", "pdqlToken"):
        assert secret not in str(caught.value)


@pytest.mark.parametrize("body,error_type", [
    (b"<html>private-response-pat-test</html>", json.JSONDecodeError),
    (b"\xffprivate-response-pat-test", UnicodeDecodeError),
])
def test_export_verification_reports_invalid_json_without_response_body(
    tmp_path: Path, body: bytes, error_type: type[ValueError],
) -> None:
    transport = _transport([])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/row_count"):
            return httpx.Response(200, content=body)
        return transport.handle_request(request)

    client = MpVmClient(CONN, httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(MpVmError, match="некорректный JSON") as caught:
        client.export_csv(build_pdql(CONN), tmp_path / "failed.csv")
    assert error_type.__name__ in str(caught.value)
    assert isinstance(caught.value.__cause__, error_type)
    for secret in (CONN.host, CONN.api_token, "private-response", "exp/ort+token"):
        assert secret not in str(caught.value)
