from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from api.modules.vm.core import mpvm as mpvm_mod
from api.modules.vm.core.mpvm import MpVmClient, MpVmError, build_pdql
from api.modules.vm.services.settings import Connection

CONN = Connection(host="vm.corp", api_token="pat-test", os_exclude=["Windows 10", "O'Reilly OS"], pdql_extra="Host.UF_Zone = 'DMZ'", limit=5)


def test_build_pdql() -> None:
    pdql = build_pdql(CONN)
    assert pdql.startswith("select(@Host, Host.OsName, Host.@Groups, Host.@Vulners.CVEs, Host.UF_Criticality, Host.UF_Zone) | filter(Host.OsName != null and Host.OsName != 'Windows 10' and Host.OsName != 'O\\'Reilly OS' and (Host.UF_Zone = 'DMZ'))")
    assert pdql.endswith("| limit(5)")
    assert "limit" not in build_pdql(Connection(host="h", limit=0))
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
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_export_csv_to_file(tmp_path: Path) -> None:
    calls: list[httpx.Request] = []
    client = MpVmClient(CONN, httpx.Client(transport=_transport(calls)))
    out = tmp_path / "vm.csv"
    size = client.export_csv(build_pdql(CONN), out)
    assert size == out.stat().st_size > 0
    assert [c.url.path for c in calls] == ["/api/assets_temporal_readmodel/v1/assets_grid", "/api/assets_temporal_readmodel/v1/assets_grid/export"]
    assert client.probe().startswith("@Host")


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
