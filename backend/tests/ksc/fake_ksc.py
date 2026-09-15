"""Поддельный Open API KSC: отвечает данными synthetic.build_export().

Одна реализация на два транспорта: `handle(method, body) -> (status, json)`
используется и MockTransport-ом (Task 10), и HTTP-сервером для прогона
скрипта в контейнере (fake_ksc_http.py).
"""
from __future__ import annotations

import base64
import json
import re
from typing import Any

import httpx

from tests.ksc.synthetic import build_export

USER = "audit"
PASSWORD = "audit-pass"
SESSION = "n4QFPNjYK2oXRMYkis5CMcg=="


class FakeKsc:
    def __init__(self, data: dict[str, Any] | None = None) -> None:
        self.data = data or build_export()
        self.calls: list[str] = []
        self.accessors: dict[str, list[dict[str, Any]]] = {}
        self.iterators: dict[str, list[dict[str, Any]]] = {}
        self.fail_login = False
        self.fail_after: str | None = None  # имя метода, на котором отвечать PxgError

    def _auth_ok(self, headers: dict[str, str]) -> bool:
        auth = headers.get("authorization", "")
        m = re.match(r'KSCBasic user="([^"]*)", pass="([^"]*)"', auth)
        if not m:
            return False
        user = base64.b64decode(m.group(1)).decode()
        pw = base64.b64decode(m.group(2)).decode()
        return user == USER and pw == PASSWORD and not self.fail_login

    def handle(self, method: str, body: dict[str, Any], headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
        self.calls.append(method)
        if method == "Session.StartSession":
            return (200, {"PxgRetVal": SESSION}) if self._auth_ok(headers) else (403, {})
        if headers.get("x-ksc-session") != SESSION:
            return 401, {}
        if self.fail_after == method:
            return 200, {"PxgError": {"code": 1, "message": "boom"}}  # KSC отдаёт ошибки метода со статусом 200
        d = self.data
        if method == "Session.EndSession":
            return 200, {}
        if method == "HostGroup.GetStaticInfo":
            return 200, {"PxgRetVal": d["static"]}
        if method == "HostGroup.GetDomains":
            return 200, {"PxgRetVal": d["domains"]}
        if method == "HostGroup.FindGroups":
            self.accessors["g1"] = d["groups"]
            return 200, {"PxgRetVal": len(d["groups"]), "strAccessor": "g1"}
        if method == "HostGroup.FindHosts":
            self.accessors["h1"] = d["hosts"]
            return 200, {"PxgRetVal": len(d["hosts"]), "strAccessor": "h1"}
        if method == "ChunkAccessor.GetItemsCount":
            return 200, {"PxgRetVal": len(self.accessors[body["strAccessor"]])}
        if method == "ChunkAccessor.GetItemsChunk":
            items = self.accessors[body["strAccessor"]][body["nStart"] : body["nStart"] + body["nCount"]]
            return 200, {"PxgRetVal": len(items), "pChunk": {"KLCSP_ITERATOR_ARRAY": items}}
        if method == "ChunkAccessor.Release":
            return 200, {}
        if method == "HostGroup.GetHostProducts":
            return 200, {"PxgRetVal": d["host_products"].get(body["strHostName"], {})}
        if method == "HostGroup.GetComponentsForProductOnHost":
            key = f"{body['strProductName']}/{body['strProductVersion']}"
            return 200, {"PxgRetVal": d["host_components"].get(body["strHostName"], {}).get(key, [])}
        if method == "Policy.GetPoliciesForGroup":
            gid = body["nGroupId"]
            return 200, {"PxgRetVal": d["policies"] if gid == -1 else [p for p in d["policies"] if p["KLPOL_GROUP_ID"] == gid]}
        if method == "Policy.GetEffectivePoliciesForGroup":
            return 200, {"PxgRetVal": d["effective_policies"].get(str(body["nGroupId"]), [])}
        if method == "Tasks.ResetTasksIterator":
            self.iterators["t1"] = list(d["tasks"])
            return 200, {"strTaskIteratorId": "t1"}
        if method == "Tasks.GetNextTask":
            items = self.iterators[body["strTaskIteratorId"]]
            return 200, {"pTaskData": items.pop(0) if items else {}}
        if method == "Tasks.ReleaseTasksIterator":
            return 200, {}
        if method == "Tasks.GetTaskStatistics":
            return 200, {"PxgRetVal": {"1": 0, "4": 3}}
        if method == "LicenseKeys.EnumKeys":
            self.iterators["l1"] = list(d["licenses"])
            return 200, {"lKeyCount": len(d["licenses"]), "wstrIterator": "l1"}
        if method == "GroupSyncIterator.GetNextItems":
            items = self.iterators[body["szwIterator"]]
            chunk, self.iterators[body["szwIterator"]] = items[: body["nCount"]], items[body["nCount"] :]
            return 200, {"PxgRetVal": len(chunk), "bEOF": not self.iterators[body["szwIterator"]], "pData": {"KLCSP_ITERATOR_ARRAY": chunk}}
        if method == "GroupSyncIterator.ReleaseIterator":
            return 200, {}
        return 404, {}


def parse_request(path: str, raw_body: bytes) -> tuple[str, dict[str, Any]]:
    method = path.rsplit("/api/v1.0/", 1)[-1]
    body = json.loads(raw_body or b"{}") if raw_body.strip() else {}
    return method, body if isinstance(body, dict) else {}


def mock_transport(fake: FakeKsc) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        method, body = parse_request(request.url.path, request.content)
        status, payload = fake.handle(method, body, {k.lower(): v for k, v in request.headers.items()})
        return httpx.Response(status, json=payload)
    return httpx.MockTransport(handler)


def http_factory_for(fake: FakeKsc):
    def factory(verify: bool) -> httpx.Client:
        return httpx.Client(transport=mock_transport(fake), timeout=5)
    return factory
