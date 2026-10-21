"""Поддельная база знаний MaxPatrol: ответы в той форме, которую описывает SDK
mpsiemlib (спека §2). Одна на тесты клиента и тесты сбора."""
from __future__ import annotations

import json
from typing import Any

import httpx

DB = "Default"
#: Персональный API-токен подключения в тестах (не настоящий).
TOKEN = "pat_test_token"
ROOT = "00000000-0000-0000-0000-000000000001"
INSTALL_SET = "11111111-1111-1111-1111-111111111111"
DATABASES: list[dict[str, Any]] = [
    {"Name": "Archive", "Uid": "a", "Status": "Ready", "IsDeployable": False},
    {"Name": DB, "Uid": "d", "Status": "Ready", "IsDeployable": True, "ParentName": "PT"},
]
SETS: list[dict[str, Any]] = [
    {"Id": ROOT, "Name": "Все объекты", "SystemName": "all", "GeneralStatus": "Ok",
     "CompilationStatus": {"Name": "Success"}, "DeploymentStatuses": [{"PipelineId": "p1", "Status": "Installed"}]},
    {"Id": INSTALL_SET, "ParentSetId": ROOT, "Name": "install", "SystemName": "install", "GeneralStatus": "Outdated",
     "CompilationStatus": "Success", "DeploymentStatuses": {"p1": "Outdated"}},
]


def kb_object(guid: str, name: str, *, installed: bool, folder: str = "PT\\Windows", short_id: str = "") -> dict[str, Any]:
    return {"Id": guid, "ObjectId": short_id or name, "SystemName": name, "FolderPath": folder, "OriginId": "pt",
            "DeploymentStatus": "Installed" if installed else "NotInstalled"}


def many_objects(count: int) -> list[dict[str, Any]]:
    return [kb_object(f"00000000-0000-0000-0000-{i:012d}", f"Rule_{i}", installed=bool(i % 2)) for i in range(count)]


class FakeKb:
    def __init__(
        self,
        export: bytes = b"PK\x05\x06" + b"\x00" * 18,
        objects: list[dict[str, Any]] | None = None,
        sets: list[dict[str, Any]] | None = None,
        members: dict[str, list[str]] | None = None,
    ) -> None:
        self.export = export
        self.objects = many_objects(501) if objects is None else objects
        self.sets = SETS if sets is None else sets
        #: Состав наборов: id набора → guid'ы; корневой набор содержит всё.
        self.members = {INSTALL_SET: [o["Id"] for o in self.objects[:3]]} if members is None else members
        self.databases = DATABASES
        self.unauthorized = False
        self.forbidden = False
        self.export_status = 200
        #: Новый экспорт (KB 27+/R28): `POST /api-studio/siem/export` отвечает 201 с потоком файла;
        #: None — путь не существует (KB 26), тогда клиент обязан откатиться на старый GET.
        self.studio_export_status: int | None = 201
        self.calls: list[httpx.Request] = []
        #: Потолок строк на страницу: настоящий сервер может отдавать меньше `take`.
        self.page_cap: int | None = None

    def http_factory(self, conn: Any, timeout: float = 60.0) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        p = request.url.path
        assert request.headers["Authorization"] == f"Bearer {TOKEN}" and request.url.port == 8091
        if self.unauthorized:
            return httpx.Response(401, json={"detail": "unauthorized"})
        if self.forbidden:
            return httpx.Response(403, json={"detail": "forbidden"})
        if p == "/api-studio/content-database-selector/content-databases":
            return httpx.Response(200, json=self.databases)
        assert request.headers["Content-Database"] == DB and request.headers["Content-Locale"] == "RUS"
        if p == "/api-studio/aboutSystem":
            return httpx.Response(200, json={"CoreVersion": "27.1.1234"})
        if p == "/api-studio/siem/deploymentSets":
            return httpx.Response(200, json=self.sets)
        if p == "/api-studio/siem/deploy/stats":
            installed = sum(1 for o in self.objects if o["DeploymentStatus"] == "Installed")
            return httpx.Response(200, json={"Installed": installed, "NotInstalled": len(self.objects) - installed, "Outdated": 0})
        if p == "/api-studio/siem/objects/list":
            body = json.loads(request.content)
            assert body["filters"] == {"SiemObjectType": ["Correlation"]} and body["recursive"] is True
            rows = self.objects
            group = body.get("groupId")
            if group and group != ROOT:
                allowed = set(self.members.get(group, []))
                rows = [o for o in rows if o["Id"] in allowed]
            take = body["take"] if self.page_cap is None else min(body["take"], self.page_cap)
            return httpx.Response(200, json={"Rows": rows[body["skip"] : body["skip"] + take]})
        if p == "/api-studio/siem/export" and request.method == "POST":
            if self.studio_export_status is None:
                return httpx.Response(404)
            body = json.loads(request.content)
            assert body == {"mode": "deploymentSet", "setId": ROOT}
            ok = self.studio_export_status in (200, 201)
            return httpx.Response(self.studio_export_status, content=self.export if ok else b"")
        if p == "/api/siem/export/kbpackage":
            assert request.url.params["contentMode"] == "deploymentSet" and request.url.params["groupId"] == ROOT
            assert request.url.params["contentDatabase"] == DB
            return httpx.Response(self.export_status, content=self.export if self.export_status == 200 else b"")
        return httpx.Response(404)
