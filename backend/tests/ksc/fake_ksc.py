"""Поддельный Open API KSC: отвечает данными synthetic.build_export().

Одна реализация на два транспорта: `handle(method, body) -> (status, json)`
используется и MockTransport-ом (Task 10), и HTTP-сервером для прогона
скрипта в контейнере (fake_ksc_http.py).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any

import httpx

from tests.ksc.synthetic import build_export

USER = "audit"
PASSWORD = "audit-pass"
SESSION = "n4QFPNjYK2oXRMYkis5CMcg=="
#: Сессия, которую KSC выдаёт между паролем и вторым фактором.
PENDING_SESSION = "pending-mfa-session"
MFA_SECRET = "JBSWY3DPEHPK3PXP"


def totp_code(secret: str, at: float | None = None) -> str:
    """RFC 6238: SHA1, шаг 30 с, 6 цифр, секрет в base32."""
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    counter = int((time.time() if at is None else at) // 30)
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return f"{(int.from_bytes(digest[offset:offset + 4], 'big') & 0x7FFFFFFF) % 1_000_000:06d}"


def sparse_export() -> dict[str, Any]:
    """Тот же KSC, но скупой: у хоста нет части полей, ключей нет вовсе,
    у сервера не сказана версия продукта. Сборщик не должен спотыкаться."""
    d = build_export()
    for field in ("KLHST_WKS_LAST_VISIBLE", "KLHST_WKS_RTP_AV_VERSION", "KLHST_WKS_STATUS"):
        d["hosts"][0].pop(field, None)
    d["licenses"] = []
    d["static"].pop("KLADMSRV_PRODUCT_FULL_VERSION", None)
    return d


class FakeKsc:
    def __init__(self, data: dict[str, Any] | None = None, variant: str = "", mfa_secret: str = "") -> None:
        self.data = data or (sparse_export() if variant == "sparse" else build_export())
        #: Непустой секрет включает второй фактор: пароль даёт 401 + KSCMFA, сессию даёт только код.
        self.mfa_secret = mfa_secret or (MFA_SECRET if variant == "mfa" else "")
        #: Заголовки последнего ответа — оба транспорта отдают их клиенту.
        self.response_headers: dict[str, str] = {}
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

    def _mfa_ok(self, headers: dict[str, str]) -> bool:
        m = re.match(r'KSCMFA totp="(\d{6})"', headers.get("authorization", ""))
        if not m or headers.get("x-ksc-session") != PENDING_SESSION:
            return False
        now = time.time()
        return m.group(1) in {totp_code(self.mfa_secret, now + shift) for shift in (-30, 0, 30)}

    def handle(self, method: str, body: dict[str, Any], headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
        self.calls.append(method)
        self.response_headers = {}
        if method == "Session.StartSession":
            if self.mfa_secret and headers.get("authorization", "").startswith("KSCMFA"):
                return (200, {"PxgRetVal": SESSION}) if self._mfa_ok(headers) else (403, {})
            if not self._auth_ok(headers):
                return 403, {}
            if self.mfa_secret:
                self.response_headers = {"WWW-Authenticate": 'KSCMFA realm="KSC"', "X-KSC-Session": PENDING_SESSION}
                return 401, {}
            return 200, {"PxgRetVal": SESSION}
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
            if not d["licenses"]:  # ключей нет — KSC не отдаёт итератор
                return 200, {"lKeyCount": 0, "wstrIterator": ""}
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
        return httpx.Response(status, json=payload, headers=fake.response_headers)
    return httpx.MockTransport(handler)


def http_factory_for(fake: FakeKsc):
    def factory(verify: bool) -> httpx.Client:
        return httpx.Client(transport=mock_transport(fake), timeout=5)
    return factory
