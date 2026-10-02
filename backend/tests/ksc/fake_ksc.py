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

from tests.ksc.synthetic import (
    add_empty_objects,
    add_inactive_policy,
    add_secret_bait,
    build_export,
)

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


def _wrap_nested(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value.keys()) == {"type", "value"}:
            return value  # уже типизированное значение (datetime, long, binary)
        return {"type": "params", "value": {k: _wrap_nested(v) for k, v in value.items()}}
    if isinstance(value, list):
        return [_wrap_nested(v) for v in value]
    return value


def wrap_like_live(payload: dict[str, Any]) -> dict[str, Any]:
    """Как отвечает живой KSC: верхний уровень ответа плоский, а каждая запись
    списка и каждый вложенный контейнер — `{"type": "params", "value": {…}}`."""
    out: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, dict) and set(value.keys()) != {"type", "value"}:
            out[key] = {k: _wrap_nested(v) for k, v in value.items()}
        else:
            out[key] = _wrap_nested(value)
    return out


#: Методы, на которые отвечает 403 в варианте "denied".
DENIED_METHODS = {"SrvView.ResetIterator", "TotpGlobalSettings.Get2FaRequiredForAll", "CertPoolCtrl.GetCertificateInfo",
                  "ServerHierarchy.GetChildServers", "UaControl.GetUpdateAgentsList"}

#: Имена srvview → секция синтетики.
SRVVIEW_SECTIONS = {"AdmGroupsAclRolesSrvViewName": "role_assignments", "GlobalUsersListSrvViewName": "internal_users"}

#: Фильтр, которым сборщики должны запрашивать внутренние учётки — минимум персональных данных.
INTERNAL_USERS_FILTER = "(ul_InternalUser = 1)"

#: Не внутренняя учётка — попадает в ответ только если сборщик прислал не тот фильтр (или пустой).
#: В синтетику (build_export) не входит: это проверка на утечку фильтра, а не часть эталонных данных.
NON_INTERNAL_USER = {"ul_llTrusteeId": 99, "ul_nSplUserId": 0, "ul_wstrDisplayName": "Петров П.П.", "ul_wstrSamAccountName": "petrov",
                      "ul_wstrPrincipalName": "petrov@corp.local", "ul_bUser": True, "ul_Builtin": False, "ul_InternalUser": False}


def _policy_id_from_ss(ssid: Any) -> str:
    """`"ss-<KLPOL_ID>"` (как отдаёт `Policy.GetPolicyContents`) → `"<KLPOL_ID>"`, ключ `policy_contents`."""
    text = str(ssid or "")
    return text.split("-", 1)[1] if text.startswith("ss-") else ""


def _profile_sections_from_ss(data: dict[str, Any], ssid: Any) -> dict[str, Any] | None:
    """`"pss-<KLPOL_ID>-<n>"` (как отдаёт `PolicyProfiles.GetProfileSettings`) → секции n-го профиля политики;
    не идентификатор профиля — None."""
    parts = str(ssid or "").split("-")
    if len(parts) != 3 or parts[0] != "pss" or not parts[2].isdigit():
        return None
    profiles = data.get("policy_profiles", {}).get(parts[1], {}).get("profiles", [])
    n = int(parts[2])
    return profiles[n]["sections"] if n < len(profiles) else {}


class FakeKsc:
    def __init__(self, data: dict[str, Any] | None = None, variant: str = "", mfa_secret: str = "",
                 deny: set[str] | None = None, deny_cert_functions: set[int] | None = None,
                 fail_cert_functions: set[int] | None = None, deny_policy_contents: set[int] | None = None,
                 fail_policy_sections: dict[int, set[str]] | None = None, deny_tags_batch: bool = False,
                 fail_profiles: dict[str, set[str]] | None = None) -> None:
        self.data = data or (sparse_export() if variant == "sparse" else build_export())
        if data is None and variant == "params":
            # KLPOL_ACTIVE как типизированный ноль — сборщики не должны читать его как безусловную правду.
            self.data = add_inactive_policy(self.data)
        if data is None and variant == "empty_objects":
            self.data = add_empty_objects(self.data)
        if data is None and variant == "secrets":
            # Секреты под новыми маркерами, двоичное значение, параметры задач, имя сервера с «/».
            self.data = add_secret_bait(self.data)
        #: Непустой секрет включает второй фактор: пароль даёт 401 + KSCMFA, сессию даёт только код.
        self.mfa_secret = mfa_secret or (MFA_SECRET if variant == "mfa" else "")
        #: variant="params" — записи в обёртках, как у живого сервера.
        self.wrap = variant == "params"
        #: Имена методов, на которые отвечать 403 (нет прав).
        self.deny: set[str] = set(deny) if deny is not None else (set(DENIED_METHODS) if variant == "denied" else set())
        #: Теги: пакетный вызов — 403 (сборщик уходит на вызов по одному хосту); variant="tags_denied" — 403 на оба вызова.
        if deny_tags_batch:
            self.deny.add("HostsTags.ListTags.GetTags")
        if variant == "tags_denied":
            self.deny |= {"HostsTags.ListTags.GetTags", "HostTagsApi.GetHostTags"}
        #: variant="profiles_denied" — 403 на PolicyProfiles.EnumProfiles (политики читаются, профили — нет).
        if variant == "profiles_denied":
            self.deny.add("PolicyProfiles.EnumProfiles")
        #: KLPOL_ID (строкой) → имена профилей, на которые GetProfile и GetProfileSettings отвечают PxgError.
        self.fail_profiles: dict[str, set[str]] = fail_profiles or {}
        #: Номера функций CertPoolCtrl.GetCertificateInfo, на которые отвечать 403 (остальные — как обычно).
        self.deny_cert_functions: set[int] = set(deny_cert_functions) if deny_cert_functions is not None else ({2} if variant == "denied_cert2" else set())
        #: Номера функций сертификата, на которые отвечать PxgError — «сертификата для этого назначения нет».
        self.fail_cert_functions: set[int] = set(fail_cert_functions) if fail_cert_functions is not None else ({2} if variant == "failed_cert2" else set())
        #: KLPOL_ID политик, на которые Policy.GetPolicyContents отвечает 403 (нет прав).
        self.deny_policy_contents: set[int] = set(deny_policy_contents) if deny_policy_contents is not None else ({3} if variant == "policy_denied" else set())
        #: KLPOL_ID → имена секций, на которые Ss_Read отвечает PxgError (секция не читается, остальные — как обычно).
        self.fail_policy_sections: dict[int, set[str]] = fail_policy_sections if fail_policy_sections is not None else ({1: {"KLPRSS_Components"}} if variant == "policy_denied" else {})
        #: HostGroup.GetStaticInfo с непустым pValues отдаёт пусто; полный ответ — только на pValues=null.
        self.static_needs_null = False
        #: Заголовки последнего ответа — оба транспорта отдают их клиенту.
        self.response_headers: dict[str, str] = {}
        self.calls: list[str] = []
        #: (wstrViewName, wstrFilter) каждого SrvView.ResetIterator — проверить, что сборщик не потерял фильтр.
        self.srvview_filters: list[tuple[str, str]] = []
        self.accessors: dict[str, list[dict[str, Any]]] = {}
        self.iterators: dict[str, list[dict[str, Any]]] = {}
        self.fail_login = False
        #: Имя метода, на котором отвечать PxgError; variant="tasks_failed" / "hosts_failed" — для прогона скрипта.
        self.fail_after: str | None = {"tasks_failed": "Tasks.ResetTasksIterator", "hosts_failed": "HostGroup.FindHosts"}.get(variant)

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
        status, payload = self._handle(method, body, headers)
        if not self.wrap or "PxgError" in payload:
            return status, payload
        out = wrap_like_live(payload)
        if method == "Tasks.GetNextTask" and out.get("pTaskData"):
            # Живой KSC заворачивает и сам объект задачи, а не только вложенные контейнеры.
            out["pTaskData"] = {"type": "params", "value": out["pTaskData"]}
        if method == "SsContents.Ss_Read" and isinstance(out.get("PxgRetVal"), dict) and set(out["PxgRetVal"].keys()) != {"type", "value"}:
            # Живой KSC заворачивает и саму секцию целиком, а не только настройки внутри неё.
            out["PxgRetVal"] = {"type": "params", "value": out["PxgRetVal"]}
        return status, out

    def _handle(self, method: str, body: dict[str, Any], headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
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
        if method in self.deny:
            return 403, {}
        if self.fail_after == method:
            return 200, {"PxgError": {"code": 1, "message": "boom"}}  # KSC отдаёт ошибки метода со статусом 200
        d = self.data
        if method == "Session.EndSession":
            return 200, {}
        if method == "HostGroup.GetStaticInfo":
            if self.static_needs_null and body.get("pValues"):
                return 200, {"PxgRetVal": {}}
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
            task = next((t for t in d["tasks"] if t.get("TASK_UNIQUE_ID") == body.get("strTask")), None)
            return 200, {"PxgRetVal": (task or {}).get("statistics") or {"1": 0, "4": 3}}
        if method == "SrvView.ResetIterator":
            view = body.get("wstrViewName", "")
            flt = body.get("wstrFilter", "")
            self.srvview_filters.append((view, flt))
            records = list(d.get(SRVVIEW_SECTIONS.get(view, ""), []))
            # Фильтр потерян или не тот — учётки, кроме внутренних, тоже попадают в ответ:
            # так тест видит, что сборщик не запросил минимум персональных данных.
            if view == "GlobalUsersListSrvViewName" and flt != INTERNAL_USERS_FILTER:
                records = [*records, NON_INTERNAL_USER]
            iid = f"sv{len(self.iterators)}"
            self.iterators[iid] = records
            return 200, {"wstrIteratorId": iid}
        if method == "SrvView.GetRecordCount":
            return 200, {"PxgRetVal": len(self.iterators[body["wstrIteratorId"]])}
        if method == "SrvView.GetRecordRange":
            items = self.iterators[body["wstrIteratorId"]][body["nStart"] : body["nEnd"] + 1]
            return 200, {"pRecords": {"KLCSP_ITERATOR_ARRAY": items}}
        if method == "SrvView.ReleaseIterator":
            self.iterators.pop(body.get("wstrIteratorId"), None)
            return 200, {}
        if method == "TotpGlobalSettings.Get2FaRequiredForAll":
            return 200, {"PxgRetVal": d["security"]["two_factor_required_for_all"]}
        if method == "CertPoolCtrl.GetCertificateInfo":
            fn = body.get("nFunction")
            if fn in self.deny_cert_functions:
                return 403, {}
            if fn in self.fail_cert_functions:
                return 200, {"PxgError": {"code": 1, "message": "нет сертификата"}}
            cert = d["server_certs"].get(str(fn)) or {}
            # Живой контейнер несёт не только CPublic: лишние поля в выгрузку попадать не должны.
            return 200, {"PxgRetVal": {**cert, "CPrivate": "secret"} if cert else {}}
        if method == "ServerHierarchy.GetChildServers":
            return 200, {"PxgRetVal": d["secondary_servers"]}
        if method == "UaControl.GetUpdateAgentsList":
            return 200, {"pUasArr": d["update_agents"]}
        if method == "Policy.GetPolicyContents":
            npolicy = body.get("nPolicy")
            if npolicy in self.deny_policy_contents:
                return 403, {}
            return 200, {"PxgRetVal": f"ss-{npolicy}"}
        if method == "HostsTags.ListTags.GetTags":
            tags = d.get("host_tags", {})
            return 200, {"PxgRetVal": [{"KLTAGS_ITEM_ID": i, "KLTAGS_TAGS": tags[i]} for i in body.get("pIdArray", []) if i in tags]}
        if method == "HostTagsApi.GetHostTags":
            return 200, {"PxgRetVal": d.get("host_tags", {}).get(body.get("szwHostId"), [])}
        if method.startswith("PolicyProfiles."):
            return self._profiles(method, body)
        if method == "SsContents.SS_GetNames":
            profile_sections = _profile_sections_from_ss(d, body.get("wstrID"))
            if profile_sections is not None:
                return 200, {"PxgRetVal": list(profile_sections.keys())}
            sections = d.get("policy_contents", {}).get(_policy_id_from_ss(body.get("wstrID")), {}).get("sections", {})
            return 200, {"PxgRetVal": list(sections.keys())}
        if method == "SsContents.Ss_Read":
            profile_sections = _profile_sections_from_ss(d, body.get("wstrID"))
            if profile_sections is not None:
                return 200, {"PxgRetVal": profile_sections.get(body.get("wstrSection"), {})}
            npolicy = _policy_id_from_ss(body.get("wstrID"))
            section = body.get("wstrSection")
            fail_sections = self.fail_policy_sections.get(int(npolicy), set()) if npolicy.isdigit() else set()
            if section in fail_sections:
                return 200, {"PxgError": {"code": 1, "message": "boom"}}
            sections = d.get("policy_contents", {}).get(npolicy, {}).get("sections", {})
            return 200, {"PxgRetVal": sections.get(section, {})}
        if method == "SsContents.Ss_Release":
            return 200, {}
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

    def _profiles(self, method: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """`PolicyProfiles.*`: профили политики `nPolicy` из `data["policy_profiles"]`."""
        npolicy = str(body.get("nPolicy"))
        entry = self.data.get("policy_profiles", {}).get(npolicy, {})
        profiles: list[dict[str, Any]] = entry.get("profiles", [])
        if method == "PolicyProfiles.EnumProfiles":
            return 200, {"PxgRetVal": {p["name"]: p["attrs"] for p in profiles}}
        if method == "PolicyProfiles.GetPriorities":
            return 200, {"PxgRetVal": entry.get("priorities", [])}
        name = body.get("szwName")
        index = next((n for n, p in enumerate(profiles) if p["name"] == name), None)
        if index is None or name in self.fail_profiles.get(npolicy, set()):
            return 200, {"PxgError": {"code": 1, "message": "boom"}}
        if method == "PolicyProfiles.GetProfile":
            return 200, {"PxgRetVal": profiles[index]["attrs"]}
        if method == "PolicyProfiles.GetProfileSettings":
            return 200, {"PxgRetVal": f"pss-{npolicy}-{index}"}
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
