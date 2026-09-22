"""Онлайн-сбор: те же вызовы Open API, что в STools-KSC-Collector.ps1, тот же формат файла."""
from __future__ import annotations

import datetime as dt
import json
from collections.abc import Callable
from typing import Any

from api.modules.ksc.core.client import KscClient, KscError
from api.modules.ksc.core.export import (
    FORMAT,
    PRODUCT_AGENT,
    PRODUCT_SERVER,
    _int,
    _str,
    strip_params,
    unwrap,
)

COLLECTOR_VERSION = "1.0"

#: Имя секции или ключ верхнего уровня её параметров, содержащий одно из этих слов (без учёта
#: регистра), в выгрузку не идёт — значение заменяется на "<скрыто>", ключ остаётся.
SECRET_MARKERS = ("PASSWORD", "PASSWD", "SECRET", "CRYPTED")
#: Не больше стольки политик собираем за один сбор — предупреждение при превышении.
POLICY_CONTENTS_MAX_POLICIES = 200
#: Ответ секции больше этого размера не сохраняется (в errors — "секция больше лимита").
POLICY_CONTENTS_SECTION_MAX_BYTES = 2 * 1024 * 1024

HOST_FIELDS = [
    "KLHST_WKS_HOSTNAME", "KLHST_WKS_DN", "KLHST_WKS_WINHOSTNAME", "KLHST_WKS_WINDOMAIN", "KLHST_WKS_DNSDOMAIN", "KLHST_WKS_DNSNAME", "KLHST_WKS_FQDN",
    "KLHST_WKS_GROUPID", "KLHST_WKS_OS_NAME", "KLHST_WKS_OS_VER_MAJOR", "KLHST_WKS_OS_VER_MINOR", "KLHST_WKS_IP_LONG", "KLHST_WKS_CTYPE",
    "KLHST_WKS_STATUS", "KLHST_WKS_STATUS_ID", "KLHST_WKS_STATUS_MASK", "KLHST_WKS_STATUS_HSDP", "KLHST_WKS_RTP_STATE", "KLHST_WKS_RTP_ERROR_CODE",
    "KLHST_WKS_RTP_AV_VERSION", "KLHST_WKS_RTP_AV_BASES_TIME", "KLHST_WKS_LAST_FULLSCAN", "KLHST_WKS_LAST_VISIBLE", "KLHST_WKS_LAST_NAGENT_CONNECTED",
    "KLHST_WKS_LAST_UPDATE", "KLHST_WKS_LAST_INFOUDATE", "KLHST_WKS_NAG_VERSION", "KLHST_WKS_VIRUS_COUNT", "KLHST_WKS_UNCURED_COUNT",
    "KLHST_WKS_FROM_UNASSIGNED", "KLHST_WKS_RBT_REQUIRED", "KLHST_WKS_LAST_SYSTEM_START", "KLHST_WKS_CREATED",
    "KLHST_WKS_OS_BUILD_NUMBER", "KLHST_WKS_CPU_ARCH", "KLHST_WKS_RBT_REQUEST_REASON", "KLHST_WKS_RBT_REQUEST_TIME",
    "HST_VM_TYPE", "KLHST_MANAGED_OTHER_SERVER", "KLHST_WKS_EDR_STATUS", "KLHST_WKS_KEEP_CONNECTION",
]
GROUP_FIELDS = ["id", "name", "parentId", "grp_full_name", "level", "hostsNum", "childGroupsNum", "creationDate", "lastUpdate"]
LICENSE_FIELDS = [
    "KLLIC_SERIAL", "KLLIC_PROD_NAME", "KLLIC_KEY_TYPE", "KLLIC_CREATION_DATE", "KLLIC_LIMIT_DATE", "KLLIC_LICENSE_PERIOD", "KLLIC_LIC_COUNT",
    "KLLIC_NHOSTS_ASCURRENT", "KLLIC_NHOSTS_ASNEXT", "KLLIC_USED_BY_ADM_SRV", "KLLICSRV_KEY_INSTALLED", "KLLIC_APP_ID", "KLLIC_MAJ_VER",
]
STATIC_FIELDS = ["KLADMSRV_SERVER_VERSION_ID", "KLADMSRV_SERVER_HOSTNAME", "KLADMSRV_PRODUCT_FULL_VERSION"]
ROLE_FIELDS = ["nRoleId", "wstrRoleName", "wstrRoleDisplayName", "nInternalUserId", "wstrTrusteeDisplayName", "wstrUserPrincipalName", "nGroupId", "wstrGroupName"]
USER_FIELDS = ["ul_llTrusteeId", "ul_nSplUserId", "ul_wstrDisplayName", "ul_wstrSamAccountName", "ul_wstrPrincipalName", "ul_bUser", "ul_Builtin", "ul_InternalUser"]

Progress = Callable[[int, int], None]


def _ret(data: dict[str, Any]) -> Any:
    return data.get("PxgRetVal")


def _task_body(task: dict[str, Any]) -> dict[str, Any]:
    """Сам объект задачи: для `{"type": "params", "value": {…}}` — содержимое обёртки, иначе объект как есть."""
    inner = task.get("value")
    if set(task.keys()) == {"type", "value"} and task.get("type") == "params" and isinstance(inner, dict):
        return inner
    return task


def _read_srvview(client: KscClient, view: str, fields: list[str], flt: str = "") -> list[dict[str, Any]]:
    """SrvView: итератор постранично по 500 записей, `ReleaseIterator` всегда, даже при ошибке чтения."""
    reset = client.call("SrvView.ResetIterator", {"wstrViewName": view, "wstrFilter": flt, "vecFieldsToReturn": fields, "vecFieldsToOrder": [], "pParams": {}, "lifetimeSec": 600})
    it = reset.get("wstrIteratorId")
    if not it:
        raise KscError(f"SrvView.ResetIterator ({view}): KSC не выдал итератор")
    try:
        try:
            total = int(unwrap(_ret(client.call("SrvView.GetRecordCount", {"wstrIteratorId": it}))) or 0)
        except (TypeError, ValueError) as exc:
            raise KscError(f"SrvView.GetRecordCount ({view}): KSC вернул не число") from exc
        items: list[dict[str, Any]] = []
        start = 0
        while start < total:
            end = min(start + 500, total) - 1
            chunk = client.call("SrvView.GetRecordRange", {"wstrIteratorId": it, "nStart": start, "nEnd": end})
            arr = (chunk.get("pRecords") or {}).get("KLCSP_ITERATOR_ARRAY") or []
            if not arr:
                break
            items.extend(arr)
            start += len(arr)
        return items
    finally:
        client.call("SrvView.ReleaseIterator", {"wstrIteratorId": it})


def _has_secret_marker(name: str) -> bool:
    """`name` содержит один из `SECRET_MARKERS` подстрокой, без учёта регистра: `PASSWORD_HASH`,
    `KLPRSS_Password` и `AdminPassword` — да."""
    upper = str(name).upper()
    return any(marker in upper for marker in SECRET_MARKERS)


def _is_binary_wrapper(value: Any) -> bool:
    return isinstance(value, dict) and set(value.keys()) == {"type", "value"} and value.get("type") == "binary"


def _is_secret_value(value: Any) -> bool:
    """Прячем только строки и двоичные значения: булевы и числа секретом быть не могут, даже если
    имя настройки содержит одно из `SECRET_MARKERS` (например, `EnablePasswordProtection`)."""
    return isinstance(value, str) or _is_binary_wrapper(value)


def _is_params_wrapper(value: Any) -> bool:
    return isinstance(value, dict) and set(value.keys()) == {"type", "value"} and value.get("type") == "params"


def _hide_secrets(section_name: str, raw: Any) -> Any:
    """Секреты в содержимом политики: имя секции или ключ верхнего уровня её параметров с одним из
    `SECRET_MARKERS` (подстрокой, без учёта регистра) — значение "<скрыто>", ключ остаётся, но
    только если само значение строка или двоичные данные (`{"type": "binary", "value": …}`).
    Секция хранится как пришла — меняются только значения секретных ключей, обёртки не снимаются
    (кроме собственно секретного значения); секция целиком в обёртке `{"type": "params", "value": …}`
    (так приходит с живого сервера) обрабатывается через её `value`, обёртка остаётся."""
    hide_all = _has_secret_marker(section_name)
    if _is_params_wrapper(raw):
        return {"type": "params", "value": _hide_secrets(section_name, raw["value"])}
    if _is_binary_wrapper(raw):
        return "<скрыто>" if hide_all else raw
    if not isinstance(raw, dict):
        return "<скрыто>" if (hide_all and isinstance(raw, str)) else raw
    out: dict[str, Any] = {}
    for k, v in raw.items():
        hide = (hide_all or _has_secret_marker(str(k))) and _is_secret_value(v)
        out[k] = "<скрыто>" if hide else v
    return out


def _policy_contents(client: KscClient, policies: list[dict[str, Any]], warnings: list[str], *, max_policies: int | None = None) -> dict[str, Any]:
    """Содержимое активных политик продуктов защиты: `Policy.GetPolicyContents` →
    `SsContents.SS_GetNames`/`Ss_Read` по каждой секции, `Ss_Release` в finally. Каждая политика в
    своём try: ошибка открытия — политики нет в результате, строка в `warnings`; ошибка секции — она
    в `errors` этой политики, остальные секции остаются. `max_policies=None` — берётся
    `POLICY_CONTENTS_MAX_POLICIES` (константа сборщика; `KscConfig.policy_contents_max_policies` для
    онлайн-сбора передаётся явно через `collect`)."""
    limit = POLICY_CONTENTS_MAX_POLICIES if max_policies is None else max_policies
    out: dict[str, Any] = {}
    count = 0
    for raw_policy in policies:
        policy = strip_params(raw_policy)
        if not bool(unwrap(policy.get("KLPOL_ACTIVE"))):
            continue
        product = _str(policy.get("KLPOL_PRODUCT"))
        if product in (PRODUCT_AGENT, PRODUCT_SERVER):
            continue
        count += 1
        if count > limit:
            warnings.append(f"policy_contents: политик больше лимита {limit}, часть пропущена")
            break
        npolicy = _int(policy.get("KLPOL_ID"))
        version = _str(policy.get("KLPOL_VERSION"))
        try:
            ssid = _ret(client.call("Policy.GetPolicyContents", {"nPolicy": npolicy, "nRevisionId": 0, "nLifeTime": 0}))
            try:
                names = _ret(client.call("SsContents.SS_GetNames", {"wstrID": ssid, "wstrProduct": product, "wstrVersion": version})) or []
                sections: dict[str, Any] = {}
                errors: list[str] = []
                for section_name in names:
                    try:
                        section_raw = _ret(client.call("SsContents.Ss_Read", {"wstrID": ssid, "wstrProduct": product, "wstrVersion": version, "wstrSection": section_name}))
                    except KscError as exc:
                        errors.append(f"{section_name}: {exc}")
                        continue
                    value = _hide_secrets(section_name, section_raw)
                    if len(json.dumps(value, ensure_ascii=False).encode("utf-8")) > POLICY_CONTENTS_SECTION_MAX_BYTES:
                        errors.append(f"{section_name}: секция больше лимита")
                        continue
                    sections[section_name] = value
                out[str(npolicy)] = {"product": product, "version": version, "sections": sections, "errors": errors}
            finally:
                client.call("SsContents.Ss_Release", {"wstrID": ssid})
        except KscError as exc:
            warnings.append(f"policy_contents[{npolicy}]: {exc}")
    return out


def collect(client: KscClient, *, skip_products: bool = False, skip_policy_contents: bool = False, max_policies: int | None = None, progress: Progress | None = None, username: str = "", host: str = "") -> dict[str, Any]:
    warnings: list[str] = []

    def _section(name: str, fn: Callable[[], Any], default: Any) -> Any:
        try:
            return fn()
        except KscError as exc:
            warnings.append(f"{name}: {exc}")
            return default

    static = _ret(client.call("HostGroup.GetStaticInfo", {"pValues": STATIC_FIELDS})) or {}
    if not any(k in static for k in STATIC_FIELDS):
        static = _ret(client.call("HostGroup.GetStaticInfo", {"pValues": None})) or {}
    domains = _ret(client.call("HostGroup.GetDomains")) or []
    ga = client.call("HostGroup.FindGroups", {"wstrFilter": "", "vecFieldsToReturn": GROUP_FIELDS, "vecFieldsToOrder": [], "lMaxLifeTime": 600})["strAccessor"]
    groups = client.read_accessor(ga)
    ha = client.call("HostGroup.FindHosts", {"wstrFilter": "", "vecFieldsToReturn": HOST_FIELDS, "vecFieldsToOrder": [], "pParams": {"KLGRP_FIND_FROM_CUR_VS_ONLY": True}, "lMaxLifeTime": 600})["strAccessor"]
    hosts = client.read_accessor(ha)

    products: dict[str, Any] = {}
    components: dict[str, Any] = {}
    if not skip_products:
        # KSC заворачивает записи в {"type": "params"}: читаем сквозь обёртку, в файл кладём как пришло.
        plain_hosts = [strip_params(h) for h in hosts]
        with_agent = [h for h in plain_hosts if _int(h.get("KLHST_WKS_STATUS")) & 4 and h.get("KLHST_WKS_HOSTNAME")]
        for n, h in enumerate(with_agent, 1):
            hid = str(h["KLHST_WKS_HOSTNAME"])
            try:
                p = _ret(client.call("HostGroup.GetHostProducts", {"strHostName": hid})) or {}
            except KscError:
                p = {}
            products[hid] = p
            comp: dict[str, list[dict[str, Any]]] = {}
            for prod, versions in strip_params(p).items():
                if prod in (PRODUCT_AGENT, PRODUCT_SERVER) or not isinstance(versions, dict):
                    continue
                for ver in versions:
                    try:
                        comp[f"{prod}/{ver}"] = list(_ret(client.call("HostGroup.GetComponentsForProductOnHost", {"strHostName": hid, "strProductName": prod, "strProductVersion": ver})) or [])
                    except KscError:
                        continue
            if comp:
                components[hid] = comp
            if progress:
                progress(n, len(with_agent))

    policies = _ret(client.call("Policy.GetPoliciesForGroup", {"nGroupId": -1})) or []
    effective: dict[str, Any] = {}
    for g in strip_params(groups):
        gid = _int(g.get("id"))
        try:
            effective[str(gid)] = _ret(client.call("Policy.GetEffectivePoliciesForGroup", {"nGroupId": gid})) or []
        except KscError as exc:
            warnings.append(f"effective_policies[{gid}]: {exc}")

    tasks: list[dict[str, Any]] = []
    it = client.call("Tasks.ResetTasksIterator", {"nGroupId": -1, "bGroupIdSignificant": False, "strProductName": "", "strVersion": "", "strComponentName": "", "strInstanceId": "", "strTaskName": "", "bIncludeSupergroups": False})["strTaskIteratorId"]
    while True:
        t = client.call("Tasks.GetNextTask", {"strTaskIteratorId": it}).get("pTaskData") or {}
        if not t:
            break
        tid = strip_params(t).get("TASK_UNIQUE_ID")
        if tid:
            try:
                stats = _ret(client.call("Tasks.GetTaskStatistics", {"strTask": str(tid)}))
            except KscError:
                pass
            else:
                # Живой KSC отдаёт саму задачу в обёртке: статистику кладём внутрь неё,
                # иначе обёртка перестаёт быть обёрткой и задача теряется при разборе.
                _task_body(t)["statistics"] = stats
        tasks.append(t)
    client.call("Tasks.ReleaseTasksIterator", {"strTaskIteratorId": it})

    licenses: list[dict[str, Any]] = []
    lk = client.call("LicenseKeys.EnumKeys", {"pFields": LICENSE_FIELDS, "pFieldsToOrder": [], "pOptions": {}, "lTimeoutSec": 600})
    li = lk.get("wstrIterator")
    if li:
        while True:
            chunk = client.call("GroupSyncIterator.GetNextItems", {"szwIterator": li, "nCount": 50})
            licenses.extend((chunk.get("pData") or {}).get("KLCSP_ITERATOR_ARRAY") or [])
            if chunk.get("bEOF", True):
                break
        client.call("GroupSyncIterator.ReleaseIterator", {"szwIterator": li})

    policy_contents: dict[str, Any] = {} if skip_policy_contents else _policy_contents(client, policies, warnings, max_policies=max_policies)

    role_assignments = _section("role_assignments", lambda: _read_srvview(client, "AdmGroupsAclRolesSrvViewName", ROLE_FIELDS), [])
    internal_users = _section("internal_users", lambda: _read_srvview(client, "GlobalUsersListSrvViewName", USER_FIELDS, "(ul_InternalUser = 1)"), [])
    two_factor = _section("security", lambda: _ret(client.call("TotpGlobalSettings.Get2FaRequiredForAll", {})), None)
    security = {"two_factor_required_for_all": two_factor}

    def _certs() -> dict[str, Any]:
        """Из контейнера сертификата берём только `CPublic` — приватная часть и прочие поля в выгрузку не идут.

        Отказ в правах (HTTP 403) — это отказ на весь метод: секция остаётся пустой (KscError уходит
        в `_section`). Любая другая ошибка функции — у сервера нет сертификата для этого назначения:
        функция пропускается, остальные собираются."""
        out: dict[str, Any] = {}
        for n in range(1, 5):
            try:
                c = strip_params(_ret(client.call("CertPoolCtrl.GetCertificateInfo", {"nVServerId": -1, "nFunction": n})))
            except KscError as exc:
                if exc.code == 403:
                    raise
                warnings.append(f"server_certs[{n}]: {exc}")
                continue
            public = c.get("CPublic") if isinstance(c, dict) else None
            if public is not None:
                out[str(n)] = {"CPublic": public}
        return out

    server_certs = _section("server_certs", _certs, {})
    secondary_servers = _section("secondary_servers", lambda: _ret(client.call("ServerHierarchy.GetChildServers", {"nGroupId": -1})) or [], [])
    update_agents = _section("update_agents", lambda: client.call("UaControl.GetUpdateAgentsList", {}).get("pUasArr") or [], [])

    name = str(static.get("KLADMSRV_SERVER_HOSTNAME") or host or "ksc")
    return {
        "format": FORMAT,
        "server": {"name": name, "version": str(static.get("KLADMSRV_PRODUCT_FULL_VERSION") or ""), "collected_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "collector": "online", "collector_version": COLLECTOR_VERSION, "user": username, "host": host, "warnings": warnings},
        "groups": groups, "hosts": hosts, "host_products": products, "host_components": components,
        "policies": policies, "effective_policies": effective, "tasks": tasks, "licenses": licenses, "static": static, "domains": domains,
        "role_assignments": role_assignments, "internal_users": internal_users, "security": security,
        "server_certs": server_certs, "secondary_servers": secondary_servers, "update_agents": update_agents,
        "policy_contents": policy_contents,
    }
