"""Онлайн-сбор: те же вызовы Open API, что в STools-KSC-Collector.ps1, тот же формат файла."""
from __future__ import annotations

import base64
import binascii
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
from api.modules.ksc.core.secrets import hide_secrets, hide_task_params

COLLECTOR_VERSION = "1.4"

#: Не больше стольки политик собираем за один сбор — предупреждение при превышении.
POLICY_CONTENTS_MAX_POLICIES = 200
#: Ответ секции больше этого размера не сохраняется (в errors — "секция больше лимита").
POLICY_CONTENTS_SECTION_MAX_BYTES = 2 * 1024 * 1024
#: Сколько хостов спрашиваем у `ListTags.GetTags` за один вызов.
TAGS_BATCH = 500
#: Вызовов `HostTagsApi.GetHostTags` подряд, если все они отказали, достаточно, чтобы бросить чтение тегов по одному хосту.
TAGS_FALLBACK_GIVE_UP = 20
#: Отказов подряд при чтении пользователей устройств, после которых остальные хосты не запрашиваются (у них `null`).
HOST_USERS_GIVE_UP = 20

HOST_FIELDS = [
    "KLHST_WKS_HOSTNAME", "KLHST_WKS_DN", "KLHST_WKS_WINHOSTNAME", "KLHST_WKS_WINDOMAIN", "KLHST_WKS_DNSDOMAIN", "KLHST_WKS_DNSNAME", "KLHST_WKS_FQDN",
    "KLHST_WKS_GROUPID", "KLHST_WKS_OS_NAME", "KLHST_WKS_OS_VER_MAJOR", "KLHST_WKS_OS_VER_MINOR", "KLHST_WKS_IP_LONG", "KLHST_WKS_CTYPE",
    "KLHST_WKS_STATUS", "KLHST_WKS_STATUS_ID", "KLHST_WKS_STATUS_MASK", "KLHST_WKS_STATUS_HSDP", "KLHST_WKS_RTP_STATE", "KLHST_WKS_RTP_ERROR_CODE",
    "KLHST_WKS_RTP_AV_VERSION", "KLHST_WKS_RTP_AV_BASES_TIME", "KLHST_WKS_LAST_FULLSCAN", "KLHST_WKS_LAST_VISIBLE", "KLHST_WKS_LAST_NAGENT_CONNECTED",
    "KLHST_WKS_LAST_UPDATE", "KLHST_WKS_LAST_INFOUDATE", "KLHST_WKS_NAG_VERSION", "KLHST_WKS_VIRUS_COUNT", "KLHST_WKS_UNCURED_COUNT",
    "KLHST_WKS_FROM_UNASSIGNED", "KLHST_WKS_RBT_REQUIRED", "KLHST_WKS_LAST_SYSTEM_START", "KLHST_WKS_CREATED",
    "KLHST_WKS_OS_BUILD_NUMBER", "KLHST_WKS_CPU_ARCH", "KLHST_WKS_RBT_REQUEST_REASON", "KLHST_WKS_RBT_REQUEST_TIME",
    "HST_VM_TYPE", "KLHST_MANAGED_OTHER_SERVER", "KLHST_WKS_EDR_STATUS", "KLHST_WKS_KEEP_CONNECTION",
    "KLHST_WKS_OWNER_ID", "KLHST_WKS_OWNER_IS_CUSTOM",
]
GROUP_FIELDS = ["id", "name", "parentId", "grp_full_name", "level", "hostsNum", "childGroupsNum", "creationDate", "lastUpdate"]
LICENSE_FIELDS = [
    "KLLIC_SERIAL", "KLLIC_PROD_NAME", "KLLIC_KEY_TYPE", "KLLIC_CREATION_DATE", "KLLIC_LIMIT_DATE", "KLLIC_LICENSE_PERIOD", "KLLIC_LIC_COUNT",
    "KLLIC_NHOSTS_ASCURRENT", "KLLIC_NHOSTS_ASNEXT", "KLLIC_USED_BY_ADM_SRV", "KLLICSRV_KEY_INSTALLED", "KLLIC_APP_ID", "KLLIC_MAJ_VER",
]
STATIC_FIELDS = ["KLADMSRV_SERVER_VERSION_ID", "KLADMSRV_SERVER_HOSTNAME", "KLADMSRV_PRODUCT_FULL_VERSION"]
ROLE_FIELDS = ["nRoleId", "wstrRoleName", "wstrRoleDisplayName", "nInternalUserId", "wstrTrusteeDisplayName", "wstrUserPrincipalName", "nGroupId", "wstrGroupName"]
#: Пользователи одного устройства (`GlobalUsersListSrvViewName` с `pParams.strHostId`), секция `host_users`.
HOST_USER_FIELDS = ["ul_binId", "ul_nVServer", "ul_bUser", "ul_Local", "ul_imgSid", "ul_wstrSamAccountName", "ul_wstrPrincipalName",
                    "ul_wstrDisplayName", "ul_wstrDomainSAM", "ul_wstrDomain2000", "ul_bVisited"]
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


def _read_srvview(client: KscClient, view: str, fields: list[str], flt: str = "", params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """SrvView: итератор постранично по 500 записей, `ReleaseIterator` всегда, даже при ошибке чтения."""
    reset = client.call("SrvView.ResetIterator", {"wstrViewName": view, "wstrFilter": flt, "vecFieldsToReturn": fields, "vecFieldsToOrder": [], "pParams": params or {}, "lifetimeSec": 600})
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


def _protection_policies(policies: list[dict[str, Any]]) -> list[tuple[int, str, str]]:
    """Активные политики продуктов защиты (не Агент и не Сервер) как `(KLPOL_ID, продукт, версия)` —
    общий отбор для содержимого политик и их профилей."""
    out: list[tuple[int, str, str]] = []
    for raw_policy in policies:
        policy = strip_params(raw_policy)
        if not bool(unwrap(policy.get("KLPOL_ACTIVE"))):
            continue
        product = _str(policy.get("KLPOL_PRODUCT"))
        if product in (PRODUCT_AGENT, PRODUCT_SERVER):
            continue
        out.append((_int(policy.get("KLPOL_ID")), product, _str(policy.get("KLPOL_VERSION"))))
    return out


def _read_sections(client: KscClient, ssid: Any, product: str, version: str) -> tuple[dict[str, Any], list[str]]:
    """Секции хранилища `ssid` (политики или её профиля): `SS_GetNames` → `Ss_Read` по каждой, `Ss_Release` в finally.
    Ошибка секции — строка в `errors`, остальные остаются; ошибка `SS_GetNames` уходит вызывающему."""
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
            value = hide_secrets(section_raw, section_name)
            # Компактный JSON — как `ConvertTo-Json -Compress` в скрипте.
            if len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > POLICY_CONTENTS_SECTION_MAX_BYTES:
                errors.append(f"{section_name}: секция больше лимита")
                continue
            sections[section_name] = value
        return sections, errors
    finally:
        client.call("SsContents.Ss_Release", {"wstrID": ssid})


def _policy_contents(client: KscClient, policies: list[dict[str, Any]], warnings: list[str], *, max_policies: int | None = None) -> dict[str, Any]:
    """Содержимое активных политик продуктов защиты: `Policy.GetPolicyContents` →
    `SsContents.SS_GetNames`/`Ss_Read` по каждой секции, `Ss_Release` в finally. Каждая политика в
    своём try: ошибка открытия — политики нет в результате, строка в `warnings`; ошибка секции — она
    в `errors` этой политики, остальные секции остаются. Политики сверх лимита не читаются, но
    записываются с пустыми `sections` и `errors == ["лимит политик"]`. `max_policies=None` — берётся
    `POLICY_CONTENTS_MAX_POLICIES` (константа сборщика; `KscConfig.policy_contents_max_policies` для
    онлайн-сбора передаётся явно через `collect`)."""
    limit = POLICY_CONTENTS_MAX_POLICIES if max_policies is None else max_policies
    out: dict[str, Any] = {}
    for count, (npolicy, product, version) in enumerate(_protection_policies(policies), 1):
        if count > limit:
            # Пропущенная по лимиту политика остаётся в секции с причиной — POLICY_CONTENT_MISSING её покажет.
            if count == limit + 1:
                warnings.append(f"policy_contents: политик больше лимита {limit}, часть пропущена")
            out[str(npolicy)] = {"product": product, "version": version, "sections": {}, "errors": ["лимит политик"]}
            continue
        try:
            ssid = _ret(client.call("Policy.GetPolicyContents", {"nPolicy": npolicy, "nRevisionId": 0, "nLifeTime": 0}))
            sections, errors = _read_sections(client, ssid, product, version)
            out[str(npolicy)] = {"product": product, "version": version, "sections": sections, "errors": errors}
        except KscError as exc:
            warnings.append(f"policy_contents[{npolicy}]: {exc}")
    return out


def _policy_profiles(client: KscClient, policies: list[dict[str, Any]], *, max_policies: int | None = None) -> dict[str, Any]:
    """Профили активных политик продуктов защиты (тот же отбор и лимит, что у `_policy_contents`):
    `PolicyProfiles.EnumProfiles` → по каждому имени `GetProfile` (атрибуты, секреты скрыты) и
    `GetProfileSettings` (хранилище, секции читаются как у политики), плюс `GetPriorities`.
    Ошибки — строки `errors` на своём уровне: отказ `EnumProfiles` — у политики (профилей и порядка нет),
    `GetPriorities` — у политики, `GetProfile`/`GetProfileSettings` — у профиля, остальные профили читаются.
    Политика сверх лимита записывается с `errors == ["лимит политик"]`."""
    limit = POLICY_CONTENTS_MAX_POLICIES if max_policies is None else max_policies
    out: dict[str, Any] = {}
    for count, (npolicy, product, version) in enumerate(_protection_policies(policies), 1):
        entry: dict[str, Any] = {"profiles": [], "priorities": [], "errors": []}
        out[str(npolicy)] = entry
        if count > limit:
            entry["errors"].append("лимит политик")
            continue
        base = {"nPolicy": npolicy, "nRevision": 0}
        try:
            names = [str(name) for name in strip_params(_ret(client.call("PolicyProfiles.EnumProfiles", base)) or {})]
        except KscError as exc:
            entry["errors"].append(str(exc))
            continue
        for name in names:
            profile: dict[str, Any] = {"name": name, "attrs": {}, "sections": {}, "errors": []}
            try:
                profile["attrs"] = hide_secrets(_ret(client.call("PolicyProfiles.GetProfile", {**base, "szwName": name})) or {})
            except KscError as exc:
                profile["errors"].append(str(exc))
            try:
                ssid = _ret(client.call("PolicyProfiles.GetProfileSettings", {**base, "szwName": name, "nLifeTime": 0}))
                profile["sections"], section_errors = _read_sections(client, ssid, product, version)
                profile["errors"].extend(section_errors)
            except KscError as exc:
                profile["errors"].append(str(exc))
            entry["profiles"].append(profile)
        try:
            entry["priorities"] = [str(name) for name in unwrap(_ret(client.call("PolicyProfiles.GetPriorities", base))) or []]
        except KscError as exc:
            entry["errors"].append(str(exc))
    return out


def _hosts_with_agent(hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Хосты с Агентом администрирования (бит 4 статуса) и именем — только у них спрашиваем продукты и теги."""
    plain_hosts = [strip_params(h) for h in hosts]
    return [h for h in plain_hosts if _int(h.get("KLHST_WKS_STATUS")) & 4 and h.get("KLHST_WKS_HOSTNAME")]


def _host_tags(client: KscClient, hosts: list[dict[str, Any]], warnings: list[str]) -> dict[str, list[str]] | None:
    """Теги хостов с агентом: пакетный `ListTags.GetTags` экземпляра HostsTags (чужие идентификаторы и записи
    без идентификатора отбрасываются); не сработал пакет — по одному хосту через `HostTagsApi.GetHostTags`.
    Отказ на одном хосте не теряет остальные: у него `[]`, одна строка `host_tags: теги не прочитаны у N хостов`
    в `warnings`. Если отказали все первые `TAGS_FALLBACK_GIVE_UP` вызовов (или все, когда хостов меньше) —
    None (секции в выгрузке не будет) и строка `host_tags: …` в `warnings`."""
    ids = [str(h["KLHST_WKS_HOSTNAME"]) for h in _hosts_with_agent(hosts)]
    out: dict[str, list[str]] = {i: [] for i in ids}
    try:
        for start in range(0, len(ids), TAGS_BATCH):
            items = strip_params(_ret(client.call("HostsTags.ListTags.GetTags", {"pIdArray": ids[start:start + TAGS_BATCH], "pParams": {}})) or [])
            for item in items:
                key = _str(item.get("KLTAGS_ITEM_ID"))
                if key in out:
                    out[key] = [str(t) for t in (unwrap(item.get("KLTAGS_TAGS")) or [])]
        return out
    except KscError as batch_exc:
        out = {i: [] for i in ids}
        failed = 0
        first_error: KscError | None = None
        probe = min(TAGS_FALLBACK_GIVE_UP, len(ids))
        for n, host_id in enumerate(ids, 1):
            try:
                out[host_id] = [str(t) for t in (unwrap(_ret(client.call("HostTagsApi.GetHostTags", {"szwHostId": host_id}))) or [])]
            except KscError as exc:
                failed += 1
                first_error = first_error or exc
            if n == probe and failed == n:
                warnings.append(f"host_tags: {batch_exc}; по одному хосту: {first_error}")
                return None
        if failed:
            warnings.append(f"host_tags: теги не прочитаны у {failed} хостов: {first_error}")
        return out


def sid_string(value: Any) -> str:
    """SID из `ul_imgSid` строкой `S-1-5-21-…`: двоичный (base64 из `{"type": "binary"}`) — разбирается (ревизия,
    число подчинённых значений, 6 байт старшинства big-endian, подчинённые по 4 байта little-endian); уже строка
    `S-…` — как есть; пусто или не разбирается — `""`. То же правило — `SidString` в скрипте."""
    text = _str(value)
    if not text:
        return ""
    if text.upper().startswith("S-"):
        return text
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return ""
    if len(raw) < 8 or len(raw) < 8 + 4 * raw[1]:
        return ""
    subs = [str(int.from_bytes(raw[8 + 4 * i:12 + 4 * i], "little")) for i in range(raw[1])]
    return "-".join(["S", str(raw[0]), str(int.from_bytes(raw[2:8], "big")), *subs])


def _host_user(record: dict[str, Any]) -> dict[str, Any]:
    """Запись `GlobalUsersListSrvViewName` по хосту → элемент секции `host_users` (контракт спеки «Пользователи как
    активы» §2.1) и `bin_id` — `ul_binId` как пришёл (base64): по нему разбор связывает владельца устройства
    (`KLHST_WKS_OWNER_ID`) с пользователем. `group` — только явное `ul_bUser = false`. То же — `Convert-HostUser` в скрипте."""
    r = strip_params(record)
    domain_sam = _str(r.get("ul_wstrDomainSAM"))
    name = _str(r.get("ul_wstrSamAccountName"))
    is_user = unwrap(r.get("ul_bUser"))
    return {
        "sid": sid_string(r.get("ul_imgSid")), "sam": f"{domain_sam}\\{name}" if domain_sam and name else name,
        "upn": _str(r.get("ul_wstrPrincipalName")), "display_name": _str(r.get("ul_wstrDisplayName")),
        "domain": _str(r.get("ul_wstrDomain2000")) or domain_sam, "local": bool(unwrap(r.get("ul_Local"))),
        "group": is_user is not None and not bool(is_user), "active": bool(unwrap(r.get("ul_bVisited"))),
        "bin_id": _str(r.get("ul_binId")),
    }


def _host_users(client: KscClient, hosts: list[dict[str, Any]], warnings: list[str]) -> dict[str, list[dict[str, Any]] | None]:
    """Пользователи каждого хоста с агентом: `GlobalUsersListSrvViewName` с `pParams.strHostId`. Отказ по хосту — у него
    `None` («не собрано для этого хоста»), остальные читаются; `HOST_USERS_GIVE_UP` отказов подряд — чтение бросается,
    остальные хосты получают `None` без запроса. Предупреждение — одна строка `host_users: …` на весь шаг."""
    ids = [str(h["KLHST_WKS_HOSTNAME"]) for h in _hosts_with_agent(hosts)]
    out: dict[str, list[dict[str, Any]] | None] = {}
    failed = streak = 0
    first_error: KscError | None = None
    for host_id in ids:
        if streak >= HOST_USERS_GIVE_UP:
            out[host_id] = None
            continue
        try:
            records = _read_srvview(client, "GlobalUsersListSrvViewName", HOST_USER_FIELDS, params={"strHostId": host_id})
        except KscError as exc:
            out[host_id] = None
            failed += 1
            streak += 1
            first_error = first_error or exc
            continue
        out[host_id] = [_host_user(r) for r in records]
        streak = 0
    if streak >= HOST_USERS_GIVE_UP:
        missing = sum(1 for v in out.values() if v is None)
        warnings.append(f"host_users: {HOST_USERS_GIVE_UP} отказов подряд, чтение прекращено; пользователи не собраны у {missing} хостов: {first_error}")
    elif failed:
        warnings.append(f"host_users: пользователи не прочитаны у {failed} хостов: {first_error}")
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
        with_agent = _hosts_with_agent(hosts)
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

    host_tags = _host_tags(client, hosts, warnings)
    host_users = _host_users(client, hosts, warnings)

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
        # Параметры задачи несут и учётные данные запуска: то же скрытие, что у содержимого политик.
        hide_task_params(_task_body(t))
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
    result: dict[str, Any] = {
        "format": FORMAT,
        "server": {"name": name, "version": str(static.get("KLADMSRV_PRODUCT_FULL_VERSION") or ""), "collected_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "collector": "online", "collector_version": COLLECTOR_VERSION, "user": username, "host": host, "warnings": warnings},
        "groups": groups, "hosts": hosts, "host_products": products, "host_components": components,
        "policies": policies, "effective_policies": effective, "tasks": tasks, "licenses": licenses, "static": static, "domains": domains,
        "role_assignments": role_assignments, "internal_users": internal_users, "security": security,
        "server_certs": server_certs, "secondary_servers": secondary_servers, "update_agents": update_agents,
        "policy_contents": policy_contents, "host_users": host_users,
    }
    # Секции «не собрано» в файл не попадают вовсе — «не собрано» отличается от «пусто».
    if host_tags is not None:
        result["host_tags"] = host_tags
    if not skip_policy_contents:
        result["policy_profiles"] = _policy_profiles(client, policies, max_policies=max_policies)
    return result
