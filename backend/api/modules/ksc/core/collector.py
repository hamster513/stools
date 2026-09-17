"""Онлайн-сбор: те же вызовы Open API, что в STools-KSC-Collector.ps1, тот же формат файла."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from typing import Any

from api.modules.ksc.core.client import KscClient, KscError
from api.modules.ksc.core.export import FORMAT, PRODUCT_AGENT, PRODUCT_SERVER, _int, strip_params

COLLECTOR_VERSION = "1.0"

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


def _read_srvview(client: KscClient, view: str, fields: list[str], flt: str = "") -> list[dict[str, Any]]:
    """SrvView: итератор постранично по 500 записей, `ReleaseIterator` всегда, даже при ошибке чтения."""
    it = client.call("SrvView.ResetIterator", {"wstrViewName": view, "wstrFilter": flt, "vecFieldsToReturn": fields, "vecFieldsToOrder": [], "pParams": {}, "lifetimeSec": 600})["wstrIteratorId"]
    try:
        total = _ret(client.call("SrvView.GetRecordCount", {"wstrIteratorId": it})) or 0
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


def collect(client: KscClient, *, skip_products: bool = False, progress: Progress | None = None, username: str = "", host: str = "") -> dict[str, Any]:
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
        except KscError:
            continue

    tasks: list[dict[str, Any]] = []
    it = client.call("Tasks.ResetTasksIterator", {"nGroupId": -1, "bGroupIdSignificant": False, "strProductName": "", "strVersion": "", "strComponentName": "", "strInstanceId": "", "strTaskName": "", "bIncludeSupergroups": False})["strTaskIteratorId"]
    while True:
        t = client.call("Tasks.GetNextTask", {"strTaskIteratorId": it}).get("pTaskData") or {}
        if not t:
            break
        tid = strip_params(t).get("TASK_UNIQUE_ID")
        if tid:
            try:
                t["statistics"] = _ret(client.call("Tasks.GetTaskStatistics", {"strTask": str(tid)}))
            except KscError:
                pass
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

    role_assignments = _section("role_assignments", lambda: _read_srvview(client, "AdmGroupsAclRolesSrvViewName", ROLE_FIELDS), [])
    internal_users = _section("internal_users", lambda: _read_srvview(client, "GlobalUsersListSrvViewName", USER_FIELDS, "(ul_InternalUser = 1)"), [])
    two_factor = _section("security", lambda: _ret(client.call("TotpGlobalSettings.Get2FaRequiredForAll", {})), None)
    security = {"two_factor_required_for_all": two_factor}

    def _certs() -> dict[str, Any]:
        out: dict[str, Any] = {}
        for n in range(1, 5):
            c = _ret(client.call("CertPoolCtrl.GetCertificateInfo", {"nVServerId": -1, "nFunction": n})) or {}
            if c:
                out[str(n)] = c
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
    }
