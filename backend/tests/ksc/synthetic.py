"""Синтетический KSC с известными ответами на все проверки (см. таблицу в плане)."""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

NOW = dt.datetime(2026, 9, 15, 12, 0, tzinfo=dt.UTC)
FORMAT = "stools-ksc/1"


def dtv(value: dt.datetime) -> dict[str, str]:
    return {"type": "datetime", "value": value.strftime("%Y-%m-%dT%H:%M:%SZ")}


def _host(n: int, name: str, group: int, status: int, rtp: int, *, now: dt.datetime, **over: Any) -> dict[str, Any]:
    protected = bool(status & 16)
    h: dict[str, Any] = {
        "KLHST_WKS_HOSTNAME": f"h-{name.lower()}",
        "KLHST_WKS_DN": name, "KLHST_WKS_WINHOSTNAME": name, "KLHST_WKS_DNSNAME": name.lower(),
        "KLHST_WKS_WINDOMAIN": "CORP", "KLHST_WKS_DNSDOMAIN": "corp.local", "KLHST_WKS_FQDN": f"{name.lower()}.corp.local",
        "KLHST_WKS_GROUPID": group, "KLHST_WKS_OS_NAME": "Microsoft Windows 11", "KLHST_WKS_CTYPE": 1,
        "KLHST_WKS_IP_LONG": {"type": "long", "value": 3232235777 + n},
        "KLHST_WKS_STATUS": status, "KLHST_WKS_STATUS_ID": 0, "KLHST_WKS_STATUS_MASK": 0,
        "KLHST_WKS_RTP_STATE": rtp, "KLHST_WKS_VIRUS_COUNT": 0, "KLHST_WKS_UNCURED_COUNT": 0,
        "KLHST_WKS_FROM_UNASSIGNED": group == 1,
        "KLHST_WKS_LAST_VISIBLE": dtv(now - dt.timedelta(hours=1)),
        "KLHST_WKS_NAG_VERSION": "15.1.0.0" if status & 4 else "",
        "KLHST_WKS_RTP_AV_VERSION": "12.0.0.0" if protected else "",
    }
    if status & 4:
        h["KLHST_WKS_LAST_NAGENT_CONNECTED"] = dtv(now - dt.timedelta(hours=1))
    if protected:
        h["KLHST_WKS_RTP_AV_BASES_TIME"] = dtv(now - dt.timedelta(days=1))
        h["KLHST_WKS_LAST_FULLSCAN"] = dtv(now - dt.timedelta(days=3))
    h.update(over)
    return h


COMPONENTS = ["File Threat Protection", "Behavior Detection", "Exploit Prevention", "Firewall", "Network Threat Protection", "Web Control", "Device Control"]


def build_export(*, now: dt.datetime = NOW) -> dict[str, Any]:
    ok = 1 | 4 | 8 | 16
    hosts = [
        _host(1, "WS01", 2, ok, 7, now=now),
        _host(2, "WS02", 2, ok, 1, now=now),
        _host(3, "WS03", 2, ok, 7, now=now, KLHST_WKS_RTP_AV_BASES_TIME=dtv(now - dt.timedelta(days=10))),
        _host(4, "WS04", 2, ok, 7, now=now, KLHST_WKS_LAST_FULLSCAN=dtv(now - dt.timedelta(days=45))),
        _host(5, "WS05", 2, 1 | 4, 0, now=now, KLHST_WKS_LAST_NAGENT_CONNECTED=dtv(now - dt.timedelta(days=20)), KLHST_WKS_LAST_VISIBLE=dtv(now - dt.timedelta(days=20))),
        _host(6, "WS06", 2, 1, 0, now=now),
        _host(7, "WS07", 2, 1 | 4 | 8, 10, now=now),
        _host(8, "WS08", 1, 1, 0, now=now),
        _host(9, "WS09", 2, ok, 7, now=now, KLHST_WKS_UNCURED_COUNT=3, KLHST_WKS_STATUS_ID=1, KLHST_WKS_STATUS_MASK=1 << 10),
        _host(10, "WS10", 2, ok, 7, now=now, KLHST_WKS_RTP_AV_VERSION="11.0.0.0", KLHST_WKS_NAG_VERSION="14.0.0.0"),
        _host(11, "WS11", 2, ok, 7, now=now),
        _host(12, "SRV01", 3, ok, 7, now=now, KLHST_WKS_CTYPE=2, KLHST_WKS_OS_NAME="Microsoft Windows Server 2022"),
        _host(13, "LAB01", 4, ok, 7, now=now),
        _host(14, "WG01", 2, ok, 7, now=now, KLHST_WKS_WINDOMAIN="WORKGROUP", KLHST_WKS_DNSDOMAIN="", KLHST_WKS_FQDN="wg01"),
    ]
    products: dict[str, Any] = {}
    components: dict[str, Any] = {}
    for h in hosts:
        hid = h["KLHST_WKS_HOSTNAME"]
        p: dict[str, Any] = {}
        if h["KLHST_WKS_STATUS"] & 4:
            p["1103"] = {"1.0.0.0": {"DisplayName": "Агент администрирования", "ProdVersion": h["KLHST_WKS_NAG_VERSION"]}}
        if h["KLHST_WKS_STATUS"] & 16:
            ver = h["KLHST_WKS_RTP_AV_VERSION"]
            p["KES"] = {ver: {"DisplayName": "Kaspersky Endpoint Security для Windows", "ProdVersion": ver}}
            components[hid] = {f"KES/{ver}": [
                {"KLHST_PRCST_COMPONENT_DN": c, "KLHST_PRCST_COMPONENT_STATUS": 1 if (h["KLHST_WKS_DN"] == "WS11" and c == "Firewall") else 4,
                 "KLHST_PRCST_COMPONENT_ID": {"type": "binary", "value": "AAAA"}}
                for c in COMPONENTS
            ]}
        if p:  # как оба сборщика: продукты запрашиваются только у хостов с агентом
            products[hid] = p
    groups = [
        {"id": 0, "name": "Managed devices", "parentId": -1, "grp_full_name": "Managed devices", "level": 0},
        {"id": 1, "name": "Unassigned devices", "parentId": -1, "grp_full_name": "Unassigned devices", "level": 0},
        {"id": 2, "name": "Workstations", "parentId": 0, "grp_full_name": "Managed devices/Workstations", "level": 1},
        {"id": 3, "name": "Servers", "parentId": 0, "grp_full_name": "Managed devices/Servers", "level": 1},
        {"id": 4, "name": "Lab", "parentId": 2, "grp_full_name": "Managed devices/Workstations/Lab", "level": 2},
    ]
    def pol(i: int, dn: str, product: str, group: int, *, accept_parent: bool = True, inherited: bool = False) -> dict[str, Any]:
        return {"KLPOL_ID": i, "KLPOL_DN": dn, "KLPOL_PRODUCT": product, "KLPOL_VERSION": "12.0.0.0" if product == "KES" else "1.0.0.0",
                "KLPOL_GROUP_ID": group, "KLPOL_ACTIVE": True, "KLPOL_INHERITED": inherited, "KLPOL_ACCEPT_PARENT": accept_parent,
                "KLPOL_FORCE_DISTRIB2CHILDREN": True, "KLPOL_FORCED": False, "KLPOL_MODIFIED": dtv(now - dt.timedelta(days=30)),
                "KLPOL_CREATED": dtv(now - dt.timedelta(days=300)), "KLPOL_GROUP_NAME": next(g["name"] for g in groups if g["id"] == group)}
    policies = [pol(1, "KES workstations", "KES", 0), pol(2, "Agent", "1103", 0), pol(3, "KES lab", "KES", 4, accept_parent=False)]
    effective = {
        "0": [policies[0], policies[1]],
        "1": [],
        "2": [dict(policies[0], KLPOL_INHERITED=True), dict(policies[1], KLPOL_INHERITED=True)],
        "3": [dict(policies[1], KLPOL_INHERITED=True)],
        "4": [policies[2], dict(policies[1], KLPOL_INHERITED=True)],
    }
    tasks = [
        {"TASK_UNIQUE_ID": "t-upd", "TASKID_PRODUCT_NAME": "KES", "TASKID_VERSION": "12.0.0.0", "TASK_NAME": "Update",
         "TASK_INFO_PARAMS": {"DisplayName": "Обновление", "PRTS_TASK_GROUPID": 0, "TASKSCH_TYPE": 1}},
        {"TASK_UNIQUE_ID": "t-scan", "TASKID_PRODUCT_NAME": "KES", "TASKID_VERSION": "12.0.0.0", "TASK_NAME": "Scan",
         "TASK_INFO_PARAMS": {"DisplayName": "Поиск вирусов", "PRTS_TASK_GROUPID": 2, "TASKSCH_TYPE": 1}},
    ]
    licenses = [{"KLLIC_SERIAL": "AAAA-BBBB", "KLLIC_PROD_NAME": "Kaspersky Endpoint Security для бизнеса", "KLLIC_KEY_TYPE": 1,
                 "KLLIC_LIMIT_DATE": dtv(now + dt.timedelta(days=15)), "KLLIC_LIC_COUNT": 10, "KLLIC_NHOSTS_ASCURRENT": 12,
                 "KLLIC_USED_BY_ADM_SRV": 0, "KLLICSRV_KEY_INSTALLED": True}]
    return {
        "format": FORMAT,
        "server": {"name": "ksc01", "version": "15.1.0.11225", "collected_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "collector": "powershell", "collector_version": "1.0", "user": "KL\\audit", "host": "ksc01.corp.local"},
        "groups": groups, "hosts": hosts, "host_products": products, "host_components": components,
        "policies": policies, "effective_policies": effective, "tasks": tasks, "licenses": licenses,
        "static": {"KLADMSRV_SERVER_VERSION_ID": 983296, "KLADMSRV_SERVER_HOSTNAME": "ksc01", "KLADMSRV_PRODUCT_FULL_VERSION": "15.1.0.11225"},
        "domains": [{"KLHST_WKS_WINDOMAIN": "CORP", "KLHST_WKS_DNSDOMAIN": "corp.local"}],
    }


def export_bytes(**kwargs: Any) -> bytes:
    return json.dumps(build_export(**kwargs), ensure_ascii=False).encode("utf-8")
