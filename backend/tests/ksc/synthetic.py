"""Синтетический KSC с известными ответами на все проверки (см. таблицу в плане)."""
from __future__ import annotations

import base64
import datetime as dt
import json
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NOW = dt.datetime(2026, 9, 15, 12, 0, tzinfo=dt.UTC)
FORMAT = "stools-ksc/1"


def dtv(value: dt.datetime) -> dict[str, str]:
    return {"type": "datetime", "value": value.strftime("%Y-%m-%dT%H:%M:%SZ")}


def _self_signed_cert_der(now: dt.datetime) -> bytes:
    """Самоподписанный сертификат сервера (EC, SECP256R1): истекает через 30 дней от `now`."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ksc01")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=300))
        .not_valid_after(now + dt.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


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
        "KLHST_WKS_OS_BUILD_NUMBER": 22631, "KLHST_WKS_CPU_ARCH": 2, "HST_VM_TYPE": 3,
    }
    if status & 4:
        h["KLHST_WKS_LAST_NAGENT_CONNECTED"] = dtv(now - dt.timedelta(hours=1))
    if protected:
        h["KLHST_WKS_RTP_AV_BASES_TIME"] = dtv(now - dt.timedelta(days=1))
        h["KLHST_WKS_LAST_FULLSCAN"] = dtv(now - dt.timedelta(days=3))
    h.update(over)
    return h


COMPONENTS = ["File Threat Protection", "Behavior Detection", "Exploit Prevention", "Firewall", "Network Threat Protection", "Web Control", "Device Control"]


def _lock(value: Any, *, locked: bool | None = False, inherited: bool = False, lock_policy: str = "", lock_group: str = "") -> dict[str, Any]:
    """Контейнер настройки; `locked=None` — без признака замка `KLPRSS_Mnd`."""
    node: dict[str, Any] = {"KLPRSS_Val": value, "KLPRSS_ValLck": inherited, "KLPRSS_ValLckPolicy": lock_policy, "KLPRSS_ValLckGroup": lock_group}
    if locked is not None:
        node["KLPRSS_Mnd"] = locked
    return node


#: Глубина вложенности `KLPRSS_Deep` — больше 20 (старый `-Depth 20` скрипта обрезал бы её).
DEEP_LEVELS = 25


def _deep(levels: int) -> dict[str, Any]:
    node: dict[str, Any] = {"Leaf": "deep-value"}
    for n in range(levels, 0, -1):
        node = {f"L{n}": node}
    return node


def _policy_sections(*, locked: bool) -> dict[str, Any]:
    """Секции содержимого политики. Секреты (признак в имени ключа или секции на любой глубине —
    всё поддерево под ним: строки и двоичные значения скрываются, булевы и числа остаются):
    `AdminPassword` — контейнер в документированной форме (строка в `KLPRSS_Val`);
    `ProxyPassword` — контейнер в обёртке params; `PasswordProtection` — вложенный двоичный
    `PasswordHash` внутри `KLPRSS_Val`; `KLPRSS_Password` — ключ `PASSWORD_HASH` (строка);
    `KLPRSS_Passwords` — секция с признаком, внутри контейнеры; `KLPRSS_Secret` — секция целиком
    двоичное значение. `EnablePasswordProtection` — булев контейнер с тем же словом в имени:
    значение и замок остаются. Для формы хранения: `Exclusions` — список из одного элемента,
    `TrustedApps` — пустой список и без признака замка, `KLPRSS_Deep` — вложенность глубже 20.
    Замки: `EnableSelfProtection` — наследованный, `KLPRSS_Components` — вложенный `KLPRSS_Val`."""
    return {
        "KLPRSS_Basic": {
            "EnableSelfProtection": _lock(True, locked=locked, inherited=locked,
                                          lock_policy="KES root" if locked else "", lock_group="Managed devices" if locked else ""),
            "EnablePasswordProtection": _lock(True, locked=locked),
            "ReportsMaxSize": _lock(1024, locked=False),
            "AdminPassword": _lock("hunter2", locked=locked),
            "ProxyPassword": {"type": "params", "value": _lock("proxy-secret", locked=False)},
            "PasswordProtection": _lock({"PasswordHash": {"type": "binary", "value": "aGFzaC1ibG9i"}, "Enabled": True}, locked=locked),
            "Exclusions": _lock(["C:\\Tools\\a.exe"], locked=False),
            "TrustedApps": _lock([], locked=None),
        },
        "KLPRSS_Components": {
            "KLPRSS_Val": {
                "FileThreatProtection": {"KLPRSS_Val": {"Enabled": _lock(True, locked=locked)}},
                "Firewall": {"KLPRSS_Val": {"Enabled": _lock(True, locked=False)}},
            }
        },
        "KLPRSS_Password": {"PASSWORD_HASH": "e10adc3949ba59abbe56e057f20f883e"},
        "KLPRSS_Passwords": {
            "Uninstall": _lock("uninstall-secret", locked=locked),
            "Exit": _lock({"Value": "exit-secret", "Required": True, "Attempts": 3}, locked=False),
        },
        "KLPRSS_Secret": {"type": "binary", "value": "c2VjcmV0LWJsb2I="},
        "KLPRSS_Deep": _deep(DEEP_LEVELS),
    }


#: Значения-секреты синтетики: ни одно не должно попасть в выгрузку ни одного сборщика.
SECRET_VALUES = ("hunter2", "proxy-secret", "aGFzaC1ibG9i", "e10adc3949ba59abbe56e057f20f883e", "uninstall-secret", "exit-secret", "c2VjcmV0LWJsb2I=",
                 "profile-secret")


def _policy_contents() -> dict[str, Any]:
    """Содержимое активных политик защиты: «KES workstations» (id 1, часть настроек замкнута) и
    «KES lab» (id 3, без единого замка). Политика агента (id 2) сюда не входит: она не собирается."""
    return {
        "1": {"product": "KES", "version": "12.0.0.0", "sections": _policy_sections(locked=True), "errors": []},
        "3": {"product": "KES", "version": "12.0.0.0", "sections": _policy_sections(locked=False), "errors": []},
    }


#: Профили политики 1: включённый (с замком и секретом) и выключенный.
P_NOTEBOOKS: dict[str, Any] = {
    "name": "Ноутбуки",
    "attrs": {"KLSSPOL_PRF_ENABLED": True, "EXPRESSION": {"type": "params", "value": {"KLSSPOL_TAG": "Notebook"}}},
    "sections": {
        "KLPRSS_Components": {"KLPRSS_Val": {"Firewall": {"KLPRSS_Val": {"Enabled": _lock(False, locked=True)}}}},
        "KLPRSS_Basic": {"ProxyPassword": _lock("profile-secret", locked=True)},
    },
    "errors": [],
}
P_DISABLED: dict[str, Any] = {"name": "Выключенный", "attrs": {"KLSSPOL_PRF_ENABLED": False}, "sections": {}, "errors": []}


def _host_tags(hosts: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Теги хостов с агентом (по тому же правилу, что `host_products`): у WS01 два, у SRV01 один, у остальных пусто."""
    tags: dict[str, list[str]] = {h["KLHST_WKS_HOSTNAME"]: [] for h in hosts if h["KLHST_WKS_STATUS"] & 4}
    tags["h-ws01"] = ["VIP", "Бухгалтерия"]
    tags["h-srv01"] = ["Server"]
    return tags


def _policy_profiles() -> dict[str, Any]:
    return {
        "1": {"profiles": [P_NOTEBOOKS, P_DISABLED], "priorities": ["Ноутбуки", "Выключенный"], "errors": []},
        "3": {"profiles": [], "priorities": [], "errors": []},
    }


def build_export(*, now: dt.datetime = NOW) -> dict[str, Any]:
    ok = 1 | 4 | 8 | 16
    hosts = [
        _host(1, "WS01", 2, ok, 7, now=now),
        _host(2, "WS02", 2, ok, 1, now=now),
        _host(3, "WS03", 2, ok, 7, now=now, KLHST_WKS_RTP_AV_BASES_TIME=dtv(now - dt.timedelta(days=10))),
        _host(4, "WS04", 2, ok, 7, now=now, KLHST_WKS_LAST_FULLSCAN=dtv(now - dt.timedelta(days=45)),
              KLHST_WKS_RBT_REQUIRED=True, KLHST_WKS_RBT_REQUEST_TIME=dtv(now - dt.timedelta(days=15)), KLHST_WKS_RBT_REQUEST_REASON=4),
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
         "TASK_INFO_PARAMS": {"DisplayName": "Обновление", "PRTS_TASK_GROUPID": 0, "TASKSCH_TYPE": 1},
         "TASK_LAST_EXEC_TIME": dtv(now - dt.timedelta(days=1)), "statistics": {"4": 6, "8": 1, "16": 3}},
        {"TASK_UNIQUE_ID": "t-scan", "TASKID_PRODUCT_NAME": "KES", "TASKID_VERSION": "12.0.0.0", "TASK_NAME": "Scan",
         "TASK_INFO_PARAMS": {"DisplayName": "Поиск вирусов", "PRTS_TASK_GROUPID": 2, "TASKSCH_TYPE": 1},
         "TASK_LAST_EXEC_TIME": dtv(now - dt.timedelta(days=40)), "statistics": {"4": 5}},
    ]
    licenses = [{"KLLIC_SERIAL": "AAAA-BBBB", "KLLIC_PROD_NAME": "Kaspersky Endpoint Security для бизнеса", "KLLIC_KEY_TYPE": 1,
                 "KLLIC_LIMIT_DATE": dtv(now + dt.timedelta(days=15)), "KLLIC_LIC_COUNT": 10, "KLLIC_NHOSTS_ASCURRENT": 12,
                 "KLLIC_USED_BY_ADM_SRV": 0, "KLLICSRV_KEY_INSTALLED": True}]
    role_assignments = [
        {"nRoleId": 1, "wstrRoleName": "Main Administrator", "wstrRoleDisplayName": "Main Administrator",
         "nInternalUserId": 5, "wstrTrusteeDisplayName": "kladmin", "wstrUserPrincipalName": "", "nGroupId": 0, "wstrGroupName": "Managed devices"},
        {"nRoleId": 2, "wstrRoleName": "Administrator", "wstrRoleDisplayName": "Administrator",
         "nInternalUserId": 0, "wstrTrusteeDisplayName": "CORP\\ivanov", "wstrUserPrincipalName": "ivanov@corp.local", "nGroupId": 0, "wstrGroupName": "Managed devices"},
        {"nRoleId": 3, "wstrRoleName": "Auditor", "wstrRoleDisplayName": "Auditor",
         "nInternalUserId": 0, "wstrTrusteeDisplayName": "CORP\\audit", "wstrUserPrincipalName": "audit@corp.local", "nGroupId": 0, "wstrGroupName": "Managed devices"},
    ]
    internal_users = [
        {"ul_llTrusteeId": 5, "ul_nSplUserId": 5, "ul_wstrDisplayName": "kladmin", "ul_wstrSamAccountName": "kladmin",
         "ul_wstrPrincipalName": "", "ul_bUser": True, "ul_Builtin": False, "ul_InternalUser": True},
        {"ul_llTrusteeId": 1, "ul_nSplUserId": 1, "ul_wstrDisplayName": "KLAdmins", "ul_wstrSamAccountName": "KLAdmins",
         "ul_wstrPrincipalName": "", "ul_bUser": False, "ul_Builtin": True, "ul_InternalUser": True},
    ]
    security = {"two_factor_required_for_all": False}
    server_certs = {"1": {"CPublic": {"type": "binary", "value": base64.b64encode(_self_signed_cert_der(now)).decode("ascii")}}}
    secondary_servers = [
        {"KLSRVH_SRV_ID": 2, "KLSRVH_SRV_DN": "ksc02", "KLSRVH_SRV_ADDR": "ksc02.corp.local", "KLSRVH_SRV_VERSION": "15.1.0.11225",
         "KLSRVH_SRV_STATUS": 1, "KLSRVH_SRV_LAST_CONNECTED": dtv(now - dt.timedelta(days=20)), "KLSRVH_SRV_GROUPID": 0, "KLSRVH_SRV_PASSIVE": False},
    ]
    update_agents = [{"KLUAGNT_HOST_NAME": "h-ws01", "KLUAGNT_GROUP_ID": 2, "KLUAGNT_HOST_DN": "WS01"}]
    return {
        "format": FORMAT,
        "server": {"name": "ksc01", "version": "15.1.0.11225", "collected_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "collector": "powershell", "collector_version": "1.0", "user": "KL\\audit", "host": "ksc01.corp.local"},
        "groups": groups, "hosts": hosts, "host_products": products, "host_components": components,
        "policies": policies, "effective_policies": effective, "tasks": tasks, "licenses": licenses,
        "static": {"KLADMSRV_SERVER_VERSION_ID": 983296, "KLADMSRV_SERVER_HOSTNAME": "ksc01", "KLADMSRV_PRODUCT_FULL_VERSION": "15.1.0.11225"},
        "domains": [{"KLHST_WKS_WINDOMAIN": "CORP", "KLHST_WKS_DNSDOMAIN": "corp.local"}],
        "role_assignments": role_assignments, "internal_users": internal_users, "security": security,
        "server_certs": server_certs, "secondary_servers": secondary_servers, "update_agents": update_agents,
        "policy_contents": _policy_contents(),
        "host_tags": _host_tags(hosts), "policy_profiles": _policy_profiles(),
    }


def without_new_sections(export: dict[str, Any]) -> dict[str, Any]:
    """Копия выгрузки без `host_tags` и `policy_profiles` — как у старого сборщика."""
    return {k: v for k, v in export.items() if k not in ("host_tags", "policy_profiles")}


def expected_policy_contents() -> dict[str, Any]:
    """`_policy_contents()` как должны отдать оба сборщика (после разбора, без обёрток params):
    каждая строка и каждое двоичное значение под ключом или секцией с признаком секрета —
    "<скрыто>", булевы и числа остаются; `EnablePasswordProtection` видима и замкнута (кроме
    строк замка — они тоже под признаком)."""
    out = json.loads(json.dumps(_policy_contents()))
    hidden_lock = {"KLPRSS_ValLckPolicy": "<скрыто>", "KLPRSS_ValLckGroup": "<скрыто>"}
    for pid in ("1", "3"):
        sections = out[pid]["sections"]
        basic = sections["KLPRSS_Basic"]
        basic["EnablePasswordProtection"].update(hidden_lock)
        basic["AdminPassword"].update(hidden_lock, KLPRSS_Val="<скрыто>")
        basic["ProxyPassword"] = {**basic["ProxyPassword"]["value"], **hidden_lock, "KLPRSS_Val": "<скрыто>"}
        basic["PasswordProtection"].update(hidden_lock)
        basic["PasswordProtection"]["KLPRSS_Val"]["PasswordHash"] = "<скрыто>"
        sections["KLPRSS_Password"]["PASSWORD_HASH"] = "<скрыто>"
        passwords = sections["KLPRSS_Passwords"]
        passwords["Uninstall"].update(hidden_lock, KLPRSS_Val="<скрыто>")
        passwords["Exit"].update(hidden_lock)
        passwords["Exit"]["KLPRSS_Val"]["Value"] = "<скрыто>"
        sections["KLPRSS_Secret"] = "<скрыто>"
    return out


def expected_policy_profiles() -> dict[str, Any]:
    """`_policy_profiles()` как должен отдать онлайн-сборщик после разбора (без обёрток params):
    секрет профиля «Ноутбуки» — `ProxyPassword` — скрыт вместе со строками замка, булевы остаются."""
    from api.modules.ksc.core.export import strip_params

    out = strip_params(json.loads(json.dumps(_policy_profiles())))
    proxy = out["1"]["profiles"][0]["sections"]["KLPRSS_Basic"]["ProxyPassword"]
    proxy.update(KLPRSS_Val="<скрыто>", KLPRSS_ValLckPolicy="<скрыто>", KLPRSS_ValLckGroup="<скрыто>")
    return out


def assert_secrets_hidden(policy_contents: dict[str, Any]) -> None:
    """Секреты синтетики скрыты в секции `policy_contents` сборщика — как пришла (с обёртками
    params) или разобранная: ни одно значение из `SECRET_VALUES` не попало в неё, каждый случай
    скрыт на своём месте, `EnablePasswordProtection` осталась видимой и замкнутой (политика 1)."""
    from api.modules.ksc.core.export import strip_params

    text = json.dumps(policy_contents, ensure_ascii=False)
    assert not [v for v in SECRET_VALUES if v in text]
    sections = strip_params(policy_contents)["1"]["sections"]
    basic = sections["KLPRSS_Basic"]
    assert basic["AdminPassword"]["KLPRSS_Val"] == "<скрыто>" and basic["AdminPassword"]["KLPRSS_Mnd"] is True
    assert basic["ProxyPassword"]["KLPRSS_Val"] == "<скрыто>"
    assert basic["PasswordProtection"]["KLPRSS_Val"] == {"PasswordHash": "<скрыто>", "Enabled": True}
    assert sections["KLPRSS_Password"]["PASSWORD_HASH"] == "<скрыто>"
    assert sections["KLPRSS_Passwords"]["Uninstall"]["KLPRSS_Val"] == "<скрыто>"
    assert sections["KLPRSS_Passwords"]["Exit"]["KLPRSS_Val"] == {"Value": "<скрыто>", "Required": True, "Attempts": 3}
    assert sections["KLPRSS_Secret"] == "<скрыто>"
    assert basic["EnablePasswordProtection"]["KLPRSS_Val"] is True and basic["EnablePasswordProtection"]["KLPRSS_Mnd"] is True


def assert_storage_shapes(policy_contents: dict[str, Any]) -> None:
    """Форма хранения переживает сборщик: список из одного элемента остаётся списком, пустой —
    пустым списком, вложенность `KLPRSS_Deep` не обрезана."""
    from api.modules.ksc.core.export import strip_params

    sections = strip_params(policy_contents)["1"]["sections"]
    assert sections["KLPRSS_Basic"]["Exclusions"]["KLPRSS_Val"] == ["C:\\Tools\\a.exe"]
    assert sections["KLPRSS_Basic"]["TrustedApps"]["KLPRSS_Val"] == []
    assert sections["KLPRSS_Deep"] == _deep(DEEP_LEVELS)


def add_inactive_policy(raw: dict[str, Any]) -> dict[str, Any]:
    """Политика продукта защиты с `KLPOL_ACTIVE` типизированным нулём
    (`{"type": "boolean", "value": false}`) — типизированная ложь, не безусловная правда: не должна
    попасть в `policy_contents`."""
    base = raw["policies"][0]
    inactive = {**base, "KLPOL_ID": 9, "KLPOL_DN": "KES retired", "KLPOL_ACTIVE": {"type": "boolean", "value": False}}
    raw["policies"].append(inactive)
    return raw


#: Имя сервера с косой чертой и пробелом: в имя файла выгрузки оно идёт только очищенным (аудит L8).
BAIT_SERVER_NAME = "ksc 01/lab"
#: Значения-секреты `add_secret_bait`: новые маркеры, двоичное значение под обычным ключом,
#: параметры задач (аудит M4). Ни одно не должно попасть в выгрузку или в разобранный файл.
BAIT_VALUES = ("pp-secret", "ak-secret", "ak2-secret", "auth-secret", "pin-secret", "key-secret", "YmluLWJsb2I=",
               "task-pass-secret", "task-apikey-secret", "dGFzay1ibG9i", "task-auth-secret")


def add_secret_bait(raw: dict[str, Any]) -> dict[str, Any]:
    """Секреты, которые старые маркеры пропускали: `Passphrase`, `ApiKey`, `API_KEY`, `AuthCode`,
    `PIN`, `EncryptionKey`, двоичный `Certificate` под ключом без признака — в секции `KLPRSS_Extra`
    политики 1; учётные данные в `TASK_ADDITIONAL_PARAMS` и `TASK_INFO_PARAMS` задачи обновления;
    имя сервера с `/` и пробелом. Рядом — то, что должно остаться видимым (`assert_bait_hidden`)."""
    raw["static"]["KLADMSRV_SERVER_HOSTNAME"] = BAIT_SERVER_NAME
    raw["policy_contents"]["1"]["sections"]["KLPRSS_Extra"] = {
        "Passphrase": "pp-secret", "ApiKey": "ak-secret", "API_KEY": "ak2-secret", "AuthCode": "auth-secret",
        "PIN": "pin-secret", "EncryptionKey": "key-secret", "Certificate": {"type": "binary", "value": "YmluLWJsb2I="},
        "Comment": "visible-text", "Enabled": True, "Timeout": 30,
    }
    task = raw["tasks"][0]
    task["TASK_ADDITIONAL_PARAMS"] = {
        "KLTSK_ACCOUNT_PASSWORD": "task-pass-secret", "Mode": "full",
        "ServerSettings": {"ApiKey": "task-apikey-secret", "Port": 8080, "Blob": {"type": "binary", "value": "dGFzay1ibG9i"}},
    }
    task["TASK_INFO_PARAMS"]["AuthCode"] = "task-auth-secret"
    return raw


def assert_bait_hidden(export: Any) -> None:
    """Разобранная выгрузка (`KscExport`) с `add_secret_bait`: секреты скрыты, соседние значения видны."""
    hidden = "<скрыто>"
    text = json.dumps(export.model_dump(mode="json"), ensure_ascii=False)
    assert not [v for v in BAIT_VALUES + SECRET_VALUES if v in text]
    assert export.policy_contents["1"]["sections"]["KLPRSS_Extra"] == {
        "Passphrase": hidden, "ApiKey": hidden, "API_KEY": hidden, "AuthCode": hidden, "PIN": hidden, "EncryptionKey": hidden,
        "Certificate": hidden, "Comment": "visible-text", "Enabled": True, "Timeout": 30,
    }
    task = next(t for t in export.tasks if t["TASK_UNIQUE_ID"] == "t-upd")
    assert task["TASK_ADDITIONAL_PARAMS"] == {
        "KLTSK_ACCOUNT_PASSWORD": hidden, "Mode": "full", "ServerSettings": {"ApiKey": hidden, "Port": 8080, "Blob": hidden},
    }
    assert task["TASK_INFO_PARAMS"] == {"DisplayName": "Обновление", "PRTS_TASK_GROUPID": 0, "TASKSCH_TYPE": 1, "AuthCode": hidden}


def add_ws02_twin(raw: dict[str, Any]) -> dict[str, Any]:
    """Второе устройство с тем же отображаемым именем WS02, но в другой группе и домене:
    KLHST_WKS_DN в KSC не уникален."""
    ws02 = next(h for h in raw["hosts"] if h["KLHST_WKS_DN"] == "WS02")
    raw["hosts"].append(dict(ws02, KLHST_WKS_HOSTNAME="h-ws02-dup", KLHST_WKS_GROUPID=3,
                             KLHST_WKS_DNSDOMAIN="lab.local", KLHST_WKS_FQDN="ws02.lab.local"))
    return raw


def export_bytes(**kwargs: Any) -> bytes:
    return json.dumps(build_export(**kwargs), ensure_ascii=False).encode("utf-8")


def add_empty_objects(raw: dict[str, Any]) -> dict[str, Any]:
    """Пустые объекты `{}` в параметрах задач и в секции политики: живой KSC отдаёт их у задач без
    расписания и у пустых наборов настроек. В строгом режиме PowerShell перечисление свойств пустого
    объекта через `.Properties.Name` — ошибка: сбор падал на шаге «Задачи»."""
    raw["tasks"][0]["TASK_ADDITIONAL_PARAMS"] = {"Mode": "full", "Schedule": {}, "Nested": {"Inner": {}, "Items": [{}]}}
    raw["tasks"][1]["TASK_INFO_PARAMS"]["Extra"] = {}
    raw["policy_contents"]["1"]["sections"]["KLPRSS_Empty"] = {"Settings": {}, "Enabled": True}
    return raw
