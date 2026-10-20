"""Проверки GPO по файлам SYSVOL (спека §3.2): параметры реестра, аудит на контроллерах,
файлы с серверов вне домена, права на папки GPO.

Находки «на домен» (ни одна GPO не задаёт нужное) без блока gpo не выдаются: Registry.pol
и audit.csv не прочитаны, отсутствие настройки не доказано — это пишется в «не проверено».
"""
from __future__ import annotations

import re

from api.modules.ad.core.checks.adcs_rules import severity_for
from api.modules.ad.core.checks.gpo_settings import LINKS_UNKNOWN, _domain_finding, _finding, _gpos
from api.modules.ad.core.checks.principals import tier0_kind
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import GPO_FLAG_MACHINE_DISABLED, AdObject, ExportIndex
from api.modules.ad.core.findings import Finding, finalize

_GPO_FLAG_USER_DISABLED = 1
_POL = "software\\policies\\microsoft\\windows"
_DNS_CLIENT = _POL + " nt\\dnsclient"
_HARDENED_PATHS = _POL + "\\networkprovider\\hardenedpaths"
_WSUS = _POL + "\\windowsupdate"
_SCRIPT_BLOCK_LOGGING = _POL + "\\powershell\\scriptblocklogging"


def _values(idx: ExportIndex, gpo: AdObject, key: str, scopes: tuple[str, ...] = ("machine",)) -> dict[str, object]:
    """Значения Registry.pol под ключом: имя (нижний регистр) → данные; ключ без учёта регистра."""
    data = idx.gpo_data(gpo)
    rows = data.registry if data else []
    return {r.value.lower(): r.data for r in rows if r.scope in scopes and r.key.strip("\\").lower() == key}


def _as_int(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _linked(idx: ExportIndex, gpo: AdObject) -> bool:
    links = idx.gpo_links(gpo)
    return links is None or bool(links)


# ---- GpoRegistrySettings -------------------------------------------------------

def _hardened_paths_issues(values: dict[str, object]) -> list[str]:
    out: list[str] = []
    for name, data in values.items():
        if not name.rstrip("\\*").endswith(("\\sysvol", "\\netlogon")) or not isinstance(data, str):
            continue
        flags = {k.lower(): v for k, v in re.findall(r"(\w+)\s*=\s*(\d+)", data)}
        if "0" in (flags.get("requiremutualauthentication"), flags.get("requireintegrity")):
            out.append(f"{name}: {data}")
    return out


def check_gpo_registry_settings(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out: list[Finding] = []
    llmnr_off = ps_logging = False

    def add(g: AdObject, kind: str, severity: str, text: str) -> None:
        out.append(_finding(idx, cfg, "GpoRegistrySettings", severity, g, text, key_extra=kind, details={"kind": kind}))

    for g in _gpos(idx):
        multicast = _as_int(_values(idx, g, _DNS_CLIENT).get("enablemulticast"))
        if multicast == 1:
            add(g, "llmnr", "Low", "EnableMultiCast = 1: LLMNR явно включён, ответы на широковещательные запросы имён можно подделать")
        llmnr_off = llmnr_off or (multicast == 0 and _linked(idx, g))
        logging = _values(idx, g, _SCRIPT_BLOCK_LOGGING, ("machine", "user")).get("enablescriptblocklogging")
        ps_logging = ps_logging or (_as_int(logging) == 1 and _linked(idx, g))
        if issues := _hardened_paths_issues(_values(idx, g, _HARDENED_PATHS)):
            add(g, "hardened_paths", "Medium", "Hardened Paths без взаимной проверки подлинности или целостности для SYSVOL/NETLOGON: " + "; ".join(issues))
        wsus = _values(idx, g, _WSUS)
        server = wsus.get("wuserver")
        if isinstance(server, str) and server.strip().lower().startswith("http://"):
            add(g, "wsus_http", "Medium", f"WUServer = {server}: обновления WSUS по HTTP можно подменить в сети")
        if _as_int(wsus.get("setproxybehaviorforupdatedetection")) == 1:
            add(g, "wsus_user_proxy", "Low", "SetProxyBehaviorForUpdateDetection = 1: при поиске обновлений разрешён прокси пользователя")
        if _as_int(wsus.get("donotenforceenterprisetlscertpinningforupdatedetection")) == 1:
            add(g, "wsus_no_pinning", "Low", "DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection = 1: закрепление сертификата WSUS выключено")
    if idx.export.gpo is None:
        return out
    if not llmnr_off:
        text = "Ни одна привязанная GPO не выключает LLMNR (EnableMultiCast = 0): ответы на широковещательные запросы имён можно подделать и перехватить хэши NTLM"
        out.append(_domain_finding(idx, cfg, "GpoRegistrySettings", "Low", text, key_extra="llmnr"))
    if not ps_logging:
        text = "Ни одна привязанная GPO не включает журналирование блоков сценариев PowerShell (EnableScriptBlockLogging = 1)"
        out.append(_domain_finding(idx, cfg, "GpoRegistrySettings", "Low", text, key_extra="ps_logging"))
    return out


# ---- DcAuditPolicy -------------------------------------------------------------

_AUDIT_SUFFIX = "-69ae-11d9-bed3-505054503030"

#: Подкатегории расширенного аудита, нужные на контроллерах (спека §3.2): GUID → название.
DC_AUDIT_SUBCATEGORIES: dict[str, str] = {
    f"{guid}{_AUDIT_SUFFIX}": name for guid, name in (
        ("0cce923f", "Проверка учётных данных (Credential Validation)"),
        ("0cce9242", "Служба проверки подлинности Kerberos (Kerberos Authentication Service)"),
        ("0cce9240", "Операции с билетами службы Kerberos (Kerberos Service Ticket Operations)"),
        ("0cce9235", "Управление учётными записями пользователей (User Account Management)"),
        ("0cce9236", "Управление учётными записями компьютеров (Computer Account Management)"),
        ("0cce9237", "Управление группами безопасности (Security Group Management)"),
        ("0cce923c", "Изменения службы каталогов (Directory Service Changes)"),
        ("0cce9215", "Вход в систему (Logon)"),
        ("0cce921b", "Специальный вход (Special Logon)"),
        ("0cce922b", "Создание процесса (Process Creation)"),
        ("0cce9211", "Расширение системы безопасности (Security System Extension)"),
        ("0cce9228", "Использование важных привилегий (Sensitive Privilege Use)"),
        ("0cce922f", "Изменение политики аудита (Audit Policy Change)"),
        ("0cce9230", "Изменение политики проверки подлинности (Authentication Policy Change)"),
        ("0cce922d", "Активность DPAPI (DPAPI Activity)"),
    )
}


def check_dc_audit_policy(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    if idx.export.gpo is None:
        return []
    covered: set[str] = set()
    for g in idx.objects("groupPolicyContainer"):
        data = idx.gpo_data(g)
        if data is None or idx.applies_to_dcs(g) is False:
            continue
        covered |= {a.subcategory.strip("{}").lower() for a in data.audit if a.setting & 1}
    out: list[Finding] = []
    for guid, name in DC_AUDIT_SUBCATEGORIES.items():
        if guid in covered:
            continue
        text = (f"Аудит успеха «{name}» не включён ни в одной GPO, применимой к контроллерам домена; учтена только расширенная политика "
                "аудита (audit.csv), старая политика [Event Audit] из GptTmpl.inf не учитывается")
        if idx.gpo_link_map is None:
            text += f"; {LINKS_UNKNOWN}: учтены все GPO"
        f = _domain_finding(idx, cfg, "DcAuditPolicy", "Medium", text, key_extra=guid)
        f.details.update({"subcategory": guid, "name": name})
        out.append(f)
    return out


# ---- GpoExternalFiles ----------------------------------------------------------

def _internal_hosts(idx: ExportIndex) -> set[str]:
    if "gpo_internal_hosts" not in idx.cache:
        d = idx.export.domain
        names = [d.dns_root, d.netbios] + [n for c in idx.dcs for n in (c.dNSHostName, (c.dNSHostName or "").split(".", 1)[0], c.name)]
        idx.cache["gpo_internal_hosts"] = {n.lower() for n in names if n}
    hosts: set[str] = idx.cache["gpo_internal_hosts"]
    return hosts


def _clean(path: str) -> str:
    return path.strip().strip('"').strip()


def is_external(path: str, idx: ExportIndex) -> bool:
    """UNC-путь, сервер которого не домен (dns_root, NetBIOS) и не контроллер (FQDN или короткое имя)."""
    p = _clean(path)
    if not p.startswith("\\\\"):
        return False
    host = p[2:].split("\\", 1)[0].lower()
    return bool(host) and host not in _internal_hosts(idx)


def _part_enabled(gpo: AdObject, scope: str) -> bool:
    # Сценарии входа часто лежат в GPO с выключенной компьютерной частью: часть выбирается по scope записи.
    flag = _GPO_FLAG_USER_DISABLED if scope == "user" else GPO_FLAG_MACHINE_DISABLED
    return not (gpo.flags or 0) & flag


def check_gpo_external_files(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out: list[Finding] = []
    for g in idx.objects("groupPolicyContainer"):
        if g.gpcFileSysPath and is_external(g.gpcFileSysPath, idx):
            # Папку GPO читает каждый клиент домена: чужой сервер получает их аутентификацию SMB и подменяет политику.
            path = _clean(g.gpcFileSysPath)
            text = f"Папка GPO (gPCFileSysPath) на сервере вне домена и контроллеров: {path}"
            out.append(_finding(idx, cfg, "GpoExternalFiles", "High", g, text, key_extra=f"gpc_path|{path}",
                                details={"path": path, "source": "gpc_path"}, allowlist=False))
        data = idx.gpo_data(g)
        if data is None:
            continue
        seen: set[str] = set()
        sources = [(s.scope, s.command, f"сценарий {s.phase} ({s.scope})", "script") for s in data.scripts]
        sources += [(i.scope, i.path, f"{i.file}: файл «{i.name}» копируется", "gpp") for i in data.gpp if i.kind == "File"]
        for scope, raw, what, source in sources:
            path = _clean(raw)
            if path.lower() in seen or not _part_enabled(g, scope) or not is_external(path, idx):
                continue
            seen.add(path.lower())
            text = f"{what} с сервера вне домена и контроллеров: {path}"
            out.append(_finding(idx, cfg, "GpoExternalFiles", "Medium", g, text, key_extra=path, details={"path": path, "source": source}, allowlist=False))
    for u in idx.objects("user"):
        if u.scriptPath and is_external(u.scriptPath, idx):
            path = _clean(u.scriptPath)
            text = f"Сценарий входа учётной записи (scriptPath) с сервера вне домена и контроллеров: {path}"
            f = Finding(check="GpoExternalFiles", severity="Medium", target=u.dn, key_extra=path, details={"details": text, "path": path, "source": "scriptPath"})
            out.append(finalize(f, cfg, allowlist=False))
    return out


# ---- SysvolAcl -----------------------------------------------------------------

def check_sysvol_acl(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out: list[Finding] = []
    for g in idx.objects("groupPolicyContainer"):
        data = idx.gpo_data(g)
        if data is None or data.acl is None:
            continue
        for record in data.acl:
            where = f"файл {record.path}" if record.path else "папку GPO"
            for sid in record.writers:
                kind = tier0_kind(idx, cfg, sid)
                if kind == "safe":
                    continue
                who = "широкая группа" if kind == "broad" else "субъект вне администраторов домена"
                text = f"SYSVOL: {who} может менять {where}, изменения применятся везде, куда привязана GPO"
                out.append(_finding(idx, cfg, "SysvolAcl", severity_for("Critical", [kind]), g, text, identity=idx.principal_name(sid), identity_sid=sid,
                                    right="write", key_extra=record.path, details={"path": record.path, "kind": kind}))
    return out
