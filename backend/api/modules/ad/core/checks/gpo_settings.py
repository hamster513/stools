"""Проверки GPO по файлам SYSVOL (спека §3.2): пароли в настройках, параметры
безопасности, права входа на контроллеры, запрет входа админов, Restricted Groups.

GPO с выключенной компьютерной частью (flags & 2) не проверяется, кроме
GppPasswords: файл с паролем читается из SYSVOL, применяется GPO или нет. Привязка
неизвестна (выгрузка без gPLink) — GPO считается применимой, это пишется в описании.
"""
from __future__ import annotations

from api.modules.ad.core.checks.gpo import SID_RE, parse_privilege_rights
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import GPO_FLAG_MACHINE_DISABLED, AdObject, ExportIndex
from api.modules.ad.core.findings import Finding, finalize, is_low_priv, short_name
from api.modules.ad.core.gpo_files import REG_DWORD, inf_group_membership, inf_registry_values

LINKS_UNKNOWN = "привязка GPO неизвестна (сборщик старой версии)"
_MACHINE = "machine\\"
_WINLOGON = "software\\microsoft\\windows nt\\currentversion\\winlogon"
_LSA = "system\\currentcontrolset\\control\\lsa\\"
NTLM_LEVEL = _LSA + "lmcompatibilitylevel"
ADMINISTRATORS = "S-1-5-32-544"


def _gpos(idx: ExportIndex) -> list[AdObject]:
    """GPO с включённой компьютерной частью."""
    return [g for g in idx.objects("groupPolicyContainer") if not (g.flags or 0) & GPO_FLAG_MACHINE_DISABLED]


def _has_gpo_files(idx: ExportIndex) -> bool:
    return bool(idx.export.sysvol) or idx.export.gpo is not None


def _reg_key(key: str) -> str:
    return key.strip("\\").lower().removeprefix(_MACHINE)


def _registry(idx: ExportIndex, gpo: AdObject) -> dict[str, int]:
    """Числовые значения реестра GPO: путь\\имя (нижний регистр, без MACHINE\\) → значение; GptTmpl.inf важнее Registry.pol."""
    cache: dict[str, dict[str, int]] = idx.cache.setdefault("gpo_registry", {})
    if gpo.dn.lower() not in cache:
        out: dict[str, int] = {}
        data = idx.gpo_data(gpo)
        for r in data.registry if data else []:
            if r.scope == "machine" and isinstance(r.data, int):
                out[_reg_key(r.key.strip("\\") + "\\" + r.value)] = r.data
        for key, (type_, value) in inf_registry_values(idx.inf_sections(gpo)).items():
            if type_ == REG_DWORD:
                try:
                    out[_reg_key(key)] = int(value)
                except ValueError:
                    pass
        cache[gpo.dn.lower()] = out
    return cache[gpo.dn.lower()]


def gpo_setting(idx: ExportIndex, gpo: AdObject, key: str) -> int | None:
    """Значение ключа реестра «путь\\имя» из [Registry Values] либо из Registry.pol; без учёта регистра и префикса MACHINE\\."""
    return _registry(idx, gpo).get(_reg_key(key))


def linked_text(idx: ExportIndex, gpo: AdObject) -> str:
    links = idx.gpo_links(gpo)
    if links is None:
        return LINKS_UNKNOWN
    if not links:
        return "не привязана"
    return "применяется к: " + ", ".join(link.container_dn for link in links)


def _finding(
    idx: ExportIndex, cfg: AdConfig, check: str, severity: str, gpo: AdObject, text: str, *,
    identity: str = "", identity_sid: str = "", right: str = "", key_extra: str = "", details: dict[str, object] | None = None,
    allowlist: bool = True,
) -> Finding:
    f = Finding(
        check=check,
        severity=severity,
        identity=identity,
        identity_sid=identity_sid,
        target=gpo.displayName or gpo.dn,
        right=right,
        key_extra=key_extra,
        details={"details": f"{text}; {linked_text(idx, gpo)}", "gpo_dn": gpo.dn, "gpo_path": gpo.gpcFileSysPath or "", **(details or {})},
    )
    return finalize(f, cfg, allowlist=allowlist)


def _domain_finding(idx: ExportIndex, cfg: AdConfig, check: str, severity: str, text: str, key_extra: str = "") -> Finding:
    f = Finding(check=check, severity=severity, target=idx.export.domain.dn, key_extra=key_extra, details={"details": text})
    return finalize(f, cfg, allowlist=False)


def _rights(gpo_inf: str | None) -> dict[str, list[str]]:
    return {right.lower(): entries for right, entries in parse_privilege_rights(gpo_inf or "").items()}


def _subject(idx: ExportIndex, entry: str, name: str = "") -> tuple[str, str]:
    """(имя, SID) записи GPO: «S-1-…» — SID, иначе имя как записано."""
    if not SID_RE.match(entry):
        return entry, ""
    resolved = idx.principal_name(entry)
    return (name if resolved == entry and name else resolved), entry


def _broad(idx: ExportIndex, cfg: AdConfig, identity: str, sid: str) -> bool:
    return is_low_priv(identity, sid or None, cfg, idx.domain_sid)


# ---- GppPasswords --------------------------------------------------------------

def check_gpp_passwords(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out: list[Finding] = []
    # Субъект — учётка, чей пароль раскрыт, а не держатель права: allowlist не понижает.
    for g in idx.objects("groupPolicyContainer"):
        data = idx.gpo_data(g)
        if data is None:
            continue
        for item in data.gpp:
            if item.cpassword:
                text = f"{item.file}: пароль «{item.name}» в cpassword — ключ шифрования опубликован, пароль читает любой пользователь домена"
                out.append(_finding(idx, cfg, "GppPasswords", "High", g, text, identity=item.user, key_extra=f"{item.scope}|{item.file}|{item.name}",
                                    details={"file": item.file, "scope": item.scope, "kind": item.kind}, allowlist=False))
        winlogon = {r.value.lower(): r.data for r in data.registry if r.key.strip("\\").lower() == _WINLOGON}
        if "defaultpassword" in winlogon:
            user = winlogon.get("defaultusername")
            text = "Registry.pol: пароль автологона (DefaultPassword) лежит открытым текстом в SYSVOL"
            out.append(_finding(idx, cfg, "GppPasswords", "High", g, text, key_extra="autologon",
                                details={"file": "Registry.pol", "user": user if isinstance(user, str) else ""}, allowlist=False))
    return out


# ---- GpoSecurityOptions --------------------------------------------------------

#: (вид, ключ реестра, опасное значение или «<N», серьёзность, текст).
_OPTIONS: tuple[tuple[str, str, str, str, str], ...] = (
    ("ntlm_level", NTLM_LEVEL, "<3", "High", "LmCompatibilityLevel = {v}: разрешены LM и NTLMv1"),
    ("lm_hash", _LSA + "nolmhash", "0", "Medium", "NoLMHash = 0: хэш LM пароля сохраняется"),
    ("anonymous", _LSA + "everyoneincludesanonymous", "1", "Medium", "EveryoneIncludesAnonymous = 1: анонимные подключения получают права Everyone"),
    ("anonymous", _LSA + "restrictanonymous", "0", "Medium", "RestrictAnonymous = 0: анонимное перечисление учётных записей и общих папок"),
    ("blank_password", _LSA + "limitblankpassworduse", "0", "Medium", "LimitBlankPasswordUse = 0: вход по сети локальной учёткой с пустым паролем"),
    ("ldap_signing", "system\\currentcontrolset\\services\\ntds\\parameters\\ldapserverintegrity", "1", "Medium",
     "LDAPServerIntegrity = 1: контроллер не требует подписи LDAP"),
    ("refuse_pwd_change", "system\\currentcontrolset\\services\\netlogon\\parameters\\refusepasswordchange", "1", "Low",
     "RefusePasswordChange = 1: контроллер запрещает компьютерам менять пароль учётки"),
    ("recovery_console", "software\\microsoft\\windows nt\\currentversion\\setup\\recoveryconsole\\securitylevel", "1", "Medium",
     "Recovery Console SecurityLevel = 1: консоль восстановления входит без пароля администратора"),
)


def _matches(value: int, bad: str) -> bool:
    return value < int(bad[1:]) if bad.startswith("<") else value == int(bad)


def _security_issues(idx: ExportIndex, gpo: AdObject) -> dict[str, tuple[str, list[str]]]:
    """Вид → (серьёзность, тексты): у вида «anonymous» два условия, находка одна."""
    out: dict[str, tuple[str, list[str]]] = {}
    for kind, key, bad, severity, text in _OPTIONS:
        value = gpo_setting(idx, gpo, key)
        if value is not None and _matches(value, bad):
            out.setdefault(kind, (severity, []))[1].append(text.format(v=value))
    access = {k.lower(): v for k, v in idx.inf_sections(gpo).get("system access", {}).items()}
    if access.get("cleartextpassword", "").strip() == "1":
        out["cleartext_password"] = ("High", ["ClearTextPassword = 1: пароли хранятся с обратимым шифрованием"])
    return out


def check_gpo_security_options(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    if not _has_gpo_files(idx):
        return []
    out: list[Finding] = []
    ntlm_v2_only = False
    for g in _gpos(idx):
        for kind, (severity, texts) in _security_issues(idx, g).items():
            out.append(_finding(idx, cfg, "GpoSecurityOptions", severity, g, "; ".join(texts), key_extra=kind, details={"kind": kind}))
        if idx.applies_to_dcs(g) is not False and gpo_setting(idx, g, NTLM_LEVEL) == 5:
            ntlm_v2_only = True
    if not ntlm_v2_only:
        text = "Ни одна GPO, применимая к контроллерам, не задаёт LmCompatibilityLevel = 5 (только NTLMv2, LM и NTLMv1 отвергаются)"
        if idx.gpo_link_map is None:
            text += f"; {LINKS_UNKNOWN}: учтены все GPO"
        out.append(_domain_finding(idx, cfg, "GpoSecurityOptions", "Medium", text, key_extra="ntlm_level_missing"))
    return out


# ---- DcLogonRights, TieringLogonDeny -------------------------------------------

_DC_LOGON_RIGHTS = ("SeInteractiveLogonRight", "SeRemoteInteractiveLogonRight", "SeBatchLogonRight")
_DENY_RIGHTS = ("sedenyinteractivelogonright", "sedenyremoteinteractivelogonright")


def check_dc_logon_rights(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out: list[Finding] = []
    for g in _gpos(idx):
        if idx.applies_to_dcs(g) is False:
            continue
        rights = _rights(idx.gpo_inf(g))
        for right in _DC_LOGON_RIGHTS:
            for entry in rights.get(right.lower(), []):
                identity, sid = _subject(idx, entry)
                if _broad(idx, cfg, identity, sid):
                    text = f"{right}: широкая группа может входить на контроллеры домена"
                    out.append(_finding(idx, cfg, "DcLogonRights", "High", g, text, identity=identity, identity_sid=sid, right=right))
    return out


def check_tiering_logon_deny(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    if not idx.export.sysvol:  # права входа есть только в GptTmpl.inf
        return []
    da_sid = idx.domain_rid_sid(512).upper()
    da = idx.group_by_rid(512)
    names = {"DOMAIN ADMINS"} | ({short_name(n) for n in (da.sam, da.name) if n} if da else set())
    for g in _gpos(idx):
        rights = _rights(idx.gpo_inf(g))
        for right in _DENY_RIGHTS:
            if any(e.upper() == da_sid or short_name(e) in names for e in rights.get(right, [])):
                return []
    text = "Ни одна GPO не запрещает Domain Admins локальный вход и вход по RDP (SeDenyInteractiveLogonRight, SeDenyRemoteInteractiveLogonRight): учётки администраторов домена могут оставлять учётные данные на рабочих станциях и серверах"
    return [_domain_finding(idx, cfg, "TieringLogonDeny", "Low", text)]


# ---- RestrictedGroups ----------------------------------------------------------

def _group_sid(idx: ExportIndex, group: str) -> str:
    if SID_RE.match(group):
        return group
    obj = idx.group_by_name(group.rsplit("\\", 1)[-1])
    return obj.sid if obj is not None and obj.sid else ""


def check_restricted_groups(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out: list[Finding] = []

    def add(g: AdObject, source: str, group_sid: str, identity: str, sid: str) -> None:
        if not group_sid.startswith("S-1-5-32-") or not _broad(idx, cfg, identity, sid):
            return
        group_name = idx.principal_name(group_sid)
        severity = "High" if group_sid == ADMINISTRATORS else "Medium"
        where = "[Group Membership] GptTmpl.inf" if source == "inf" else "Groups.xml (GPP)"
        text = f"{where}: широкая группа добавляется в локальную группу {group_name}"
        out.append(_finding(idx, cfg, "RestrictedGroups", severity, g, text, identity=identity, identity_sid=sid, key_extra=f"{source}|{group_sid}",
                            details={"group": group_sid, "group_name": group_name, "source": source}))

    for g in _gpos(idx):
        for group, kind, entries in inf_group_membership(idx.inf_sections(g)):
            if kind == "members":
                group_sid = _group_sid(idx, group)
                for entry in entries:
                    add(g, "inf", group_sid, *_subject(idx, entry))
            else:  # «группа__Memberof = цели»: субъект — сама группа, записи — группы, куда она входит
                subject = _subject(idx, group)
                for entry in entries:
                    add(g, "inf", _group_sid(idx, entry), *subject)
        data = idx.gpo_data(g)
        for item in data.gpp if data else []:
            # Элемент «D» удаляет группу; участник «REMOVE» из группы исключается.
            if item.kind != "Group" or item.action.upper() == "D":
                continue
            for m in item.members:
                if m.action.upper() == "ADD":
                    add(g, "gpp", item.group_sid, *(_subject(idx, m.sid, m.name) if m.sid else (m.name, "")))
    return out
