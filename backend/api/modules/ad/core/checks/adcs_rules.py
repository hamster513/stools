"""AD CS: кто заявитель — безопасный, широкая группа или прочий; серьёзность.

Правило перевёрнуто относительно остальных проверок: безопасны только
заведомые администраторы (adcs_safe_*), любой другой субъект — под вопросом.
Широкие группы (low_priv_*) дают базовую серьёзность ESC, прочие — на ступень
ниже: состав такой группы надо смотреть руками.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Literal

from api.modules.ad.core import sd
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import AdObject, ExportIndex
from api.modules.ad.core.findings import SEVERITIES, short_name
from api.modules.ad.core.sd import Ace, SecurityDescriptor

Kind = Literal["safe", "broad", "other"]
#: (sid, kind, права): права — имена из sd.RIGHT_NAMES и «owner» для владельца.
Writer = tuple[str, Kind, list[str]]

WRITE_RIGHTS = sd.GENERIC_ALL | sd.GENERIC_WRITE | sd.WRITE_DACL | sd.WRITE_OWNER | sd.WRITE_PROPERTY
#: Контейнеры PKI: право создавать потомков — подложный корневой ЦС, ЦС предприятия или шаблон.
CONTAINER_WRITE_RIGHTS = WRITE_RIGHTS | sd.CREATE_CHILD
OWNER = "owner"
#: Конкретные права, в которые разворачиваются общие (сопоставление AD):
#: GenericAll — полный доступ, GenericWrite — ReadControl, WriteProperty и Self.
FULL_CONTROL = 0xF01FF
GENERIC_WRITE_MAPPED = sd.READ_CONTROL | sd.WRITE_PROPERTY | sd.SELF_WRITE

#: Сверх low_priv_*: Pre-Windows 2000 Compatible Access, Guests и Domain Guests
#: (RID любого домена) — для выпуска сертификатов это тоже «все».
ADCS_BROAD_SIDS = ("S-1-5-32-554", "S-1-5-32-546")
ADCS_BROAD_RIDS = (514,)

CHECK_MEMBERS_NOTE = "проверьте состав группы"


def _forest_rid(sid: str) -> int | None:
    """RID доменного SID любого домена (S-1-5-21-…); у прочих — None."""
    if not sid.startswith("S-1-5-21-"):
        return None
    try:
        return int(sid.rsplit("-", 1)[1])
    except ValueError:
        return None


def _name_in(name: str, names: list[str]) -> bool:
    wanted = {n.upper().strip() for n in names}
    return name.upper().strip() in wanted or short_name(name) in wanted


def _broad(cfg: AdConfig, sid: str | None, name: str) -> bool:
    """low_priv_sids и ADCS_BROAD_SIDS, low_priv_rids и ADCS_BROAD_RIDS любого домена, low_priv_groups по имени."""
    rid = _forest_rid(sid) if sid else None
    return (
        sid in cfg.low_priv_sids
        or sid in ADCS_BROAD_SIDS
        or (rid is not None and (rid in cfg.low_priv_rids or rid in ADCS_BROAD_RIDS))
        or _name_in(name, cfg.low_priv_groups)
    )


def _fsp_sid(dn: str) -> str | None:
    """SID из DN вида CN=S-1-5-11,CN=ForeignSecurityPrincipals,… — самих FSP в выгрузке нет."""
    first, _, rest = dn.partition(",")
    value = first.partition("=")[2]
    return value if rest.upper().startswith("CN=FOREIGNSECURITYPRINCIPALS,") and value.upper().startswith("S-") else None


def _nested_broad(idx: ExportIndex, cfg: AdConfig, group: AdObject) -> bool:
    """Среди прямых или вложенных членов своей группы есть широкая группа."""
    seen: set[str] = set()
    stack = [group]
    while stack:
        g = stack.pop()
        if g.dn.lower() in seen:
            continue
        seen.add(g.dn.lower())
        for dn in g.member:
            sid = _fsp_sid(dn)
            m = None if sid else idx.get(dn)
            if m is not None:
                sid = m.sid
            name = idx.principal_name(sid) if sid else (m.label if m else "")
            if _broad(cfg, sid, name):
                return True
            if m is not None and m.cls == "group":
                stack.append(m)
    return False


def requester_kind(idx: ExportIndex, cfg: AdConfig, sid: str) -> Kind:
    """safe — из adcs_safe_* (RID — для любого домена S-1-5-21-…, имя или SID из
    adcs_safe_principals); broad — широкая группа сама или среди вложенных членов
    своей группы; иначе other."""
    rid = _forest_rid(sid)
    name = idx.principal_name(sid)
    if (
        sid in cfg.adcs_safe_sids
        or (rid is not None and rid in cfg.adcs_safe_rids)
        or _name_in(name, cfg.adcs_safe_principals)
        or sid.upper() in {p.upper().strip() for p in cfg.adcs_safe_principals}
    ):
        return "safe"
    if _broad(cfg, sid, name):
        return "broad"
    obj = idx.by_sid.get(sid)
    if obj is not None and obj.cls == "group" and _nested_broad(idx, cfg, obj):
        return "broad"
    return "other"


def specific_rights(mask: int) -> int:
    """Маска с общими правами, развёрнутыми в конкретные."""
    if mask & sd.GENERIC_ALL:
        mask |= FULL_CONTROL
    if mask & sd.GENERIC_WRITE:
        mask |= GENERIC_WRITE_MAPPED
    return mask


def denials(desc: SecurityDescriptor, denied: Callable[[Ace], int]) -> Callable[[Ace], int]:
    """По запрещающим ACE — функция «что запрещено субъекту разрешающего ACE».

    denied(ace) — запрещаемые проверке биты. Inherit-only запреты не действуют на сам
    объект. Канонический порядок DACL: явные запреты, явные разрешения, унаследованные
    запреты, унаследованные разрешения — унаследованный запрет не отменяет явного разрешения.
    """
    explicit: dict[str, int] = {}
    every: dict[str, int] = {}
    for ace in desc.dacl:
        if ace.allow or ace.inherit_only:
            continue
        bits = denied(ace)
        every[ace.sid] = every.get(ace.sid, 0) | bits
        if not ace.inherited:
            explicit[ace.sid] = explicit.get(ace.sid, 0) | bits
    return lambda allow: (every if allow.inherited else explicit).get(allow.sid, 0)


def step_down(severity: str) -> str:
    """Critical→High→Medium→Low→Low; Info остаётся Info."""
    if severity not in SEVERITIES or severity in ("Low", "Info"):
        return severity
    return SEVERITIES[SEVERITIES.index(severity) + 1]


def severity_for(base: str, kinds: Iterable[Kind]) -> str:
    """base, если среди заявителей есть broad; иначе на ступень ниже."""
    return base if "broad" in kinds else step_down(base)


def _ca_server_sid(idx: ExportIndex, obj: AdObject) -> str | None:
    """SID учётной записи компьютера самого сервера ЦС (<хост>$ из dNSHostName), только своего домена."""
    host, _, suffix = (obj.dNSHostName or "").partition(".")
    dns_root = idx.export.domain.dns_root
    if not host or (suffix and dns_root and suffix.lower() != dns_root.lower()):
        return None
    sam = f"{host}$".lower()
    return next((c.sid for c in idx.objects("computer") if (c.sam or "").lower() == sam and c.sid), None)


def unsafe_writers(idx: ExportIndex, cfg: AdConfig, obj: AdObject, desc: SecurityDescriptor) -> list[Writer]:
    """Небезопасные субъекты с правом менять объект: разрешающие ACE с WRITE_RIGHTS
    (у контейнеров PKI и CreateChild) и владелец — он неявно имеет WriteDacl."""
    dangerous = CONTAINER_WRITE_RIGHTS if obj.cls == "pkiContainer" else WRITE_RIGHTS
    concrete = specific_rights(dangerous) & ~(sd.GENERIC_ALL | sd.GENERIC_WRITE) & dangerous
    # Сервер ЦС управляет своим объектом pKIEnrollmentService.
    own = _ca_server_sid(idx, obj) if obj.cls == "pKIEnrollmentService" else None
    # Запрет на отдельный атрибут (ACE с object_type) общее право записи не отменяет.
    denied = denials(desc, lambda a: 0 if a.object_type else specific_rights(a.mask))
    rights: dict[str, set[str]] = {}
    for ace in desc.dacl:
        # inherit-only ACE действует только на потомков, не на сам объект.
        if not ace.allow or ace.inherit_only or not (ace.mask & dangerous):
            continue
        full = specific_rights(ace.mask) & concrete
        granted = full & ~denied(ace)
        if not granted:
            continue
        # Без запретов права показываются как в ACE (GenericAll), с запретами — что осталось.
        rights.setdefault(ace.sid, set()).update(sd.describe_rights(ace.mask & dangerous if granted == full else granted))
    if desc.owner:
        rights.setdefault(desc.owner, set()).add(OWNER)
    order = [name for _, name in sd.RIGHT_NAMES] + [OWNER]
    out: list[Writer] = []
    for sid, names in rights.items():
        if sid == own:
            continue
        kind = requester_kind(idx, cfg, sid)
        if kind != "safe":
            out.append((sid, kind, sorted(names, key=order.index)))
    return out


def _common(text: str, kinds: list[Kind], base: str) -> tuple[str, bool, str]:
    broad = "broad" in kinds
    return severity_for(base, kinds), broad, text if broad else f"{text}; {CHECK_MEMBERS_NOTE}"


def requesters_details(idx: ExportIndex, principals: list[tuple[str, Kind]], text: str, base: str) -> tuple[str, dict[str, object]]:
    """Серьёзность по худшему заявителю и общие поля деталей находки о выпуске."""
    severity, broad, text = _common(text, [k for _, k in principals], base)
    return severity, {"details": text, "requesters": sorted({idx.principal_name(s) for s, _ in principals}), "requesters_broad": broad}


def writers_details(idx: ExportIndex, writers: list[Writer], text: str, base: str) -> tuple[str, dict[str, object]]:
    """То же для права менять объект (ESC4, ESC5): у каждого субъекта — его права."""
    severity, broad, text = _common(text, [k for _, k, _ in writers], base)
    principals = sorted(({"name": idx.principal_name(s), "sid": s, "kind": k, "rights": r} for s, k, r in writers), key=lambda p: (str(p["name"]), str(p["sid"])))
    return severity, {"details": text, "principals": principals, "principals_broad": broad}
