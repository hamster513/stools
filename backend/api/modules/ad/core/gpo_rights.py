"""Права через GPO: кто становится членом каких локальных групп на каких компьютерах.

Источники — Restricted Groups ([Group Membership] в GptTmpl.inf) и GPP Groups.xml
компьютерной части. Хосты ссылки — компьютеры в контейнере и ниже с учётом
блокировки наследования OU (gPOptions & 1) и принудительных ссылок; компьютеры
сайта не определяются. Индекс «контейнер → хосты» строится один раз на выгрузку,
список хостов GPO — один раз на GPO и общий для её записей.
"""
from __future__ import annotations

import re
from typing import Any

from api.modules.ad.core.checks.gpo import SID_RE
from api.modules.ad.core.export import GPO_FLAG_MACHINE_DISABLED, AdObject, ExportIndex
from api.modules.ad.core.gpo_files import inf_group_membership

#: Встроенные локальные группы S-1-5-32-<RID> (в WELL_KNOWN_SIDS есть не все).
BUILTIN_LOCAL_GROUPS: dict[int, str] = {
    544: "Administrators",
    545: "Users",
    546: "Guests",
    547: "Power Users",
    548: "Account Operators",
    549: "Server Operators",
    550: "Print Operators",
    551: "Backup Operators",
    552: "Replicator",
    555: "Remote Desktop Users",
    556: "Network Configuration Operators",
    558: "Performance Monitor Users",
    559: "Performance Log Users",
    562: "Distributed COM Users",
    568: "IIS_IUSRS",
    569: "Cryptographic Operators",
    573: "Event Log Readers",
    578: "Hyper-V Administrators",
    579: "Access Control Assistance Operators",
    580: "Remote Management Users",
}
_BUILTIN_BY_NAME = {name.lower(): rid for rid, name in BUILTIN_LOCAL_GROUPS.items()}
_BUILTIN = "S-1-5-32-"
_BUILTIN_SUFFIX = " (built-in)"
_BLOCK_INHERITANCE = 1
_SUBJECT_CLASSES = ("group", "user", "computer")
#: RDN в DN: экранированные запятые (\,) не делят.
_RDN = re.compile(r"(?:[^,\\]|\\.)+")


def host_id(obj: AdObject) -> str:
    """dNSHostName, без него — sAMAccountName без «$», затем имя."""
    return obj.dNSHostName or (obj.sam or "").removesuffix("$") or obj.name or obj.rdn_value


def _container_hosts(idx: ExportIndex) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Контейнер со ссылкой (DN в нижнем регистре) → хосты в нём и ниже: все и без заблокированных
    наследованием OU между контейнером и компьютером. Один проход по компьютерам на выгрузку."""
    cached: tuple[dict[str, list[str]], dict[str, list[str]]] | None = idx.cache.get("gpo_rights_hosts")
    if cached is not None:
        return cached
    linked = {link.container_dn.lower() for links in (idx.gpo_link_map or {}).values() for link in links if not link.disabled}
    blocking = {o.dn.lower() for o in idx.objects("organizationalUnit") if (o.gpOptions or 0) & _BLOCK_INHERITANCE}
    every: dict[str, list[str]] = {}
    open_: dict[str, list[str]] = {}
    for c in idx.objects("computer"):
        dn = c.dn.lower()
        hid = host_id(c)
        blocked = False
        for m in _RDN.finditer(dn):  # от самого компьютера вверх
            ancestor = dn[m.start():]
            if ancestor in linked:
                every.setdefault(ancestor, []).append(hid)
                if not blocked:
                    open_.setdefault(ancestor, []).append(hid)
            if ancestor in blocking:
                blocked = True
    idx.cache["gpo_rights_hosts"] = (every, open_)
    return every, open_


def scope_hosts(idx: ExportIndex, gpo: AdObject) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """(scope, отсортированные id хостов, notes) по включённым ссылкам GPO; привязка неизвестна — пусто."""
    links = idx.gpo_links(gpo)
    if not links:
        return [], [], []
    every, open_ = _container_hosts(idx)
    scope: list[dict[str, Any]] = []
    hosts: set[str] = set()
    notes: list[str] = []
    for link in links:
        scope.append({"dn": link.container_dn, "enforced": link.enforced})
        container = idx.get(link.container_dn)
        if container is not None and container.cls == "site":
            notes.append(f"привязка к сайту {link.container_dn}: компьютеры сайта не определяются")
            continue
        hosts.update((every if link.enforced else open_).get(link.container_dn.lower(), ()))
    return scope, sorted(hosts, key=lambda h: (h.lower(), h)), notes


class _Resolver:
    def __init__(self, idx: ExportIndex) -> None:
        self.idx = idx
        self.netbios = (idx.export.domain.netbios or "").lower()
        self.by_sam: dict[str, AdObject] = {}
        for cls in _SUBJECT_CLASSES:
            for o in idx.objects(cls):
                if o.sam and o.sid:
                    self.by_sam.setdefault(o.sam.lower(), o)

    def own(self, name: str) -> AdObject | None:
        """Учётка или группа своего домена по `DOMAIN\\sam` (NetBIOS своего домена) или `sam`."""
        domain, sep, sam = name.rpartition("\\")
        if sep and domain.lower() != self.netbios:
            return None
        return self.by_sam.get(sam.strip().lower())

    def subject(self, sid: str, name: str = "") -> tuple[str, str, str]:
        """(SID, имя, класс) участника; без SID — по имени в своём домене, не найден — имя как записано."""
        if not sid and SID_RE.match(name):
            sid = name
        if sid:
            resolved = self.idx.principal_name(sid)
            obj = self.idx.by_sid.get(sid)
            cls = obj.cls if obj is not None and obj.cls in _SUBJECT_CLASSES else ""
            return sid, (name if resolved == sid and name else resolved), cls
        obj = self.own(name)
        if obj is not None and obj.sid:
            return obj.sid, self.idx.principal_name(obj.sid), obj.cls
        return "", name, ""

    def target(self, sid: str, name: str = "") -> tuple[str, str, str | None]:
        """(имя локальной группы, её SID, имя доменной группы) — третье не None, если цель доменная."""
        if not sid and SID_RE.match(name):
            sid = name
        if sid.startswith(_BUILTIN):
            try:
                rid = int(sid.removeprefix(_BUILTIN))
            except ValueError:
                return sid, "", None
            return BUILTIN_LOCAL_GROUPS.get(rid, f"RID-{rid}"), sid, None
        if sid.startswith(self.idx.domain_sid + "-"):
            return "", "", self.idx.principal_name(sid)
        written = name.strip()
        if written.lower().endswith(_BUILTIN_SUFFIX):
            written = written[: -len(_BUILTIN_SUFFIX)].strip()
        if not written:
            return sid, "", None
        short = written[len("BUILTIN\\"):] if written.lower().startswith("builtin\\") else written
        builtin = _BUILTIN_BY_NAME.get(short.lower())
        if builtin is not None:
            return BUILTIN_LOCAL_GROUPS[builtin], f"{_BUILTIN}{builtin}", None
        obj = self.own(written)
        if obj is not None and obj.cls == "group" and obj.sid and not obj.sid.startswith(_BUILTIN):
            return "", "", self.idx.principal_name(obj.sid)
        return written, "", None


def _assignments(idx: ExportIndex, res: _Resolver, g: AdObject, label: str) -> tuple[list[dict[str, Any]], list[str], int, bool]:
    """Записи GPO без scope и хостов, её общие notes, число Group-элементов GPP в user-части и есть ли назначения групп."""
    rows: list[dict[str, Any]] = []
    notes: list[str] = []
    user_items = 0
    has = False

    def target(sid: str, name: str = "") -> tuple[str, str] | None:
        local, local_sid, domain_group = res.target(sid, name)
        if domain_group is not None:
            notes.append(f"GPO «{label}»: цель {domain_group} — доменная группа, не локальная")
            return None
        return local, local_sid

    def row(subject: tuple[str, str, str], local: tuple[str, str], via: str, action: str, filtered: bool | None) -> None:
        rows.append({"group_sid": subject[0], "group_name": subject[1], "subject_class": subject[2],
                     "local_group": local[0], "local_group_sid": local[1], "via": via,
                     "gpo": {"name": label, "dn": g.dn}, "action": action, "filtered": filtered})

    for group, kind, entries in inf_group_membership(idx.inf_sections(g)):
        has = True
        if kind == "members":
            local = target("", group)
            if local is None:
                continue
            if not entries:
                notes.append(f"GPO «{label}»: Restricted Groups очищает группу {local[0]}")
            for entry in entries:
                row(res.subject("", entry), local, "restricted_groups", "member", False)
        else:  # «X__Memberof = цели»: субъект X входит в каждую цель
            subject = res.subject("", group)
            for entry in entries:
                if (local := target("", entry)) is not None:
                    row(subject, local, "restricted_groups", "memberof", False)

    data = idx.gpo_data(g)
    for item in data.gpp if data else []:
        if item.kind != "Group" or item.action.upper() == "D":
            continue
        if item.scope == "user":
            user_items += 1
            continue
        if item.scope != "machine":
            continue
        has = True
        local = target(item.group_sid, item.group_name or item.name)
        if local is None:
            continue
        if item.delete_all is True and not item.members:
            notes.append(f"GPO «{label}»: GPP очищает группу {local[0]}")
        for m in item.members:
            action = {"ADD": "replace" if item.delete_all is True else "add", "REMOVE": "delete"}.get(m.action.upper())
            if action is not None:
                row(res.subject(m.sid, m.name), local, "gpp", action, item.filtered)
    return rows, notes, user_items, has


def gpo_rights(idx: ExportIndex) -> dict[str, Any]:
    """Ответ по контракту `gpo_rights`. Списки hosts общие для записей одной GPO — не изменять."""
    links_known = idx.gpo_link_map is not None
    res = _Resolver(idx)
    rights: list[dict[str, Any]] = []
    notes: list[str] = []
    user_items = 0
    unlinked = 0
    gpos = [g for g in idx.objects("groupPolicyContainer") if not (g.flags or 0) & GPO_FLAG_MACHINE_DISABLED]
    for g in sorted(gpos, key=lambda o: ((o.displayName or o.label).lower(), o.dn.lower())):
        label = g.displayName or g.label
        rows, gpo_notes, users, has = _assignments(idx, res, g, label)
        if links_known and not idx.gpo_links(g):
            unlinked += has
            continue
        notes += gpo_notes
        user_items += users
        if not rows:
            continue
        scope, hosts, row_notes = scope_hosts(idx, g)
        for r in rows:
            rights.append({**r, "scope": scope, "hosts": hosts, "hosts_total": len(hosts), "notes": list(row_notes)})
    if user_items:
        notes.append(f"GPP: элементов групп в пользовательской части — {user_items}, не учтены (применяются на компьютерах входа пользователя)")
    if unlinked:
        notes.append(f"GPO с назначениями групп без включённых ссылок не учтены: {unlinked}")
    rights.sort(key=lambda r: (r["gpo"]["name"].lower(), r["local_group"].lower(), r["group_name"].lower(),
                               r["gpo"]["dn"].lower(), r["via"], r["action"], r["group_sid"]))
    return {
        "links_known": links_known,
        "files_known": bool(idx.export.sysvol) or idx.export.gpo is not None,
        "notes": list(dict.fromkeys(notes)),
        "rights": rights,
    }
