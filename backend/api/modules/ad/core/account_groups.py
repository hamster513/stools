"""Группы учёток: прямые и вложенные, с первичной группой и участниками из других доменов.

Учётка — пользователь или компьютер с SID, а также участник группы вида
CN=S-1-…,CN=ForeignSecurityPrincipals,… (самих FSP в выгрузке нет). Предки
групп считаются один раз на группу и переиспользуются всеми учётками.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypedDict

from api.modules.ad.core.export import AdObject, ExportIndex, fsp_sid

#: Размеры, на которых сборщик мог упереться в предел выдачи `member` (диапазонная выборка, страница).
TRUNCATION_SIZES = (1500, 5000)


class GroupRef(TypedDict):
    sid: str
    name: str
    direct: bool
    primary: bool


@dataclass
class AccountGroups:
    #: SID учётки → группы: сначала прямые, затем вложенные, внутри — по имени.
    #: Записи GroupRef общие для всех учёток — не изменять.
    groups: dict[str, list[GroupRef]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def account_groups(idx: ExportIndex) -> AccountGroups:
    groups = {g.dn.lower(): g for g in idx.objects("group") if g.sid}
    names = {key: idx.principal_name(g.sid) for key, g in groups.items()}
    order = {key: (names[key].lower(), g.sid or "") for key, g in groups.items()}
    refs: dict[tuple[str, bool, bool], GroupRef] = {}

    def ref(key: str, direct: bool, primary: bool) -> GroupRef:
        r = refs.get((key, direct, primary))
        if r is None:
            r = refs[(key, direct, primary)] = {"sid": groups[key].sid or "", "name": names[key], "direct": direct, "primary": primary}
        return r

    # Обратный индекс: DN участника → группы, где он записан в member.
    parents: dict[str, list[str]] = {}
    foreign: dict[str, str] = {}
    for key, g in groups.items():
        for dn in g.member:
            low = dn.lower()
            parents.setdefault(low, []).append(key)
            if low not in idx.by_dn and (sid := fsp_sid(dn)) is not None:
                foreign[sid] = low

    ancestors: dict[str, set[str]] = {}

    def ancestors_of(key: str) -> set[str]:
        """Все группы, куда вложена группа key; готовые наборы предков не раскрываются заново."""
        got = ancestors.get(key)
        if got is not None:
            return got
        out: set[str] = set()
        stack = list(parents.get(key, ()))
        while stack:
            p = stack.pop()
            if p in out:
                continue
            out.add(p)
            done = ancestors.get(p)
            if done is not None:
                out |= done
            else:
                stack.extend(parents.get(p, ()))
        ancestors[key] = out
        return out

    def collect(dn_low: str, account: AdObject | None) -> list[GroupRef]:
        direct = set(parents.get(dn_low, ()))
        primary = None
        if account is not None and account.primaryGroupID is not None:
            pg = idx.by_sid.get(idx.domain_rid_sid(account.primaryGroupID))
            if pg is not None and pg.dn.lower() in groups:
                primary = pg.dn.lower()
                direct.add(primary)
        nested: set[str] = set()
        for key in direct:
            nested |= ancestors_of(key)
        nested -= direct
        return [ref(k, True, k == primary) for k in sorted(direct, key=order.__getitem__)] + [
            ref(k, False, False) for k in sorted(nested, key=order.__getitem__)
        ]

    res = AccountGroups()
    for cls in ("user", "computer"):
        for obj in idx.objects(cls):
            if obj.sid:
                res.groups[obj.sid] = collect(obj.dn.lower(), obj)
    for sid, low in foreign.items():
        res.groups.setdefault(sid, collect(low, None))
    res.notes = [
        f"у группы {names[key]} ровно {len(g.member)} участников: список мог быть обрезан при сборе"
        for key, g in sorted(groups.items(), key=lambda kv: order[kv[0]])
        if len(g.member) in TRUNCATION_SIZES
    ]
    return res
