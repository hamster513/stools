"""Расхождения между источниками (спека §2). Считаются на лету при чтении: это фильтры
списка и подсветка карточки. Решения людей по ним (статусы находок платформы) хранятся
по ключу `finding_key`, сами расхождения не хранятся.

Сравниваются имя, FQDN и IP: ОС и домен источники пишут каждый по-своему
(«Windows Server 2022» и «Microsoft Windows Server 2022 Standard», `CORP` и
`corp.local`), их расхождение — шум, а не устаревшие данные.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
from dataclasses import dataclass
from typing import Any

from api.modules.assets.core.matching import Observed, normalize_fqdn, normalize_ip, normalize_name

#: no_network — адрес актива не входит ни в одну описанную сеть; считается по реестру сетей,
#: а не по наблюдениям, поэтому его добавляет services.assets, а не `discrepancies`.
CODES = ("stale", "conflict", "no_av", "ad_inactive", "no_network")
#: Виды `extra.cluster` наблюдения AD, при которых актив — виртуальное имя кластера, а не хост.
VIRTUAL_CLUSTER_KINDS = ("cluster", "role")
COMPARED = ("name", "fqdn", "ip")
FIELD_TITLES = {"name": "имя", "fqdn": "FQDN", "ip": "IP"}
#: «в VM IP …», «данные VM устарели»
WHERE = {"vm": "в VM", "ksc": "в KSC", "ad": "в AD", "dns": "в DNS", "rt": "в RackTables"}
WHOSE = {"vm": "VM", "ksc": "KSC", "ad": "AD", "dns": "DNS", "rt": "RackTables"}
TITLES = {"vm": "VM", "ksc": "KSC", "ad": "AD", "dns": "DNS", "rt": "RackTables"}

_EPOCH = dt.datetime.min.replace(tzinfo=dt.UTC)


@dataclass(slots=True)
class Discrepancy:
    code: str
    source: str
    field: str
    value: str
    current: str
    text: str


#: Расхождения полей: у одного актива их несколько, ключ находки — ещё с источником и полем.
FIELD_CODES = frozenset({"stale", "conflict"})


def finding_key(asset_id: int, d: Discrepancy) -> str:
    """Ключ расхождения как находки (статусы платформы): `asset_id|code`, у расхождений полей —
    `asset_id|code|source|field`. Значений в ключе нет: смена значения — та же находка."""
    if d.code in FIELD_CODES:
        return f"{asset_id}|{d.code}|{d.source}|{d.field}"
    return f"{asset_id}|{d.code}"


def _norm(name: str, value: str) -> str:
    if name == "name":
        return normalize_name(value)[0]
    if name == "fqdn":
        return normalize_fqdn(value)
    return normalize_ip(value) or value.strip()


def _day(value: dt.datetime | None) -> str:
    return value.strftime("%d.%m") if value else "—"


def _seen(o: Observed) -> dt.datetime:
    return o.seen_at or _EPOCH


def _iso(value: Any) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


def _is_global(ip: str) -> bool | None:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return None


def _field_discrepancies(asset: dict[str, Any], live: list[Observed], stale_days: int) -> list[Discrepancy]:
    out: list[Discrepancy] = []
    threshold = dt.timedelta(days=stale_days)
    newest = max((_seen(o) for o in live), default=_EPOCH)
    for name in COMPARED:
        current = str(asset.get(name) or "")
        reference = _norm(name, current)
        if not reference:
            continue
        # Опорное наблюдение — самое свежее с каноническим значением; у закреплённого
        # вручную значения его может не быть, тогда опора — самое свежее вообще.
        ref = max((o for o in live if _norm(name, getattr(o, name)) == reference), key=_seen, default=None)
        ref_seen = _seen(ref) if ref else newest
        for o in live:
            value = getattr(o, name)
            mine = _norm(name, value)
            if not mine or mine == reference or (name == "ip" and reference in {normalize_ip(x) for x in o.ips}):
                continue
            # Публичный и частный адрес одного хоста — NAT, а не разногласие: сравниваются адреса одной области.
            if name == "ip" and _is_global(mine) != _is_global(reference):
                continue
            title = FIELD_TITLES[name]
            ref_text = f"{TITLES[ref.source]}, {_day(ref.seen_at)}" if ref else "закреплено вручную"
            if ref_seen - _seen(o) >= threshold:
                text = (f"{WHERE[o.source]} {title} {value} от {_day(o.seen_at)}, актуальный {current} ({ref_text})"
                        f" — данные {WHOSE[o.source]} устарели")
                out.append(Discrepancy("stale", o.source, name, value, current, text))
            else:
                text = f"источники расходятся: {title} {WHERE[o.source]} {value} ({_day(o.seen_at)}), актуальный {current} ({ref_text})"
                out.append(Discrepancy("conflict", o.source, name, value, current, text))
    return out


def discrepancies(
    asset: dict[str, Any],
    observations: list[Observed],
    *,
    stale_days: int,
    inactive_days: int,
    now: dt.datetime,
) -> list[Discrepancy]:
    """`asset` — каноническая карточка (`canonical`)."""
    live = [o for o in observations if o.gone_at is None]
    if not live:
        return []
    out = _field_discrepancies(asset, live, stale_days)
    sources = {o.source for o in live}

    limit = now - dt.timedelta(days=inactive_days)
    # Учётка кластера и его роль — виртуальные имена, не хосты: у них нет агента, входов и своего адреса.
    virtual = any(o.source == "ad" and o.extra.get("cluster") in VIRTUAL_CLUSTER_KINDS for o in live)
    # Выключенный компьютер AD не «неактивный» и не «без агента»: он выключен.
    ad = [o for o in live if o.source == "ad" and o.extra.get("enabled")]
    ad_active = any((d := _iso(o.extra.get("last_logon"))) and d >= limit for o in ad)
    if "ksc" not in sources and not virtual and (sources & {"dns", "vm"} or ad_active):
        out.append(Discrepancy("no_av", "", "", "", "", "нет агента антивируса"))

    if ad and not virtual:
        logons = [d for d in (_iso(o.extra.get("last_logon")) for o in ad) if d]
        others = [o for o in live if o.source != "ad" and o.seen_at and o.seen_at >= limit]
        if not others and not any(d >= limit for d in logons):
            last = max(logons, default=None)
            text = f"неактивный компьютер AD: последний вход {_day(last)}" if last else "неактивный компьютер AD: входов не было"
            out.append(Discrepancy("ad_inactive", "ad", "", last.isoformat() if last else "", "", text))
    return out
