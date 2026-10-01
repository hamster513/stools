"""Расхождения между источниками (спека §2). Считаются на лету при чтении: находок и
вердиктов у них нет, это фильтры списка и подсветка карточки.

Сравниваются имя, FQDN и IP: ОС и домен источники пишут каждый по-своему
(«Windows Server 2022» и «Microsoft Windows Server 2022 Standard», `CORP` и
`corp.local`), их расхождение — шум, а не устаревшие данные.
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from api.modules.assets.core.matching import Observed, normalize_fqdn, normalize_ip, normalize_name

#: no_network — адрес актива не входит ни в одну описанную сеть; считается по реестру сетей,
#: а не по наблюдениям, поэтому его добавляет services.assets, а не `discrepancies`.
CODES = ("stale", "conflict", "no_av", "ad_inactive", "unreachable", "unknown_host", "dns_orphan", "no_network")
COMPARED = ("name", "fqdn", "ip")
FIELD_TITLES = {"name": "имя", "fqdn": "FQDN", "ip": "IP"}
#: «в VM IP …», «данные VM устарели»
WHERE = {"vm": "в VM", "ksc": "в KSC", "ad": "в AD", "scan": "в скане", "dns": "в DNS"}
WHOSE = {"vm": "VM", "ksc": "KSC", "ad": "AD", "scan": "скана", "dns": "DNS"}
TITLES = {"vm": "VM", "ksc": "KSC", "ad": "AD", "scan": "скан", "dns": "DNS"}

_EPOCH = dt.datetime.min.replace(tzinfo=dt.UTC)


@dataclass(slots=True)
class Discrepancy:
    code: str
    source: str
    field: str
    value: str
    current: str
    text: str


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
    scanned_networks: Callable[[str], bool],
    scan_alive: Callable[[str], bool | None],
    now: dt.datetime,
) -> list[Discrepancy]:
    """`asset` — каноническая карточка (`canonical`), `scanned_networks(ip)` — адрес в сети,
    которую сканируют, `scan_alive(ip)` — ответил ли он последнему скану (None — не знаем)."""
    live = [o for o in observations if o.gone_at is None]
    if not live:
        return []
    out = _field_discrepancies(asset, live, stale_days)
    sources = {o.source for o in live}
    ip = str(asset.get("ip") or "")

    limit = now - dt.timedelta(days=inactive_days)
    # Выключенный компьютер AD не «неактивный» и не «без агента»: он выключен.
    ad = [o for o in live if o.source == "ad" and o.extra.get("enabled")]
    ad_active = any((d := _iso(o.extra.get("last_logon"))) and d >= limit for o in ad)
    if "ksc" not in sources and (sources & {"scan", "dns", "vm"} or ad_active):
        out.append(Discrepancy("no_av", "", "", "", "", "нет агента антивируса"))

    if ad:
        logons = [d for d in (_iso(o.extra.get("last_logon")) for o in ad) if d]
        others = [o for o in live if o.source != "ad" and o.seen_at and o.seen_at >= limit]
        if not others and not any(d >= limit for d in logons):
            last = max(logons, default=None)
            text = f"неактивный компьютер AD: последний вход {_day(last)}" if last else "неактивный компьютер AD: входов не было"
            out.append(Discrepancy("ad_inactive", "ad", "", last.isoformat() if last else "", "", text))

    zone_dns = [o for o in live if o.source == "dns" and o.extra.get("record_type") != "PTR"]
    if sources == {"dns"} and len(zone_dns) == len(live):
        # Только запись зоны: «не отвечает» здесь и есть «запись без живого хоста».
        for o in zone_dns:
            if o.ip and scanned_networks(o.ip) and scan_alive(o.ip) is False:
                out.append(Discrepancy("dns_orphan", "dns", "ip", o.ip, ip, "запись DNS без живого хоста"))
                break
    else:
        checked: set[str] = set()
        for o in live:
            if o.source not in ("ksc", "vm", "dns") or not o.ip or o.ip in checked:
                continue
            checked.add(o.ip)
            if scanned_networks(o.ip) and scan_alive(o.ip) is False:
                out.append(Discrepancy("unreachable", o.source, "ip", o.ip, ip, f"не отвечает по известному адресу {o.ip}"))

    ptr_only = all(o.extra.get("record_type") == "PTR" for o in live if o.source == "dns")
    if "scan" in sources and sources <= {"scan", "dns"} and ptr_only:
        out.append(Discrepancy("unknown_host", "scan", "", ip, "", "найдено сканером, нигде не описано"))
    return out
