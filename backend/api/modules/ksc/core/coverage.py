"""Сверка хостов KSC с компьютерами AD: чистые функции без базы."""
from __future__ import annotations

from dataclasses import dataclass, field

from api.modules.ad.core.export import AdExport, filetime_to_datetime
from api.modules.ksc.core.export import HostRecord


@dataclass(frozen=True)
class AdComputer:
    name: str
    fqdn: str
    domain: str
    netbios: str
    os: str = ""
    last_logon: str = ""


@dataclass
class Coverage:
    ad_total: int
    ksc_total: int
    both: set[str] = field(default_factory=set)  # host_id KSC
    ksc_only: set[str] = field(default_factory=set)
    ad_only: list[AdComputer] = field(default_factory=list)


def ad_computers_from_export(export: AdExport) -> list[AdComputer]:
    out = []
    dns_root = export.domain.dns_root.lower()
    for o in export.objects:
        if o.cls != "computer" or not o.enabled:
            continue
        name = (o.sam or o.name or "").rstrip("$")
        if not name:
            continue
        last = filetime_to_datetime(o.lastLogonTimestamp)
        out.append(AdComputer(name=name, fqdn=f"{name.lower()}.{dns_root}" if dns_root else name.lower(), domain=dns_root, netbios=export.domain.netbios.upper(), os=str(getattr(o, "operatingSystem", "") or ""), last_logon=last.strftime("%Y-%m-%d") if last else ""))
    return out


def match(hosts: list[HostRecord], computers: list[AdComputer]) -> Coverage:
    by_fqdn = {c.fqdn: c for c in computers}
    by_short = {(c.name.lower(), c.netbios): c for c in computers}
    by_short_dns = {(c.name.lower(), c.domain): c for c in computers}
    cov = Coverage(ad_total=len(computers), ksc_total=len(hosts))
    seen: set[AdComputer] = set()
    for h in hosts:
        c = by_fqdn.get(h.fqdn) or by_short.get((h.winhostname.lower(), h.windomain.upper())) or by_short_dns.get((h.winhostname.lower(), h.domain))
        if c is None:
            cov.ksc_only.add(h.host_id)
        else:
            cov.both.add(h.host_id)
            seen.add(c)
    cov.ad_only = [c for c in computers if c not in seen]
    return cov
