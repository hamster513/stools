"""Зоны DNS, интегрированные в AD: небезопасные динамические обновления и создание записей кем угодно."""
from __future__ import annotations

from api.modules.ad.core import sd
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import WELL_KNOWN_SIDS, ExportIndex
from api.modules.ad.core.findings import Finding, finalize

#: Служебные зоны: корневые подсказки и якоря DNSSEC — записей узлов в них нет.
SKIP_ZONES = ("rootdnsservers", "..trustanchors")
#: dNSProperty DSPROPERTY_ZONE_ALLOW_UPDATE: 1 — разрешены и небезопасные обновления, 2 — только безопасные.
ALLOW_UPDATE_NONSECURE = 1
AUTHENTICATED_USERS = "S-1-5-11"


def check_dns_zones(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    dns_root = (idx.export.domain.dns_root or "").lower()
    out = []
    for z in idx.objects("dnsZone"):
        name = z.name or z.rdn_value
        low = name.lower()
        if low in SKIP_ZONES:
            continue
        if z.allowUpdate == ALLOW_UPDATE_NONSECURE:
            # Подмена записей зоны домена и _msdcs уводит на себя контроллеры и службы (Kerberos, LDAP, GC).
            core = low == dns_root or low.startswith("_msdcs.")
            f = Finding(
                check="DnsZones", severity="High" if core else "Medium", target=z.dn, key_extra="insecure_update",
                details={"details": f"Зона {name}: разрешены небезопасные динамические обновления — записи меняет кто угодно без входа", "zone": name, "partition": z.partition},
            )
            out.append(finalize(f, cfg, allowlist=False))
        desc = idx.sd_of(z)
        if desc is not None and any(a.allow and a.sid == AUTHENTICATED_USERS and a.has(sd.CREATE_CHILD) and not a.inherit_only for a in desc.dacl):
            f = Finding(
                check="DnsZones", severity="Info", identity=WELL_KNOWN_SIDS[AUTHENTICATED_USERS], identity_sid=AUTHENTICATED_USERS, target=z.dn, key_extra="au_create",
                details={"details": f"Зона {name}: Authenticated Users могут создавать записи (настройка по умолчанию; позволяет занять несуществующие имена, например WPAD)", "zone": name, "partition": z.partition},
            )
            out.append(finalize(f, cfg, allowlist=False))
    return out
