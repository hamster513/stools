"""Словари очистки из базы STools (спека §4): домены и хосты из AD, Активов и KSC, подсети Активов и
настроек, учётки AD — только по галочке задания. Собираются один раз на задание и уходят в движок
параметром: движок к базе не обращается."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.ad.core.export import load_export_path
from api.modules.ad.models import AdDomain
from api.modules.ad.services.snapshots import latest_snapshot as latest_ad_snapshot
from api.modules.ad.services.snapshots import snapshot_path as ad_snapshot_path
from api.modules.assets.models import Asset, Network
from api.modules.ksc.models import KscHost, KscServer
from api.modules.ksc.services.snapshots import latest_snapshot as latest_ksc_snapshot
from api.modules.toolbox.core.scrub.rules import AUTO, candidate
from api.modules.toolbox.core.scrub.types import Ctx
from api.modules.toolbox.models import ToolboxSettings

#: Имя хоста короче — слишком много ложных совпадений в обычном тексте.
MIN_HOST = 3


class RulesError(ValueError):
    """Подсети настроек заданы неверно."""


def parse_subnets(pairs: Iterable[Mapping[str, str]]) -> list[tuple[IPv4Network, IPv4Network]]:
    """Пары «что → во что» из настроек; сети одной длины, иначе адреса одной сети разъехались бы."""
    out = []
    for pair in pairs:
        try:
            old, new = IPv4Network(pair["cidr"], strict=False), IPv4Network(pair["to"], strict=False)
        except (KeyError, ValueError) as exc:
            raise RulesError(f"подсеть {pair.get('cidr', '')!s} → {pair.get('to', '')!s}: не сеть IPv4") from exc
        if old.prefixlen != new.prefixlen:
            raise RulesError(f"подсеть {old} → {new}: длина маски должна совпадать")
        out.append((old, new))
    return out


def _shifted(net: IPv4Network, hmac_key: bytes, empty: Ctx) -> IPv4Network | None:
    """Сеть Активов целиком — одним сдвигом по ключу внутри своей частной зоны. Сеть шире, чем зона
    позволяет сдвинуть, или публичная — None: её адреса меняет обычная автозамена по одному."""
    if not any(net.subnet_of(zone) and net.prefixlen > keep for zone, keep in AUTO):
        return None
    alias = candidate("ip4", str(net.network_address), hmac_key, lambda _: False, empty)
    new = IPv4Network(f"{IPv4Address(alias)}/{net.prefixlen}", strict=False)
    # Сдвиг мог прийтись на биты внутри сети: такая «замена» ничего не прятала бы.
    return None if new == net else new


def build_ctx(db: Session, settings: ToolboxSettings, *, users_from_ad: bool, data_dir: Path,
              extra_words: dict[str, str] | None = None) -> Ctx:
    domains: set[str] = set()
    hosts: set[str] = set()
    users: set[str] = set()
    for ad in db.scalars(select(AdDomain)):
        domains.update((ad.dns_root, ad.netbios))
        if users_from_ad:
            snap = latest_ad_snapshot(db, ad.id)
            path = ad_snapshot_path(data_dir, snap.id) if snap is not None else None
            if path is not None and path.is_file():
                export = load_export_path(path)
                users.update(o.sam for o in export.objects if o.cls == "user" and o.sam)
    for name_key, fqdn, domain in db.execute(
        select(Asset.name_key, Asset.fqdn, Asset.domain).where(Asset.merged_into.is_(None))
    ):
        hosts.update((name_key, fqdn))
        domains.add(domain)
    for server_id in db.scalars(select(KscServer.id)):
        ksc = latest_ksc_snapshot(db, server_id)
        if ksc is None:
            continue
        for name, fqdn, domain in db.execute(
            select(KscHost.name, KscHost.fqdn, KscHost.domain).where(KscHost.snapshot_id == ksc.id)
        ):
            hosts.update((name, fqdn))
            domains.add(domain)

    empty = Ctx(domains=frozenset(), hosts=frozenset(), users=frozenset(), words={}, subnets=[])
    # Подсети настроек — первыми: при равной длине явная пара важнее сдвига сети Активов.
    subnets = parse_subnets(settings.subnets or [])
    for cidr in db.scalars(select(Network.cidr)):
        try:
            net = IPv4Network(cidr, strict=False)
        except ValueError:
            continue  # IPv6 и прочее — не про таблицу подсетей IPv4
        new = _shifted(net, settings.key, empty)
        if new is not None:
            subnets.append((net, new))
    subnets.sort(key=lambda pair: pair[0].prefixlen, reverse=True)

    words = {w["word"]: w.get("alias", "") for w in settings.words or [] if w.get("word")}
    words.update(extra_words or {})
    return Ctx(
        domains=frozenset(d.lower() for d in domains if d),
        hosts=frozenset(h.lower() for h in hosts if len(h) >= MIN_HOST),
        users=frozenset(u.lower() for u in users),
        words=words,
        subnets=subnets,
    )
