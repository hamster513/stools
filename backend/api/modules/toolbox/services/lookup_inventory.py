"""Inventory evidence from current Assets, AD observations and latest AV snapshots."""

from urllib.parse import urlencode

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from api.modules.ad.models import AdDomain, AdSnapshot
from api.modules.assets.models import Asset, AssetObservation
from api.modules.ksc.models import KscHost, KscServer, KscSnapshot

from .lookup_types import LIMIT, Evidence, Group, facts, identity, ip_list_contains


def assets(db: Session, q: str, kind: str) -> list[Group]:
    match = identity(
        q, kind, name=Asset.name_key, fqdn=Asset.fqdn, domain=Asset.domain, ip=Asset.ip,
        dialect=db.get_bind().dialect.name,
    )
    if kind == "ip":
        secondary = select(AssetObservation.asset_id).where(
            AssetObservation.gone_at.is_(None),
            or_(AssetObservation.ip == q, ip_list_contains(AssetObservation.ips, q, db.get_bind().dialect.name)),
        )
        match = or_(match, Asset.id.in_(secondary))
    rows = db.scalars(
        select(Asset).where(Asset.merged_into.is_(None), match).order_by(Asset.id).limit(LIMIT + 1)
    )
    return [
        Group(
            id="assets",
            title="Активы",
            note="Точные совпадения в карточках; для IP также проверены текущие наблюдения источников.",
        ).fill(
            [
                Evidence(
                    id=str(a.id),
                    title=a.fqdn or a.name or a.ip,
                    reason="Совпадение IP в карточке или наблюдении"
                    if kind == "ip"
                    else "Совпадение имени или домена"
                    if kind == "name"
                    else f"Совпадение: {q}",
                    source="Assets",
                    href=f"/assets/list?asset={a.id}",
                    observed_at=a.last_seen,
                    date_label="Последнее наблюдение",
                    facts=facts(
                        **{
                            "IP карточки": a.ip,
                            "Домен": a.domain,
                            "ОС": a.os,
                            "Критичность": a.criticality,
                        }
                    ),
                )
                for a in rows
            ]
        )
    ]


def ad(db: Session, q: str, kind: str) -> list[Group]:
    domains = Group(id="ad_domains", title="Домены AD")
    if kind not in ("ip", "host"):
        stamp = (
            select(AdSnapshot.collected_at)
            .where(AdSnapshot.domain_id == AdDomain.id)
            .order_by(AdSnapshot.collected_at.desc(), AdSnapshot.id.desc())
            .limit(1)
            .scalar_subquery()
        )
        rows = db.execute(
            select(AdDomain, stamp)
            .where(or_(func.lower(AdDomain.dns_root) == q, func.lower(AdDomain.netbios) == q))
            .order_by(AdDomain.id)
            .limit(LIMIT + 1)
        )
        domains.fill(
            [
                Evidence(
                    id=str(d.id),
                    title=d.dns_root or d.netbios,
                    reason="Совпадение DNS-имени или NetBIOS-домена",
                    source="AD",
                    href=f"/ad/domains/{d.id}",
                    observed_at=seen,
                    date_label="Снимок AD",
                    facts=facts(NetBIOS=d.netbios),
                )
                for d, seen in rows
            ]
        )
    else:
        domains.status = "not_applicable"
    observations = db.scalars(
        select(AssetObservation)
        .where(
            AssetObservation.source == "ad",
            AssetObservation.gone_at.is_(None),
            identity(
                q,
                kind,
                name=AssetObservation.name,
                fqdn=AssetObservation.fqdn,
                domain=AssetObservation.domain,
                ip=AssetObservation.ip,
                dialect=db.get_bind().dialect.name,
            ),
        )
        .order_by(AssetObservation.id)
        .limit(LIMIT + 1)
    )
    items = []
    for h in observations:
        domain_id = h.extra.get("domain_id")
        items.append(
            Evidence(
                id=str(h.id),
                title=h.fqdn or h.name,
                reason="Совпадение в наблюдении компьютера AD",
                source="AD → синхронизация Assets",
                href=f"/ad/domains/{domain_id}" if isinstance(domain_id, int) else "/ad",
                observed_at=h.seen_at,
                date_label="Снимок AD в Assets",
                facts=facts(
                    **{
                        "Домен": h.domain,
                        "ОС": h.os,
                        "Учётная запись": {"True": "Включена", "False": "Выключена"}.get(
                            str(h.extra.get("enabled"))
                        ),
                        "Последний вход": h.extra.get("last_logon"),
                    }
                ),
            )
        )
    return [
        domains,
        Group(
            id="ad_hosts",
            title="Компьютеры AD",
            note="По последней синхронизации AD → Assets; только компьютеры. IP в выгрузке AD может отсутствовать. Ссылка открывает домен.",
        ).fill(items),
    ]


def antivirus(db: Session, q: str, kind: str) -> list[Group]:
    latest = (
        select(KscSnapshot.id)
        .where(KscSnapshot.server_id == KscServer.id)
        .order_by(KscSnapshot.collected_at.desc(), KscSnapshot.id.desc())
        .limit(1)
        .correlate(KscServer)
        .scalar_subquery()
    )
    rows = db.execute(
        select(KscHost, KscServer.name, KscServer.id, KscSnapshot.collected_at)
        .select_from(KscServer)
        .join(KscSnapshot, KscSnapshot.id == latest)
        .join(KscHost, KscHost.snapshot_id == KscSnapshot.id)
        .where(
            identity(
                q, kind, name=KscHost.name, fqdn=KscHost.fqdn, domain=KscHost.domain, ip=KscHost.ip,
                dialect=db.get_bind().dialect.name,
            )
        )
        .order_by(KscServer.id, KscHost.id)
        .limit(LIMIT + 1)
    )
    return [
        Group(
            id="antivirus",
            title="Антивирус",
            note="Последний по дате сбора снимок каждого сервера AV. Это состояние снимка, не проверка хоста сейчас.",
        ).fill(
            [
                Evidence(
                    id=str(h.id),
                    title=h.fqdn or h.name or h.ip,
                    reason="Совпадение в инвентаре AV",
                    source=f"AV · {server}",
                    href=f"/ksc/servers/{sid}/hosts?" + urlencode({"host": h.host_id}),
                    observed_at=seen,
                    date_label="Снимок AV",
                    facts=facts(
                        **{
                            "IP": h.ip,
                            "Защита": {
                                "on": "Включена",
                                "off": "Выключена",
                                "none": "Нет данных",
                            }.get(h.protection, h.protection),
                            "Статус": h.status,
                            "Угрозы в снимке": h.threats,
                            "Группа": h.group_path,
                        }
                    ),
                )
                for h, server, sid, seen in rows
            ]
        )
    ]
