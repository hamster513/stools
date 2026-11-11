"""Snapshot policy scope, explicitly distinct from endpoint RSoP/application."""

import re
from urllib.parse import urlencode

from sqlalchemy import select

from api.modules.ad.core.export import ExportFormatError, ExportIndex
from api.modules.ad.services.snapshots import latest_snapshot
from api.modules.assets.models import (
    Asset,
    AssetGroup,
    AssetGroupGpo,
    AssetObservation,
    AssetUser,
    AssetUserHost,
    AssetUserObservation,
)
from api.modules.assets.services.users import read_ad_export
from api.modules.ksc.models import KscHost, KscPolicy, KscPolicyScope, KscSnapshot
from api.modules.toolbox.services.lookup_types import facts
from api.platform.services.access import allows

from .ksc_groups import ManagementGroup
from .ksc_groups import entity as management_group_entity
from .models import Row, Section
from .relations import CAP, entity, fill

RDN = re.compile(r"(?:[^,\\]|\\.)+")


def applicable_links(idx, obj, gpo):
    """OU ancestry including block inheritance and enforced links; not security/WMI filtering."""
    if (gpo.flags or 0) & (1 if obj.cls == "user" else 2):
        return []
    dn = obj.dn.lower()
    ancestors = [dn[m.start() :] for m in RDN.finditer(dn)][1:]
    links = {l.container_dn.lower(): l for l in idx.gpo_links(gpo) or []}
    found = []
    blocked = False
    for ancestor in ancestors:
        link = links.get(ancestor)
        if link and (not blocked or link.enforced):
            found.append(link)
        container = idx.get(ancestor)
        if container and (container.gpOptions or 0) & 1:
            blocked = True
    return found


def ad_policies(db, obj, access, data_dir):
    section = Section(
        id="ad_policies",
        title="Политики AD",
        note="Область действия по включённым ссылкам GPO и наследованию OU. Security/WMI-фильтры, loopback и фактическое применение на машине не подтверждены (не RSoP).",
    )
    if not allows(access, "ad", "read"):
        section.note = "Нет доступа к AD."
        return section
    if isinstance(obj, AssetGroup):
        rows = db.scalars(
            select(AssetGroupGpo)
            .where(AssetGroupGpo.domain == obj.domain, AssetGroupGpo.group_sid == obj.sid)
            .order_by(AssetGroupGpo.id)
            .limit(CAP + 1)
        ).all()
        section.note = "Назначения группы через GPO, а не политики, применённые к самой группе. Целевые хосты — область действия; фактическое применение не подтверждено."
        return fill(
            section,
            [
                Row(
                    id=str(r.id),
                    title=r.gpo_name,
                    href=entity(obj).href,
                    source="AD",
                    reason=f"{r.local_group}: {r.action}",
                    observed_at=r.seen_at,
                    facts=facts(
                        Механизм=r.via,
                        Фильтрация="Есть" if r.filtered else "Не подтверждена",
                        Хостов=r.hosts_total,
                    ),
                )
                for r in rows
            ],
        )
    model = AssetUserObservation if isinstance(obj, AssetUser) else AssetObservation
    condition = model.user_id == obj.id if isinstance(obj, AssetUser) else model.asset_id == obj.id
    observations = db.scalars(
        select(model)
        .where(condition, model.source == "ad", model.gone_at.is_(None))
        .order_by(model.id)
        .limit(CAP + 1)
    ).all()
    rows = []
    seen = set()
    cache = {}
    for obs in observations:
        info = obs.data if isinstance(obj, AssetUser) else obs.extra
        did = (info or {}).get("domain_id")
        if not isinstance(did, int):
            continue
        snap = latest_snapshot(db, did)
        if not snap:
            continue
        try:
            idx = ExportIndex(read_ad_export(cache, data_dir, snap.id))
        except (OSError, ValueError, ExportFormatError):
            section.note += " Последняя выгрузка AD недоступна; область GPO не определена."
            continue
        if idx.gpo_link_map is None:
            section.note += " Привязки GPO не собраны в выгрузке."
            continue
        subject = idx.by_sid.get(obs.source_key) or idx.get(obs.source_key)
        if not subject:
            continue
        for gpo in idx.objects("groupPolicyContainer"):
            links = applicable_links(idx, subject, gpo)
            key = f"{snap.id}:{gpo.dn.lower()}"
            if not links or key in seen:
                continue
            seen.add(key)
            rows.append(
                Row(
                    id=key,
                    title=gpo.displayName or gpo.label,
                    href=f"/ad/domains/{did}/summary",
                    source="AD",
                    observed_at=snap.collected_at,
                    reason="В области действия пользовательской части"
                    if isinstance(obj, AssetUser)
                    else "В области действия компьютерной части",
                    facts=facts(
                        Привязки="; ".join(l.container_dn for l in links),
                        Принудительная="Да" if any(l.enforced for l in links) else "Нет",
                    ),
                )
            )
            if len(rows) > CAP:
                return fill(section, rows)
    return fill(section, rows)


def antivirus(db, obj, access):
    section = Section(
        id="antivirus",
        title="Группы и политики KSC",
        note="Политики группы управления из последнего снимка KSC. Наличие в области действия не подтверждает доставку настроек; активация профилей зависит от тегов хоста.",
    )
    if not allows(access, "ksc", "read"):
        section.note = "Нет доступа к AV."
        return section
    if isinstance(obj, AssetGroup):
        section.note = "Группы AD/локальные группы и группы управления KSC — разные объекты. Политики KSC смотрите в досье хостов."
        return section
    host_ids = [obj.id]
    if isinstance(obj, AssetUser):
        host_ids = list(
            db.scalars(
                select(AssetUserHost.asset_id)
                .where(
                    AssetUserHost.user_id == obj.id,
                    AssetUserHost.source == "ksc",
                    AssetUserHost.gone_at.is_(None),
                )
                .distinct()
                .limit(CAP + 1)
            )
        )
        section.note = "Политики связанных хостов, не политики учётной записи. " + section.note
    observations = db.execute(
        select(AssetObservation, Asset)
        .join(Asset, Asset.id == AssetObservation.asset_id)
        .where(
            AssetObservation.asset_id.in_(host_ids),
            AssetObservation.source == "ksc",
            AssetObservation.gone_at.is_(None),
        )
        .order_by(AssetObservation.id)
        .limit(CAP + 1)
    ).all()
    rows = []
    seen = set()
    for obs, host in observations:
        sid, sep, hid = obs.source_key.partition(":")
        if not sep or not sid.isdigit():
            continue
        snap = db.scalar(
            select(KscSnapshot)
            .where(KscSnapshot.server_id == int(sid))
            .order_by(KscSnapshot.collected_at.desc(), KscSnapshot.id.desc())
            .limit(1)
        )
        if not snap:
            continue
        h = db.scalar(
            select(KscHost).where(KscHost.snapshot_id == snap.id, KscHost.host_id == hid).limit(1)
        )
        if not h:
            continue
        key = f"{snap.id}:{h.host_id}"
        if key in seen:
            continue
        seen.add(key)
        href = f"/ksc/servers/{sid}/hosts?" + urlencode({"host": hid})
        rows.append(
            Row(
                id=f"{snap.id}:group:{h.group_id}",
                title=h.group_path or "Группа управления не указана",
                target=management_group_entity(
                    ManagementGroup(
                        snap.server_id, snap.id, h.group_id, h.group_path, snap.collected_at
                    )
                )
                if h.group_id is not None
                else None,
                href=href,
                source="KSC",
                observed_at=snap.collected_at,
                reason=f"Хост: {host.fqdn or host.name}",
                facts=facts(Защита=h.protection, Статус=h.status),
            )
        )
        policies = (
            db.execute(
                select(KscPolicy, KscPolicyScope.own)
                .join(
                    KscPolicyScope,
                    (KscPolicyScope.snapshot_id == KscPolicy.snapshot_id)
                    & (KscPolicyScope.policy_id == KscPolicy.policy_id),
                )
                .where(KscPolicy.snapshot_id == snap.id, KscPolicyScope.group_id == h.group_id)
                .order_by(KscPolicy.id)
                .limit(CAP + 1)
            ).all()
            if h.group_id is not None
            else []
        )
        for p, own in policies:
            rows.append(
                Row(
                    id=f"{snap.id}:policy:{p.id}",
                    title=p.name,
                    href=href,
                    source="KSC",
                    observed_at=snap.collected_at,
                    reason=f"{host.fqdn or host.name}: "
                    + ("собственная политика группы" if own else "унаследованная политика"),
                    facts=facts(Продукт=p.product, Активна="Да" if p.active else "Нет"),
                )
            )
        if len(rows) > CAP:
            break
    return fill(section, rows)
