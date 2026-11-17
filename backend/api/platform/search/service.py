"""Bounded, local entity dossier backed by existing collected inventories."""

from pathlib import Path
from urllib.parse import urlencode

from fastapi import HTTPException
from sqlalchemy import func, or_, select

from api.modules.ad.models import AdDomain
from api.modules.assets.models import Asset, AssetGroup, AssetObservation, AssetUser, AssetUserHost
from api.modules.toolbox.services.lookup import lookup
from api.modules.toolbox.services.lookup_types import facts, identity, ip_list_contains, parse_query
from api.modules.vm.models import VmHost, VmHostCve, VmImport
from api.platform.services.access import allows

from . import ksc_groups, policies, relations
from .models import Dossier, Row, SearchResult, Section
from .observations import observations

MODELS = {"host": Asset, "user": AssetUser, "group": AssetGroup}


def candidate_rows(db, q, kind):
    found = []
    if kind in ("auto", "host", "ip"):
        try:
            normalized, parsed = parse_query(q, "auto" if kind == "auto" else kind)
        except ValueError:
            pass
        else:
            if parsed != "cve":
                condition = identity(
                    normalized,
                    "host" if parsed == "name" else parsed,
                    name=Asset.name_key,
                    fqdn=Asset.fqdn,
                    domain=Asset.domain,
                    ip=Asset.ip,
                    dialect=db.get_bind().dialect.name,
                )
                if parsed == "ip":
                    secondary = select(AssetObservation.asset_id).where(
                        AssetObservation.gone_at.is_(None),
                        or_(
                            AssetObservation.ip == normalized,
                            ip_list_contains(AssetObservation.ips, normalized, db.get_bind().dialect.name),
                        ),
                    )
                    condition = or_(condition, Asset.id.in_(secondary))
                found.extend(
                    db.scalars(
                        select(Asset)
                        .where(Asset.merged_into.is_(None), condition)
                        .order_by(Asset.id)
                        .limit(21)
                    )
                )
    if kind in ("auto", "user", "group"):
        lower = q.casefold()
        qualified = lower
        if "\\" in lower:
            domain, name = lower.split("\\", 1)
            dns = db.scalar(
                select(AdDomain.dns_root).where(func.lower(AdDomain.netbios) == domain).limit(1)
            )
            qualified = f"{dns.lower()}\\{name}" if dns else lower
        if kind in ("auto", "user"):
            condition = or_(
                *(
                    func.lower(c) == lower
                    for c in (AssetUser.sam, AssetUser.upn, AssetUser.sid, AssetUser.display_name)
                ),
                func.lower(AssetUser.name_key) == qualified,
            )
            found.extend(
                db.scalars(
                    select(AssetUser)
                    .where(AssetUser.merged_into.is_(None), condition)
                    .order_by(AssetUser.id)
                    .limit(21)
                )
            )
        if kind in ("auto", "group"):
            condition = or_(
                func.lower(AssetGroup.name) == lower,
                func.lower(AssetGroup.sid) == lower,
                func.lower(AssetGroup.domain + "\\" + AssetGroup.name) == qualified,
            )
            found.extend(
                db.scalars(
                    select(AssetGroup)
                    .where(AssetGroup.gone_at.is_(None), condition)
                    .order_by(AssetGroup.id)
                    .limit(21)
                )
            )
    return found


def vulnerabilities(db, obj, access):
    section = Section(
        id="vulnerabilities",
        title="Уязвимости",
        note="Находки последнего сохранённого импорта VM, включая находки с решениями аналитика. Отсутствие записей не означает отсутствие уязвимостей.",
    )
    if not allows(access, "vm", "read"):
        section.note = "Нет доступа к VM."
        return section
    if isinstance(obj, AssetGroup):
        section.note = "Уязвимости относятся к хостам. Откройте досье участника группы."
        return section
    host_ids = [obj.id]
    if isinstance(obj, AssetUser):
        sources = [s for s in ("ad", "ksc", "vm") if allows(access, s, "read")]
        host_ids = select(AssetUserHost.asset_id).where(
            AssetUserHost.user_id == obj.id,
            AssetUserHost.source.in_(sources),
            AssetUserHost.gone_at.is_(None),
        )
        section.note = "Уязвимости связанных хостов, не самой учётной записи. " + section.note
    # Keep the complete scope in SQL; limiting it would hide high-risk hosts from both totals and ranking.
    # VM source_key is hostname|IP, matching the indexed key in vm_host rather than a shared IP.
    keys = select(AssetObservation.source_key).where(
        AssetObservation.asset_id.in_(host_ids),
        AssetObservation.source == "vm",
        AssetObservation.gone_at.is_(None),
        AssetObservation.source_key.contains("|"),
    )
    if db.execute(keys.limit(1)).first() is None:
        section.note += " Нет подтверждённой связи с инвентарём VM."
        return section
    condition = (VmHost.hostname + "|" + VmHost.ip).in_(keys)
    total, unique, risk = db.execute(
        select(func.count(), func.count(func.distinct(VmHostCve.cve_id)), func.max(VmHostCve.risk))
        .select_from(VmHost)
        .join(VmHostCve)
        .where(condition)
    ).one()
    section.note = (
        f"Пар хост–CVE: {total}; уникальных CVE: {unique}; максимальный риск: {risk if risk is not None else 'нет данных'}. "
        + section.note
    )
    pairs = db.execute(
        select(VmHost, VmHostCve)
        .join(VmHostCve)
        .where(condition)
        .order_by(VmHostCve.risk.desc(), VmHost.id, VmHostCve.cve_id)
        .limit(101)
    ).all()
    imported = db.scalar(
        select(VmImport.finished_at)
        .order_by(VmImport.finished_at.desc(), VmImport.id.desc())
        .limit(1)
    )
    return relations.fill(
        section,
        [
            Row(
                id=f"{h.id}:{v.cve_id}",
                title=v.cve_id,
                href="/vm/vulns?" + urlencode({"host_id": h.id, "cve": v.cve_id, "status": "all"}),
                source="VM",
                observed_at=imported,
                reason=h.hostname or h.ip,
                facts=facts(Риск=v.risk),
            )
            for h, v in pairs
        ],
    )


def dossier(db, obj, access, data_dir):
    sections = [observations(db, obj, access), relations.groups(db, obj, access, data_dir)]
    if isinstance(obj, AssetGroup):
        sections.append(relations.members(db, obj, access))
    else:
        sections.append(relations.devices(db, obj, access))
    sections.extend(
        [
            policies.ad_policies(db, obj, access, data_dir),
            policies.antivirus(db, obj, access),
            vulnerabilities(db, obj, access),
        ]
    )
    return Dossier(
        entity=relations.entity(obj),
        sections=sections,
        notes=[
            "Сведения получены из сохранённых снимков. Пустой раздел означает отсутствие доступных подтверждений, а не отсутствие связи."
        ],
    )


def search(db, payload, access, data_dir: Path):
    q = payload.query.strip()
    if not q or any(ord(c) < 32 for c in q):
        raise HTTPException(422, "Введите идентификатор или имя объекта.")
    result = SearchResult(query=q)
    if payload.entity_id and payload.entity_id.startswith("kscgroup:"):
        if not allows(access, "ksc", "read"):
            raise HTTPException(403, "Нет доступа к AV.")
        _, sid, gid = payload.entity_id.split(":")
        candidates = ksc_groups.find(db, q, (int(sid), int(gid)))
        if not candidates:
            raise HTTPException(404, "Группа KSC не найдена в последнем снимке.")
    elif payload.entity_id:
        if not allows(access, "assets", "read"):
            raise HTTPException(403, "Нет доступа к реестру Assets.")
        kind, id_ = payload.entity_id.split(":")
        obj = db.get(MODELS[kind], int(id_))
        if obj is None or getattr(obj, "merged_into", None) or getattr(obj, "gone_at", None):
            raise HTTPException(404, "Объект не найден.")
        candidates = [obj]
    else:
        candidates = candidate_rows(db, q, payload.kind) if allows(access, "assets", "read") else []
    if (
        not payload.entity_id
        and payload.kind in ("auto", "group")
        and allows(access, "ksc", "read")
    ):
        candidates.extend(ksc_groups.find(db, q))
    result.has_more = len(candidates) > 20
    result.matches = [
        ksc_groups.entity(o) if isinstance(o, ksc_groups.ManagementGroup) else relations.entity(o)
        for o in candidates[:20]
    ]
    if len(candidates) == 1:
        obj = candidates[0]
        result.dossier = (
            ksc_groups.dossier(db, obj, access)
            if isinstance(obj, ksc_groups.ManagementGroup)
            else dossier(db, obj, access, data_dir)
        )
    elif not candidates:
        if payload.kind in ("user", "group"):
            if not allows(access, "assets", "read"):
                result.notes.append("Нет доступа к Assets для поиска пользователей и групп.")
        else:
            try:
                normalized, kind = parse_query(q, payload.kind)
            except ValueError:
                if payload.kind != "auto":
                    raise HTTPException(422, "Проверьте идентификатор и выбранный тип запроса.")
            else:
                result.groups = lookup(db, normalized, kind, access).groups
    return result
