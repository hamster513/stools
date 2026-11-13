"""Only persisted identity links; never join accounts or hosts by display name."""

from collections import defaultdict

from sqlalchemy import func, select

from api.modules.ad.core.account_groups import account_groups
from api.modules.ad.core.export import ExportFormatError, ExportIndex
from api.modules.ad.services.snapshots import latest_snapshot
from api.modules.assets.models import (
    Asset,
    AssetGroup,
    AssetGroupMember,
    AssetUser,
    AssetUserGroup,
    AssetUserHost,
    AssetUserObservation,
)
from api.modules.assets.services.users import read_ad_export
from api.modules.toolbox.services.lookup_types import facts
from api.platform.services.access import allows

from .models import Entity, Row, Section

CAP = 100


def entity(obj):
    if isinstance(obj, Asset):
        return Entity(
            id=f"host:{obj.id}",
            kind="host",
            title=obj.fqdn or obj.name or obj.ip or f"Хост #{obj.id}",
            domain=obj.domain,
            href=f"/assets/list?asset={obj.id}",
            facts=facts(IP=obj.ip, ОС=obj.os, Критичность=obj.criticality),
        )
    if isinstance(obj, AssetUser):
        return Entity(
            id=f"user:{obj.id}",
            kind="user",
            title=obj.display_name or obj.upn or obj.sam or f"Пользователь #{obj.id}",
            domain=obj.domain,
            href=f"/assets/users?user={obj.id}",
            facts=facts(
                Логин=obj.sam,
                UPN=obj.upn,
                SID=obj.sid,
                Тип="Локальная" if obj.local else "Доменная",
                Состояние="Неизвестно"
                if obj.enabled is None
                else "Включена"
                if obj.enabled
                else "Выключена",
                Привилегированная="Да" if obj.privileged else "Нет",
            ),
        )
    return Entity(
        id=f"group:{obj.id}",
        kind="group",
        title=obj.name or f"Группа #{obj.id}",
        domain=obj.domain,
        href=f"/assets/groups?id={obj.id}",
        facts=facts(
            SID=obj.sid, Тип="Локальная" if obj.local else "Доменная", Описание=obj.description
        ),
    )


def row(obj, reason, source, seen=None, extra=None):
    target = entity(obj)
    return Row(
        id=target.id,
        title=target.title,
        href=target.href,
        target=target,
        reason=reason,
        source=source,
        observed_at=seen,
        facts=extra or [],
    )


def fill(section, rows):
    # One visible row per linked object; preserve all distinct evidence.
    unique = {}
    for item in rows:
        previous = unique.get(item.id)
        if previous is None:
            unique[item.id] = item
            continue
        previous_source = previous.source
        if item.source not in previous.source.split(", "):
            previous.source += ", " + item.source
        if item.reason not in previous.reason.split("; "):
            previous.reason += "; " + item.reason
        for fact in item.facts:
            if fact not in previous.facts:
                previous.facts.append(fact)
        if item.observed_at != previous.observed_at:
            for source, observed_at in (
                (previous_source, previous.observed_at),
                (item.source, item.observed_at),
            ):
                if observed_at:
                    for fact in facts(**{f"Наблюдение {source}": observed_at.isoformat()}):
                        if fact not in previous.facts:
                            previous.facts.append(fact)
    section.has_more = section.has_more or len(rows) > CAP
    rows = list(unique.values())
    section.items = rows[:CAP]
    if section.has_more:
        section.note += " Показаны первые 100 связей; полный состав доступен в источнике."
    return section


def _snapshot_user_groups(db, obj, data_dir, section):
    # Resolve the exact persisted AD identity, never a display name or login.
    observation = db.scalar(
        select(AssetUserObservation).where(
            AssetUserObservation.user_id == obj.id,
            AssetUserObservation.source == "ad",
            AssetUserObservation.source_key == obj.sid,
            AssetUserObservation.gone_at.is_(None),
        )
    )
    domain_id = (observation.data or {}).get("domain_id") if observation else None
    snapshot = latest_snapshot(db, domain_id) if isinstance(domain_id, int) else None
    if snapshot is None:
        return None
    try:
        idx = ExportIndex(read_ad_export(None, data_dir, snapshot.id))
    except (OSError, ExportFormatError, ValueError):
        return None
    result = account_groups(idx)
    section.note += f" Последний снимок AD #{snapshot.id} от {snapshot.collected_at.isoformat()}."
    links = result.groups.get(observation.source_key)
    if links is None:
        section.note += " Учётка с этим SID отсутствует в снимке; членство не определено."
        links = []
    # Preserve AD's warnings about incomplete exported memberships.
    if result.notes:
        section.note += " " + " ".join(result.notes)
    return sorted(links, key=lambda x: (not x["direct"], x["name"]))[: CAP + 1], snapshot.collected_at


def groups(db, obj, access, data_dir):
    section = Section(
        id="groups",
        title="Группы",
        note="AD: прямое/вложенное членство. Локальные группы из VM указаны отдельно; группы управления KSC — в разделе антивируса.",
    )
    rows = []
    if isinstance(obj, AssetUser) and not allows(access, "ad", "read"):
        section.note = "Нет доступа к AD для групп пользователя."
        return section
    if isinstance(obj, AssetUser) and allows(access, "ad", "read"):
        current = _snapshot_user_groups(db, obj, data_dir, section)
        if current is None:
            section.note += (
                " Последний снимок AD недоступен или не связан с учёткой;"
                " показаны сохранённые группы Assets, которые могли устареть."
            )
            links = [
                {"sid": x.group_sid, "name": x.group_name, "direct": x.direct}
                for x in db.scalars(
                    select(AssetUserGroup)
                    .where(AssetUserGroup.user_id == obj.id, AssetUserGroup.source == "ad")
                    .order_by(AssetUserGroup.direct.desc(), AssetUserGroup.group_name)
                    .limit(CAP + 1)
                )
            ]
            stamp = db.scalar(
                select(func.max(AssetUserObservation.seen_at)).where(
                    AssetUserObservation.user_id == obj.id,
                    AssetUserObservation.source == "ad",
                    AssetUserObservation.gone_at.is_(None),
                )
            )
        else:
            links, stamp = current
        sids = [x["sid"] for x in links]
        found = {
            g.sid: g
            for g in db.scalars(
                select(AssetGroup)
                .where(
                    AssetGroup.sid.in_(sids),
                    AssetGroup.domain == obj.domain,
                    AssetGroup.gone_at.is_(None),
                )
                .limit(CAP + 1)
            )
        }
        for link in links:
            g = found.get(link["sid"])
            reason = "Прямое членство" if link["direct"] else "Вложенное членство"
            if g:
                item = row(g, reason, "AD", stamp)
                # The asset reference may predate a group rename in the AD snapshot.
                item.title = item.target.title = link["name"]
                rows.append(item)
            else:
                rows.append(
                    Row(
                        id=link["sid"],
                        title=link["name"],
                        href=f"/assets/users?user={obj.id}",
                        reason=reason,
                        source="AD",
                        observed_at=stamp,
                        facts=facts(SID=link["sid"]),
                    )
                )
    else:
        condition = (
            AssetGroupMember.asset_id == obj.id
            if isinstance(obj, Asset)
            else AssetGroupMember.member_group_id == obj.id
        )
        sources = [s for s in ("ad", "vm") if allows(access, s, "read")]
        pairs = db.execute(
            select(AssetGroup, AssetGroupMember)
            .join(AssetGroupMember, AssetGroupMember.group_id == AssetGroup.id)
            .where(condition, AssetGroupMember.source.in_(sources), AssetGroup.gone_at.is_(None))
            .order_by(AssetGroup.id)
            .limit(CAP + 1)
        ).all()
        seen = {obj.id} if isinstance(obj, AssetGroup) else set()
        depth = 0
        while pairs:
            section.has_more = section.has_more or len(pairs) > CAP
            frontier = []
            for g, link in pairs:
                if g.id in seen:
                    continue
                seen.add(g.id)
                frontier.append(g.id)
                rows.append(
                    row(
                        g,
                        "Вложенное членство"
                        if depth
                        else "Основная группа"
                        if link.primary
                        else "Прямое членство",
                        link.source.upper(),
                        g.last_seen,
                    )
                )
            if len(rows) > CAP:
                break
            depth += 1
            if depth >= 20:
                section.has_more = True
                section.note += " Глубина вложенности ограничена 20 уровнями."
                break
            pairs = (
                db.execute(
                    select(AssetGroup, AssetGroupMember)
                    .join(AssetGroupMember, AssetGroupMember.group_id == AssetGroup.id)
                    .where(
                        AssetGroupMember.member_group_id.in_(frontier),
                        AssetGroupMember.source.in_(sources),
                        AssetGroup.gone_at.is_(None),
                    )
                    .order_by(AssetGroup.id)
                    .limit(CAP + 1)
                ).all()
                if frontier
                else []
            )
    if not any(allows(access, s, "read") for s in ("ad", "vm")):
        section.note = "Нет доступа к AD/VM для сведений о членстве."
    return fill(section, rows)


def devices(db, obj, access):
    is_host = isinstance(obj, Asset)
    target_model = AssetUser if is_host else Asset
    section = Section(
        id="users" if is_host else "hosts",
        title="Пользователи на хосте" if is_host else "Хосты пользователя",
        note="Сеанс, владелец устройства и локальная группа — разные виды связи. Это данные на момент сбора, не присутствие сейчас.",
    )
    sources = [s for s in ("ad", "ksc", "vm") if allows(access, s, "read")]
    condition = AssetUserHost.asset_id == obj.id if is_host else AssetUserHost.user_id == obj.id
    join = target_model.id == (AssetUserHost.user_id if is_host else AssetUserHost.asset_id)
    targets = db.scalars(
        select(target_model)
        .where(
            target_model.merged_into.is_(None),
            select(AssetUserHost.id)
            .where(condition, join, AssetUserHost.source.in_(sources))
            .exists(),
        )
        .order_by(target_model.id)
        .limit(CAP + 1)
    ).all()
    ids = [x.id for x in targets]
    key = AssetUserHost.user_id if is_host else AssetUserHost.asset_id
    # At most 101 targets, three source/kind links per target in normal inventory.
    links = db.scalars(
        select(AssetUserHost)
        .where(condition, key.in_(ids), AssetUserHost.source.in_(sources))
        .order_by(AssetUserHost.id)
        .limit((CAP + 1) * 20)
    ).all()
    by_id = defaultdict(list)
    for link in links:
        by_id[getattr(link, "user_id" if is_host else "asset_id")].append(link)
    rows = []
    for target in targets:
        mine = by_id[target.id]
        kinds = []
        for link in mine:
            text = {
                "session": "Сеанс: активен на момент сбора"
                if link.active
                else "Сеанс: ранее замечен",
                "owner": "Владелец устройства",
                "local_group": "Член локальной группы",
            }.get(link.kind, link.kind)
            if link.gone_at:
                text += " (историческая связь)"
            if text not in kinds:
                kinds.append(text)
        rows.append(
            row(
                target,
                "; ".join(kinds),
                ", ".join(sorted({x.source.upper() for x in mine})),
                max((x.seen_at for x in mine), default=None),
            )
        )
    if not sources:
        section.note = "Нет доступа к источникам AD/AV/VM для связей с хостами."
    return fill(section, rows)


def members(db, obj, access):
    section = Section(
        id="members",
        title="Участники группы",
        note="Прямой состав группы из последних сохранённых данных; вложенные группы открываются отдельно.",
    )
    sources = [s for s in ("ad", "vm") if allows(access, s, "read")]
    links = db.scalars(
        select(AssetGroupMember)
        .where(AssetGroupMember.group_id == obj.id, AssetGroupMember.source.in_(sources))
        .order_by(AssetGroupMember.id)
        .limit(CAP + 1)
    ).all()
    rows = []
    for link in links:
        cls, id_ = (
            (AssetUser, link.user_id)
            if link.user_id
            else (Asset, link.asset_id)
            if link.asset_id
            else (AssetGroup, link.member_group_id)
        )
        target = db.get(cls, id_) if id_ else None
        if target and (getattr(target, "merged_into", None) or getattr(target, "gone_at", None)):
            target = None
        if target:
            rows.append(
                row(
                    target,
                    {
                        "user": "Пользователь",
                        "computer": "Компьютер",
                        "group": "Вложенная группа",
                    }.get(link.member_kind, link.member_kind),
                    link.source.upper(),
                    obj.last_seen,
                )
            )
        else:
            rows.append(
                Row(
                    id=str(link.id),
                    title=link.member_name or link.member_sid,
                    href=entity(obj).href,
                    source=link.source.upper(),
                    reason="Объект не сопоставлен",
                    observed_at=obj.last_seen,
                    facts=facts(SID=link.member_sid),
                )
            )
    return fill(section, rows)
