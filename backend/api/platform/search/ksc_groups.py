"""KSC management groups are distinct from AD/security groups."""

import datetime as dt
from dataclasses import dataclass
from urllib.parse import urlencode

from sqlalchemy import func, or_, select

from api.modules.assets.models import Asset, AssetObservation
from api.modules.ksc.models import KscHost, KscPolicy, KscPolicyScope, KscSnapshot
from api.modules.toolbox.services.lookup_types import facts
from api.platform.services.access import allows

from .models import Dossier, Entity, Row, Section
from .relations import fill, row


@dataclass
class ManagementGroup:
    server_id: int
    snapshot_id: int
    group_id: int
    path: str
    seen_at: dt.datetime


def find(db, q, selected=None):
    ranked = select(
        KscSnapshot.id, KscSnapshot.server_id, KscSnapshot.collected_at,
        func.row_number().over(
            partition_by=KscSnapshot.server_id,
            order_by=(KscSnapshot.collected_at.desc(), KscSnapshot.id.desc()),
        ).label("position"),
    ).subquery()
    latest = select(ranked.c.id, ranked.c.server_id, ranked.c.collected_at).where(
        ranked.c.position == 1,
    ).subquery()
    found = {}
    for model in (KscHost, KscPolicyScope):
        leaf = (
            func.stools_path_leaf(model.group_path)
            if db.get_bind().dialect.name == "sqlite"
            else func.regexp_replace(model.group_path, r"^.*[\\/]", "")
        )
        condition = (
            (model.group_id == selected[1]) & (latest.c.server_id == selected[0])
            if selected
            else or_(
                func.lower(model.group_path) == q.lower(),
                func.lower(leaf) == q.lower(),
            )
        )
        rows = db.execute(
            select(
                latest.c.id,
                latest.c.server_id,
                latest.c.collected_at,
                model.group_id,
                model.group_path,
            )
            .join(model, model.snapshot_id == latest.c.id)
            .where(model.group_id.is_not(None), condition)
            .distinct()
            .order_by(latest.c.server_id, model.group_id, model.group_path)
            .limit(21)
        )
        for snap, server, seen, id_, path in rows:
            found.setdefault((server, id_), ManagementGroup(server, snap, id_, path, seen))
    return list(found.values())


def entity(g):
    return Entity(
        id=f"kscgroup:{g.server_id}:{g.group_id}",
        kind="group",
        title=g.path or f"Группа {g.group_id}",
        domain=f"KSC #{g.server_id}",
        href=f"/ksc/servers/{g.server_id}/hosts?" + urlencode({"group": g.path}),
        facts=facts(Тип="Группа управления KSC"),
    )


def dossier(db, g, access):
    members = Section(
        id="members",
        title="Хосты группы",
        note="Прямой состав группы управления в последнем снимке KSC; не членство в AD.",
    )
    hosts = db.scalars(
        select(KscHost)
        .where(KscHost.snapshot_id == g.snapshot_id, KscHost.group_id == g.group_id)
        .order_by(KscHost.id)
        .limit(101)
    ).all()
    rows = []
    for h in hosts:
        asset = None
        if allows(access, "assets", "read"):
            asset = db.scalar(
                select(Asset)
                .join(AssetObservation, AssetObservation.asset_id == Asset.id)
                .where(
                    AssetObservation.source == "ksc",
                    AssetObservation.source_key == f"{g.server_id}:{h.host_id}",
                    AssetObservation.gone_at.is_(None),
                    Asset.merged_into.is_(None),
                )
                .limit(1)
            )
        if asset:
            rows.append(row(asset, "В группе управления KSC", "KSC", g.seen_at))
        else:
            rows.append(
                Row(
                    id=str(h.id),
                    title=h.fqdn or h.name or h.ip,
                    href=f"/ksc/servers/{g.server_id}/hosts?" + urlencode({"host": h.host_id}),
                    reason="Хост KSC; нет доступной связи с Assets",
                    source="KSC",
                    observed_at=g.seen_at,
                    facts=facts(IP=h.ip),
                )
            )
    fill(members, rows)
    policies = Section(
        id="antivirus",
        title="Политики KSC",
        note="Область действия политик группы; фактическая доставка на хосты не подтверждена.",
    )
    pairs = db.execute(
        select(KscPolicy, KscPolicyScope.own)
        .join(
            KscPolicyScope,
            (KscPolicyScope.snapshot_id == KscPolicy.snapshot_id)
            & (KscPolicyScope.policy_id == KscPolicy.policy_id),
        )
        .where(KscPolicy.snapshot_id == g.snapshot_id, KscPolicyScope.group_id == g.group_id)
        .order_by(KscPolicy.id)
        .limit(101)
    ).all()
    fill(
        policies,
        [
            Row(
                id=str(p.id),
                title=p.name,
                href=entity(g).href,
                reason="Собственная" if own else "Унаследованная",
                source="KSC",
                observed_at=g.seen_at,
                facts=facts(Продукт=p.product, Активна="Да" if p.active else "Нет"),
            )
            for p, own in pairs
        ],
    )
    return Dossier(entity=entity(g), sections=[members, policies])
