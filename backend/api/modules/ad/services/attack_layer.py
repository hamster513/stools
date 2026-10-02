"""Экспозиция AD как слой платформенной матрицы ATT&CK.

Экспозицией считается то, что на экранах модуля учитывается в подсчётах:
находки последних снапшотов каждого домена без allowlist, статус которых
велено учитывать (настройка платформы `counted`). Принятый риск или ложное
срабатывание по умолчанию экспозицией быть перестаёт — иначе матрица
спорила бы с решением, которое человек уже принял.
"""
from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.ad.core.checks import CHECK_BY_CODE
from api.modules.ad.core.findings import SEVERITY_RANK
from api.modules.ad.models import AdDomain, AdFinding
from api.modules.ad.services.snapshots import latest_snapshot
from api.modules.attack.layers import (
    MAX_ITEMS,
    Layer,
    LayerCell,
    LayerItem,
    LayerResult,
    parent_of,
)
from api.platform.findings import service as finding_svc


def build(db: Session) -> LayerResult:
    """Ячейки слоя по последнему снапшоту каждого домена."""
    domains = db.execute(select(AdDomain)).scalars().all()
    per_technique: dict[str, list[tuple[int, LayerItem]]] = defaultdict(list)
    # Полные идентификаторы, а не родители: платформе нужно отличать
    # открытую подтехнику от техники целиком.
    ids: set[str] = set()
    covered_domains = 0
    counted = finding_svc.counted_statuses(db)
    for domain in domains:
        snap = latest_snapshot(db, domain.id)
        if snap is None:
            continue
        covered_domains += 1
        states = finding_svc.state_map(db, "ad", domain.id)
        rows = db.execute(
            select(AdFinding).where(
                AdFinding.snapshot_id == snap.id, AdFinding.allowlisted.is_(False)
            )
        ).scalars()
        label = domain.dns_root or domain.netbios or domain.sid
        for finding in rows:
            if not finding_svc.is_counted(states.get(finding.key), counted):
                continue
            spec = CHECK_BY_CODE.get(finding.check)
            if spec is None:
                continue
            item = LayerItem(
                title=finding.identity or finding.target,
                subtitle=f"{spec.title} · {finding.severity} · {label}",
                href=f"/ad/domains/{domain.id}/findings?check={finding.check}",
            )
            rank = SEVERITY_RANK.get(finding.severity, 9)
            for technique in spec.techniques:
                ids.add(technique)
                per_technique[parent_of(technique)].append((rank, item))
    if covered_domains == 0:
        return LayerResult(cells={}, note="нет снапшотов AD", available=False)
    cells = {
        technique: LayerCell(
            count=len(entries),
            # Сначала самое тяжёлое: в карточку техники помещается
            # двадцать строк, и это должны быть худшие двадцать.
            items=tuple(
                item for _, item in sorted(entries, key=lambda e: e[0])[:MAX_ITEMS]
            ),
        )
        for technique, entries in per_technique.items()
    }
    return LayerResult(
        cells=cells, technique_ids=frozenset(ids), note=f"доменов: {covered_domains}"
    )


LAYER = Layer(
    id="ad",
    title="Active Directory",
    kind="exposure",
    unit=("находка", "находки", "находок"),
    build=build,
)
