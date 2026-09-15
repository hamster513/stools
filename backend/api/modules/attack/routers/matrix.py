"""Матрица, карточка техники и цепочки кампаний — общие для всех модулей.

Матрица говорит о технике, а не о правиле, узле или уязвимости: каждый
модуль отдаёт ей свой слой, а склейка живёт здесь. Поэтому ни адреса, ни
ответа модуля в них нет — только идентификаторы слоёв.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser, RuTtpProcedure
from api.deps import get_current_user
from api.modules.attack import layers as layers_module
from api.modules.attack.layers import collect, parent_of
from api.modules.attack.services.attack_bundle import current as current_bundle
from api.modules.attack.services.matrix import (
    build_matrix,
    cell_json,
    covered_ids,
    exposed_ids,
    is_covered,
    is_exposed,
)
from api.modules.attack.services.prevalence import UNOBSERVABLE_TACTICS, prevalence_raw
from api.modules.attack.services.prevalence import campaigns as campaigns_pack
from api.modules.attack.services.ru_ttp import layer as ru_layer
from api.modules.attack.services.ru_ttp import ru_actors, ru_cell, ru_source
from kbaudit.attack.campaigns import chains as build_chains

router = APIRouter(tags=["attack"])


@router.get("/matrix")
def matrix(
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Матрица ATT&CK со слоями всех модулей по каждой технике."""
    return build_matrix(db)


@router.get("/technique/{technique_id}")
def technique_detail(
    technique_id: str,
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Всё о технике: описание, подтехники, чем закрыта и чем открыта.

    Одного названия мало: увидев ячейку матрицы, человек хочет понять,
    что это за техника, есть ли внутри неё что-то незакрытое и что о ней
    говорят слои модулей.
    """
    book = current_bundle(db)
    technique = book.by_id().get(technique_id)
    if technique is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="техника не найдена")

    results = collect(db)
    parent = parent_of(technique_id)
    ids = covered_ids(results)

    # Подтехники сортируются по распространённости, а не по номеру:
    # у T1003 их восемь, и человеку, который пришёл уточнять разметку,
    # важно с чего начать, а не в каком порядке MITRE их занумеровала.
    stats = prevalence_raw()
    ru = ru_layer(db)
    child_cells: list[dict[str, Any]] = [
        {
            "technique_id": child.technique_id,
            "name": child.name,
            "name_ru": child.name_ru,
            "covered": child.technique_id in ids,
            "level": stats.level(child.technique_id),
            "actor_groups": s.groups if (s := stats.stats.get(child.technique_id)) else 0,
            "sightings": s.sightings if (s := stats.stats.get(child.technique_id)) else 0,
            "ru": ru_cell(ru, child.technique_id),
        }
        for child in book.children_of(parent)
    ]
    children = sorted(
        child_cells,
        # Замеченное здесь идёт первым: человек уточняет разметку ради
        # своей инфраструктуры, а не ради мировой статистики. Ключ явный
        # и раскладывается обратно — видно, чем поднята каждая строка.
        key=lambda c: (
            -ru_actors(ru, c["technique_id"]),
            -c["level"],
            -c["actor_groups"],
            c["technique_id"],
        ),
    )
    procedures = (
        db.query(RuTtpProcedure)
        .filter(
            RuTtpProcedure.technique_id.in_(
                [technique.technique_id, *(c["technique_id"] for c in children)]
            )
        )
        .order_by(RuTtpProcedure.command_line == "", RuTtpProcedure.id)
        .limit(20)
        .all()
    )

    return {
        "technique_id": technique.technique_id,
        "name": technique.name,
        "name_ru": technique.name_ru,
        "description_ru": technique.description_ru,
        "description": technique.description,
        "tactics": technique.tactics,
        "is_subtechnique": technique.is_subtechnique,
        "parent_id": technique.parent_id,
        "subtechniques": children,
        # Слои с подробностями: не только счётчик, но и чем именно
        # техника закрыта или открыта — ради этого карточку и открывают.
        "layers": {
            lid: cell_json(results[lid].cells.get(parent), with_items=True)
            for lid in layers_module.LAYERS
        },
        "covered": is_covered(results, parent),
        "gap": is_exposed(results, parent) and not is_covered(results, parent),
        "ru": ru_cell(ru, technique.technique_id, folded=not technique.is_subtechnique),
        # Процедуры с командами идут первыми: непокрытой технике это
        # готовый материал для правила, а не справка о том, что бывает.
        "ru_procedures": [
            {
                "technique_id": row.technique_id,
                "procedure": row.procedure,
                "command_line": row.command_line,
                "actors": json.loads(row.actors_json or "[]"),
                "malware": json.loads(row.malware_json or "[]"),
                "tools": json.loads(row.tools_json or "[]"),
            }
            for row in procedures
        ],
    }


@router.get("/chains")
def chains(
    limit: int = Query(default=40, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Цепочки реальных кампаний и наши пробелы в них.

    Пробел, попавший на шаг кампании, которая уже случилась, весит больше
    пробела вообще: по нему видно не «техника не закрыта», а «такой путь
    проходили, и вот здесь мы бы его не увидели».

    Порядок шагов — порядок тактик матрицы: последовательность шагов
    атаки задана MITRE, выдумывать её не нужно и нельзя.
    """
    book = current_bundle(db)
    results = collect(db)
    ours = covered_ids(results)
    built = build_chains(
        list(campaigns_pack()),
        {t.technique_id: t.tactics for t in book.techniques},
        [t.shortname for t in book.tactics],
        ours,
        unobservable=UNOBSERVABLE_TACTICS,
    )
    described = book.by_id()
    ru = ru_layer(db)

    def name_of(technique_id: str) -> str:
        found = described.get(technique_id) or described.get(parent_of(technique_id))
        return (found.name_ru or found.name) if found else technique_id

    items = [
        {
            "id": chain.id,
            "name": chain.name,
            "first_seen": chain.first_seen,
            "last_seen": chain.last_seen,
            "technique_count": chain.technique_count,
            "uncovered_count": chain.uncovered_count,
            "blind_steps": chain.blind_steps,
            "steps": [
                {
                    "tactic": step.tactic,
                    "blind": step.blind,
                    "observable": step.observable,
                    "total": len(step.techniques),
                    "covered": len(step.covered),
                    # Непокрытые техники шага — то, ради чего таблицу
                    # открывают: это готовый список, что писать.
                    # Замеченное здесь идёт первым: пробел на технике,
                    # которую применяют против таких же, весит больше
                    # пробела на технике из чужого отчёта.
                    "uncovered": [
                        {"technique_id": t, "name": name_of(t), "ru": ru_cell(ru, t)}
                        for t in sorted(step.uncovered, key=lambda t: -ru_actors(ru, t))[:12]
                    ],
                }
                for step in chain.steps
            ],
        }
        for chain in built[:limit]
    ]
    return {
        "total": len(built),
        "items": items,
        "attack_version": book.version,
        # Техники, у которых в инфраструктуре есть чем их выполнить.
        # Непокрытый шаг цепочки, попавший сюда, — не абстрактный пробел.
        "exposed": sorted(exposed_ids(results)),
        # Кампаний в ATT&CK немного, и они отстают: самая свежая на 19.2
        # датирована сентябрём 2025 года. Об этом надо сказать на экране,
        # а не оставлять читателя думать, что это оперативные данные.
        "latest_seen": max((c.last_seen or "" for c in campaigns_pack()), default=""),
        "ru_source": ru_source(ru),
    }
