"""Склейка матрицы из бандла, распространённости, РФ TTP и слоёв модулей."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

# Реестр читается через модуль, а не по имени: слои регистрируются при
# импорте модулей, а тесты подменяют сам словарь — связанное на импорте
# имя указывало бы на прежний реестр.
from api.modules.attack import layers as layers_module
from api.modules.attack.layers import LayerCell, LayerResult, collect
from api.modules.attack.services.attack_bundle import current as current_bundle
from api.modules.attack.services.prevalence import UNOBSERVABLE_TACTICS, prevalence_for
from api.modules.attack.services.ru_ttp import layer as ru_layer
from api.modules.attack.services.ru_ttp import ru_cell, ru_source

COVERED = ("confirmed", "suggested")


def cell_json(cell: LayerCell | None, with_items: bool) -> dict[str, Any] | None:
    if cell is None:
        return None
    out: dict[str, Any] = {"count": cell.count, "status": cell.status}
    if with_items:
        out["items"] = [
            {"title": i.title, "subtitle": i.subtitle, "href": i.href} for i in cell.items
        ]
    return out


def layers_json(results: dict[str, LayerResult]) -> list[dict[str, Any]]:
    return [
        {
            "id": layer.id,
            "title": layer.title,
            "kind": layer.kind,
            "unit": list(layer.unit),
            "available": results[layer.id].available,
            "note": results[layer.id].note,
        }
        for layer in layers_module.LAYERS.values()
    ]


def is_covered(results: dict[str, LayerResult], technique_id: str) -> bool:
    return any(
        (c := results[layer.id].cells.get(technique_id)) is not None and c.status in COVERED
        for layer in layers_module.LAYERS.values()
        if layer.kind == "coverage"
    )


def is_exposed(results: dict[str, LayerResult], technique_id: str) -> bool:
    return any(
        technique_id in results[layer.id].cells
        for layer in layers_module.LAYERS.values()
        if layer.kind == "exposure"
    )


def covered_ids(results: dict[str, LayerResult]) -> set[str]:
    return {
        technique_id
        for layer in layers_module.LAYERS.values()
        if layer.kind == "coverage"
        for technique_id in results[layer.id].technique_ids
    }


def exposed_ids(results: dict[str, LayerResult]) -> set[str]:
    return {
        technique_id
        for layer in layers_module.LAYERS.values()
        if layer.kind == "exposure"
        for technique_id in results[layer.id].technique_ids
    }


def build_matrix(db: Session) -> dict[str, Any]:
    """Матрица целиком: смысл её в том, чтобы видеть незакрытое.

    Подтехники не разворачиваются: их 475 против 222 родительских, и в
    матрице они дают колонки высотой в экран. Слои засчитывают разметку
    подтехникой её родителю сами.
    """
    book = current_bundle(db)
    stats = prevalence_for(db)
    ru = ru_layer(db)
    results = collect(db)
    by_tactic: dict[str, list[dict[str, Any]]] = {t.shortname: [] for t in book.tactics}
    for technique in book.parents_only():
        tid = technique.technique_id
        stat = stats.stats.get(tid)
        covered = is_covered(results, tid)
        exposed = is_exposed(results, tid)
        cell = {
            "technique_id": tid,
            "name": technique.name,
            "name_ru": technique.name_ru,
            "subtechnique_count": len(book.children_of(tid)),
            # Уровень 0..4 для наложения. Ноль означает «данных нет»,
            # а не «редко»: у техник разведки нулевая телеметрия — это
            # свойство сенсора, а не редкость приёма.
            "level": stats.level(tid),
            "actor_groups": stat.groups if stat else 0,
            "campaigns": stat.campaigns if stat else 0,
            "sightings": stat.sightings if stat else 0,
            # Применяемость здесь — отдельная величина, а не поправка
            # к мировой. Складывать их в один балл значит скрыть, почему
            # техника поднялась; пусто, пока выгрузку не загрузили.
            "ru": ru_cell(ru, tid, folded=True),
            "layers": {
                lid: cell_json(results[lid].cells.get(tid), with_items=False)
                for lid in layers_module.LAYERS
            },
            "covered": covered,
            # Пробел, у которого есть экспозиция, весит больше пробела
            # вообще: техника не закрыта, и в инфраструктуре есть чем её
            # выполнить.
            "gap": exposed and not covered,
        }
        for tactic in technique.tactics:
            if tactic in by_tactic:
                by_tactic[tactic].append(cell)
    return {
        "attack_version": book.version,
        "sightings_window": stats.sightings_window,
        # Чьи это данные и когда загружены. Показывать чужую аналитику
        # как безымянный факт нельзя.
        "ru_source": ru_source(ru),
        "layers": layers_json(results),
        "tactics": [
            {
                "shortname": t.shortname,
                "name": t.name,
                "techniques": by_tactic[t.shortname],
                "covered": sum(1 for c in by_tactic[t.shortname] if c["covered"]),
                "gaps": sum(1 for c in by_tactic[t.shortname] if c["gap"]),
                # Тактика, не закрытая ничем, — качественно иное
                # состояние, чем пробел внутри закрытой тактики: целый
                # шаг атаки проходит незамеченным. Пустая колонка при
                # этом не слепая: покрывать в ней нечего.
                "blind": bool(by_tactic[t.shortname])
                and not any(c["covered"] for c in by_tactic[t.shortname]),
                # Разведку и подготовку ресурсов сенсоры не видят
                # по своей природе, и требовать правил на них нельзя.
                "observable": t.shortname not in UNOBSERVABLE_TACTICS,
            }
            for t in book.tactics
        ],
    }
