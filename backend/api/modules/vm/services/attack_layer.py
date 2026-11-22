"""Экспозиция VM: пары хост–CVE с риском не ниже порога → техники.

Считается не на заход на матрицу, а после пересчёта риска и после загрузки
справочника CTID: меняется слой ровно тогда же, когда меняется риск.
Смена порога тоже пересчитывает — её видно по несовпадению порога в кэше.

Пары со статусом, который не учитывается (настройка платформы `counted`,
по умолчанию «Принят риск», «Ложное срабатывание», «Устранена»), в слой не
входят. Смена статуса или настройки делает кэш устаревшим: в нём хранится
отметка состояний VM (`_state_mark`), и несовпадение пересчитывает слой.

Считает СУБД: пар миллионы, выше порога — сотни тысяч, и тащить их в
процесс незачем. Правило по вектору живёт в `attack_map.technique_for`
как читаемое определение, а здесь повторено выражением `CASE`; что они
совпадают, проверяет тест `test_sql_case_matches_the_python_rule`.
"""
from __future__ import annotations

import datetime as dt
import json
from collections import defaultdict
from typing import Any

from sqlalchemy import SQLColumnExpression, Subquery, and_, case, false, func, select
from sqlalchemy.orm import Session
from sqlalchemy.sql import ColumnElement

from api.db.models import AppSetting
from api.modules.attack.layers import (
    MAX_ITEMS,
    Layer,
    LayerCell,
    LayerItem,
    LayerResult,
    parent_of,
)
from api.modules.vm.models import VmCve, VmRefAttack, VmZone
from api.modules.vm.risk_models import RiskHost as VmHost
from api.modules.vm.risk_models import RiskHostCve as VmHostCve
from api.modules.vm.services.query import (
    MODULE,
    SCOPE,
    ST,
    StatusFilter,
    state_on,
    status_conditions,
)
from api.modules.vm.services.settings import load_settings
from api.modules.vm.services.stats import lock_cache_row
from api.platform.findings import service as finding_svc
from api.platform.findings.models import FindingEvent, FindingState

CACHE_KEY = "vm.attack_layer"


def _or_none(col: SQLColumnExpression[str | None]) -> ColumnElement[str]:
    """`v3_pr or "NONE"` в SQL: и NULL, и пустая строка значат «нет»."""
    return case((and_(col.is_not(None), col != ""), col), else_="NONE")


def _rule(
    av: SQLColumnExpression[str | None],
    pr_none: SQLColumnExpression[bool],
    ui_required: SQLColumnExpression[bool],
    internet: SQLColumnExpression[bool],
) -> ColumnElement[str]:
    """Тело `technique_for` после того, как вектор выбран (v3 или v2)."""
    return case(
        (
            av == "NETWORK",
            case(
                (ui_required, "T1203"),
                (and_(pr_none, internet), "T1190"),
                else_="T1210",
            ),
        ),
        (av == "ADJACENT_NETWORK", "T1557"),
        else_="T1068",
    )


def _technique_expr() -> ColumnElement[str | None]:
    """Техника пары: размётка CTID, иначе правило по вектору, иначе NULL.

    Размётка замещает правило целиком — там, где человек разобрал CVE
    руками, догадка по вектору только мешает; LEFT JOIN даёт по строке на
    каждую размеченную технику и одну строку с NULL, если размётки нет.
    """
    internet = VmZone.internet_access
    return func.coalesce(
        VmRefAttack.technique_id,
        case(
            (
                and_(VmCve.v3_av.is_not(None), VmCve.v3_av != ""),
                _rule(
                    VmCve.v3_av,
                    _or_none(VmCve.v3_pr) == "NONE",
                    _or_none(VmCve.v3_ui) == "REQUIRED",
                    internet,
                ),
            ),
            (
                and_(VmCve.v2_av.is_not(None), VmCve.v2_av != ""),
                # У v2 нет UI, а «требуется аутентификация» — это PR выше NONE.
                _rule(VmCve.v2_av, _or_none(VmCve.v2_au) == "NONE", false(), internet),
            ),
        ),
    )


def _counted(counted: frozenset[str] | None) -> list[ColumnElement[bool]]:
    """Условия «статус пары учитывается»; None — все пары."""
    return [] if counted is None else status_conditions(StatusFilter(statuses=counted))


def _state_mark(db: Session) -> str:
    """Отметка состояний VM и настройки `counted`. Любая смена статуса пары — ручная, массовая
    или системная — пишет событие истории, поэтому отметка — последнее событие области VM:
    растёт с каждой сменой и не зависит от совпадения времени двух правок."""
    last = db.scalar(
        select(FindingEvent.id).join(FindingState, FindingState.id == FindingEvent.state_id)
        .where(FindingState.module == MODULE, FindingState.scope_id == SCOPE)
        .order_by(FindingEvent.id.desc()).limit(1)
    )
    return f"{','.join(sorted(finding_svc.counted_statuses(db)))}|{last or 0}"


def _exposure(threshold: int, counted: frozenset[str] | None = None) -> Subquery:
    """Пары выше порога с техникой: `technique` может быть NULL (вектора нет).
    `counted` — учитываемые статусы пар; None — все пары."""
    stmt = (
        select(
            _technique_expr().label("technique"),
            VmHostCve.host_id.label("host_id"),
            VmHostCve.cve_id.label("cve_id"),
            VmHostCve.risk.label("risk"),
            VmHost.hostname.label("hostname"),
            VmHost.zone.label("zone"),
        )
        .select_from(VmHostCve)
        .join(VmHost, VmHost.id == VmHostCve.host_id)
        .join(VmCve, VmCve.cve_id == VmHostCve.cve_id)
        # Зона без разметки — не «смотрит наружу»: NULL в условии не истина.
        .outerjoin(VmZone, VmZone.name == VmHost.zone)
        .outerjoin(VmRefAttack, VmRefAttack.cve_id == VmHostCve.cve_id)
        .where(VmHostCve.risk >= threshold)
    )
    if counted is not None:
        stmt = stmt.outerjoin(ST, state_on()).where(*_counted(counted))
    return stmt.subquery("exposure")


def compute(db: Session) -> dict[str, Any]:
    threshold = load_settings(db).attack_min_risk
    counted = finding_svc.counted_statuses(db)
    mark = _state_mark(db)
    pairs = int(
        db.execute(
            select(func.count()).select_from(VmHostCve)
            .join(VmHost, VmHost.id == VmHostCve.host_id)
            .outerjoin(ST, state_on())
            .where(VmHostCve.risk >= threshold, *_counted(counted))
        ).scalar() or 0
    )
    sub = _exposure(threshold, counted)
    marked = sub.c.technique.is_not(None)

    hosts: dict[str, set[int]] = defaultdict(set)
    ids: set[str] = set()
    # Хост × техника, а не пара × техника: строк тысячи, а не миллионы.
    for technique, host_id in db.execute(
        select(sub.c.technique, sub.c.host_id).where(marked).distinct()
    ):
        ids.add(technique)
        hosts[parent_of(technique)].add(host_id)

    # Двадцать строк карточки отбираются по родительской технике, а не по
    # подтехнике: ячейка у них одна, и делить двадцатку на каждую подтехнику
    # значит считать не то. Идентификатор техники — «T» и четыре цифры,
    # поэтому родитель — первые пять символов; `substr` понимают и SQLite,
    # и Postgres, разбирать строку в Python ради этого незачем.
    #
    # Ранг плотный, а не порядковый: одна и та же пара, размеченная двумя
    # подтехниками одного родителя, даёт две строки с одинаковым ключом
    # порядка, и плотный ранг считает их за одну. С порядковым дубликаты
    # занимали бы места в двадцатке, а после схлопывания карточка
    # оказывалась бы короче двадцати строк.
    rank = (
        func.dense_rank()
        .over(
            partition_by=func.substr(sub.c.technique, 1, 5),
            order_by=(sub.c.risk.desc(), sub.c.host_id, sub.c.cve_id),
        )
        .label("rn")
    )
    ranked = select(sub, rank).where(marked).subquery("ranked")
    items: dict[str, list[dict[str, str]]] = defaultdict(list)
    seen: dict[str, set[tuple[int, str]]] = defaultdict(set)
    for row in db.execute(
        select(ranked)
        .where(ranked.c.rn <= MAX_ITEMS)
        .order_by(ranked.c.risk.desc(), ranked.c.host_id, ranked.c.cve_id)
    ):
        parent = parent_of(row.technique)
        key = (row.host_id, row.cve_id)
        # Подтехники одной техники схлопываются в одну ячейку: пара, попавшая
        # в неё дважды, — одна строка карточки. Длину держит плотный ранг,
        # проверка на MAX_ITEMS остаётся страховкой.
        if key in seen[parent] or len(items[parent]) >= MAX_ITEMS:
            continue
        seen[parent].add(key)
        items[parent].append(
            {
                "title": f"{row.hostname}: {row.cve_id}",
                "subtitle": f"риск {row.risk} · {row.technique}" + (f" · {row.zone}" if row.zone else ""),
                "href": f"/vm/vulns?host={row.host_id}&cve={row.cve_id}",
            }
        )

    return {
        "threshold": threshold,
        "state_mark": mark,
        "pairs": pairs,
        "computed_at": dt.datetime.now(dt.UTC).isoformat(),
        "technique_ids": sorted(ids),
        "cells": {t: {"hosts": len(hosts[t]), "items": items[t]} for t in hosts},
    }


def refresh(db: Session) -> dict[str, Any]:
    row = lock_cache_row(db, CACHE_KEY)
    data = compute(db)
    row.value_json = json.dumps(data, ensure_ascii=False)
    row.updated_at = dt.datetime.now(dt.UTC)
    db.commit()
    return data


def load(db: Session) -> dict[str, Any]:
    row = db.get(AppSetting, CACHE_KEY)
    if row is None or not row.value_json:
        return refresh(db)
    data: dict[str, Any] = json.loads(row.value_json)
    if data.get("threshold") != load_settings(db).attack_min_risk or data.get("state_mark") != _state_mark(db):
        return refresh(db)
    return data


def build(db: Session) -> LayerResult:
    data = load(db)
    # Пусто и хостов нет — модуль не наполняли; пусто при живых хостах —
    # это ответ «выше порога ничего нет», а не отсутствие данных.
    if not data["cells"] and data["pairs"] == 0 and db.execute(select(VmHost.id).limit(1)).first() is None:
        return LayerResult(cells={}, note="выгрузка VM не загружена", available=False)
    cells = {
        t: LayerCell(
            count=c["hosts"],
            items=tuple(LayerItem(i["title"], i["subtitle"], i["href"]) for i in c["items"]),
        )
        for t, c in data["cells"].items()
    }
    return LayerResult(
        cells=cells,
        technique_ids=frozenset(data["technique_ids"]),
        note=f"риск ≥ {data['threshold']}",
    )


LAYER = Layer(id="vm", title="Уязвимости", kind="exposure", unit=("хост", "хоста", "хостов"), build=build)
