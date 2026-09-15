"""Применяемость техник в России рядом с мировыми данными MITRE.

Два источника меряют разное и не складываются в один балл. MITRE считает,
сколько мировых группировок и кампаний применяют технику; выгрузка Bi.Zone
показывает, что видели здесь. Техника, которой в мировой статистике нет
вовсе, может быть рабочим инструментом группировок, которые ходят именно
сюда — и наоборот.

Отсюда четыре состояния вместо двух флагов. «Только мир» не значит
«здесь не применяют», а «только здесь» не значит «в мире не применяют»:
и то и другое означает лишь, что источник об этом не отчитывался.
"""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from api.db.models import RuTtpImport, RuTtpProcedure
from api.modules.attack.services.attack_bundle import current as current_bundle
from kbaudit.attack.prevalence import load_revoked, migrate
from kbaudit.attack.ru_ttp import ParsedRuTtp

#: Состояния техники в двух источниках.
STATE_BOTH = "both"
STATE_RU_ONLY = "ru_only"
STATE_WORLD_ONLY = "world_only"
STATE_NONE = "none"


class Usage(BaseModel):
    """Что известно о применении техники здесь."""

    actors: list[str] = Field(default_factory=list)
    malware: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    procedures: int = 0
    #: Процедур с конкретной командой. Это и есть материал для правила.
    commands: int = 0


class RuTtp(BaseModel):
    """Слой применяемости целиком, как он лежит в базе."""

    #: Пусто, если выгрузку не загружали. Законное состояние: без неё
    #: продукт работает и ведёт себя как раньше.
    present: bool = False
    source: str = ""
    imported_by: str | None = None
    imported_at: dt.datetime | None = None
    attack_version: str | None = None
    row_count: int = 0
    unknown: list[str] = Field(default_factory=list)
    #: Как в файле — вид для карточки техники, где подтехники сравнивают
    #: между собой.
    raw: dict[str, Usage] = Field(default_factory=dict)
    #: С подтехниками, свёрнутыми в родителя, — вид для матрицы, где
    #: подтехник нет как отдельных клеток.
    folded: dict[str, Usage] = Field(default_factory=dict)

    def usage(self, technique_id: str, folded: bool = False) -> Usage | None:
        return (self.folded if folded else self.raw).get(technique_id)


def _merge(into: Usage, other: Usage) -> None:
    for name in other.actors:
        if name not in into.actors:
            into.actors.append(name)
    for name in other.malware:
        if name not in into.malware:
            into.malware.append(name)
    for name in other.tools:
        if name not in into.tools:
            into.tools.append(name)
    into.procedures += other.procedures
    into.commands += other.commands


#: Разобранный слой и отпечаток загрузки, на которой он посчитан. Строк
#: тринадцать тысяч, а матрица открывается часто: разбирать их заново на
#: каждый запрос значит платить за неизменные данные.
#:
#: В отпечаток входит дата загрузки, а не только идентификатор: таблица
#: при замене очищается целиком, и в SQLite идентификатор начинается
#: заново — без даты новая выгрузка того же размера попала бы в кеш
#: предыдущей.
_cache: tuple[tuple[int, dt.datetime | None, int], RuTtp] | None = None


def layer(db: Session) -> RuTtp:
    """Слой применяемости для действующей матрицы."""
    global _cache
    last = db.query(RuTtpImport).order_by(RuTtpImport.id.desc()).first()
    if last is None:
        return RuTtp()
    key = (last.id, last.imported_at, db.query(func.count(RuTtpProcedure.id)).scalar() or 0)
    if _cache is not None and _cache[0] == key:
        return _cache[1]

    raw: dict[str, Usage] = {}
    for row in db.query(RuTtpProcedure).all():
        entry = raw.setdefault(row.technique_id, Usage())
        _merge(
            entry,
            Usage(
                actors=json.loads(row.actors_json or "[]"),
                malware=json.loads(row.malware_json or "[]"),
                tools=json.loads(row.tools_json or "[]"),
                procedures=1,
                commands=1 if (row.command_line or "").strip() else 0,
            ),
        )

    folded: dict[str, Usage] = {}
    for technique_id, usage in raw.items():
        for target in {technique_id, technique_id.split(".")[0]}:
            _merge(folded.setdefault(target, Usage()), usage)

    built = RuTtp(
        present=True,
        source=last.source,
        imported_by=last.imported_by,
        imported_at=last.imported_at,
        attack_version=last.attack_version,
        row_count=last.row_count,
        unknown=json.loads(last.unknown_json or "[]"),
        raw=raw,
        folded=folded,
    )
    _cache = (key, built)
    return built


def import_ru_ttp(
    db: Session, parsed: ParsedRuTtp, source: str, login: str | None
) -> dict[str, object]:
    """Заменить слой содержимым разобранной выгрузки.

    Заменить, а не дополнить: выгрузка — один документ на дату. Слияние
    двух её версий дало бы картину, которой нет ни в одной из них.
    """
    global _cache
    book = current_bundle(db)
    live = {t.technique_id for t in book.techniques}
    replaced = load_revoked()

    db.query(RuTtpProcedure).delete()
    db.query(RuTtpImport).delete()

    unknown: set[str] = set()
    moved = 0
    kept = 0
    techniques: set[str] = set()
    for row in parsed.rows:
        resolved = migrate(row.technique_id, replaced, live)
        if resolved is None:
            unknown.add(row.technique_id)
            continue
        if resolved != row.technique_id:
            moved += 1
        kept += 1
        techniques.add(resolved)
        db.add(
            RuTtpProcedure(
                technique_id=resolved,
                technique_name=row.technique_name[:255],
                procedure=row.procedure,
                command_line=row.command_line,
                actors_json=json.dumps(row.actors, ensure_ascii=False),
                malware_json=json.dumps(row.malware, ensure_ascii=False),
                tools_json=json.dumps(row.tools, ensure_ascii=False),
            )
        )

    db.add(
        RuTtpImport(
            source=source[:255],
            imported_by=login,
            imported_at=dt.datetime.now(dt.UTC),
            attack_version=book.version,
            row_count=kept,
            technique_count=len(techniques),
            unknown_json=json.dumps(sorted(unknown)),
        )
    )
    db.commit()
    _cache = None
    return {
        "rows": kept,
        "techniques": len(techniques),
        "without_technique": parsed.without_technique,
        "moved": moved,
        "unknown": sorted(unknown),
        "columns": parsed.columns,
        "attack_version": book.version,
    }


def drop(db: Session) -> None:
    """Снять слой. Разметки и мировых данных это не касается."""
    global _cache
    db.query(RuTtpProcedure).delete()
    db.query(RuTtpImport).delete()
    db.commit()
    _cache = None


def state_of(technique_id: str, ru: RuTtp, world: bool) -> str:
    """Состояние техники в двух источниках."""
    here = technique_id in ru.raw
    if here and world:
        return STATE_BOTH
    if here:
        return STATE_RU_ONLY
    return STATE_WORLD_ONLY if world else STATE_NONE


# ---- Представление слоя: одно и то же в матрице и на странице слоя -------


def ru_cell(ru: RuTtp, technique_id: str, folded: bool = False) -> dict[str, Any] | None:
    """Применяемость техники здесь — или пусто, если выгрузки нет.

    Пусто, а не нули: ноль читается как «здесь не применяют», хотя на
    самом деле никто не отчитывался.
    """
    usage = ru.usage(technique_id, folded=folded)
    if usage is None:
        return None
    return {
        "actors": len(usage.actors),
        "malware": len(usage.malware),
        "tools": len(usage.tools),
        "procedures": usage.procedures,
        "commands": usage.commands,
        # Имена нужны в подсказке: «замечено у 11 группировок» без имён
        # проверить нельзя, а проверять придётся.
        "actor_names": usage.actors[:12],
    }


def ru_actors(ru: RuTtp, technique_id: str) -> int:
    """Сколько группировок применяли технику здесь."""
    usage = ru.usage(technique_id)
    return len(usage.actors) if usage else 0


def ru_source(ru: RuTtp) -> dict[str, Any] | None:
    """Происхождение слоя: чей файл, когда, на какой версии матрицы."""
    if not ru.present:
        return None
    return {
        "source": ru.source,
        "imported_at": ru.imported_at.isoformat() if ru.imported_at else None,
        "imported_by": ru.imported_by,
        "attack_version": ru.attack_version,
        "row_count": ru.row_count,
    }
