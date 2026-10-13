"""Таблица соответствий в базе (спека §2): протокол `Aliases` движка поверх `toolbox_alias`.

Таблица читается в память один раз на задание: при скане крупной выгрузки — десятки тысяч значений,
запрос на каждое был бы дороже самого поиска. Окончательные псевдонимы назначаются в `finalize` под
`pg_advisory_xact_lock`, который держится до фиксации транзакции применения: между скан-предложением
и применением другое задание могло записать тот же номер, а файл результата должен совпасть с таблицей.
"""
from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable, Iterator
from itertools import batched
from typing import Any

from sqlalchemy import Select, func, or_, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from api.jobs import INSERT_CHUNK
from api.modules.toolbox.core.scrub.rules import candidate, numbered
from api.modules.toolbox.core.scrub.types import STORED_KINDS, Ctx, Finding
from api.modules.toolbox.models import ToolboxAlias

LOCK = "SELECT pg_advisory_xact_lock(hashtext('toolbox_alias'))"
#: Псевдонимы, которые выдаются по ключу (кандидат по HMAC), а не по номеру.
HASHED = ("ip4", "ip6", "mac", "sid", "secret")
#: Номер нумерованного псевдонима: host-0001, user-0001, word-0001, dom1.example, DOM1.
NUMBER = {
    "host": re.compile(r"host-(\d+)", re.IGNORECASE),
    "user": re.compile(r"user-(\d+)", re.IGNORECASE),
    "word": re.compile(r"word-(\d+)", re.IGNORECASE),
    "domain": re.compile(r"dom(\d+)(?:\.example)?", re.IGNORECASE),
}


def _number(kind: str, alias: str) -> int:
    pattern = NUMBER.get(kind)
    m = pattern.fullmatch(alias) if pattern else None
    return int(m.group(1)) if m else 0


class AliasTaken(ValueError):
    """Псевдоним, заданный человеком, занят другим значением."""


class DbAliases:
    def __init__(self, db: Session, hmac_key: bytes, created_by: str, job_id: int | None, ctx: Ctx) -> None:
        self.db = db
        self.hmac_key = hmac_key
        self.created_by = created_by
        self.job_id = job_id
        self.ctx = ctx
        self._load()

    def _load(self) -> None:
        self.table: dict[tuple[str, str], str] = {}
        self.ids: dict[tuple[str, str], int] = {}
        # Занятость — без учёта регистра: обратный перевод регистр не различает.
        self.owners: dict[tuple[str, str], str] = {}  # (kind, alias.casefold()) → real_key
        self.top: dict[str, int] = {}
        for row_id, kind, key, alias in self.db.execute(
            select(ToolboxAlias.id, ToolboxAlias.kind, ToolboxAlias.real_key, ToolboxAlias.alias)
        ):
            self.table[(kind, key)] = alias
            self.ids[(kind, key)] = row_id
            self.owners[(kind, alias.casefold())] = key
            self.top[kind] = max(self.top.get(kind, 0), _number(kind, alias))
        self.proposed: dict[tuple[str, str], str] = {}
        self.used: dict[tuple[str, str], str] = {}  # предложенные в задании: (kind, alias.casefold()) → key
        self.issued: dict[str, int] = {}

    def reserve(self, triples: Iterable[tuple[str, str, str]]) -> None:
        """Предложения, уже сделанные заданию раньше (находки в базе): новые не должны с ними совпасть."""
        for kind, key, alias in triples:
            self.proposed.setdefault((kind, key), alias)
            self.used[(kind, alias.casefold())] = key
            self.issued[kind] = max(self.issued.get(kind, 0), _number(kind, alias))

    def alias_id(self, kind: str, key: str) -> int | None:
        return self.ids.get((kind, key))

    def get(self, kind: str, key: str) -> str | None:
        return self.table.get((kind, key))

    def _taken(self, kind: str, alias: str, key: str) -> bool:
        folded = (kind, alias.casefold())
        owner = self.owners.get(folded, self.used.get(folded, key))
        return owner != key

    def _next(self, kind: str) -> int:
        n = max(self.top.get(kind, 0), self.issued.get(kind, 0)) + 1
        self.issued[kind] = n
        return n

    def _fresh(self, kind: str, key: str) -> str:
        if kind not in HASHED:
            while True:
                alias = numbered(kind, self._next(kind), key)
                if not self._taken(kind, alias, key):
                    return alias

        def taken(alias: str) -> bool:
            return self._taken(kind, alias, key)

        alias = candidate(kind, key, self.hmac_key, taken, self.ctx)
        # Таблица подсетей даёт адрес без проверки занятости: занят — автозамена по ключу, она проверяет.
        if kind == "ip4" and taken(alias):
            alias = candidate(kind, key, self.hmac_key, taken, dataclasses.replace(self.ctx, subnets=[]))
        return alias

    def propose(self, kind: str, value: str, key: str) -> str:
        if (kind, key) not in self.proposed:
            alias = self._fresh(kind, key)
            self.proposed[(kind, key)] = alias
            self.used[(kind, alias.casefold())] = key
        return self.proposed[(kind, key)]

    def finalize(self, findings: list[Finding]) -> list[Finding]:
        """Под замком таблицы — окончательные псевдонимы включённых находок. Уже записанное значение
        получает псевдоним из таблицы; предложенный номер или адрес, занятый с тех пор другим значением,
        — следующий свободный. Псевдоним, заданный человеком и занятый, — `AliasTaken`. Возвращает
        находки, у которых псевдоним изменился; замок держится до конца транзакции вызывающего."""
        self.db.execute(text(LOCK))
        self._load()
        changed = []
        mine = [f for f in findings if f.checked and f.kind in STORED_KINDS]
        # Новые номера — после всех предложенных заданию: переназначение одного не задевает другие.
        for f in mine:
            self.issued[f.kind] = max(self.issued.get(f.kind, 0), _number(f.kind, f.alias))
        for f in mine:
            stored = self.table.get((f.kind, f.value_key))
            if stored is not None and stored != f.alias:
                f.alias = stored
                changed.append(f)
        for f in mine:
            if (f.kind, f.value_key) in self.table:
                continue
            if self._taken(f.kind, f.alias, f.value_key):
                if f.kind not in HASHED and not _number(f.kind, f.alias):
                    raise AliasTaken(f"псевдоним {f.alias} уже занят другим значением ({f.kind})")
                f.alias = self._fresh(f.kind, f.value_key)
                changed.append(f)
            self.used[(f.kind, f.alias.casefold())] = f.value_key
        return changed

    def commit(self, pairs: Iterable[tuple[str, str, str, str]]) -> None:
        rows = [
            {"kind": kind, "real_key": key, "real": real, "alias": alias, "created_by": self.created_by,
             "first_job_id": self.job_id}
            for kind, key, real, alias in pairs if kind in STORED_KINDS
        ]
        for chunk in batched(rows, INSERT_CHUNK):
            # Под замком finalize чужой записи того же значения быть не может; DO NOTHING — на случай
            # вызова без finalize: записанное значение сохраняет прежний псевдоним.
            stmt = (insert(ToolboxAlias).values(list(chunk))
                    .on_conflict_do_nothing(index_elements=["kind", "real_key"])
                    .returning(ToolboxAlias.id, ToolboxAlias.kind, ToolboxAlias.real_key, ToolboxAlias.alias))
            for row_id, kind, key, alias in self.db.execute(stmt):
                self.table[(kind, key)] = alias
                self.ids[(kind, key)] = row_id
                self.owners[(kind, alias.casefold())] = key


def _filtered(q: str, kind: str | None) -> Select[tuple[ToolboxAlias]]:
    """Отбор списка и выгрузки — один, чтобы выгрузилось ровно то, что видно на экране."""
    stmt = select(ToolboxAlias)
    if kind:
        stmt = stmt.where(ToolboxAlias.kind == kind)
    if q:
        needle = q.lower()
        stmt = stmt.where(or_(func.lower(ToolboxAlias.real).contains(needle, autoescape=True),
                              func.lower(ToolboxAlias.alias).contains(needle, autoescape=True)))
    return stmt


def list_aliases(db: Session, *, q: str, kind: str | None, limit: int, offset: int) -> tuple[list[ToolboxAlias], int]:
    stmt = _filtered(q, kind)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(ToolboxAlias.kind, ToolboxAlias.id).limit(limit).offset(offset)).all()
    return list(rows), int(total)


def forget_alias(db: Session, alias_id: int) -> None:
    row = db.get(ToolboxAlias, alias_id)
    if row is None:
        raise LookupError("запись не найдена")
    db.delete(row)
    db.commit()


def export_rows(db: Session, *, q: str, kind: str | None) -> Iterator[dict[str, Any]]:
    """Строки выгрузки по тем же фильтрам, что у списка; партиями — таблица бывает большой."""
    stmt = _filtered(q, kind).order_by(ToolboxAlias.kind, ToolboxAlias.id)
    for a in db.scalars(stmt).yield_per(1000):
        yield {"kind": a.kind, "real": a.real, "alias": a.alias, "created_at": a.created_at,
               "created_by": a.created_by, "first_job_id": a.first_job_id}
