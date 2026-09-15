"""Массовая вставка: COPY на Postgres, executemany на остальном.

Импорт пишет миллионы пар; построчный INSERT на них — часы. COPY — минуты.
SQLite COPY не умеет — если базу переключили на него вручную, остаётся
обычный executemany.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from sqlalchemy import Table, insert
from sqlalchemy.orm import Session


def bulk_insert(db: Session, table: Table, columns: Sequence[str], rows: Iterable[Sequence[Any]]) -> int:
    rows = list(rows)
    if not rows:
        return 0
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        raw = db.connection().connection.driver_connection
        assert raw is not None
        cols = ", ".join(f'"{c}"' for c in columns)
        with raw.cursor() as cur, cur.copy(f'COPY "{table.name}" ({cols}) FROM STDIN') as copy:
            for row in rows:
                copy.write_row(row)
        return len(rows)
    db.execute(insert(table), [dict(zip(columns, row, strict=True)) for row in rows])
    return len(rows)
