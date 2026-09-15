"""Работа с datetime, переносимая между Postgres и SQLite.

Postgres возвращает `TIMESTAMP WITH TIME ZONE` как aware-объект; SQLite
(тесты, `tests/api/`) хранит тот же столбец как наивный — драйвер не несёт
понятия часового пояса. Сравнение aware/naive роняет `TypeError`, поэтому
любое значение, прочитанное из БД, приводится к aware UTC перед сравнением.
"""
from __future__ import annotations

import datetime as dt


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def as_aware_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.UTC)
    return value.astimezone(dt.UTC)
