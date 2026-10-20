"""Границы ночного окна Threat Hunting.

Решение владельца: ночь — это 24 часа, заканчивающиеся в час начала окна
расписания по поясу инсталляции (`STOOLS_TZ`), а не в момент фактического
старта. Опоздавший прогон (API был выключен, очередь занята большим хантом)
всё равно ищет свои сутки, поэтому границы считаются от даты ночи, а не от
«сейчас».

В ночь перехода на летнее или зимнее время окно длится 23 или 25 часов:
границы — местный час окна, поэтому соседние ночи стыкуются без пропусков
и перекрытий.
"""
from __future__ import annotations

import datetime as dt
from zoneinfo import ZoneInfo


def _local_at(day: dt.date, hhmm: str, tz: str) -> dt.datetime:
    hour, minute = (int(part) for part in hhmm.split(":"))
    return dt.datetime.combine(day, dt.time(hour, minute), tzinfo=ZoneInfo(tz))


def nightly_window(target_date: dt.date, window_from: str, tz: str) -> tuple[dt.datetime, dt.datetime]:
    """(накануне в `window_from`, `target_date` в `window_from`) по поясу `tz`, в UTC."""
    start = _local_at(target_date - dt.timedelta(days=1), window_from, tz)
    end = _local_at(target_date, window_from, tz)
    return start.astimezone(dt.UTC), end.astimezone(dt.UTC)


def target_date_for(now: dt.datetime, window_from: str, tz: str) -> dt.date:
    """Дата последней ночи, чьё окно уже наступило к `now`: до часа окна — ещё вчерашняя."""
    local = now.astimezone(ZoneInfo(tz))
    day = local.date()
    return day if local >= _local_at(day, window_from, tz) else day - dt.timedelta(days=1)
