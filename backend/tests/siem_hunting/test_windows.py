"""Окно ночного прогона считается от часа расписания в поясе инсталляции, а не от момента старта."""
from __future__ import annotations

import datetime as dt

from api.modules.siem.hunting.windows import nightly_window, target_date_for

UTC = dt.UTC


def test_nightly_window_moscow() -> None:
    start, end = nightly_window(dt.date(2026, 10, 19), "01:00", "Europe/Moscow")
    assert start == dt.datetime(2026, 10, 17, 22, 0, tzinfo=UTC)
    assert end == dt.datetime(2026, 10, 18, 22, 0, tzinfo=UTC)
    assert end.tzinfo is not None and end - start == dt.timedelta(hours=24)
    # Ночь 19-го наступает в 01:00 по Москве, до этого ещё идёт ночь 18-го.
    assert target_date_for(dt.datetime(2026, 10, 18, 22, 30, tzinfo=UTC), "01:00", "Europe/Moscow") == dt.date(2026, 10, 19)
    assert target_date_for(dt.datetime(2026, 10, 18, 21, 30, tzinfo=UTC), "01:00", "Europe/Moscow") == dt.date(2026, 10, 18)
    assert target_date_for(dt.datetime(2026, 10, 19, 12, 0, tzinfo=UTC), "01:00", "Europe/Moscow") == dt.date(2026, 10, 19)
