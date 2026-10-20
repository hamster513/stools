"""Настройки Threat Hunting в `app_setting['siem_th']` и ночное расписание.

Окно ночного прогона живёт в двух местах: человек видит его в настройках
раздела, а запускает прогон платформенный планировщик по строке
`platform_schedule`. Чтобы они не расходились, сохранение настроек
обновляет и расписание в той же транзакции. Человек задаёт только время
старта; конец окна для планировщика выводится из него (`window_end`).
"""
from __future__ import annotations

import datetime as dt
import json
import re
from typing import Annotated

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.models import AppSetting
from api.llm_settings import read_setting
from api.modules.siem.hunting.windows import window_end
from api.platform.scheduler import PlatformSchedule, next_run, upsert_schedule
from api.settings import get_settings
from api.timeutil import as_aware_utc, utcnow

TH_KEY = "siem_th"
SCHEDULE_MODULE = "siem"
SCHEDULE_KIND = "th_nightly"
SCHEDULE_TARGET = 1
#: Раз в сутки: окно задаёт час, интервал — период.
SCHEDULE_INTERVAL_H = 24
#: Диспетчер очереди раздела: подбирает задачи, оставшиеся после перезапуска, и чистит события по сроку.
DISPATCH_KIND = "th_dispatch"
DISPATCH_INTERVAL_H = 1

_HHMM = re.compile(r"([01]\d|2[0-3]):[0-5]\d")


class ThSettings(BaseModel):
    nightly_enabled: bool = True
    window_from: str = "01:00"
    #: Пауза между хантами ночного прогона — не нагружать MaxPatrol; запросы одного ханта идут подряд.
    hunt_pause_s: int = Field(default=30, ge=1)
    request_timeout_s: int = Field(default=300, ge=1)
    #: Пауза в минутах перед каждым повтором упавшего запроса; длина списка — число повторов.
    retry_minutes: list[Annotated[int, Field(ge=1, le=1440)]] = Field(
        default_factory=lambda: [10, 20, 30, 30, 30, 30, 30], min_length=1, max_length=20,
    )
    #: Через сколько часов от начала окна незавершённый прогон снимается.
    nightly_deadline_h: int = Field(default=20, ge=1)
    default_limit: int = Field(default=5000, ge=1, le=100000)
    #: Горячие сутки: свежие дни, где события ещё в быстром хранилище.
    hot_days: int = Field(default=7, ge=1)
    slice_hours: int = Field(default=3, ge=1)
    slice_pause_s: int = Field(default=5, ge=1)
    default_depth_months: int = Field(default=3, ge=1, le=36)
    retention_days: int = Field(default=180, ge=1)

    @field_validator("window_from")
    @classmethod
    def check_time(cls, value: str) -> str:
        if not _HHMM.fullmatch(value):
            raise ValueError("время в формате ЧЧ:ММ (00:00–23:59)")
        return value


def migrate_legacy_json(raw: str) -> str:
    """Старые ключи настроек в новые: `query_pause_s` → `hunt_pause_s`, `window_to` убран (конец
    окна теперь выводится из начала). То же делает миграция c4e8a2d6f1b3 в SQL; здесь — для базы,
    поднятой из копии до миграции. Нечитаемый текст возвращается как есть: его отвергнет pydantic."""
    try:
        data = json.loads(raw)
    except ValueError:
        return raw
    if not isinstance(data, dict):
        return raw
    if "query_pause_s" in data:
        data.setdefault("hunt_pause_s", data.pop("query_pause_s"))
    data.pop("window_to", None)
    return json.dumps(data, ensure_ascii=False)


def load_th_settings(db: Session) -> ThSettings:
    raw = read_setting(db, TH_KEY)
    return ThSettings() if raw is None else ThSettings.model_validate_json(migrate_legacy_json(raw))


def save_th_settings(db: Session, data: ThSettings, login: str) -> ThSettings:
    """Сохранить настройки и привести ночное расписание в соответствие с ними (одна транзакция)."""
    row = db.get(AppSetting, TH_KEY)
    if row is None:
        row = AppSetting(key=TH_KEY)
        db.add(row)
    row.value_json = data.model_dump_json()
    row.updated_at = dt.datetime.now(dt.UTC)
    row.updated_by = login
    ensure_th_schedules(db, data)
    db.commit()
    return data


def ensure_th_schedules(db: Session, data: ThSettings | None = None, *, now: dt.datetime | None = None) -> None:
    """Расписания раздела по настройкам: ночное (окно и выключатель из настроек) и диспетчер
    очереди (раз в час, без окна, всегда включён). Фиксирует вызывающий."""
    data = data or load_th_settings(db)
    now = now or utcnow()
    tz = get_settings().tz
    window_to = window_end(data.window_from)
    nightly = upsert_schedule(
        db,
        module=SCHEDULE_MODULE,
        kind=SCHEDULE_KIND,
        target_id=SCHEDULE_TARGET,
        interval_hours=SCHEDULE_INTERVAL_H,
        window_from=data.window_from,
        window_to=window_to,
        enabled=data.nightly_enabled,
        now=now,
        tz=tz,
    )
    # Платформа считает срок как «сейчас + интервал, потом ближайшее окно»: расписание, созданное
    # днём, впервые сработало бы через ночь, и первая ночь после установки (или смены окна)
    # пропала бы. Срок дальше суток — подтягиваем к ближайшему открытию окна.
    far = now + dt.timedelta(hours=SCHEDULE_INTERVAL_H)
    if nightly.enabled and nightly.next_run_at is not None and as_aware_utc(nightly.next_run_at) > far:
        nightly.next_run_at = next_run(now, 0, data.window_from, window_to, tz)
        db.flush()
    upsert_schedule(
        db,
        module=SCHEDULE_MODULE,
        kind=DISPATCH_KIND,
        target_id=SCHEDULE_TARGET,
        interval_hours=DISPATCH_INTERVAL_H,
        window_from=None,
        window_to=None,
        enabled=True,
        now=now,
    )


def _schedule(db: Session, kind: str) -> PlatformSchedule | None:
    return db.execute(
        select(PlatformSchedule).where(
            PlatformSchedule.module == SCHEDULE_MODULE,
            PlatformSchedule.kind == kind,
            PlatformSchedule.target_id == SCHEDULE_TARGET,
        )
    ).scalar_one_or_none()


def nightly_schedule(db: Session) -> PlatformSchedule | None:
    return _schedule(db, SCHEDULE_KIND)


def dispatch_schedule(db: Session) -> PlatformSchedule | None:
    return _schedule(db, DISPATCH_KIND)
