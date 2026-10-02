"""Ежесуточное истечение принятых рисков (спека §1): расписание платформы `platform/risk_expiry`.

Принятый риск со сроком `risk_until` в прошлом снова становится новой находкой
(`service.expire_risks`, событие `risk_expired`). Работа короткая — строки
состояния с истёкшим сроком, — поэтому идёт прямо в тике планировщика, без
задачи (`jobless`). Расписание заводится при старте API, если его нет; уже
заведённое не трогается: перезапуск не должен сдвигать срок запуска.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_sessionmaker
from api.db.models import _utcnow
from api.platform.findings import service
from api.platform.scheduler import PlatformSchedule, register_schedule_kind, upsert_schedule

MODULE = "platform"
KIND = "risk_expiry"


def run_risk_expiry(db: Session, _sched: PlatformSchedule) -> None:
    service.expire_risks(db, service.today())


register_schedule_kind(MODULE, KIND, run_risk_expiry, jobless=True)


def ensure_risk_expiry_schedule(db: Session) -> PlatformSchedule:
    """Расписание раз в сутки; новое — с запуском на ближайшем тике, а не через сутки после старта."""
    existing = db.scalars(select(PlatformSchedule).where(
        PlatformSchedule.module == MODULE, PlatformSchedule.kind == KIND, PlatformSchedule.target_id == 0,
    )).first()
    if existing is not None:
        return existing
    sched = upsert_schedule(db, module=MODULE, kind=KIND, target_id=0, interval_hours=24,
                            window_from=None, window_to=None, enabled=True)
    sched.next_run_at = _utcnow()
    db.commit()
    return sched


def ensure_platform_schedules() -> None:
    """Для lifespan: расписания платформы, своей сессией."""
    with get_sessionmaker()() as db:
        ensure_risk_expiry_schedule(db)
