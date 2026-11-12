"""Расписания пользовательских синхронизаций. Системные задачи в каталог не входят."""
from dataclasses import dataclass

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.platform.schedule_views import ScheduleIn, schedule_view
from api.platform.scheduler import PlatformSchedule, upsert_schedule
from api.platform.services.access import Access, allows
from api.rbac import current_access
from api.settings import get_settings

router = APIRouter(prefix="/schedules", tags=["settings"])


@dataclass(frozen=True)
class Target:
    kind: str
    id: int
    title: str


def _sources(db: Session, module: str) -> list[Target]:
    if module == "platform":
        return [Target("storage", 0, "Замер объёма хранилища")]
    if module in ("ad", "ksc"):
        from api.modules.ad.models import AdConnection
        from api.modules.ksc.models import KscConnection

        model = AdConnection if module == "ad" else KscConnection
        rows = db.execute(select(model.id, model.title, model.host).order_by(model.id))
        return [Target("collect", id_, title or host) for id_, title, host in rows]
    if module == "assets":
        from api.modules.assets.models import AssetDns, AssetRacktables

        result = [Target("sync", 0, "Синхронизация активов из VM, KSC и AD")]
        for kind, label, model in (("dns", "DNS", AssetDns), ("rt", "RackTables", AssetRacktables)):
            for id_, title in db.execute(select(model.id, model.title).order_by(model.id)):
                result.append(Target(kind, id_, f"{label} · {title or f'#{id_}'}"))
        return result
    if module == "vm":
        from api.modules.vm.services.refs_view import TITLES

        return [Target("import_vm", 0, "Импорт MaxPatrol VM"), Target("harbor", 0, "Синхронизация Harbor"),
                Target("trends_pull", 0, "Получение трендовых уязвимостей"),
                *(Target(f"ref_{name}", 0, title) for name, title in TITLES.items())]
    if module == "siem":
        return [Target("kb_collect", 0, "Сбор базы знаний MaxPatrol SIEM")]
    if module == "attack":
        return [Target("download", 0, "Скачать матрицу MITRE ATT&CK для подтверждения")]
    return []


@router.get("")
def list_schedules(db: Session = Depends(get_db), access: Access = Depends(current_access)):
    modules = [m for m in ("ad", "ksc", "vm", "assets", "siem", "attack", "platform") if allows(access, m, "read")]
    schedules = {(s.module, s.kind, s.target_id): s for s in db.scalars(
        select(PlatformSchedule).where(PlatformSchedule.module.in_(modules)))}
    items = []
    for module in modules:
        for target in _sources(db, module):
            s = schedules.get((module, target.kind, target.id))
            items.append(dict(module=module, kind=target.kind, target_id=target.id, title=target.title,
                              schedule=schedule_view(s) if s else None))
    return {"items": items, "tz": get_settings().tz}


class Timing(ScheduleIn):
    weekdays: list[int] = Field(default_factory=list, max_length=7)
    run_time: str | None = None


def _target(db: Session, module: str, kind: str, target_id: int, access: Access):
    if not allows(access, module, "admin"):
        raise HTTPException(403, "нужны права администратора модуля")
    # Сериализуем создание отсутствующей записи двумя редакторами.
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
               {"key": f"sync_schedule:{module}:{kind}:{target_id}"})
    from api.modules.ad.models import AdConnection
    from api.modules.assets.models import AssetDns, AssetRacktables
    from api.modules.ksc.models import KscConnection

    owners = {("ad", "collect"): AdConnection, ("ksc", "collect"): KscConnection,
              ("assets", "dns"): AssetDns, ("assets", "rt"): AssetRacktables}
    model = owners.get((module, kind))
    if model is not None:
        owner = db.get(model, target_id, with_for_update=True)
        if owner is not None:
            return owner
    elif any(t.kind == kind and t.id == target_id for t in _sources(db, module)):
        return None
    raise HTTPException(404, "задача синхронизации не найдена")


@router.put("/{module}/{kind}/{target_id}")
def save(module: str, kind: str, target_id: int, payload: Timing,
         db: Session = Depends(get_db), access: Access = Depends(current_access)):
    owner = _target(db, module, kind, target_id, access)
    if any(d < 0 or d > 6 for d in payload.weekdays):
        raise HTTPException(422, "дни недели должны быть в диапазоне 0–6")
    days = "".join(str(d) for d in sorted(set(payload.weekdays))) or None
    try:
        schedule = upsert_schedule(db, module=module, kind=kind, target_id=target_id,
                                   interval_hours=payload.interval_hours, window_from=payload.window_from,
                                   window_to=payload.window_to, enabled=payload.enabled, weekdays=days,
                                   run_time=payload.run_time)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    if module == "assets" and owner is not None:
        owner.schedule_id = schedule.id
    db.commit()
    return schedule_view(schedule)


@router.delete("/{module}/{kind}/{target_id}", status_code=204)
def remove(module: str, kind: str, target_id: int, db: Session = Depends(get_db), access: Access = Depends(current_access)):
    owner = _target(db, module, kind, target_id, access)
    schedule = db.scalar(select(PlatformSchedule).filter_by(module=module, kind=kind, target_id=target_id))
    if schedule is not None:
        if module == "assets" and owner is not None:
            owner.schedule_id = None
        db.delete(schedule)
    db.commit()
    return Response(status_code=204)
