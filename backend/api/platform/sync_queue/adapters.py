"""Reuse module launchers and normalize their job records for the queue."""
import datetime as dt
from dataclasses import dataclass
from typing import Any

from fastapi.encoders import jsonable_encoder
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.jobs import JobHandle, run_job, start_job

from .catalog import Task
from .models import SyncJob, SyncStep


class SourceUnavailable(ValueError):
    """Saved source configuration cannot currently launch an update."""


@dataclass(frozen=True)
class JobRef:
    model: str
    id: int


@dataclass(frozen=True)
class JobState:
    status: str
    message: str = ""
    finished_at: dt.datetime | None = None
    result: dict[str, Any] | None = None


def job_models() -> dict[str, type[Any]]:
    from api.db.models import Job
    from api.modules.ad.models import AdJob
    from api.modules.assets.models import AssetJob
    from api.modules.attack.models import AttackJob
    from api.modules.ksc.models import KscJob
    from api.modules.siem.logons.models import SiemLogonJob
    from api.modules.vm.models import VmJob
    return {model.__tablename__: model for model in (Job, AdJob, KscJob, VmJob, AssetJob, AttackJob, SiemLogonJob, SyncJob)}


def task_model(task: Task) -> type[Any]:
    from api.db.models import Job
    from api.modules.ad.models import AdJob
    from api.modules.assets.models import AssetJob
    from api.modules.attack.models import AttackJob
    from api.modules.ksc.models import KscJob
    from api.modules.siem.logons.models import SiemLogonJob
    from api.modules.vm.models import VmJob
    return {"ad": AdJob, "ksc": KscJob, "vm": VmJob, "assets": AssetJob, "attack": AttackJob,
            "siem": SiemLogonJob if task.kind == "logons" else Job, "platform": SyncJob}[task.module]


def job_state(db: Session, ref: JobRef) -> JobState:
    model = job_models().get(ref.model)
    row = db.get(model, ref.id, populate_existing=True) if model is not None else None
    if row is None:
        return JobState("failed", "Запись выполнявшейся задачи отсутствует")
    status = row.status
    result = getattr(row, "result", None)
    if status == "done" and isinstance(result, dict):
        if result.get("status") in ("failed", "partial", "cancelled"):
            status = result["status"]
        elif result.get("complete") is False:
            status = "partial"
    return JobState(status, getattr(row, "error", None) or getattr(row, "message", "") or "",
                    getattr(row, "finished_at", None), result)


def start_task(db: Session, task: Task, actor: str, options: dict[str, Any]) -> JobRef | None:
    from api import collector_routes
    from api.platform.scheduler import PlatformSchedule, _handlers

    job_id: int | None
    if task.module == "assets" and task.kind in ("dns", "rt"):
        from api.modules.assets.models import AssetDns, AssetRacktables
        source = db.get(AssetDns, task.target_id) if task.kind == "dns" else db.get(AssetRacktables, task.target_id)
        if source is None or not source.enabled:
            raise SourceUnavailable("Источник отключён или удалён; проверьте настройки подключения")

    if task.module == "platform":
        platform_job_id = start_job(db, SyncJob, task.kind, actor)
        def work(session: Session, handle: JobHandle) -> None:
            if task.kind == "storage":
                from api.platform.storage_usage.service import measure
                result = measure(session)
            elif task.kind == "assets_read_refresh":
                from api.platform.read_model_jobs import run
                result = run(session, handle)
            else:
                from api.platform import storage_retention
                preview_id = options.get("preview_id")
                if not preview_id:
                    preview_id = storage_retention.preview(session)["preview_id"]  # type: ignore[no-untyped-call]
                result = storage_retention.run(session, preview_id)  # type: ignore[no-untyped-call]
            row = session.get(SyncJob, handle.id)
            assert row is not None
            row.result = jsonable_encoder(result)
            session.commit()
        collector_routes.spawn(lambda: run_job(SyncJob, platform_job_id, work))
        return JobRef(SyncJob.__tablename__, platform_job_id)

    if task.key == "vm/trends_pull/0" and options:
        from fastapi import HTTPException

        from api.modules.vm.services.trends.sync import start_trend_sync
        try:
            job_id = start_trend_sync(db, actor, collector_routes.spawn, **options)
        except HTTPException as exc:
            if exc.status_code == 409:
                return None
            raise
    elif task.module == "vm" and task.kind.startswith("ref_"):
        from fastapi import HTTPException

        from api.modules.vm.routers.refs import start_download
        try:
            job_id = start_download(db, actor, collector_routes.spawn, name=task.kind[4:], **options)
        except HTTPException as exc:
            if exc.status_code == 409:
                return None
            raise
    else:
        handler = _handlers.get((task.module, task.kind))
        if handler is None:
            raise ValueError("Обработчик задачи не зарегистрирован")
        # A transient schedule supplies identity without modifying the user's timing settings.
        schedule = PlatformSchedule(module=task.module, kind=task.kind, target_id=task.target_id,
                                    interval_hours=24, enabled=True)
        job_id = handler(db, schedule)
        if not schedule.enabled:
            raise SourceUnavailable("Источник не настроен или отключён; проверьте настройки подключения")
        if job_id is None:
            return None
    assert job_id is not None
    model = task_model(task)
    row = db.get(model, job_id)
    if row is not None and hasattr(row, "started_by"):
        row.started_by = actor
        db.commit()
    return JobRef(model.__tablename__, job_id)


def data_key(task: Task) -> str | None:
    keys = {
        ("ad", "collect"): f"conn:{task.target_id}", ("ksc", "collect"): f"conn:{task.target_id}",
        ("assets", "dns"): f"dns:{task.target_id}", ("assets", "rt"): f"racktables:{task.target_id}",
        ("assets", "sync"): "sync", ("vm", "import_vm"): "import", ("vm", "harbor"): "harbor",
        ("siem", "kb_collect"): "kb-connection",
    }
    return f"ref:{task.kind[4:]}" if task.module == "vm" and task.kind.startswith("ref_") else keys.get((task.module, task.kind))


def observations(db: Session, tasks: list[Task]) -> dict[str, dt.datetime | None]:
    """One provider call per module even when it has many configured connections."""
    from sqlalchemy import func

    from api.platform.data_status import _PROVIDERS

    keys = [task.key for task in tasks]
    stamps: dict[str, dt.datetime | None] = dict(db.execute(select(SyncStep.key, func.max(SyncStep.checked_at))
                  .where(SyncStep.key.in_(keys), SyncStep.status == "done").group_by(SyncStep.key)).tuples().all())
    for module in {task.module for task in tasks if data_key(task) is not None}:
        provider = _PROVIDERS.get(module)
        if provider is None:
            continue
        try:
            with db.begin_nested():
                values = {item.key: item for item in provider(db)}
        except Exception:  # noqa: BLE001 — failed providers cannot establish fresh data
            for task in tasks:
                if task.module == module:
                    stamps[task.key] = None
            continue
        for task in tasks:
            if task.module != module:
                continue
            provider_key = data_key(task)
            if provider_key is None:
                continue
            item = values.get(provider_key)
            if item is None or item.updated_at is None or item.state == "running":
                stamps[task.key] = None
            elif item.updated_at is not None:
                source = item.updated_at
                if source.tzinfo is None:
                    source = source.replace(tzinfo=dt.UTC)
                previous = stamps.get(task.key)
                if previous is None or source > previous:
                    stamps[task.key] = source
    # A partial/failed refresh may update the provider timestamp without producing a complete source.
    incomplete = db.execute(select(SyncStep.key, func.max(SyncStep.finished_at))
        .where(SyncStep.key.in_(keys), SyncStep.status.in_(("failed", "partial")), SyncStep.job_id.is_not(None))
        .group_by(SyncStep.key)).all()
    for key, failed_at in incomplete:
        if failed_at is not None and stamps.get(key) is not None and stamps[key] <= failed_at:
            stamps[key] = None
    return stamps


def observed_at(db: Session, task: Task) -> dt.datetime | None:
    return observations(db, [task]).get(task.key)
