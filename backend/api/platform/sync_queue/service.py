"""Validation, authorization and durable queue submission; no network work here."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from typing import TYPE_CHECKING, Any

from fastapi import HTTPException
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from api.platform.services.access import Access, allows

from .catalog import Task, authorized, resolve
from .models import SyncRun, SyncStep, SyncTaskConfig

if TYPE_CHECKING:
    from api.platform.scheduler import PlatformSchedule

ACTIVE = ("queued", "running")
SUCCESS = ("done", "fresh")
TERMINAL = ("done", "partial", "failed", "cancelled")


def lock(db: Session) -> None:
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('stools_sync_queue_config'))"))


def configs(db: Session) -> dict[str, list[dict[str, Any]]]:
    return {row.key: row.dependencies for row in db.scalars(select(SyncTaskConfig).limit(10000))}


def validate_graph(graph: dict[str, list[dict[str, Any]]]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()
    def visit(key: str) -> None:
        if key in visiting:
            raise HTTPException(422, "Зависимости образуют цикл")
        if key in visited:
            return
        visiting.add(key)
        if len(visiting) > 64:
            raise HTTPException(422, "Слишком глубокая цепочка зависимостей")
        for edge in graph.get(key, []):
            visit(edge["key"])
        visiting.remove(key)
        visited.add(key)
    for key in graph:
        visit(key)


def save_dependencies(db: Session, key: str, dependencies: list[dict[str, Any]], access: Access) -> list[dict[str, Any]]:
    lock(db)
    task = resolve(db, key)
    authorized(task, access, configure=True)
    normalized: list[dict[str, Any]] = []
    seen = set()
    for edge in dependencies:
        other = resolve(db, edge["key"])
        authorized(other, access)
        if not other.dependency_allowed:
            raise HTTPException(422, "Эта задача не предоставляет данные для зависимостей")
        if other.key in seen:
            raise HTTPException(422, "Зависимость указана дважды")
        seen.add(other.key)
        normalized.append({"key": other.key, "max_age_minutes": edge["max_age_minutes"]})
    graph = configs(db)
    graph[key] = normalized
    validate_graph(graph)
    row = db.get(SyncTaskConfig, key)
    if row is None:
        row = SyncTaskConfig(key=key)
        db.add(row)
    row.dependencies = normalized
    row.updated_at = dt.datetime.now(dt.UTC)
    db.commit()
    return normalized


def validate_options(task: Task, options: dict[str, Any] | None) -> dict[str, Any]:
    options = dict(options or {})
    if task.module == "vm" and task.kind.startswith("ref_"):
        from api.modules.vm.routers.refs import DownloadRequest
        try:
            return DownloadRequest.model_validate(options).model_dump(exclude_none=True)
        except ValueError as exc:
            raise HTTPException(422, "Некорректные параметры загрузки справочника") from exc
    if task.key == "vm/trends_pull/0" and options:
        if set(options) != {"reset"} or not isinstance(options["reset"], bool):
            raise HTTPException(422, "Некорректные параметры синхронизации публикаций")
        return options
    if task.key == "platform/storage_cleanup/0" and options:
        from api.platform.routers.storage import RetentionRunIn
        try:
            return RetentionRunIn.model_validate(options).model_dump()
        except ValueError as exc:
            raise HTTPException(422, "Нужен действующий предварительный расчёт очистки") from exc
    if options:
        raise HTTPException(422, "Эта задача не принимает дополнительные параметры")
    return {}


def enqueue(db: Session, roots: list[dict[str, Any]], *, actor: str, user_id: int | None = None,
            access: Access | None = None, origin: str = "manual") -> SyncRun:
    lock(db)
    graph = configs(db)
    validate_graph(graph)
    requests: dict[str, dict[str, Any]] = {}
    for root in roots:
        task = resolve(db, root["key"])
        if access is not None:
            authorized(task, access)
        opts = validate_options(task, root.get("options"))
        if task.key == "platform/storage_cleanup/0" and origin == "manual" and not opts.get("preview_id"):
            raise HTTPException(422, "Сначала выполните предварительный расчёт очистки в разделе Хранилище")
        if task.key == "vm/trends_pull/0" and opts.get("reset") and access is not None and not allows(access, "vm", "admin"):
            raise HTTPException(403, "Для полной синхронизации нужны права администратора VM")
        if task.key in requests and requests[task.key] != opts:
            raise HTTPException(422, "Одна задача выбрана с разными параметрами")
        requests[task.key] = opts
    if not requests:
        raise HTTPException(422, "Выберите хотя бы одну задачу")
    plan: dict[str, Task] = {}
    def visit(key: str) -> None:
        if key in plan:
            return
        if len(plan) >= 256:
            raise HTTPException(422, "В одном запуске допускается не более 256 шагов")
        task = resolve(db, key)
        if access is not None:
            authorized(task, access)
        plan[key] = task
        for edge in graph.get(key, []):
            visit(edge["key"])
    for key in requests:
        visit(key)
    fingerprint = hashlib.sha256(json.dumps(
        {"roots": requests, "user_id": user_id, "origin": origin}, sort_keys=True
    ).encode()).hexdigest()
    previous = db.scalar(select(SyncRun).where(SyncRun.fingerprint == fingerprint, SyncRun.status.in_(ACTIVE))
                         .order_by(SyncRun.id).limit(1))
    if previous is not None:
        db.commit()
        return previous
    count = db.scalar(select(func.count()).select_from(SyncRun).where(SyncRun.status.in_(ACTIVE)))
    if (count or 0) >= 1000:
        raise HTTPException(429, "Очередь заполнена; дождитесь выполнения или отмените ожидающие запуски")
    run = SyncRun(actor=actor, user_id=user_id, origin=origin, fingerprint=fingerprint)
    db.add(run)
    db.flush()
    for key, task in plan.items():
        db.add(SyncStep(run_id=run.id, key=key, title=task.title, module=task.module, kind=task.kind,
                        target_id=task.target_id, is_root=key in requests,
                        dependencies=graph.get(key, []), options=requests.get(key, {})))
    db.commit()
    return run


def steps(db: Session, run: SyncRun) -> list[SyncStep]:
    return list(db.scalars(select(SyncStep).where(SyncStep.run_id == run.id).order_by(SyncStep.id).limit(256)))


def visible(db: Session, run: SyncRun, access: Access) -> bool:
    return all(allows(access, row.module, "read") for row in steps(db, run))


def get_run(db: Session, run_id: int, access: Access) -> SyncRun:
    run = db.get(SyncRun, run_id)
    if run is None or not visible(db, run, access):
        raise HTTPException(404, "Запуск не найден")
    return run


def view(db: Session, run: SyncRun, *, include_result: bool = True) -> dict[str, Any]:
    rows = steps(db, run)
    return {"id": run.id, "actor": run.actor, "origin": run.origin, "status": run.status,
            "created_at": run.created_at, "started_at": run.started_at, "finished_at": run.finished_at,
            "cancel_requested": run.cancel_requested,
            "steps": [{field: getattr(row, field) for field in (
                "id", "key", "title", "module", "kind", "target_id", "is_root", "dependencies",
                "status", "message", "job_id", "checked_at", "started_at", "finished_at"
            )} | {"result": row.result if include_result else None} for row in rows]}


def cancel(db: Session, run: SyncRun, access: Access) -> SyncRun:
    for row in steps(db, run):
        authorized(Task(row.module, row.kind, row.target_id, row.title), access, options=row.options)
    if run.status in ACTIVE:
        run.cancel_requested = True
        db.commit()
    return run

def defer_asset_sync(db: Session, source: str) -> bool:
    """An import already owned by the queue schedules its derived update in the same queue."""
    parent = db.scalar(select(SyncStep.id).where(
        SyncStep.module == source, SyncStep.status.in_(("starting", "running"))).limit(1))
    if parent is None:
        return False
    pending = db.scalar(select(SyncStep.id).where(
        SyncStep.key == "assets/sync/0", SyncStep.status.in_(("queued", "waiting", "starting", "running"))).limit(1))
    if pending is None:
        enqueue(db, [{"key": "assets/sync/0"}], actor="автосинхронизация", origin="automatic")
    return True


def schedule_failure(db: Session, schedule: PlatformSchedule, message: str) -> SyncRun:
    task = resolve(db, f"{schedule.module}/{schedule.kind}/{schedule.target_id}")
    now = dt.datetime.now(dt.UTC)
    run = SyncRun(actor="расписание", origin="schedule", status="failed",
                  fingerprint=hashlib.sha256(f"{task.key}:{now}".encode()).hexdigest(),
                  created_at=now, finished_at=now)
    db.add(run)
    db.flush()
    db.add(SyncStep(run_id=run.id, key=task.key, title=task.title, module=task.module,
                    kind=task.kind, target_id=task.target_id, is_root=True, status="failed",
                    message=message[:2000], finished_at=now))
    schedule.last_run_id = run.id
    return run
