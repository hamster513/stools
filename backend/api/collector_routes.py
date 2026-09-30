"""Общий код роутеров модулей-сборщиков (AD, KSC): подключения, снапшоты, находки.

Модули устроены одинаково, а модели у каждого свои (`AdSnapshot` и
`KscSnapshot`, `domain_id` и `server_id`), поэтому модели, колонки и
модульные функции приходят параметрами. Маршруты, зависимости, схемы
ответов и тексты, которыми модули различаются, остаются в их роутерах.
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any, Protocol

from fastapi import BackgroundTasks, HTTPException, Request, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.audit import changes_summary
from api.crypto import encrypt, reseal
from api.db.models import AppUser
from api.hosts import take_slot
from api.jobs import UPLOAD_INTERRUPTED, JobHandle, active_job, fail_job, run_job, start_job

#: Задачи, при которых нельзя начать ещё одну: все пишут в те же снапшоты.
BUSY_KINDS = ("import_file", "collect", "reanalyze")
FINDING_STATUSES = ("new", "persisting", "accepted", "fixed")
SNAPSHOT_NOT_FOUND = "снапшот не найден"
REENTER_SECRET_TEXT = "при смене адреса или учётной записи пароль нужно ввести заново"


class Comparison(Protocol):
    """Сравнение снапшота с предыдущим (`services.snapshots.compare` модуля)."""

    @property
    def previous_id(self) -> int | None: ...
    @property
    def previous_collected_at(self) -> dt.datetime | None: ...
    @property
    def new_keys(self) -> set[str]: ...
    @property
    def fixed(self) -> Sequence[Any]: ...
    @property
    def new(self) -> int: ...


def comparison_summary(cmp_: Comparison) -> dict[str, Any]:
    return {
        "previous_id": cmp_.previous_id,
        "collected_at": cmp_.previous_collected_at.isoformat() if cmp_.previous_collected_at else None,
        "new": cmp_.new, "fixed": len(cmp_.fixed),
    }


# ---- Подключения ----------------------------------------------------------


def add_connection(db: Session, model: type[Any], payload: BaseModel) -> Any:
    data = payload.model_dump()
    data["password"] = encrypt(data["password"])
    c = model(**data)
    db.add(c)
    db.commit()
    return c


def edit_connection(db: Session, c: Any, payload: BaseModel, request: Request, address_fields: frozenset[str]) -> None:
    """Поле со значением None в схеме обновления — «оставить прежнее»."""
    data = {k: v for k, v in payload.model_dump().items() if v is not None}
    changed = [k for k, v in data.items() if v != getattr(c, k) and (k != "password" or v)]
    request.state.audit_summary = changes_summary(changed)
    if not data["password"]:
        # Сохранённый пароль не уходит на новый адрес или под новым именем.
        if c.password and address_fields.intersection(changed):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=REENTER_SECRET_TEXT)
        #: Пароль, сохранённый до шифрования, шифруется при этой записи.
        data["password"] = reseal(c.password)
    else:
        data["password"] = encrypt(data["password"])
    for k, v in data.items():
        setattr(c, k, v)
    db.commit()


def run_connection_test(
    module: str, user_id: int, test: Callable[[], dict[str, Any]], public_error: Callable[[Exception], str],
) -> dict[str, Any]:
    slot = take_slot(module, user_id)
    try:
        return test()
    # Любая причина отказа доходит до человека классом, без текста сервера.
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "message": public_error(exc)}
    finally:
        slot.release()


def start_collect(
    background_tasks: BackgroundTasks, db: Session, user: AppUser, c: Any, *,
    module: str, job_model: type[Any], collect: Callable[[Session, JobHandle, Any], Any],
) -> int:
    """Сбор по подключению `c` в фоне; `collect(session, handle, conn)` возвращает снапшот."""
    if not c.username or not c.password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="у подключения нет логина или пароля")
    connection_model, connection_id = type(c), c.id
    running = active_job(db, job_model, BUSY_KINDS)
    if running is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"идёт задача #{running.id}, дождитесь её")
    slot = take_slot(module, user.id)
    try:
        job_id = start_job(db, job_model, "collect", user.login, message=c.host)
    except Exception:
        slot.release()
        raise

    def work(session: Session, handle: JobHandle) -> None:
        conn = session.get(connection_model, connection_id)
        if conn is None:
            raise ValueError("подключение удалено")
        snap = collect(session, handle, conn)
        handle.stage("done", message=f"снапшот #{snap.id}: находок {snap.findings}")

    def guarded() -> None:
        try:
            run_job(job_model, job_id, work)
        finally:
            slot.release()

    background_tasks.add_task(guarded)
    return job_id


# ---- Снапшоты -------------------------------------------------------------


def snapshot_or_404(db: Session, model: type[Any], snapshot_id: int) -> Any:
    s = db.get(model, snapshot_id)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=SNAPSHOT_NOT_FOUND)
    return s


def reject_if_running(db: Session, job_model: type[Any]) -> None:
    running = active_job(db, job_model, BUSY_KINDS)
    if running is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"идёт задача #{running.id} ({running.kind}), дождитесь её")


async def read_upload(db: Session, job_model: type[Any], file: UploadFile) -> bytes:
    """Файл выгрузки целиком; 409, пока идёт другая задача, 422 на пустой файл."""
    reject_if_running(db, job_model)
    data = await file.read()
    if not data:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="пустой файл")
    return data


def start_import(
    background_tasks: BackgroundTasks, db: Session, user: AppUser, data: bytes, filename: str | None, *,
    upload_dir: Path, job_model: type[Any], load: Callable[[Session, JobHandle, Path, str], str],
) -> int:
    """Разбор загруженной выгрузки в фоне; `load(session, handle, path, name)`
    возвращает текст итоговой стадии. Файл лежит на диске до конца задачи: `load`
    читает его сам и может перенести в хранилище, остаток убирается здесь."""
    name = filename or "export.json"
    job_id = start_job(db, job_model, "import_file", user.login, message=name)
    upload = upload_dir / f"upload-{job_id}.bin"
    try:
        upload.parent.mkdir(parents=True, exist_ok=True)
        upload.write_bytes(data)
    # Запись оборвалась (нет места, нет прав): задача не остаётся «в работе», обрывок не лежит.
    except Exception:
        upload.unlink(missing_ok=True)
        fail_job(db, job_model, job_id, UPLOAD_INTERRUPTED)
        raise

    def work(session: Session, handle: JobHandle) -> None:
        try:
            handle.stage("done", message=load(session, handle, upload, name))
        finally:
            upload.unlink(missing_ok=True)

    def guarded() -> None:
        # Задачу могли снять до старта потока: `work` тогда не вызывается, а файл остаётся.
        try:
            run_job(job_model, job_id, work)
        finally:
            upload.unlink(missing_ok=True)

    background_tasks.add_task(guarded)
    return job_id


def start_reanalyze(
    background_tasks: BackgroundTasks, db: Session, user: AppUser, snapshot_id: int, *,
    job_model: type[Any], snapshot_model: type[Any], reanalyze: Callable[[Session, JobHandle, Any], Any],
) -> int:
    snapshot_or_404(db, snapshot_model, snapshot_id)
    reject_if_running(db, job_model)
    job_id = start_job(db, job_model, "reanalyze", user.login, message=f"снапшот #{snapshot_id}")

    def work(session: Session, handle: JobHandle) -> None:
        s = session.get(snapshot_model, snapshot_id)
        if s is None:
            raise ValueError("снапшот удалён")
        reanalyze(session, handle, s)

    background_tasks.add_task(run_job, job_model, job_id, work)
    return job_id


def checks_overview(
    rows: Iterable[Sequence[Any]], checks: Iterable[Any], severities: Iterable[str], cmp_: Comparison, accepted: set[str],
) -> list[dict[str, Any]]:
    """Сводка по проверкам последнего снапшота: `rows` — (check, severity, key) его находок."""
    per_check: dict[str, dict[str, Any]] = {
        c.code: {"code": c.code, "title": c.title, "description": c.description, "total": 0, "by_severity": dict.fromkeys(severities, 0), "new": 0, "accepted": 0}
        for c in checks
    }
    for check, severity, key in rows:
        entry = per_check.get(check)
        if entry is None:
            continue
        entry["total"] += 1
        entry["by_severity"][severity] = entry["by_severity"].get(severity, 0) + 1
        if key in cmp_.new_keys:
            entry["new"] += 1
        if key in accepted:
            entry["accepted"] += 1
    fixed_by_check: dict[str, int] = {}
    for f in cmp_.fixed:
        fixed_by_check[f.check] = fixed_by_check.get(f.check, 0) + 1
    for code, entry in per_check.items():
        entry["fixed"] = fixed_by_check.get(code, 0)
    return list(per_check.values())


# ---- Находки --------------------------------------------------------------


def finding_rows(
    db: Session, finding_model: type[Any], snapshot_id: int, cmp_: Comparison, accepted: set[str], status_: str | None,
) -> tuple[list[Any], dict[int, str]]:
    """Находки снапшота (или исправленные — для статуса fixed) и статус каждой."""
    if status_ == "fixed":
        rows = list(cmp_.fixed)
        return rows, {f.id: "fixed" for f in rows}
    rows = list(db.execute(select(finding_model).where(finding_model.snapshot_id == snapshot_id)).scalars())
    return rows, {
        f.id: "accepted" if f.key in accepted else "new" if f.key in cmp_.new_keys else "persisting" for f in rows
    }


def filter_findings(
    rows: Iterable[Any], statuses: dict[int, str], *, check: str | None, severity: str | None,
    allowlisted: bool | None, status_: str | None, q: str | None, haystack: Callable[[Any], Iterable[str]],
) -> list[Any]:
    """Отбор по фильтрам списка; `q` ищется без учёта регистра в полях `haystack(f)`."""

    def keep(f: Any) -> bool:
        if check and f.check != check:
            return False
        if severity and f.severity != severity:
            return False
        if allowlisted is not None and f.allowlisted != allowlisted:
            return False
        if status_ and status_ != "fixed" and statuses[f.id] != status_:
            return False
        if q:
            needle = q.lower()
            return any(needle in text.lower() for text in haystack(f))
        return True

    return [f for f in rows if keep(f)]


def findings_page(
    filtered: list[Any], statuses: dict[int, str], cmp_: Comparison, *, status_: str | None, offset: int, limit: int,
    item: Callable[[Any, str], dict[str, Any]], severities: Iterable[str], check_titles: dict[str, str],
) -> dict[str, Any]:
    """Страница отобранных находок с фасетами (только на первой странице)."""
    facets: dict[str, dict[str, int]] = {"check": {}, "severity": dict.fromkeys(severities, 0), "status": dict.fromkeys(FINDING_STATUSES, 0), "allowlisted": {"yes": 0, "no": 0}}
    for f in filtered:
        facets["check"][f.check] = facets["check"].get(f.check, 0) + 1
        facets["severity"][f.severity] = facets["severity"].get(f.severity, 0) + 1
        facets["status"][statuses[f.id]] += 1
        facets["allowlisted"]["yes" if f.allowlisted else "no"] += 1
    if status_ != "fixed":
        facets["status"]["fixed"] = len(cmp_.fixed)
    page = filtered[offset : offset + limit]
    return {
        "total": len(filtered),
        "items": [item(f, statuses[f.id]) for f in page],
        "facets": facets if offset == 0 else None,
        "compared_to": comparison_summary(cmp_),
        "check_titles": check_titles,
    }


def finding_or_404(db: Session, finding_model: type[Any], snapshot_id: int, key: str) -> Any:
    f = db.execute(select(finding_model).where(finding_model.snapshot_id == snapshot_id, finding_model.key == key)).scalars().first()
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="находка не найдена")
    return f


def finding_history(
    db: Session, snapshot_model: type[Any], finding_model: type[Any], owner_column: Any, owner_id: int, key: str,
) -> list[dict[str, Any]]:
    """Снапшоты того же домена или сервера (`owner_column == owner_id`), где была находка `key`."""
    history = db.execute(
        select(snapshot_model.id, snapshot_model.collected_at)
        .join(finding_model, finding_model.snapshot_id == snapshot_model.id)
        .where(owner_column == owner_id, finding_model.key == key)
        .order_by(snapshot_model.collected_at.desc())
    ).all()
    return [{"snapshot_id": sid, "collected_at": at.isoformat()} for sid, at in history]


def verdict_view(verdict: Any) -> dict[str, Any] | None:
    if verdict is None:
        return None
    return {"status": verdict.status, "reason": verdict.reason, "decided_by": verdict.decided_by, "decided_at": verdict.decided_at.isoformat()}
