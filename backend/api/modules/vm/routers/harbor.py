"""Подключение к Harbor: просмотр, сохранение, проверка; синхронизация образов и её расписание."""
from __future__ import annotations

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.audit import changes_summary
from api.crypto import SecretUnreadable
from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.hosts import NO_LINK, TLS_FAILED, is_tls_error, server_error, take_slot
from api.modules.vm.core.harbor import HarborClient, HarborError, make_harbor_client
from api.modules.vm.routers.import_ import JobStarted
from api.modules.vm.services.harbor_settings import (
    HarborConnection,
    HarborConnectionIn,
    SecretsRequired,
    changed_fields,
    load_harbor,
    save_harbor,
)
from api.modules.vm.services.harbor_sync import (
    SCHEDULE_KIND,
    SCHEDULE_TARGET_ID,
    SYNC_CONFLICTS,
    SYNC_KIND,
    LastSyncView,
    last_sync_view,
    public_url,
    sync_work,
)
from api.modules.vm.services.jobs import active_job, lock_job_start, run_job, start_job
from api.platform.schedule_views import ScheduleIn, ScheduleView, schedule_view
from api.platform.scheduler import PlatformSchedule, delete_schedule, upsert_schedule

router = APIRouter(prefix="/harbor", tags=["vm"])


class HarborView(BaseModel):
    url: str
    robot_name: str
    robot_secret_set: bool
    verify_tls: bool
    projects: list[str]
    tags_per_repo: int
    configured: bool
    last_sync: LastSyncView | None = None
    schedule: ScheduleView | None = None


def _schedule(db: Session) -> PlatformSchedule | None:
    return db.execute(
        select(PlatformSchedule).where(
            PlatformSchedule.module == "vm", PlatformSchedule.kind == SCHEDULE_KIND,
            PlatformSchedule.target_id == SCHEDULE_TARGET_ID,
        )
    ).scalar_one_or_none()


def _view(db: Session, conn: HarborConnection) -> HarborView:
    sched = _schedule(db)
    return HarborView(
        url=conn.url,
        robot_name=conn.robot_name,
        robot_secret_set=bool(conn.robot_secret),
        verify_tls=conn.verify_tls,
        projects=conn.projects,
        tags_per_repo=conn.tags_per_repo,
        configured=conn.configured,
        last_sync=last_sync_view(db),
        schedule=schedule_view(sched) if sched is not None else None,
    )


@router.get("", response_model=HarborView)
def get_harbor(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> HarborView:
    return _view(db, load_harbor(db))


@router.put("", response_model=HarborView)
def put_harbor(
    payload: HarborConnectionIn,
    request: Request,
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> HarborView:
    request.state.audit_summary = changes_summary(changed_fields(load_harbor(db), payload))
    try:
        return _view(db, save_harbor(db, payload, user.login))
    except SecretsRequired as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc


class TestResponse(BaseModel):
    ok: bool
    message: str


def _public_error(exc: BaseException) -> str:
    """Класс причины отказа для ответа проверки: без адреса и текста Harbor."""
    if isinstance(exc, SecretUnreadable):
        return str(exc)
    if isinstance(exc, HarborError):
        return exc.kind
    if isinstance(exc.__cause__, httpx.HTTPError) or isinstance(exc, httpx.HTTPError):
        return TLS_FAILED if is_tls_error(exc) else NO_LINK
    return server_error(None)


@router.post("/test", response_model=TestResponse)
def test_harbor(db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> TestResponse:
    """Проверка сохранённого подключения: версия Harbor и вход под роботом.

    Проверяется то, что сохранено, а не то, что в форме: секрет форма не
    показывает и не присылает, проверять его «из поля» нечем.
    """
    conn = load_harbor(db)
    if not conn.configured:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="подключение не настроено: нужны адрес, имя и секрет робота")
    slot = take_slot("vm", user.id)
    try:
        real = conn.unsealed()
        with make_harbor_client(real, timeout=30.0) as http:
            info = HarborClient(real, http).probe()
    # Любая причина отказа доходит до человека классом, без текста Harbor.
    except Exception as exc:  # noqa: BLE001
        return TestResponse(ok=False, message=_public_error(exc))
    finally:
        slot.release()
    return TestResponse(ok=True, message=f"Harbor {info.version}")


@router.post("/sync", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
def start_sync(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    """Синхронизация образов: под блокировкой запуска задач VM, не вместе с импортом,
    пересчётом и архивом справочников — все они пересобирают витрину CVE и риск."""
    conn = load_harbor(db)
    if not conn.configured:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="подключение к Harbor не настроено")
    lock_job_start(db)
    running = active_job(db, SYNC_CONFLICTS)
    if running is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"идёт задача #{running.id}, синхронизация после неё")
    job_id = start_job(db, SYNC_KIND, user.login, message=public_url(conn.url))
    background_tasks.add_task(run_job, job_id, sync_work(user.login))
    return JobStarted(job_id=job_id)


@router.get("/schedule", response_model=ScheduleView | None)
def get_schedule(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ScheduleView | None:
    sched = _schedule(db)
    return schedule_view(sched) if sched is not None else None


@router.put("/schedule", response_model=ScheduleView)
def put_schedule(payload: ScheduleIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ScheduleView:
    try:
        sched = upsert_schedule(
            db, module="vm", kind=SCHEDULE_KIND, target_id=SCHEDULE_TARGET_ID, interval_hours=payload.interval_hours,
            window_from=payload.window_from or None, window_to=payload.window_to or None, enabled=payload.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from None
    db.commit()
    return schedule_view(sched)


@router.delete("/schedule", status_code=status.HTTP_204_NO_CONTENT)
def remove_schedule(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> Response:
    sched = _schedule(db)
    if sched is not None:
        delete_schedule(db, sched.id)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
