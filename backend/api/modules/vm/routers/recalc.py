"""Пересчёт риска после смены весов, порога или разметки зон."""
from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.vm.routers.import_ import JobStarted
from api.modules.vm.services.jobs import JobHandle, active_job, lock_job_start, run_job, start_job
from api.modules.vm.services.scoring import recalculate
from api.modules.vm.services.settings import load_settings

router = APIRouter(prefix="/recalculate", tags=["vm"])


@router.post("", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
def start_recalculate(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    # Под блокировкой запуска задач VM, как импорт: массовая смена статусов выбирает пары
    # кусками, и пересчёт риска посреди неё сдвинул бы выбор по фильтру.
    lock_job_start(db)
    running = active_job(db, ["recalculate", "import_vm", "import_file", "ref_bundle"])
    if running is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"идёт задача #{running.id}, пересчёт после неё")
    if active_job(db, ["bulk_status"]) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="идёт массовая смена статусов")
    job_id = start_job(db, "recalculate", user.login)

    def work(session: Session, handle: JobHandle) -> None:
        recalculate(session, handle, load_settings(session).weights)

    background_tasks.add_task(run_job, job_id, work)
    return JobStarted(job_id=job_id)
