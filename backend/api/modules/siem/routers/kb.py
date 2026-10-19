"""Подключение к MaxPatrol, общее для разделов SIEM: проверка и сбор базы знаний (спека §3, §7)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.audit import changes_summary
from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.hosts import take_slot
from api.modules.siem.core.kb import KbClient, make_client, public_error
from api.modules.siem.services.kb_collect import active_collect, process_collect, start_collect
from api.modules.siem.services.kb_settings import (
    KbConnectionIn,
    SecretsRequired,
    changed_fields,
    load_connection,
    save_connection,
    view,
)

router = APIRouter(prefix="/mp", tags=["siem"])


@router.get("")
def get_connection(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    return view(load_connection(db))


@router.put("")
def put_connection(
    payload: KbConnectionIn, request: Request, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    request.state.audit_summary = changes_summary(changed_fields(load_connection(db), payload))
    try:
        return view(save_connection(db, payload, user.login))
    except SecretsRequired as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc


class TestResponse(BaseModel):
    ok: bool
    message: str
    version: str = ""
    database: str = ""


NOT_CONFIGURED = "подключение не настроено: нужны адрес и API-токен"


@router.post("/test", response_model=TestResponse)
def test_connection(db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> TestResponse:
    """Проверка сохранённого подключения: токен, БД контента, версия KB.

    Проверяется то, что сохранено, а не то, что в форме: секреты форма не
    показывает и не присылает.
    """
    conn = load_connection(db)
    if not conn.configured:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=NOT_CONFIGURED)
    slot = take_slot("siem", user.id)
    try:
        with make_client(conn, 30.0) as http:
            client = KbClient(conn.unsealed(), http)
            database = client.deployable_database()
            version = client.version(database.name)
    # Любая причина отказа доходит до человека классом, без текста KB.
    except Exception as exc:  # noqa: BLE001
        return TestResponse(ok=False, message=public_error(exc))
    finally:
        slot.release()
    return TestResponse(
        ok=True,
        message=f"база знаний {version} отвечает, БД контента: {database.name}",
        version=version,
        database=database.name,
    )


class JobStarted(BaseModel):
    job_id: int


@router.post("/collect", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
def collect(
    background_tasks: BackgroundTasks, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> JobStarted:
    """Сбор из базы знаний в фоне: инвентарь, экспорт, разбор. Одновременно — один."""
    if not load_connection(db).configured:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=NOT_CONFIGURED)
    running = active_collect(db)
    if running is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"идёт задача #{running.id}, дождитесь её")
    job_id = start_collect(db)
    background_tasks.add_task(process_collect, job_id)
    return JobStarted(job_id=job_id)
