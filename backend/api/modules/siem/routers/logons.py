"""Мастер импорта авторизаций; настройки — siem.admin, запуск — siem.write."""
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.jobs import make_jobs_router
from api.modules.siem.logons import client, service
from api.modules.siem.logons.models import SiemLogonJob
from api.modules.siem.logons.schemas import ImportConfig

router = APIRouter(prefix='/logons', tags=['siem'])
router.include_router(make_jobs_router(SiemLogonJob, 'siem-logons'))


@router.get('/settings')
def settings(db: Session = Depends(get_db)):
    config = service.load_config(db)
    return {'config': config.model_dump() if config else None}


@router.put('/settings')
def save(payload: ImportConfig, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)):
    service.save_config(db, payload, user.login)
    return {'config': payload.model_dump()}


@router.get('/catalog')
def catalog(siem_id: str = Query(default='', max_length=64), db: Session = Depends(get_db)):
    conn = service.connection(db)
    try:
        with client.make_client(conn) as http:
            return {'items': client.TablesClient(conn, http, siem_id).catalog()}
    except client.TableError as exc:
        raise HTTPException(502, str(exc)) from exc


@router.post('/preview')
def preview(payload: ImportConfig, db: Session = Depends(get_db)):
    try:
        return service.preview(db, payload)
    except client.TableError as exc:
        raise HTTPException(502, str(exc)) from exc


@router.post('/run', status_code=202)
def run(background: BackgroundTasks, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)):
    return {'job_id': service.start_import(db, user.login, background.add_task)}
