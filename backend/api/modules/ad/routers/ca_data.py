"""Данные центра сертификации домена: список загрузок и удаление.

Загрузка — той же ручкой, что и выгрузка домена (`POST /snapshots/file`).
"""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.collector_routes import reject_if_running, start_reanalyze
from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ad.models import AdCaData, AdDomain, AdJob, AdSnapshot
from api.modules.ad.routers.snapshots import JobStarted
from api.modules.ad.services.ca_data import delete_ca_data, list_ca_data
from api.modules.ad.services.settings import load_config
from api.modules.ad.services.snapshots import latest_snapshot, reanalyze
from api.settings import Settings, get_settings

router = APIRouter(tags=["ad"])


class CaDataView(BaseModel):
    id: int
    collected_at: dt.datetime
    imported_at: dt.datetime
    filename: str
    uploaded_by: str
    sections: list[str]
    cas: int
    dcs: int
    web: int


@router.get("/domains/{domain_id}/ca-data", response_model=list[CaDataView])
def list_domain_ca_data(domain_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[CaDataView]:
    if db.get(AdDomain, domain_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="домен не найден")
    return [CaDataView(**item) for item in list_ca_data(db, domain_id)]


@router.delete(
    "/ca-data/{ca_data_id}",
    response_model=JobStarted,
    status_code=status.HTTP_202_ACCEPTED,
    responses={204: {"description": "удалено; снапшотов домена нет, пересчитывать нечего"}},
)
def remove_ca_data(
    ca_data_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: AppUser = Depends(get_current_user),
) -> JobStarted | Response:
    """Удаление и пересчёт последнего снапшота домена без этих данных (202);
    снапшотов нет — 204."""
    row = db.get(AdCaData, ca_data_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="данные ЦС не найдены")
    # Пересчёт не начнётся, пока идёт другая задача: проверяем до удаления,
    # иначе данные исчезли бы, а снапшот остался посчитанным по ним.
    reject_if_running(db, AdJob)
    domain_id = row.domain_id
    delete_ca_data(db, row)
    snap = latest_snapshot(db, domain_id)
    if snap is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    data_dir = settings.data_dir
    job_id = start_reanalyze(
        background_tasks, db, user, snap.id, job_model=AdJob, snapshot_model=AdSnapshot,
        reanalyze=lambda session, handle, s: reanalyze(session, handle, s, load_config(session), data_dir),
    )
    return JobStarted(job_id=job_id)
