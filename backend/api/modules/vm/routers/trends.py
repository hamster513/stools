from typing import Any, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.deps import get_current_user
from api.modules.vm.services.jobs import active_job, run_job, start_job
from api.modules.vm.services.trends import query
from api.modules.vm.services.trends.analyze import process_pending
from api.modules.vm.services.trends.bundle import import_bundle
from api.modules.vm.services.trends.client import CollectorClient, CollectorError
from api.modules.vm.services.trends.rules import extract_identifiers
from api.modules.vm.services.trends.settings import (
    TrendConnectionIn,
    load_connection,
    merge_connection,
    public_connection,
    save_connection,
)
from api.modules.vm.services.trends.sync import start_trend_sync
from api.modules.vm.trend_models import VmTrendIngestState, VmTrendPublication

router = APIRouter(prefix="/trends", tags=["vm"])


@router.get("/settings")
def settings(db: Session = Depends(get_db)) -> Any:
    return public_connection(load_connection(db))


@router.put("/settings")
def save(payload: TrendConnectionIn, db: Session = Depends(get_db), user: Any=Depends(get_current_user)) -> Any:
    try:
        return public_connection(save_connection(db, payload, user.login))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.post("/settings/test")
def test(payload: TrendConnectionIn, db: Session = Depends(get_db)) -> Any:
    try:
        connection = merge_connection(load_connection(db), payload).unsealed()
        with CollectorClient(connection) as client:
            info = client.info()
        return {"ok": True, "message": "Подключение установлено", "route": "proxy" if connection.proxy_enabled else "direct", "info": info}
    except (ValueError, CollectorError) as exc:
        return {"ok": False, "message": str(exc)}


@router.get("/status")
def status(db: Session = Depends(get_db)) -> Any:
    state = db.get(VmTrendIngestState, 1)
    counts = {key: count for key, count in db.execute(select(VmTrendPublication.processing, func.count()).where(
        VmTrendPublication.generation == (state.generation if state else "")).group_by(VmTrendPublication.processing)).all()}
    running = active_job(db, ("trends_sync", "trends_import"))
    return {"received_at": state.received_at if state else None, "cursor": state.cursor if state else 0,
            "collector_id": state.collector_id if state else None, "processing": counts,
            "rebuilding": bool(state and state.generation != state.active_generation), "job_id": running.id if running else None}


def remote_request(db: Session, method: Any, path: Any, **kwargs: Any) -> Any:
    try:
        with CollectorClient(load_connection(db).unsealed()) as client:
            return client.request(method, path, **kwargs)
    except CollectorError as exc:
        raise HTTPException(502, str(exc)) from exc


@router.get("/sources")
def sources(db: Session = Depends(get_db)) -> Any:
    return remote_request(db, "GET", "/api/v1/sources")


@router.post("/sources")
def source_create(payload: dict[str, Any], db: Session = Depends(get_db)) -> Any:
    return remote_request(db, "POST", "/api/v1/sources", json=payload)


@router.patch("/sources/{id}")
def source_edit(id: str, payload: dict[str, Any], db: Session = Depends(get_db)) -> Any:
    return remote_request(db, "PATCH", "/api/v1/sources/" + id, json=payload)


@router.post("/sources/{id}/collect")
def collect(id: str, db: Session = Depends(get_db)) -> Any:
    return remote_request(db, "POST", "/api/v1/sources/" + id + "/collect")


@router.post("/sync", status_code=202)
def sync(background: BackgroundTasks, db: Session = Depends(get_db), user: Any=Depends(get_current_user)) -> Any:
    return {"job_id": start_trend_sync(db, user.login, background.add_task)}


@router.post("/sync/full", status_code=202)
def full_sync(background: BackgroundTasks, db: Session = Depends(get_db), user: Any=Depends(get_current_user)) -> Any:
    return {"job_id": start_trend_sync(db, user.login, background.add_task, reset=True)}


@router.post("/import", status_code=202)
@router.post("/import/full", status_code=202)
def import_file(request: Request, file: UploadFile, background: BackgroundTasks, db: Session = Depends(get_db), user: Any=Depends(get_current_user)) -> Any:
    import io
    data = file.file.read(100 * 1024 * 1024 + 1)
    if len(data) > 100 * 1024 * 1024:
        raise HTTPException(413, "пакет превышает 100 MiB")
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('vm_trend_start'))"))
    if active_job(db, ("trends_sync", "trends_import")):
        raise HTTPException(409, "получение трендов уже выполняется")
    job = start_job(db, "trends_import", user.login)
    def work(session: Session, handle: Any) -> Any:
        handle.stage("receiving")
        import_bundle(session, io.BytesIO(data), reset=request.url.path.endswith("/full"))
        handle.stage("analyzing")
        process_pending(session)
    background.add_task(run_job, job, work)
    return {"job_id": job}


@router.get("/badges")
def badge_list(ids: str = "", db: Session = Depends(get_db)) -> Any:
    return query.badges(db, ids.split(",")[:200])


@router.get("")
def listing(view: Literal["matched", "review", "all", "mentions"] = "matched", q: str = "", active: bool = True,
            limit: int = 50, offset: int = 0, region: str = "", language: str = "", reason: str = "", publisher: str = "", status: str = "", sort: Literal["priority", "date", "identifier", "impact"] = "priority",
            period: Literal["today", "7d", "30d", "custom", "all"] = "7d", tz: str = "Europe/Moscow", date_from: str = "", date_to: str = "",
            db: Session = Depends(get_db)) -> Any:
    try:
        return query.list_cards(db, view, q[:200], active, min(max(limit, 1), 100), max(offset, 0), region, language, reason, publisher, status, sort, period, tz, date_from, date_to)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/{id}/matches")
def matches(id: str, limit: int = 100, offset: int = 0, db: Session = Depends(get_db)) -> Any:
    return query.matches(db, id, min(max(limit, 1), 100), max(offset, 0))


class ReviewIn(BaseModel):
    version: int = Field(ge=1)
    status: Literal["new", "verified", "rejected"] | None = None
    publication_key: str = Field(default="", max_length=100)
    revision: int | None = None
    independent: bool | None = None
    confirm_exploitation: bool = False
    rejected: bool = False
    linked_identifier: str = Field(default="", max_length=100)
    note: str = Field(default="", max_length=4000)

    @field_validator("linked_identifier")
    @classmethod
    def valid_identifier(cls, value: Any) -> Any:
        if value and extract_identifiers(value) != [value.upper()]:
            raise ValueError("укажите CVE или GHSA")
        return value.upper()


@router.patch("/{id}/review")
def review(id: str, payload: ReviewIn, db: Session = Depends(get_db), user: Any=Depends(get_current_user)) -> Any:
    try:
        return query.review(db, id, payload, user.login)
    except KeyError as exc:
        raise HTTPException(404, "карточка не найдена") from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/{id}")
def detail(id: str, period: Literal["today", "7d", "30d", "custom", "all"] = "7d", tz: str = "Europe/Moscow", date_from: str = "", date_to: str = "", db: Session = Depends(get_db)) -> Any:
    try:
        return query.detail(db, id, period, tz, date_from, date_to)
    except KeyError as exc:
        raise HTTPException(404, "карточка не найдена") from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
