from typing import Any, Literal

from fastapi.responses import Response
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.deps import get_current_user
from api.modules.vm.services.jobs import active_job, run_job, start_job
from api.modules.vm.services.trends import query, poc, policies, assistant
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


@router.get("/monitoring")
def monitoring_status(db: Session = Depends(get_db)) -> Any:
    return remote_request(db, "GET", "/api/v1/monitoring")


@router.get("/monitoring/settings")
def monitoring_settings(db: Session = Depends(get_db)) -> Any:
    return remote_request(db, "GET", "/api/v1/monitoring/settings")


@router.put("/monitoring/settings")
def monitoring_save(payload: dict[str, Any], db: Session = Depends(get_db)) -> Any:
    return remote_request(db, "PUT", "/api/v1/monitoring/settings", json=payload)


@router.get("/outbound-profiles")
def outbound_profiles(db: Session = Depends(get_db)) -> Any:
    return remote_request(db, "GET", "/api/v1/outbound-profiles")


@router.get("/catalog/preview")
def catalog_preview(db: Session = Depends(get_db)) -> Any:
    return remote_request(db, "GET", "/api/v1/catalog/preview")


@router.post("/catalog/apply")
def catalog_apply(payload: dict[str, Any], db: Session = Depends(get_db)) -> Any:
    return remote_request(db, "POST", "/api/v1/catalog/apply", json=payload)


@router.post("/sources/bulk")
def sources_bulk(payload: dict[str, Any], db: Session = Depends(get_db)) -> Any:
    return remote_request(db, "POST", "/api/v1/sources/bulk", json=payload)


@router.post("/sources/import/preview")
def sources_import(file: UploadFile, db: Session = Depends(get_db)) -> Any:
    from api.modules.vm.services.trends.source_import import parse_sources
    try:
        rows = parse_sources(file.file.read(5*1024*1024+1), file.filename or "")
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(422, str(exc)) from exc
    result = remote_request(db, "POST", "/api/v1/sources/import/preview", json={"rows":[r["source"] for r in rows]})
    for index, row in enumerate(result["rows"]):
        row["line"] = rows[index]["line"]
        if rows[index]["error"]:
            row.update(error=rows[index]["error"], selected=False, action="error")
    return result


@router.get("/sources/export")
def sources_export(db: Session = Depends(get_db)) -> Any:
    from api.modules.vm.services.trends.source_import import export_sources
    result = remote_request(db, "GET", "/api/v1/sources")
    return Response("\ufeff"+export_sources(result["items"]), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition":'attachment; filename="trend-sources.csv"'})


@router.post("/sources/{id}/preview")
def source_preview(id: str, db: Session = Depends(get_db)) -> Any:
    return remote_request(db, "POST", "/api/v1/sources/"+id+"/preview")


@router.get("/runs")
def source_runs(source_id: str = "", db: Session = Depends(get_db)) -> Any:
    return remote_request(db, "GET", "/api/v1/runs", params={"source_id":source_id} if source_id else {})


@router.get("/collector-jobs/{id}")
def collector_job(id: str, db: Session = Depends(get_db)) -> Any:
    return remote_request(db, "GET", "/api/v1/jobs/"+id)


@router.post("/collector-jobs/{id}/{action}")
def collector_job_action(id: str, action: Literal["cancel", "resume"], db: Session = Depends(get_db)) -> Any:
    return remote_request(db, "POST", "/api/v1/jobs/"+id+"/"+action)


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
def collect(id: str, payload: dict[str, Any] | None = None, db: Session = Depends(get_db)) -> Any:
    return remote_request(db, "POST", "/api/v1/sources/" + id + "/collect", json=payload or {})


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


@router.post("/poc/{id}/review")
def poc_review(id: str, payload: poc.PocDecision, db: Session = Depends(get_db), user: Any = Depends(get_current_user)) -> Any:
    try:
        return poc.decide(db, id, payload, user.login)
    except KeyError as exc:
        raise HTTPException(404, "PoC не найден") from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/policies")
def policy_list(db: Session = Depends(get_db)) -> Any:
    return [policies.view(row) for row in db.scalars(select(policies.VmTrendPolicy).order_by(policies.VmTrendPolicy.id.desc()).limit(5000))]


@router.post("/policies")
@router.post("/policies/global")
@router.patch("/policies/{id}")
def policy_save(request: Request, payload: policies.LocalPolicy, id: int | None = None, db: Session = Depends(get_db), user: Any = Depends(get_current_user)) -> Any:
    if payload.scope == "cve_global":
        from api.rbac import current_access
        if current_access(request).get("vm") != "admin":
            raise HTTPException(403, "Глобальное исключение CVE требует прав администратора VM")
    try:
        return policies.save_policy(db, payload, user.login, id)
    except KeyError as exc:
        raise HTTPException(404, "Исключение не найдено") from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/badges")
def badge_list(ids: str = "", db: Session = Depends(get_db)) -> Any:
    return query.badges(db, ids.split(",")[:200])


@router.get("")
def listing(view: Literal["matched", "review", "all", "mentions", "archive"] = "matched", q: str = "", active: bool = True,
            limit: int = 50, offset: int = 0, region: str = "", language: str = "", reason: str = "", publisher: str = "", status: str = "", sort: Literal["priority", "date", "identifier", "impact"] = "priority",
            period: Literal["today", "24h", "3d", "7d", "30d", "90d", "custom", "all"] = "7d", tz: str = "Europe/Moscow", date_from: str = "", date_to: str = "",
            source_id: str = "", product: str = "", poc_state: Literal["", "candidate", "likely", "confirmed", "rejected"] = "",
            db: Session = Depends(get_db)) -> Any:
    try:
        return query.list_cards(db, view, q[:200], active, min(max(limit, 1), 100), max(offset, 0), region, language, reason, publisher, status, sort, period, tz, date_from, date_to, source_id, product[:200], poc_state)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/{id}/assistant")
def saved_answers(id: str, publication_key: str = "", revision: int | None = None, db: Session = Depends(get_db)) -> Any:
    try:
        payload = assistant.AssistantRequest(mode="explain", publication_key=publication_key, revision=revision)
    except ValueError as exc:
        raise HTTPException(422, "Для публикации укажите корректные ключ и версию") from exc
    return assistant.saved(db, id, payload)


@router.post("/{id}/assistant")
def explain(id: str, payload: assistant.AssistantRequest, db: Session = Depends(get_db)) -> Any:
    return assistant.respond(db, id, payload)


@router.get("/{id}/matches")
def matches(id: str, limit: int = 100, offset: int = 0, db: Session = Depends(get_db)) -> Any:
    return query.matches(db, id, min(max(limit, 1), 100), max(offset, 0))


class ReviewIn(BaseModel):
    version: int = Field(ge=1)
    status: Literal["new", "verified", "rejected"] | None = None
    publication_key: str = Field(default="", max_length=100)
    revision: int | None = None
    independent: bool | None = None
    include_background: bool | None = None
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
def detail(id: str, period: Literal["today", "24h", "3d", "7d", "30d", "90d", "custom", "all"] = "7d", tz: str = "Europe/Moscow", date_from: str = "", date_to: str = "", db: Session = Depends(get_db)) -> Any:
    try:
        return query.detail(db, id, period, tz, date_from, date_to)
    except KeyError as exc:
        raise HTTPException(404, "карточка не найдена") from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
