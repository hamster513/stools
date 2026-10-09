"""Очистка файлов (спека §3, §7): задания, предпросмотр находок, применение, скачивание, обратный перевод.

Платформа пускает GET всем ролям, поэтому всё, что показывает настоящие значения целиком (контексты,
файлы, обратный перевод), закрыто от аудитора явной проверкой здесь. Сводки журнала действий — номера
и счётчики, без имён файлов и значений.
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import ROLE_ANALYST, AppUser
from api.deps import get_current_user
from api.jobs import make_jobs_router, run_job
from api.modules.toolbox.models import ToolboxJob
from api.modules.toolbox.services import scrub
from api.rbac import allows
from api.settings import Settings, get_settings

router = APIRouter(prefix="/scrub", tags=["toolbox"])
router.include_router(make_jobs_router(ToolboxJob, "toolbox"))

MEDIA = {"report": "text/plain; charset=utf-8", "mapping": "text/csv; charset=utf-8"}


def require_analyst(user: AppUser) -> None:
    if not allows(user.role, ROLE_ANALYST):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="нужна роль: аналитик")


def _http(exc: Exception) -> HTTPException:
    if isinstance(exc, scrub.TooLarge):
        return HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, detail=str(exc))
    if isinstance(exc, scrub.ScrubError):
        return HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc))
    if isinstance(exc, scrub.JobBusy):
        return HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))
    if isinstance(exc, scrub.FilesGone):
        return HTTPException(status.HTTP_410_GONE, detail=str(exc))
    if isinstance(exc, LookupError):
        return HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
    raise exc


class JobStarted(BaseModel):
    job_id: int


class JobInfo(BaseModel):
    id: int
    input_name: str
    input_size: int
    input_kind: str
    files_deleted: bool
    result_name: str
    stats: dict[str, Any]
    users_from_ad: bool


class FindingView(BaseModel):
    id: int
    kind: str
    value: str
    alias: str
    count: int
    contexts: list[str]
    first_file: str
    checked: bool
    auto: bool
    stored: bool


class GroupView(BaseModel):
    kind: str
    total: int
    checked: int


class FindingsPage(BaseModel):
    groups: list[GroupView]
    items: list[FindingView]
    total: int


class FindingsPatch(BaseModel):
    checks: dict[int, bool] = Field(default_factory=dict)
    aliases: dict[int, str] = Field(default_factory=dict)
    words: list[str] = Field(default_factory=list, max_length=100)


class FindingsPatched(BaseModel):
    added: int


class ReverseIn(BaseModel):
    text: str


class ReverseOut(BaseModel):
    text: str
    replaced: int


@router.post("/jobs", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
def create_job(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile | None = File(default=None),
    text: str | None = Form(default=None),
    users_from_ad: bool = Form(default=False),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    try:
        job = scrub.create_job(db, user=user, upload=file, text=text, users_from_ad=users_from_ad, settings=settings)
    except (scrub.ScrubError, LookupError) as exc:
        raise _http(exc) from None
    job_id = job.id
    if job.input_kind == "file":
        background_tasks.add_task(run_job, ToolboxJob, job_id, lambda s, h: scrub.run_scan(s, h, job_id))
    request.state.audit_summary = f"задание очистки #{job_id}: {job.input_kind}, байт {job.input_size}"
    return JobStarted(job_id=job_id)


@router.get("/jobs/{job_id}/info", response_model=JobInfo)
def job_info(job_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> Any:
    job = db.get(ToolboxJob, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="задание не найдено")
    return JobInfo.model_validate(job, from_attributes=True)


@router.get("/jobs/{job_id}/findings", response_model=FindingsPage)
def list_findings(
    job_id: int,
    kind: str | None = None,
    q: str = "",
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> FindingsPage:
    # Контексты — куски исходного текста вокруг значения; аудитору — только сами находки, а значения
    # секретов (пароли, ключи) — и вовсе нет: имена хостов и учёток он читает в снапшотах, пароли — нигде.
    full = allows(user.role, ROLE_ANALYST)
    try:
        groups, items, total = scrub.findings_page(db, job_id, kind=kind, q=q, limit=limit, offset=offset,
                                                   secrets_searchable=full)
    except LookupError as exc:
        raise _http(exc) from None
    return FindingsPage(
        groups=[GroupView(**g) for g in groups],
        items=[
            FindingView(id=f.id, kind=f.kind, value=f.value if full or f.kind != "secret" else "", alias=f.alias,
                        count=f.count, contexts=list(f.contexts or []) if full else [], first_file=f.first_file,
                        checked=f.checked, auto=f.auto, stored=f.alias_id is not None)
            for f in items
        ],
        total=total,
    )


@router.patch("/jobs/{job_id}/findings", response_model=FindingsPatched)
def patch_findings(
    job_id: int, payload: FindingsPatch, request: Request,
    db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> FindingsPatched:
    try:
        added = scrub.update_findings(db, job_id, checks=payload.checks, aliases=payload.aliases, words=payload.words)
    except (scrub.ScrubError, scrub.JobBusy, scrub.FilesGone, LookupError) as exc:
        # Без rollback: он погасил бы и пользователя запроса, которого читает журнал действий;
        # незафиксированную правку откатит закрытие сессии.
        raise _http(exc) from None
    request.state.audit_summary = (
        f"задание #{job_id}: галочек {len(payload.checks)}, псевдонимов {len(payload.aliases)}, "
        f"слов {len(payload.words)}, новых находок {added}"
    )
    return FindingsPatched(added=added)


@router.post("/jobs/{job_id}/apply", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
def apply_job(
    job_id: int, request: Request, background_tasks: BackgroundTasks,
    db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> JobStarted:
    try:
        scrub.start_apply(db, job_id)
    except (scrub.JobBusy, LookupError) as exc:
        raise _http(exc) from None
    background_tasks.add_task(run_job, ToolboxJob, job_id, lambda s, h: scrub.run_apply(s, h, job_id))
    request.state.audit_summary = f"задание #{job_id}: применение запущено"
    return JobStarted(job_id=job_id)


@router.get("/jobs/{job_id}/{which}")
def download(
    job_id: int, which: Literal["result", "report", "mapping"], request: Request,
    db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> FileResponse:
    require_analyst(user)
    try:
        path = scrub.result_file(db, job_id, which)
    except (scrub.FilesGone, LookupError) as exc:
        raise _http(exc) from None
    request.state.audit_summary = f"задание #{job_id}: скачан {which}"
    filename = path.name if which == "result" else f"{job_id}-{path.name}"
    return FileResponse(path, filename=filename, media_type=MEDIA.get(which, "application/octet-stream"))


@router.delete("/jobs/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_job_files(
    job_id: int, request: Request, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> Response:
    try:
        scrub.delete_files(db, job_id)
    except (scrub.JobBusy, LookupError) as exc:
        raise _http(exc) from None
    request.state.audit_summary = f"задание #{job_id}: файлы удалены"
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/reverse", response_model=ReverseOut)
def reverse(
    payload: ReverseIn, request: Request, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> ReverseOut:
    require_analyst(user)
    try:
        text, replaced = scrub.reverse_text(db, payload.text)
    except scrub.ScrubError as exc:
        raise _http(exc) from None
    request.state.audit_summary = f"обратный перевод: замен {replaced}"
    return ReverseOut(text=text, replaced=replaced)
