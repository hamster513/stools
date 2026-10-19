"""Ручки статусов находок (спека §5): /api/findings/*, справочник исполнителей, настройки.

Права — общим правилом api/rbac.py по методу и пути: чтение всем, запись в
/api/findings — аналитику, запись /api/settings/findings — администратору.
Внутри ручек остаётся одна проверка роли — `risk_accept_role`, она зависит
от настроек, а не от пути.

В PUT отличаются «поле не передано» (не трогать) и `null` (очистить) — по
`model_fields_set` тела.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Any, Literal

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.audit import changes_summary
from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.platform.export import Column, export_response
from api.platform.filters import QueryList, QueryStatus, is_all, multi
from api.platform.findings import service as svc
from api.platform.findings.adapters import (
    BulkConflict,
    BulkJobRequest,
    FindingAdapter,
    filter_text,
    get_adapter,
    get_bulk_filter,
    get_bulk_job,
)
from api.platform.findings.core import (
    OPEN,
    STATUS_TITLES,
    STATUSES,
    FindingSettings,
    RoleRequired,
    TransitionError,
    is_overdue,
)
from api.platform.findings.models import FindingState

router = APIRouter(tags=["findings"])

MAX_BULK_KEYS = 5000
#: Область — int4: столбец `scope_id` и второй аргумент advisory-блокировки области.
MAX_SCOPE_ID = 2**31 - 1
#: Длина ключа — столбец `platform_finding_state.key` (VM: `hostname|ip|cve`).
MAX_KEY = 400
Key = Annotated[str, Field(min_length=1, max_length=MAX_KEY)]
ScopeId = Annotated[int, Field(ge=0, le=MAX_SCOPE_ID)]


class ChangeBody(BaseModel):
    status: str | None = Field(default=None, max_length=16)
    assignee: str | None = Field(default=None, max_length=255)
    due_date: dt.date | None = None
    risk_until: dt.date | None = None
    comment: str = Field(default="", max_length=4000)

    def to_change(self) -> svc.Change:
        sent = self.model_fields_set
        return svc.Change(
            status=self.status,
            assignee=self.assignee if "assignee" in sent else svc.UNSET,
            due_date=self.due_date if "due_date" in sent else svc.UNSET,
            risk_until=self.risk_until if "risk_until" in sent else svc.UNSET,
            comment=self.comment,
        )

    def describe(self) -> str:
        sent = self.model_fields_set
        parts = [f"статус {self.status}"] if self.status else []
        parts += [title for field, title in (("assignee", "исполнитель"), ("due_date", "срок"),
                                             ("risk_until", "риск до")) if field in sent]
        if not parts and self.comment.strip():
            parts.append("комментарий")
        return ", ".join(parts)


class StateChange(ChangeBody):
    module: str = Field(max_length=16)
    scope_id: ScopeId
    key: Key
    #: Подпись для «Моих находок», пока строку не обновила сверка с данными модуля.
    title: str = Field(default="", max_length=512)
    severity: str = Field(default="", max_length=16)


class CommentBody(BaseModel):
    module: str = Field(max_length=16)
    scope_id: ScopeId
    key: Key
    text: str = Field(min_length=1, max_length=4000)


class BulkBody(BaseModel):
    module: str = Field(max_length=16)
    scope_id: ScopeId
    keys: list[Key] | None = Field(default=None, min_length=1, max_length=MAX_BULK_KEYS)
    filter: dict[str, Any] | None = None
    change: ChangeBody


class SettingsPatch(BaseModel):
    """Тело PUT настроек: чего нет — остаётся прежним, в том числе отдельные статусы в `counted`."""

    counted: dict[str, bool] = Field(default_factory=dict)
    risk_max_days: int | None = Field(default=None, ge=1, le=3650)
    risk_accept_role: Literal["analyst", "admin"] = "analyst"

    @field_validator("counted")
    @classmethod
    def _known_statuses(cls, value: dict[str, bool]) -> dict[str, bool]:
        unknown = set(value) - set(STATUSES)
        if unknown:
            raise ValueError(f"неизвестные статусы: {', '.join(sorted(unknown))}")
        return value


class EventView(BaseModel):
    at: dt.datetime
    actor: str
    kind: str
    from_status: str | None
    to_status: str | None
    comment: str
    details: dict[str, Any]


class StateView(BaseModel):
    module: str
    scope_id: int
    key: str
    status: str
    status_title: str
    assignee: str | None = None
    assignee_name: str | None = None
    due_date: dt.date | None = None
    overdue: bool = False
    risk_until: dt.date | None = None
    reason: str = ""
    present: bool = True
    first_seen_at: dt.datetime | None = None
    updated_by: str = ""
    updated_at: dt.datetime | None = None
    events: list[EventView] = []


class MineItem(BaseModel):
    module: str
    module_title: str
    scope_id: int
    key: str
    title: str
    severity: str
    status: str
    status_title: str
    due_date: dt.date | None
    overdue: bool
    risk_until: dt.date | None
    present: bool
    first_seen_at: dt.datetime | None
    updated_at: dt.datetime
    link: str


class MineCount(BaseModel):
    open: int
    overdue: int


#: Подписи модулей для «Моих находок» — как в рейке интерфейса (frontend/src/platform/modules.ts).
MODULE_TITLES = {"ad": "Active Directory", "ksc": "Антивирус", "siem": "SIEM", "vm": "VM", "assets": "Assets",
                 "siem_th": "Threat Hunting"}
#: Порядок тяжести для «Моих находок»; у модулей регистр разный (AD — `High`, VM — `high`).
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class DirectoryUser(BaseModel):
    login: str
    display_name: str | None


def _adapter(module: str) -> FindingAdapter:
    try:
        return get_adapter(module)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from None


def _scoped(db: Session, module: str, scope_id: int) -> FindingAdapter:
    """Модуль подключён и область у него есть: строки не заводятся для выдуманной области."""
    adapter = _adapter(module)
    if not adapter.has_scope(db, scope_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="область не найдена")
    return adapter


def _refused(exc: TransitionError) -> HTTPException:
    code = status.HTTP_403_FORBIDDEN if isinstance(exc, RoleRequired) else status.HTTP_422_UNPROCESSABLE_CONTENT
    return HTTPException(code, detail=str(exc))


def _view(db: Session, module: str, scope_id: int, key: str) -> StateView:
    row = svc.state_map(db, module, scope_id, [key]).get(key)
    if row is None:
        return StateView(module=module, scope_id=scope_id, key=key, status="new", status_title=STATUS_TITLES["new"],
                         first_seen_at=_adapter(module).first_seen(db, scope_id, key))
    name = None
    if row.assignee:
        user = db.scalars(select(AppUser).where(AppUser.login == row.assignee)).first()
        name = (user.display_name if user else None) or row.assignee
    return StateView(
        module=module, scope_id=scope_id, key=key, status=row.status, status_title=STATUS_TITLES[row.status],
        assignee=row.assignee, assignee_name=name, due_date=row.due_date,
        overdue=is_overdue(row.status, row.due_date, svc.today()), risk_until=row.risk_until, reason=row.reason,
        present=row.present, first_seen_at=row.first_seen_at, updated_by=row.updated_by, updated_at=row.updated_at,
        events=[EventView(at=e.at, actor=e.actor, kind=e.kind, from_status=e.from_status, to_status=e.to_status,
                          comment=e.comment, details=e.details) for e in svc.events_of(db, row)],
    )


@router.get("/api/findings/state", response_model=StateView)
def get_state(
    module: str = Query(max_length=16), scope_id: int = Query(ge=0, le=MAX_SCOPE_ID),
    key: str = Query(min_length=1, max_length=MAX_KEY),
    db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> StateView:
    _adapter(module)
    return _view(db, module, scope_id, key)


@router.put("/api/findings/state", response_model=StateView)
def put_state(payload: StateChange, request: Request, db: Session = Depends(get_db),
              user: AppUser = Depends(get_current_user)) -> StateView:
    _scoped(db, payload.module, payload.scope_id)
    request.state.audit_summary = f"{payload.module}: находок 1; {payload.describe()}"
    try:
        svc.change(db, module=payload.module, scope_id=payload.scope_id, key=payload.key,
                   change=payload.to_change(), actor=user, title=payload.title, severity=payload.severity)
    except TransitionError as exc:
        raise _refused(exc) from None
    return _view(db, payload.module, payload.scope_id, payload.key)


@router.post("/api/findings/comment", response_model=StateView)
def post_comment(payload: CommentBody, request: Request, db: Session = Depends(get_db),
                 user: AppUser = Depends(get_current_user)) -> StateView:
    _scoped(db, payload.module, payload.scope_id)
    request.state.audit_summary = f"{payload.module}: находок 1; комментарий"
    try:
        svc.comment(db, module=payload.module, scope_id=payload.scope_id, key=payload.key, text=payload.text, actor=user)
    except TransitionError as exc:
        raise _refused(exc) from None
    return _view(db, payload.module, payload.scope_id, payload.key)


@router.post("/api/findings/bulk")
def post_bulk(payload: BulkBody, request: Request, response: Response, background: BackgroundTasks,
              db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> dict[str, int]:
    """Смена по списку ключей — сразу, `{changed}`. Выбор «всё по фильтру» — только у модулей,
    которые зарегистрировали разбор своего фильтра: фоновой задачей модуля (`register_bulk_job`,
    202 `{job_id}`), иначе сразу (`register_bulk_filter`). `assignee: "me"` в фильтре — автор."""
    _scoped(db, payload.module, payload.scope_id)
    if (payload.keys is None) == (payload.filter is None):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="нужны либо ключи, либо фильтр")
    what = payload.change.describe()
    bulk_id = uuid.uuid4().hex
    keys = payload.keys
    by_filter = ""
    if keys is None:
        flt = dict(payload.filter or {})
        if flt.get("assignee") == "me":
            flt["assignee"] = user.login
        by_filter = f"; фильтр {filter_text(flt)}"
        start = get_bulk_job(payload.module)
        if start is not None:
            change = payload.change.to_change()
            try:
                svc.check_change(db, change, actor=user)
                job_id, run = start(db, BulkJobRequest(payload.scope_id, flt, change, user.login, bulk_id))
            except TransitionError as exc:
                raise _refused(exc) from None
            except BulkConflict as exc:
                raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
            except ValueError as exc:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from None
            background.add_task(run)
            request.state.audit_summary = (f"{payload.module}: массовая смена по фильтру, задача #{job_id}; {what}"
                                           f"; bulk_id {bulk_id}{by_filter}")
            response.status_code = status.HTTP_202_ACCEPTED
            return {"job_id": job_id}
        select_by_filter = get_bulk_filter(payload.module)
        if select_by_filter is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="выбор по фильтру не поддерживается этим модулем")
        try:
            keys = list(select_by_filter(db, payload.scope_id, flt))
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from None
    # bulk_id — до фильтра: журнал действий хранит первые 200 символов описания.
    request.state.audit_summary = f"{payload.module}: находок {len(keys)}; {what}; bulk_id {bulk_id}{by_filter}"
    try:
        changed = svc.bulk_change(db, module=payload.module, scope_id=payload.scope_id, keys=keys,
                                  change=payload.change.to_change(), actor=user, bulk_id=bulk_id)
    except TransitionError as exc:
        raise _refused(exc) from None
    request.state.audit_summary = (f"{payload.module}: изменено находок {changed} из {len(keys)}; {what}"
                                   f"; bulk_id {bulk_id}{by_filter}")
    return {"changed": changed}


@router.get("/api/findings/mine", response_model=list[MineItem])
def get_mine(
    status_: QueryStatus = None, module: QueryList = None,
    db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> list[MineItem]:
    """Находки, назначенные текущему пользователю, из всех модулей: сначала просроченные,
    затем по сроку (без срока — в конце), затем по тяжести. По умолчанию — открытые; `all` — любые,
    как у списков модулей. `status` и `module` — повтором ключа (`status` — ещё и через запятую)."""
    wanted = STATUSES if is_all(status_) else multi(status_, commas=True) or OPEN
    unknown = set(wanted) - set(STATUSES)
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"неизвестные статусы: {', '.join(sorted(unknown))}")
    query = select(FindingState).where(FindingState.assignee == user.login, FindingState.status.in_(sorted(wanted)))
    modules = multi(module)
    if modules is not None:
        query = query.where(FindingState.module.in_(sorted(modules)))
    on = svc.today()
    items = []
    for row in db.scalars(query.order_by(FindingState.updated_at.desc())):
        try:
            link = get_adapter(row.module).link(row.scope_id, row.key)
        except LookupError:
            link = ""
        module_title = MODULE_TITLES.get(row.module, row.module)
        items.append(MineItem(
            module=row.module, module_title=module_title, scope_id=row.scope_id,
            key=row.key, title=row.title or f"{module_title}: находка {row.key[:8]}…", severity=row.severity,
            status=row.status, status_title=STATUS_TITLES[row.status], due_date=row.due_date,
            overdue=is_overdue(row.status, row.due_date, on), risk_until=row.risk_until, present=row.present,
            first_seen_at=row.first_seen_at, updated_at=row.updated_at, link=link,
        ))
    # Сортировка устойчивая: при равных сроке и тяжести — свежие изменения выше (порядок запроса).
    items.sort(key=lambda i: (not i.overdue, i.due_date is None, i.due_date or on,
                              SEVERITY_ORDER.get(i.severity.lower(), len(SEVERITY_ORDER))))
    return items


#: Подписи тяжести — как на экране «Мои находки» (SEVERITY в MyFindingsPage); неизвестная — как есть.
SEVERITY_TITLES = {"critical": "критический", "high": "высокий", "medium": "средний", "low": "низкий", "info": "инфо"}

MINE_COLUMNS = [
    Column("module", "Модуль"), Column("title", "Находка"), Column("severity", "Тяжесть"), Column("status", "Статус"),
    Column("due", "Срок"), Column("risk_until", "Риск принят до"),
]


@router.get("/api/findings/mine/export")
def export_mine(
    status_: QueryStatus = None, module: QueryList = None, fmt: str = Query(default="csv", alias="format"),
    db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """«Мои находки» под теми же фильтрами и в том же порядке, что на странице (список и так без лимита)."""
    rows = [
        {"module": i.module_title, "title": i.title, "severity": SEVERITY_TITLES.get(i.severity.lower(), i.severity),
         "status": i.status_title, "due": i.due_date, "risk_until": i.risk_until}
        for i in get_mine(status_, module, db=db, user=user)
    ]
    return export_response(fmt, MINE_COLUMNS, rows, module="findings", name="mine")


@router.get("/api/findings/mine/count", response_model=MineCount)
def get_mine_count(db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> MineCount:
    """Для значка меню: открытые находки текущего пользователя и сколько из них просрочено."""
    is_open = (FindingState.assignee == user.login, FindingState.status.in_(OPEN))
    open_, overdue = db.execute(select(
        func.count(), func.count().filter(FindingState.due_date < svc.today()),
    ).where(*is_open)).one()
    return MineCount(open=open_, overdue=overdue)


@router.get("/api/findings/summary")
def get_summary(
    module: str = Query(max_length=16), scope_id: int = Query(ge=0, le=MAX_SCOPE_ID),
    db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    adapter = _adapter(module)
    # Нет данных области — считаются только строки состояния. Адаптер, который умеет
    # сосчитать находки сам (VM), их не перечисляет.
    count_current = getattr(adapter, "count_current", None)
    if count_current is not None:
        keys_present = count_current(db, scope_id)
    else:
        current = adapter.current(db, scope_id)
        keys_present = None if current is None else len({f.key for f in current})
    return svc.summary(db, module, scope_id, keys_present=keys_present)


@router.get("/api/users/directory", response_model=list[DirectoryUser])
def get_directory(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[DirectoryUser]:
    return [DirectoryUser(login=u.login, display_name=u.display_name) for u in svc.directory(db)]


@router.get("/api/settings/findings", response_model=FindingSettings)
def get_finding_settings(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> FindingSettings:
    return svc.load_settings(db)


@router.put("/api/settings/findings", response_model=FindingSettings)
def put_finding_settings(payload: SettingsPatch, request: Request, db: Session = Depends(get_db),
                 user: AppUser = Depends(get_current_user)) -> FindingSettings:
    """Поля, которых нет в теле, остаются прежними; `counted` сливается с текущими значениями."""
    current = svc.load_settings(db)
    patch = payload.model_dump(exclude_unset=True)
    patch["counted"] = {**current.counted, **payload.counted}
    merged = FindingSettings.model_validate({**current.model_dump(), **patch})
    request.state.audit_summary = changes_summary(
        [f for f in FindingSettings.model_fields if getattr(merged, f) != getattr(current, f)]
    )
    return svc.save_settings(db, merged, updated_by=user.login)
