"""Общий код роутеров модулей-сборщиков (AD, KSC): подключения, снапшоты, находки и их статусы.

Модули устроены одинаково, а модели у каждого свои (`AdSnapshot` и
`KscSnapshot`, `domain_id` и `server_id`), поэтому модели, колонки и
модульные функции приходят параметрами. Маршруты, зависимости, схемы
ответов и тексты, которыми модули различаются, остаются в их роутерах.
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from fastapi import BackgroundTasks, HTTPException, Request, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import String, select
from sqlalchemy.orm import Session

from api.audit import changes_summary
from api.collector_findings import SnapshotFindingAdapter, first_seen_map, last_known
from api.crypto import encrypt, reseal
from api.db.models import AppUser
from api.hosts import take_slot
from api.jobs import UPLOAD_INTERRUPTED, JobHandle, active_job, fail_job, run_job, start_job
from api.platform.findings import service as finding_svc
from api.platform.findings.core import OPEN, STATUS_TITLES, STATUSES, is_overdue
from api.platform.findings.models import FindingState

#: Задачи, при которых нельзя начать ещё одну: все пишут в те же снапшоты.
BUSY_KINDS = ("import_file", "collect", "reanalyze")
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


# ---- Находки и их статусы ----------------------------------------------------

#: `delta` строки: появилась в этом снапшоте, была и раньше, нет в последнем снапшоте.
DELTAS = ("new", "same", "gone")


@dataclass
class FindingRow:
    """Находка с состоянием платформы. У `gone` данные — из последнего снапшота, где она была.
    `finding` пуст у строки, которая нужна только фасету статуса и не загружалась."""

    finding: Any
    state: FindingState | None
    delta: str

    @property
    def status(self) -> str:
        return finding_svc.effective_status(self.state)

    @property
    def assignee(self) -> str | None:
        return self.state.assignee if self.state is not None else None


@dataclass
class FindingSet:
    rows: list[FindingRow]
    #: Снапшот — последний у области: только к нему добавляются строки отсутствующих находок.
    is_latest: bool


@dataclass(frozen=True)
class FindingFilter:
    check: str | None = None
    severity: str | None = None
    allowlisted: bool | None = None
    statuses: frozenset[str] = OPEN
    delta: str | None = None
    #: Логин или `none`; `me` уже заменено логином.
    assignee: str | None = None
    overdue: bool = False
    risk_expiring: bool = False
    q: str | None = None

    @property
    def by_finding(self) -> bool:
        """Есть фильтр по данным самой находки — без них строку не отобрать."""
        return bool(self.check or self.severity or self.allowlisted is not None or self.q)


def finding_filter(
    user: AppUser, *, check: str | None, severity: str | None, allowlisted: bool | None, status_: str | None,
    delta: str | None, assignee: str | None, overdue: bool, risk_expiring: bool, q: str | None,
) -> FindingFilter:
    """Параметры списка. `status` — коды через запятую или `all`; не задан — открытые,
    а с «риск истекает» — принятые: среди открытых такого риска не бывает."""
    if not status_:
        statuses = frozenset({"risk_accepted"}) if risk_expiring else OPEN
    elif status_ == "all":
        statuses = frozenset(STATUSES)
    else:
        statuses = frozenset(s for s in status_.split(",") if s)
        unknown = statuses - set(STATUSES)
        if unknown or not statuses:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"неизвестный статус: {', '.join(sorted(unknown)) or status_}")
    if delta is not None and delta not in DELTAS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="неизвестное значение delta")
    return FindingFilter(
        check=check, severity=severity, allowlisted=allowlisted, statuses=statuses, delta=delta,
        assignee=user.login if assignee == "me" else (assignee or None), overdue=overdue, risk_expiring=risk_expiring, q=q,
    )


def _stub(adapter: SnapshotFindingAdapter, state: FindingState) -> Any:
    """Находка, которой нет ни в одном снапшоте области (вердикт пережил свою находку):
    строка из состояния, подпись — в `target`. В сессию не добавляется."""
    fm = adapter.finding_model
    f = fm(**{c.key: "" for c in fm.__table__.columns if isinstance(c.type, String)})
    f.id, f.key, f.allowlisted, f.details_json = 0, state.key, False, "{}"
    f.severity = f.severity_original = state.severity or "Info"
    f.target = state.title or state.key
    return f


def _absent_rows(db: Session, adapter: SnapshotFindingAdapter, scope_id: int, states: Sequence[FindingState]) -> list[FindingRow]:
    if not states:
        return []
    known = {f.key: f for f in last_known(db, adapter, scope_id, [st.key for st in states])}
    return [FindingRow(known.get(st.key) or _stub(adapter, st), st, "gone") for st in states]


def finding_rows(
    db: Session, adapter: SnapshotFindingAdapter, snapshot: Any, cmp_: Comparison, flt: FindingFilter, *, first_page: bool,
) -> FindingSet:
    """Находки снапшота с их состояниями. У последнего снапшота области к ним добавляются
    находки, которых в нём нет, но есть состояние (устранённые системой, принятые людьми,
    перенесённые вердикты), — иначе их негде увидеть.

    Данные отсутствующих находок (из прежних снапшотов) загружаются, только если их
    статус выбран в фильтре. Остальные нужны лишь фасету статуса первой страницы: без
    фильтров по данным находки он считается по одному состоянию, без загрузки."""
    scope_id = getattr(snapshot, adapter.owner)
    states = finding_svc.state_map(db, adapter.module, scope_id)
    fm = adapter.finding_model
    found = list(db.scalars(select(fm).where(fm.snapshot_id == snapshot.id)))
    rows = [FindingRow(f, states.get(f.key), "new" if f.key in cmp_.new_keys else "same") for f in found]
    latest = adapter.latest(db, scope_id)
    is_latest = latest is not None and latest.id == snapshot.id
    if is_latest:
        here = {f.key for f in found}
        absent = [st for st in states.values() if st.key not in here]
        listed = [st for st in absent if st.status in flt.statuses]
        rest = [st for st in absent if st.status not in flt.statuses] if first_page else []
        if flt.by_finding:
            rows += _absent_rows(db, adapter, scope_id, listed + rest)
        else:
            rows += _absent_rows(db, adapter, scope_id, listed) + [FindingRow(None, st, "gone") for st in rest]
    return FindingSet(rows, is_latest)


def _overdue(r: FindingRow, today: dt.date) -> bool:
    return r.state is not None and is_overdue(r.status, r.state.due_date, today)


def _risk_expiring(r: FindingRow, today: dt.date) -> bool:
    st = r.state
    return (st is not None and st.status == "risk_accepted" and st.risk_until is not None
            and st.risk_until <= today + dt.timedelta(days=finding_svc.RISK_EXPIRING_DAYS))


def _matches(r: FindingRow, flt: FindingFilter, today: dt.date, haystack: Callable[[Any], Iterable[str]], *skip: str) -> bool:
    """Отбор по фильтрам; `skip` — какие фильтры не применять (фасет считается без своего фильтра).
    Строка без данных находки (`finding is None`) бывает, только когда фильтров по ним нет."""
    f = r.finding
    if flt.delta and r.delta != flt.delta:
        return False
    if "status" not in skip and r.status not in flt.statuses:
        return False
    if "assignee" not in skip and flt.assignee and r.assignee != (None if flt.assignee == "none" else flt.assignee):
        return False
    if "overdue" not in skip and flt.overdue and not _overdue(r, today):
        return False
    if "risk_expiring" not in skip and flt.risk_expiring and not _risk_expiring(r, today):
        return False
    if f is None:
        return not flt.by_finding
    if flt.check and f.check != flt.check:
        return False
    if flt.severity and f.severity != flt.severity:
        return False
    if flt.allowlisted is not None and f.allowlisted != flt.allowlisted:
        return False
    if flt.q:
        needle = flt.q.lower()
        return any(needle in text.lower() for text in haystack(f))
    return True


def state_fields(db: Session, adapter: SnapshotFindingAdapter, scope_id: int, rows: Sequence[FindingRow]) -> list[dict[str, Any]]:
    """Поля состояния строк списка и карточки (спека §5). Возраст без строки
    состояния — по снапшотам области, одним запросом на страницу."""
    today = finding_svc.today()
    seen = first_seen_map(db, adapter, scope_id, [r.finding.key for r in rows if r.state is None or r.state.first_seen_at is None])
    logins = {r.assignee for r in rows if r.assignee}
    names = {u.login: u.display_name or u.login for u in db.scalars(select(AppUser).where(AppUser.login.in_(logins)))} if logins else {}
    now = dt.datetime.now(dt.UTC)
    out = []
    for r in rows:
        st = r.state
        first = (st.first_seen_at if st is not None else None) or seen.get(r.finding.key)
        out.append({
            "status": r.status,
            "status_title": STATUS_TITLES[r.status],
            "assignee": r.assignee,
            "assignee_name": names.get(r.assignee, r.assignee) if r.assignee else None,
            "due_date": st.due_date.isoformat() if st is not None and st.due_date else None,
            "overdue": _overdue(r, today),
            "risk_until": st.risk_until.isoformat() if st is not None and st.risk_until else None,
            "first_seen_at": first.isoformat() if first else None,
            "age_days": (now - first).days if first else None,
            "delta": r.delta,
        })
    return out


def findings_page(
    db: Session, adapter: SnapshotFindingAdapter, scope_id: int, found: FindingSet, flt: FindingFilter, cmp_: Comparison, *,
    offset: int, limit: int, haystack: Callable[[Any], Iterable[str]], sort_key: Callable[[Any], Any],
    item: Callable[[Any], dict[str, Any]], severities: Iterable[str], check_titles: dict[str, str],
) -> dict[str, Any]:
    """Страница отобранных находок с фасетами (только на первой странице). Фасеты
    статуса, исполнителя и флагов сроков считаются без своего фильтра — иначе выбор
    одного значения прятал бы счётчики остальных. Статусы — на сегодня, у любого
    снапшота (`statuses_as_of`); `is_latest` — смотрят ли последний снапшот области."""
    today = finding_svc.today()
    rows = found.rows
    filtered = sorted((r for r in rows if r.finding is not None and _matches(r, flt, today, haystack)),
                      key=lambda r: (sort_key(r.finding), r.finding.id, r.finding.key))
    facets: dict[str, dict[str, int]] | None = None
    if offset == 0:
        facets = {
            "check": {}, "severity": dict.fromkeys(severities, 0), "allowlisted": {"yes": 0, "no": 0},
            "delta": dict.fromkeys(DELTAS, 0), "status": dict.fromkeys(STATUSES, 0), "assignee": {"none": 0},
            "flags": {"overdue": 0, "risk_expiring": 0},
        }
        for r in filtered:
            f = r.finding
            facets["check"][f.check] = facets["check"].get(f.check, 0) + 1
            facets["severity"][f.severity] = facets["severity"].get(f.severity, 0) + 1
            facets["allowlisted"]["yes" if f.allowlisted else "no"] += 1
            facets["delta"][r.delta] += 1
        for r in rows:
            if _matches(r, flt, today, haystack, "status"):
                facets["status"][r.status] += 1
            if _matches(r, flt, today, haystack, "assignee"):
                who = r.assignee or "none"
                facets["assignee"][who] = facets["assignee"].get(who, 0) + 1
            # Флаги сроков — и без фильтра статуса: «риск истекает» бывает только у принятых,
            # «просроченные» — только у открытых; по умолчанию (открытые) первый был бы всегда 0.
            if _overdue(r, today) and _matches(r, flt, today, haystack, "overdue", "status"):
                facets["flags"]["overdue"] += 1
            if _risk_expiring(r, today) and _matches(r, flt, today, haystack, "risk_expiring", "status"):
                facets["flags"]["risk_expiring"] += 1
    page = filtered[offset : offset + limit]
    return {
        "total": len(filtered),
        "items": [{**item(r.finding), **fields} for r, fields in zip(page, state_fields(db, adapter, scope_id, page), strict=True)],
        "facets": facets,
        "compared_to": comparison_summary(cmp_),
        "check_titles": check_titles,
        "is_latest": found.is_latest,
        "statuses_as_of": "today",
    }


def finding_detail_row(
    db: Session, adapter: SnapshotFindingAdapter, snapshot: Any, key: str, cmp_: Comparison,
) -> tuple[Any, dict[str, Any]]:
    """Находка карточки и поля её состояния. Находку, которой в последнем снапшоте нет,
    карточка показывает по последнему снапшоту области, где она была (устранённая,
    принятая), а если её нет ни в одном — по строке состояния."""
    scope_id = getattr(snapshot, adapter.owner)
    fm = adapter.finding_model
    f = db.scalars(select(fm).where(fm.snapshot_id == snapshot.id, fm.key == key)).first()
    delta = "new" if key in cmp_.new_keys else "same"
    state = finding_svc.state_map(db, adapter.module, scope_id, [key]).get(key)
    if f is None:
        # Данные из другого снапшота — только у последнего: статусы показаны на сегодня,
        # а у старого снапшота находки — на его дату, и чужие данные в нём были бы ложью.
        latest = adapter.latest(db, scope_id)
        if latest is None or latest.id != snapshot.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="находка не найдена")
        known = last_known(db, adapter, scope_id, [key])
        if known:
            f = known[0]
        elif state is not None:
            f = _stub(adapter, state)
        else:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="находка не найдена")
        delta = "gone"
    row = FindingRow(f, state, delta)
    return f, state_fields(db, adapter, scope_id, [row])[0]


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


# ---- Обзор ---------------------------------------------------------------------


def findings_overview(
    db: Session, module: str, scope_id: int, rows: Sequence[Sequence[Any]], checks: Iterable[Any], severities: Iterable[str],
    cmp_: Comparison, unchecked: dict[str, str] | None = None, categories: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Сводка обзора по последнему снапшоту: `rows` — (check, severity, key) его находок.

    `total` и `by_severity` проверки и блок `counted` — находки со статусами, которые
    велено учитывать (настройка платформы); `all` — все находки проверки, `open` —
    открытые, `new` — появились в этом снапшоте, `resolved` — пропали с прошлого.
    `summary` — счётчики статусов области. `unchecked` — код проверки → почему её
    результат не проверка (в выгрузке не было данных). `categories` — код категории →
    название; у проверок без категории (KSC) оба поля пустые."""
    severities = list(severities)
    states = finding_svc.state_map(db, module, scope_id)
    counted = finding_svc.counted_statuses(db)
    per_check: dict[str, dict[str, Any]] = {
        c.code: {"code": c.code, "title": c.title, "description": c.description, "total": 0, "all": 0, "open": 0,
                 "by_severity": dict.fromkeys(severities, 0), "new": 0,
                 "category": getattr(c, "category", ""), "category_title": (categories or {}).get(getattr(c, "category", ""), "")}
        for c in checks
    }
    total, by_severity = 0, dict.fromkeys(severities, 0)
    for check, severity, key in rows:
        st = finding_svc.effective_status(states.get(key))
        if st in counted:
            total += 1
            by_severity[severity] = by_severity.get(severity, 0) + 1
        entry = per_check.get(check)
        if entry is None:
            continue
        entry["all"] += 1
        entry["open"] += st in OPEN
        entry["new"] += key in cmp_.new_keys
        if st in counted:
            entry["total"] += 1
            entry["by_severity"][severity] = entry["by_severity"].get(severity, 0) + 1
    resolved_by_check: dict[str, int] = {}
    for f in cmp_.fixed:
        resolved_by_check[f.check] = resolved_by_check.get(f.check, 0) + 1
    for code, entry in per_check.items():
        entry["resolved"] = resolved_by_check.get(code, 0)
        entry["unchecked"] = (unchecked or {}).get(code)
    return {
        # `statuses` — какие статусы учтены: ссылка с плитки ведёт на список с этим фильтром.
        "counted": {"total": total, "by_severity": by_severity, "statuses": [s for s in STATUSES if s in counted]},
        "summary": finding_svc.summary(db, module, scope_id, keys_present=len({key for _, _, key in rows})),
        "checks": list(per_check.values()),
    }
