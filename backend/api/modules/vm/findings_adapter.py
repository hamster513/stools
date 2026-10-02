"""Пары хост × CVE модуля VM на общих статусах находок (спека статусов §3).

Область одна (`scope_id = 0`), находка — пара `vm_host_cve`, ключ —
`hostname|ip|cve` (`query.pair_key`), свежие данные — пары последнего
импорта. Импорт заменяет пары целиком, поэтому сверка после него и есть
«пара исчезла / вернулась»: строка состояния пары, которой больше нет,
закрывается системой (`resolved`), вернувшаяся — переоткрывается.

Строки заводятся только для пар, о которых решали люди: исчезнувшая пара без
решения не оставляет следа (истории «устранена» у неё нет) — пар десятки
тысяч, и строка на каждую пропавшую сделала бы таблицу состояний копией
истории импортов. Возраста у пар нет: VM не хранит, в каком импорте пара
появилась впервые (`first_seen_many` → `{}`, в списке «—»).

Массовая смена по фильтру списка — фоновой задачей модуля (`vm_job`,
`kind = bulk_status`): пары выбираются кусками по `BULK_CHUNK` и меняются
`bulk_change` с общим `bulk_id`; прогресс и отмена — между кусками, сделанное
до отмены остаётся.
"""
from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Callable, Iterable, Iterator
from itertools import batched
from typing import Any
from urllib.parse import urlencode

from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.models import AppUser
from api.modules.vm.models import VmHost, VmHostCve, VmImport
from api.modules.vm.services.jobs import JobHandle, run_job, start_job
from api.modules.vm.services.query import (
    MODULE,
    SCOPE,
    VulnFilters,
    count,
    iter_keys,
    level_of,
    pair_key,
    status_filter,
)
from api.platform.findings import service as finding_svc
from api.platform.findings.adapters import BulkJobRequest, CurrentFinding, safe_reconcile

__all__ = ["ADAPTER", "BULK_CHUNK", "keys_by_filter", "pair_key", "reconcile_after_import", "start_bulk_job"]

log = logging.getLogger(__name__)

#: Пар за один кусок массовой смены: шаг прогресса и точка отмены.
BULK_CHUNK = 1000
_STREAM = 5000


def title_of(hostname: str, cve_id: str) -> str:
    return f"{cve_id} на {hostname}"


class VmFindingAdapter:
    module = MODULE

    def scopes(self, db: Session) -> Iterable[int]:
        return [SCOPE]

    def has_scope(self, db: Session, scope_id: int) -> bool:
        return scope_id == SCOPE

    def current(self, db: Session, scope_id: int) -> Iterable[CurrentFinding] | None:
        """Пары последнего импорта; импорта не было — данных нет (None). Severity — уровень риска
        пары, как в списке: `low | medium | high | critical`."""
        if scope_id != SCOPE or db.scalar(select(VmImport.id).limit(1)) is None:
            return None
        return self._stream(db)

    def _stream(self, db: Session) -> Iterator[CurrentFinding]:
        """Только четыре колонки и кусками: пар десятки тысяч, объекты ORM не нужны."""
        rows = db.execute(
            select(VmHost.hostname, VmHost.ip, VmHostCve.cve_id, VmHostCve.risk)
            .join(VmHost, VmHost.id == VmHostCve.host_id)
            .execution_options(yield_per=_STREAM)
        )
        for hostname, ip, cve_id, risk in rows:
            yield CurrentFinding(key=pair_key(hostname, ip, cve_id), title=title_of(hostname, cve_id), severity=level_of(int(risk)))

    def first_seen_many(self, db: Session, scope_id: int, keys: Iterable[str]) -> dict[str, dt.datetime]:
        return {}

    def first_seen(self, db: Session, scope_id: int, key: str) -> dt.datetime | None:
        return None

    def link(self, scope_id: int, key: str) -> str:
        return f"/vm/vulns?{urlencode({'key': key})}"


ADAPTER = VmFindingAdapter()


def reconcile_after_import(db: Session, import_id: int) -> None:
    """Сверка статусов с парами только что записанного импорта — после commit данных модуля;
    сбой сверки импорт не роняет (`safe_reconcile`)."""
    safe_reconcile(db, MODULE, SCOPE, f"импорт #{import_id}")


# ---- Массовая смена по фильтру -------------------------------------------------------


class BulkFilter(BaseModel):
    """Фильтр массовой смены — те же параметры, что у `GET /api/vm/vulns`."""

    model_config = ConfigDict(extra="forbid")

    q: str | None = None
    host: str | None = None
    cve: str | None = None
    criticality: str | None = None
    zone: str | None = None
    os: str | None = None
    level: str | None = None
    exploits: bool | None = None
    msf: bool | None = None
    cvss_source: str | None = None
    host_id: int | None = None
    status: str | None = None
    assignee: str | None = None
    overdue: bool | None = None
    risk_expiring: bool | None = None


def parse_filter(raw: dict[str, Any], *, login: str) -> VulnFilters:
    """Ошибка — ValueError (в том числе ValidationError): платформа отвечает 422 до запуска задачи."""
    b = BulkFilter.model_validate(raw)
    sf = status_filter(b.status, b.assignee, b.overdue, b.risk_expiring, login=login)
    return VulnFilters(b.q, b.host, b.cve, b.criticality, b.zone, b.os, b.level, b.exploits, b.msf, b.cvss_source,
                       b.host_id, sf)


def keys_by_filter(db: Session, scope_id: int, raw: dict[str, Any]) -> Iterator[str]:
    """`register_bulk_filter`: фильтр разбирается сразу, ключи — по мере чтения."""
    return iter_keys(db, parse_filter(raw, login=""), BULK_CHUNK)


def start_bulk_job(db: Session, req: BulkJobRequest) -> tuple[int, Callable[[], None]]:
    """`register_bulk_job`: заводит задачу `bulk_status` и отдаёт работу для фона."""
    f = parse_filter(req.filter, login=req.actor)
    job_id = start_job(db, "bulk_status", req.actor, message="массовая смена статусов по фильтру")

    def work(session: Session, handle: JobHandle) -> None:
        actor = session.scalars(select(AppUser).where(AppUser.login == req.actor)).one()
        total = count(session, f)
        handle.stage("status", total=total, message=f"пар по фильтру: {total}")
        done = changed = 0
        for chunk in batched(iter_keys(session, f, BULK_CHUNK), BULK_CHUNK):
            changed += finding_svc.bulk_change(session, module=MODULE, scope_id=SCOPE, keys=chunk, change=req.change,
                                               actor=actor, bulk_id=req.bulk_id)
            done += len(chunk)
            handle.tick(done, message=f"изменено {changed} из {done}")

    return job_id, lambda: run_job(job_id, work)
