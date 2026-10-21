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

Пар сотни тысяч, поэтому сверка и сводка платформы не перечисляют их
(`current`), а спрашивают базу: `count_current`, `present_keys`, `describe`.
Новой строке состояния пары адаптер заводит подсказку `vm_finding_state_ref`
(хост, IP, CVE), по которой список присоединяет статусы (`query.ST`).

Массовая смена по фильтру списка — фоновой задачей модуля (`vm_job`,
`kind = bulk_status`): пары выбираются кусками по `BULK_CHUNK` и меняются
`bulk_change` с общим `bulk_id`; прогресс и отмена — между кусками, сделанное
до отмены остаётся. С импортом и пересчётом она одновременно не идёт.
"""
from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Callable, Iterable, Iterator, Sequence
from itertools import batched
from typing import Any
from urllib.parse import urlencode

from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, insert, select, text
from sqlalchemy.orm import Session

from api.db.models import AppUser
from api.modules.vm.core.weights import Levels
from api.modules.vm.models import VmFindingStateRef, VmHost, VmHostCve, VmImport
from api.modules.vm.services.jobs import (
    DATA_KINDS,
    JobHandle,
    active_job,
    lock_job_start,
    run_job,
    start_job,
)
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
from api.modules.vm.services.settings import load_settings
from api.platform.filters import multi
from api.platform.findings import service as finding_svc
from api.platform.findings.adapters import (
    BulkConflict,
    BulkJobRequest,
    CurrentFinding,
    filter_text,
    safe_reconcile,
)
from api.platform.findings.models import FindingState

__all__ = ["ADAPTER", "BULK_CHUNK", "keys_by_filter", "pair_key", "reconcile_after_import", "start_bulk_job"]

log = logging.getLogger(__name__)

#: Пар за один кусок массовой смены: шаг прогресса и точка отмены.
BULK_CHUNK = 1000
_STREAM = 5000


def title_of(hostname: str, cve_id: str) -> str:
    return f"{cve_id} на {hostname}"


def split_key(key: str) -> tuple[str, str, str] | None:
    """`hostname|ip|cve` → части; разбор справа: IP и CVE символа `|` не содержат, имя хоста —
    может. None — ключ не пары VM (не те части или не той длины, что в `vm_host`)."""
    parts = key.rsplit("|", 2)
    if len(parts) != 3:
        return None
    hostname, ip, cve_id = parts
    if len(hostname) > 255 or len(ip) > 64 or len(cve_id) > 32:
        return None
    return hostname, ip, cve_id


#: Пары по ключам: ключи разобраны в Python и уходят массивами, сопоставление — в базе.
_LOOKUP = text("""
    SELECT h.hostname, h.ip, p.cve_id, p.risk
    FROM unnest(CAST(:hostnames AS text[]), CAST(:ips AS text[]), CAST(:cves AS text[])) AS k(hostname, ip, cve_id)
    JOIN vm_host h ON h.hostname = k.hostname AND h.ip = k.ip
    JOIN vm_host_cve p ON p.host_id = h.id AND p.cve_id = k.cve_id
""")

#: Подсказки для строк состояния VM, заведённых в обход адаптера (тот же разбор, что `split_key`).
_BACKFILL = text("""
    INSERT INTO vm_finding_state_ref (state_id, hostname, ip, cve_id)
    SELECT id, hostname, ip, cve_id FROM (
        SELECT s.id,
               left(s.key, length(s.key) - length(split_part(reverse(s.key), '|', 1))
                                         - length(split_part(reverse(s.key), '|', 2)) - 2) AS hostname,
               reverse(split_part(reverse(s.key), '|', 2)) AS ip,
               reverse(split_part(reverse(s.key), '|', 1)) AS cve_id,
               length(s.key) - length(replace(s.key, '|', '')) AS pipes
        FROM platform_finding_state s
        WHERE s.module = :module AND s.scope_id = :scope
          AND NOT EXISTS (SELECT 1 FROM vm_finding_state_ref r WHERE r.state_id = s.id)
    ) parsed
    WHERE pipes >= 2 AND length(hostname) <= 255 AND length(ip) <= 64 AND length(cve_id) <= 32
""")


class VmFindingAdapter:
    module = MODULE

    def scopes(self, db: Session) -> Iterable[int]:
        return [SCOPE]

    def has_scope(self, db: Session, scope_id: int) -> bool:
        return scope_id == SCOPE

    def _has_data(self, db: Session, scope_id: int) -> bool:
        return scope_id == SCOPE and db.scalar(select(VmImport.id).limit(1)) is not None

    def current(self, db: Session, scope_id: int) -> Iterable[CurrentFinding] | None:
        """Пары последнего импорта; импорта не было — данных нет (None). Severity — уровень риска
        пары, как в списке: `low | medium | high | critical`. Сверка и сводка платформы этим не
        пользуются (`present_keys`, `count_current`): пар сотни тысяч."""
        if not self._has_data(db, scope_id):
            return None
        return self._stream(db)

    def _stream(self, db: Session) -> Iterator[CurrentFinding]:
        """Только четыре колонки и кусками: объекты ORM не нужны."""
        rows = db.execute(
            select(VmHost.hostname, VmHost.ip, VmHostCve.cve_id, VmHostCve.risk)
            .join(VmHost, VmHost.id == VmHostCve.host_id)
            .execution_options(yield_per=_STREAM)
        )
        levels = load_settings(db).weights.levels
        for hostname, ip, cve_id, risk in rows:
            yield CurrentFinding(key=pair_key(hostname, ip, cve_id), title=title_of(hostname, cve_id),
                                 severity=level_of(int(risk), levels))

    def _lookup(self, db: Session, keys: Sequence[str]) -> list[Any]:
        parts = [p for p in map(split_key, keys) if p is not None]
        if not parts:
            return []
        hostnames, ips, cves = (list(col) for col in zip(*parts, strict=True))
        return list(db.execute(_LOOKUP, {"hostnames": hostnames, "ips": ips, "cves": cves}))

    def count_current(self, db: Session, scope_id: int) -> int | None:
        if not self._has_data(db, scope_id):
            return None
        return int(db.scalar(select(func.count()).select_from(VmHostCve)) or 0)

    def present_keys(self, db: Session, scope_id: int, keys: Sequence[str]) -> set[str] | None:
        """Какие из ключей — пары текущих данных; ответ — запросом, пары в память не читаются."""
        if not self._has_data(db, scope_id):
            return None
        return {pair_key(r.hostname, r.ip, r.cve_id) for r in self._lookup(db, keys)}

    def describe(self, db: Session, scope_id: int, keys: Sequence[str]) -> dict[str, CurrentFinding]:
        found = {}
        levels = load_settings(db).weights.levels
        for r in self._lookup(db, keys):
            key = pair_key(r.hostname, r.ip, r.cve_id)
            found[key] = CurrentFinding(key=key, title=title_of(r.hostname, r.cve_id), severity=level_of(int(r.risk), levels))
        return found

    def on_states_created(self, db: Session, states: Sequence[FindingState]) -> None:
        """Подсказки для новых строк состояния пар (`VmFindingStateRef`) — в той же транзакции."""
        refs = [{"state_id": s.id, "hostname": p[0], "ip": p[1], "cve_id": p[2]}
                for s in states if s.scope_id == SCOPE and (p := split_key(s.key)) is not None]
        if refs:
            db.execute(insert(VmFindingStateRef), refs)

    def backfill(self, db: Session) -> int:
        """Дописать подсказки строкам состояния VM, у которых их нет (заведены в обход адаптера).
        Транзакцию не фиксирует."""
        result = db.execute(_BACKFILL, {"module": MODULE, "scope": SCOPE})
        return int(getattr(result, "rowcount", 0) or 0)

    def first_seen_many(self, db: Session, scope_id: int, keys: Iterable[str]) -> dict[str, dt.datetime]:
        return {}

    def first_seen(self, db: Session, scope_id: int, key: str) -> dt.datetime | None:
        return None

    def link(self, scope_id: int, key: str) -> str:
        return f"/vm/vulns?{urlencode({'key': key})}"


ADAPTER = VmFindingAdapter()


def reconcile_after_import(db: Session, import_id: int) -> None:
    """Сверка статусов с парами только что записанного импорта — после commit данных модуля;
    сбой сверки импорт не роняет (`safe_reconcile`). Перед ней — подсказки строкам, заведённым
    в обход адаптера: без них список показал бы такие пары «новыми»."""
    try:
        ADAPTER.backfill(db)
        db.commit()
    except Exception:
        db.rollback()
        log.exception("подсказки статусов пар VM не дописаны")
    safe_reconcile(db, MODULE, SCOPE, f"импорт #{import_id}")


# ---- Массовая смена по фильтру -------------------------------------------------------


#: Многозначный параметр фильтра: список значений как есть ('' и `-` — «не задано») или одна строка —
#: одно значение. Через запятую делится только `status`, как в `GET /api/vm/vulns`.
Multi = str | list[str] | None


class BulkFilter(BaseModel):
    """Фильтр массовой смены — те же параметры, что у `GET /api/vm/vulns`."""

    model_config = ConfigDict(extra="forbid")

    q: str | None = None
    host: str | None = None
    cve: str | None = None
    criticality: Multi = None
    zone: Multi = None
    os: Multi = None
    level: Multi = None
    exploits: bool | None = None
    msf: bool | None = None
    kev: bool | None = None
    cvss_source: Multi = None
    host_id: int | None = None
    status: Multi = None
    assignee: Multi = None
    overdue: bool | None = None
    risk_expiring: bool | None = None


def parse_filter(raw: dict[str, Any], *, login: str, levels: Levels) -> VulnFilters:
    """Ошибка — ValueError (в том числе ValidationError): платформа отвечает 422 до запуска задачи.
    `levels` — пороги уровней из настроек: фильтр `level` выбирает те же пары, что список."""
    b = BulkFilter.model_validate(raw)
    sf = status_filter(b.status, b.assignee, b.overdue, b.risk_expiring, login=login)
    return VulnFilters(b.q, b.host, b.cve, multi(b.criticality), multi(b.zone), multi(b.os), multi(b.level),
                       b.exploits, b.msf, b.kev, multi(b.cvss_source), b.host_id, sf, levels)


def keys_by_filter(db: Session, scope_id: int, raw: dict[str, Any]) -> Iterator[str]:
    """`register_bulk_filter`: фильтр разбирается сразу, ключи — по мере чтения."""
    return iter_keys(db, parse_filter(raw, login="", levels=load_settings(db).weights.levels), BULK_CHUNK)


def start_bulk_job(db: Session, req: BulkJobRequest) -> tuple[int, Callable[[], None]]:
    """`register_bulk_job`: заводит задачу `bulk_status` и отдаёт работу для фона. Не во время
    импорта или пересчёта (`BulkConflict`): пары выбираются кусками, и замена данных посреди
    смены смешала бы два импорта. Импорт, записанный всё же посреди задачи (сменился последний
    `VmImport`), останавливает её; сделанное до остановки остаётся."""
    f = parse_filter(req.filter, login=req.actor, levels=load_settings(db).weights.levels)
    lock_job_start(db)
    if active_job(db, DATA_KINDS) is not None:
        raise BulkConflict("идёт импорт VM — повторите после него")
    about = f"bulk_id {req.bulk_id}; фильтр {filter_text(req.filter)}"
    job_id = start_job(db, "bulk_status", req.actor, message=f"массовая смена статусов; {about}")

    def work(session: Session, handle: JobHandle) -> None:
        actor = session.scalars(select(AppUser).where(AppUser.login == req.actor)).one()
        data = session.scalar(select(func.max(VmImport.id)))
        total = count(session, f)
        handle.stage("status", total=total, message=f"пар по фильтру: {total}; {about}")
        done = changed = 0
        try:
            for chunk in batched(iter_keys(session, f, BULK_CHUNK), BULK_CHUNK):
                if session.scalar(select(func.max(VmImport.id))) != data:
                    raise RuntimeError("данные VM заменены импортом посреди массовой смены — она остановлена")
                changed += finding_svc.bulk_change(session, module=MODULE, scope_id=SCOPE, keys=chunk,
                                                   change=req.change, actor=actor, bulk_id=req.bulk_id)
                done += len(chunk)
                # Пар могло стать больше, чем при подсчёте: прогресс не уходит за 100 %.
                total = max(total, done)
                handle.tick(done, message=f"изменено {changed} из {done}; {about}", total=total)
        except BaseException:
            # Строка задачи отдельной транзакцией: основную откатит run_job.
            handle.report_progress(done, total, f"применено {done} из {total} до остановки; {about}")
            raise

    return job_id, lambda: run_job(job_id, work)
