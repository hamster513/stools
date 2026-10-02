"""VM на масштабе: сверка после импорта и список при большом числе строк состояния.

Данные пишутся COPY в обход импорта: импорт 300 тыс. пар через API шёл бы
минуты, а проверяется не он. Время печатается (`-s`) для отчёта.
"""
from __future__ import annotations

import datetime as dt
import time
from collections.abc import Iterable
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Table, func, select, text

from api.modules.vm.findings_adapter import ADAPTER, pair_key
from api.modules.vm.models import VmCve, VmHost, VmHostCve, VmImport
from api.modules.vm.services.bulk import bulk_insert
from api.platform.findings import adapters
from api.platform.findings import service as svc
from api.platform.findings.adapters import CurrentFinding
from api.platform.findings.models import FindingState

STATUSES = ("in_work", "risk_accepted", "fixed", "false_positive")


def _host(i: int) -> tuple[str, str]:
    return f"ws{i:05d}.corp.local", f"10.{i // 62500}.{i // 250 % 250}.{i % 250}"


def synthetic(db: Any, *, hosts: int, cves: int, states: int, absent: int, login: str) -> list[tuple[Any, ...]]:
    """`hosts × cves` пар, `states` строк состояния на присутствующих парах (статусы по кругу
    `STATUSES`, у `in_work` — исполнитель `login`) и `absent` строк на парах, которых нет."""
    cve_ids = [f"CVE-2024-{10000 + j}" for j in range(cves)]
    bulk_insert(db, cast(Table, VmHost.__table__), ("id", "hostname", "ip", "os_name", "groups", "criticality", "zone", "impact"),
                [(i + 1, *_host(i), "Windows 11", "", "High", f"Z{i % 4}", 1.0) for i in range(hosts)])
    bulk_insert(db, cast(Table, VmCve.__table__), ("cve_id", "cvss_source", "exploits_count", "msf_modules", "cve_factor"),
                [(c, "none", 0, 0, 0.0) for c in cve_ids])
    bulk_insert(db, cast(Table, VmHostCve.__table__), ("host_id", "cve_id", "risk_raw", "risk"),
                ((i + 1, c, 0.0, (i * 7 + j * 13) % 101) for i in range(hosts) for j, c in enumerate(cve_ids)))
    db.add(VmImport(source="file", filename="synthetic.csv", hosts=hosts, pairs=hosts * cves, cves=cves))
    now = dt.datetime.now(dt.UTC)
    rows: list[tuple[Any, ...]] = []
    for n in range(states):
        # Шаг по CVE взаимно прост с числом CVE: строки ложатся на разные пары.
        h, c = _host(n % hosts), cve_ids[(n // hosts * 37 + n) % cves]
        status = STATUSES[n % len(STATUSES)]
        rows.append(("vm", 0, pair_key(h[0], h[1], c), status, login if status == "in_work" else None, "x", True, "", "", login, now))
    rows += [("vm", 0, pair_key(*_host(n % hosts), f"CVE-2099-{n:05d}"), "in_work", None, "", True, "", "", login, now)
             for n in range(absent)]
    rows = list({r[2]: r for r in rows}.values())
    bulk_insert(db, cast(Table, FindingState.__table__),
                ("module", "scope_id", "key", "status", "assignee", "reason", "present", "title", "severity", "updated_by", "updated_at"),
                rows)
    db.commit()
    # Строки состояния записаны в обход платформы — подсказки модуля дописываются так же,
    # как миграция дописывает их для строк, заведённых до неё.
    ADAPTER.backfill(db)
    db.execute(text("ANALYZE"))
    db.commit()
    return rows


class NoMaterialise:
    """Адаптер VM, у которого `current()` запрещён: сверка не должна собирать все пары."""

    module = "vm"

    def __init__(self) -> None:
        self.current_calls = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(ADAPTER, name)

    def current(self, db: Any, scope_id: int) -> Iterable[CurrentFinding] | None:
        self.current_calls += 1
        raise AssertionError("сверка VM не должна читать все пары")


def test_reconcile_200k_pairs_does_not_materialise(db_session: Any, test_user: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """200 тыс. пар × 20 тыс. строк (2 тыс. — пропавших пар): сверка < 5 с, `current()` не зовётся."""
    rows = synthetic(db_session, hosts=2000, cves=100, states=18_000, absent=2000, login=test_user.login)
    guard = NoMaterialise()
    monkeypatch.setitem(adapters._ADAPTERS, "vm", guard)

    t = time.perf_counter()
    counts = svc.reconcile(db_session, "vm", 0, ref="импорт #1")
    elapsed = time.perf_counter() - t
    print(f"\nVM 200k×20k: reconcile {elapsed:.3f}s {counts}")
    assert guard.current_calls == 0
    # Пропали 2 тыс. «в работе» → устранены; принятые и ложные остаются с present=false — их тут нет.
    assert counts["resolved"] == 2000 and counts["present"] == 200_000 and counts["reopened"] == 0
    db_session.expire_all()
    gone = db_session.scalars(select(FindingState).where(FindingState.key.like("%CVE-2099-%")).limit(1)).one()
    assert (gone.status, gone.present) == ("resolved", False)
    # Подписи — только у строк, которые сверка тронула или которые видны: у присутствующих пар.
    titled = db_session.scalar(select(func.count()).where(FindingState.title != "", FindingState.present.is_(True)))
    assert titled == len(rows) - 2000
    assert elapsed < 5, elapsed

    # Вторая сверка ничего не меняет и тоже быстрая.
    t = time.perf_counter()
    again = svc.reconcile(db_session, "vm", 0, ref="импорт #2")
    print(f"VM 200k×20k: second reconcile {time.perf_counter() - t:.3f}s {again}")
    assert again["resolved"] == 0 and again["reopened"] == 0


def test_summary_counts_without_materialising(auth_client: TestClient, db_session: Any, test_user: Any,
                                               monkeypatch: pytest.MonkeyPatch) -> None:
    synthetic(db_session, hosts=50, cves=20, states=100, absent=10, login=test_user.login)
    svc.reconcile(db_session, "vm", 0, ref="импорт #1")
    guard = NoMaterialise()
    monkeypatch.setitem(adapters._ADAPTERS, "vm", guard)
    r = auth_client.get("/api/findings/summary", params={"module": "vm", "scope_id": 0})
    assert r.status_code == 200, r.text
    assert guard.current_calls == 0
    # 1000 пар, из них 100 с решением: 25 — в работе (тоже открытые), 75 — иначе; новых — 900.
    assert r.json()["by_status"]["new"] == 900


def test_list_speed_with_100k_state_rows(auth_client: TestClient, db_session: Any, test_user: Any) -> None:
    """300 тыс. пар × 100 тыс. строк состояния: первая страница (по умолчанию, с фасетами), следующая,
    `status=in_work`, фасеты с фильтром по данным — каждая < 500 мс."""
    from api.modules.vm.services.stats import refresh_stats

    rows = synthetic(db_session, hosts=3000, cves=100, states=100_000, absent=0, login=test_user.login)
    refresh_stats(db_session)
    in_work = sum(1 for r in rows if r[3] == "in_work")

    def timed(**params: Any) -> tuple[float, dict[str, Any]]:
        best, body = float("inf"), {}
        for _ in range(2):
            t0 = time.perf_counter()
            r = auth_client.get("/api/vm/vulns", params=params)
            best = min(best, time.perf_counter() - t0)
            assert r.status_code == 200, r.text
            body = r.json()
        return best, body

    timed()  # прогрев
    t_first, first = timed()
    assert first["total"] == 300_000 - sum(1 for r in rows if r[3] in ("risk_accepted", "false_positive"))
    t_next, nxt = timed(offset=200)
    assert len(nxt["items"]) == 200
    t_work, work = timed(status="in_work")
    assert work["total"] == in_work and all(i["status"] == "in_work" for i in work["items"])
    t_zone, zone = timed(zone="Z1")
    assert zone["facets"]["zone"] == {"Z1": zone["total"]}
    t_me, me = timed(assignee="me")
    assert me["total"] == in_work
    print(f"\nVM 300k×100k: first page (default, facets) {t_first * 1000:.0f} ms; next page {t_next * 1000:.0f} ms; "
          f"status=in_work {t_work * 1000:.0f} ms; zone + facets {t_zone * 1000:.0f} ms; assignee=me {t_me * 1000:.0f} ms")
    for name, took in (("first", t_first), ("next", t_next), ("in_work", t_work), ("zone", t_zone), ("me", t_me)):
        assert took < 0.5, (name, took)
