"""Обогащение и пересчёт через базу: раскладка формулы в SQL совпадает с `explain`."""
from __future__ import annotations

import datetime as dt
import itertools
from typing import Any

import pytest
from sqlalchemy import select

from api.modules.vm.core.risk import CveInputs, explain
from api.modules.vm.core.weights import DEFAULT_WEIGHTS as W
from api.modules.vm.core.weights import Weights
from api.modules.vm.models import (
    VmCve,
    VmHost,
    VmHostCve,
    VmJob,
    VmRefEpss,
    VmRefExploitdb,
    VmRefExploitdbCve,
    VmRefKev,
    VmRefMsf,
    VmRefMsfCve,
    VmRefNvd,
    VmRefState,
    VmZone,
)
from api.modules.vm.services import scoring
from api.modules.vm.services.scoring import (
    drop_orphan_cves,
    ensure_cves,
    ensure_rescored,
    rebuild_cves,
    rebuild_hosts_value,
    rescore_pairs,
)


def _seed(db: Any) -> None:
    db.add(VmZone(name="DMZ", internet_access=True, confidential_data=True, marked=True))
    h1 = VmHost(hostname="srv01", ip="10.0.0.1", criticality="Critical", zone="DMZ")
    h2 = VmHost(hostname="ws02", ip="10.0.0.2", criticality="", zone="Unknown")
    db.add_all([h1, h2])
    db.flush()
    ensure_cves(db, ["CVE-2021-44228", "CVE-2020-0001", "CVE-1999-9999"])
    db.add_all(
        [
            VmHostCve(host_id=h1.id, cve_id="CVE-2021-44228"),
            VmHostCve(host_id=h1.id, cve_id="CVE-2020-0001"),
            VmHostCve(host_id=h2.id, cve_id="CVE-2021-44228"),
        ]
    )
    db.commit()


def _log4j_refs(db: Any) -> None:
    db.add_all(
        [
            VmRefEpss(cve_id="CVE-2021-44228", epss=0.5, percentile=0.99),
            VmRefNvd(cve_id="CVE-2021-44228", year=2021, cvss_v3=8.0, v3_av="NETWORK", v3_pr="NONE", v3_ui="NONE", description="log4j", published=dt.date(2021, 12, 10)),
            VmRefExploitdb(exploit_id=1, type="remote"),
            VmRefExploitdb(exploit_id=2, type="dos"),
            VmRefExploitdbCve(cve_id="CVE-2021-44228", exploit_id=1),
            VmRefExploitdbCve(cve_id="CVE-2021-44228", exploit_id=2),
            VmRefMsf(fullname="exploit/multi/http/log4shell", name="Log4Shell", rank=600),
            VmRefMsf(fullname="auxiliary/scanner/log4shell", name="scan", rank=300),
            VmRefMsfCve(cve_id="CVE-2021-44228", fullname="exploit/multi/http/log4shell"),
            VmRefMsfCve(cve_id="CVE-2021-44228", fullname="auxiliary/scanner/log4shell"),
        ]
    )
    db.commit()


def test_control_example_through_database(app_settings: Any, db_session: Any) -> None:
    _seed(db_session)
    _log4j_refs(db_session)

    rebuild_cves(db_session, W)
    rebuild_hosts_value(db_session, W)
    assert rescore_pairs(db_session, W) == 3

    cve = db_session.get(VmCve, "CVE-2021-44228")
    assert cve.cvss == 8.0 and cve.cvss_source == "nvd_v3" and cve.cvss10 == 0.8 and cve.av_class == "network"
    assert cve.exploitdb_type == "remote" and cve.exploits_count == 2
    assert cve.msf_rank == "excellent" and cve.msf_modules == 2
    assert cve.description == "log4j" and cve.kev is False
    # 1 − (1 − 0.5)(1 − 0.30)(1 − 0.50)
    assert cve.likelihood == pytest.approx(0.825)

    bare = db_session.get(VmCve, "CVE-2020-0001")
    assert bare.cvss_source == "none" and bare.cvss10 is None and bare.av_class == "none"
    assert bare.likelihood == pytest.approx(W.prior_epss)  # только априорный EPSS

    h1 = db_session.execute(select(VmHost).where(VmHost.hostname == "srv01")).scalar_one()
    assert h1.value == 1.0 and h1.internet is True  # Critical 1.0 + 0.1 + 0.1, потолок 1
    h2 = db_session.execute(select(VmHost).where(VmHost.hostname == "ws02")).scalar_one()
    assert h2.value == pytest.approx(0.6) and h2.internet is False  # критичность не задана, зоны нет
    risks = {(p.host_id, p.cve_id): p.risk for p in db_session.execute(select(VmHostCve)).scalars()}
    assert risks[(h1.id, "CVE-2021-44228")] == 66  # 0.825 × 0.8 × 1.0 × 1.0
    assert risks[(h2.id, "CVE-2021-44228")] == 32  # 0.825 × 0.8 × 0.8 × 0.6 = 0.3168
    assert risks[(h1.id, "CVE-2020-0001")] == 0  # 0.01 × 0.5 × 0.8 × 1.0


#: Веса, отличные от умолчаний, — проверяют, что SQL берёт их из параметров, а не из констант.
CUSTOM = Weights.model_validate(
    {
        "prior_epss": 0.05,
        "cvss_missing": 0.4,
        "reach_unknown": 0.9,
        "reach": {"network_internet": 0.95, "network_internal": 0.7, "adjacent": 0.5, "local": 0.3},
        "value": {"conf_bonus": 0.2, "inet_bonus": 0.15},
    }
)


@pytest.mark.parametrize("weights", [W, CUSTOM], ids=["default", "custom"])
def test_sql_rescore_matches_explain(app_settings: Any, db_session: Any, weights: Weights) -> None:
    """Главный тест раскладки: 5 хостов × 4 CVE — все классы вектора, с интернетом и без,
    KEV, подстановки CVSS и EPSS; балл каждой пары из UPDATE равен баллу `explain`."""
    db = db_session
    db.add_all(
        [
            VmZone(name="DMZ", internet_access=True, confidential_data=True, marked=True),
            VmZone(name="Office", internet_access=True, confidential_data=False, marked=True),
            VmZone(name="Lab", internet_access=False, confidential_data=True, marked=True),
            VmZone(name="Fresh", internet_access=False, confidential_data=False, marked=False),
        ]
    )
    hosts = [
        VmHost(hostname="h1", ip="10.9.0.1", criticality="Critical", zone="DMZ"),
        VmHost(hostname="h2", ip="10.9.0.2", criticality="High", zone="Office"),
        VmHost(hostname="h3", ip="10.9.0.3", criticality="Low", zone="Lab"),
        VmHost(hostname="h4", ip="10.9.0.4", criticality="", zone="Fresh"),
        VmHost(hostname="h5", ip="10.9.0.5", criticality="Medium", zone=""),
    ]
    db.add_all(hosts)
    db.flush()
    cves = ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"]
    ensure_cves(db, cves)
    db.add_all(VmHostCve(host_id=h.id, cve_id=c) for h, c in itertools.product(hosts, cves))
    db.add_all(
        [
            VmRefEpss(cve_id="CVE-2026-0001", epss=0.3, percentile=0.9),
            VmRefNvd(cve_id="CVE-2026-0001", year=2026, cvss_v3=9.8, v3_av="NETWORK"),
            VmRefExploitdb(exploit_id=10, type="remote"),
            VmRefExploitdbCve(cve_id="CVE-2026-0001", exploit_id=10),
            VmRefMsf(fullname="exploit/x", name="x", rank=600),
            VmRefMsfCve(cve_id="CVE-2026-0001", fullname="exploit/x"),
            VmRefNvd(cve_id="CVE-2026-0002", year=2026, cvss_v2=6.5, v2_av="ADJACENT_NETWORK"),
            VmRefEpss(cve_id="CVE-2026-0003", epss=0.9, percentile=0.99),
            VmRefNvd(cve_id="CVE-2026-0003", year=2026, cvss_v3=7.8, v3_av="LOCAL"),
            VmRefKev(cve_id="CVE-2026-0003", date_added=dt.date(2026, 1, 5), ransomware=True, vendor="v", product="p", name="n"),
            VmRefState(name="kev", source="file", records=1),
        ]
    )
    db.commit()

    rebuild_cves(db, weights)
    rebuild_hosts_value(db, weights)
    assert rescore_pairs(db, weights) == 20
    db.expire_all()

    zones = {z.name: z for z in db.execute(select(VmZone)).scalars()}
    seen = set()
    for pair in db.execute(select(VmHostCve)).scalars():
        host, cve = db.get(VmHost, pair.host_id), db.get(VmCve, pair.cve_id)
        zone = zones.get(host.zone)
        e = explain(
            CveInputs(
                epss=cve.epss, cvss=cve.cvss, av=cve.v3_av or cve.v2_av, exploitdb_type=cve.exploitdb_type,
                msf_rank=cve.msf_rank, kev=cve.kev, kev_added=cve.kev_added, kev_loaded=True,
            ),
            host.criticality or None,
            internet=bool(zone and zone.internet_access),
            confidential=bool(zone and zone.confidential_data),
            zone_marked=bool(zone and zone.marked),
            w=weights,
        )
        assert pair.risk == e.score, (host.hostname, cve.cve_id, pair.risk_raw, e.raw)
        assert pair.risk_raw == pytest.approx(e.raw)
        seen.add(e.score)
    assert len(seen) > 5  # пары действительно разные, а не 20 нулей
    kev = db.get(VmCve, "CVE-2026-0003")
    assert (kev.kev, kev.kev_added, kev.kev_ransomware, kev.likelihood) == (True, dt.date(2026, 1, 5), True, 1.0)
    assert db.get(VmCve, "CVE-2026-0002").av_class == "adjacent"


def test_rebuild_subset_and_orphans(app_settings: Any, db_session: Any) -> None:
    _seed(db_session)
    db_session.add(VmRefEpss(cve_id="CVE-2020-0001", epss=0.9, percentile=0.5))
    db_session.commit()
    rebuild_cves(db_session, W, ["CVE-2020-0001"])
    assert db_session.get(VmCve, "CVE-2020-0001").epss == 0.9
    assert db_session.get(VmCve, "CVE-2021-44228").epss is None
    assert drop_orphan_cves(db_session) == 1  # CVE-1999-9999 без пар
    assert db_session.get(VmCve, "CVE-1999-9999") is None


def test_rescore_once_after_migration(app_settings: Any, db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """После миграции вероятности нулевые, риск пар — старый: старт API ставит пересчёт один раз."""
    monkeypatch.setattr(scoring, "spawn", lambda fn: fn())
    _seed(db_session)
    assert ensure_rescored(db_session) is None  # справочников нет — пересчитывать нечем
    _log4j_refs(db_session)
    db_session.add(VmRefState(name="epss", source="file", records=1))
    db_session.commit()

    job_id = ensure_rescored(db_session)
    assert job_id is not None
    db_session.expire_all()
    job = db_session.get(VmJob, job_id)
    assert (job.kind, job.status, job.started_by) == ("recalculate", "done", scoring.AUTO_STARTED_BY)
    assert db_session.get(VmCve, "CVE-2021-44228").likelihood == pytest.approx(0.825)
    assert max(p.risk for p in db_session.execute(select(VmHostCve)).scalars()) == 66
    # Второй старт: вероятности уже посчитаны — задачи нет.
    assert ensure_rescored(db_session) is None


def test_rescore_not_started_over_running_job(app_settings: Any, db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    started: list[Any] = []
    monkeypatch.setattr(scoring, "spawn", started.append)
    _seed(db_session)
    db_session.add_all([VmRefState(name="epss", source="file", records=1), VmJob(kind="import_file", status="running", started_by="x")])
    db_session.commit()
    assert ensure_rescored(db_session) is None and started == []


def test_vm_tables_match_models(db_session: Any) -> None:
    """Колонки новой формулы и `vm_ref_kev` из миграции совпадают с моделями."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from api.db.models import Base

    ctx = MigrationContext.configure(db_session.connection(), opts={"compare_type": True, "compare_server_default": False})
    # Индексы по выражению (`ix_vm_host_key`) autogenerate не сравнивает — только таблицы и колонки.
    diffs = [
        d for d in compare_metadata(ctx, Base.metadata)
        if any(t in repr(d) for t in ("vm_cve", "vm_host", "vm_ref_kev")) and not (isinstance(d, tuple) and d[0].endswith("_index"))
    ]
    assert diffs == []
