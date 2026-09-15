"""Обогащение и пересчёт через базу: контрольный пример спеки даёт 100."""
from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import select

from api.modules.vm.core.weights import DEFAULT_WEIGHTS as W
from api.modules.vm.models import (
    VmCve,
    VmHost,
    VmHostCve,
    VmRefEpss,
    VmRefExploitdb,
    VmRefExploitdbCve,
    VmRefMsf,
    VmRefMsfCve,
    VmRefNvd,
    VmZone,
)
from api.modules.vm.services.scoring import (
    drop_orphan_cves,
    ensure_cves,
    rebuild_cves,
    rebuild_hosts_impact,
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


def test_control_example_through_database(app_settings: Any, db_session: Any) -> None:
    _seed(db_session)
    db_session.add_all(
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
    db_session.commit()

    rebuild_cves(db_session, W)
    rebuild_hosts_impact(db_session, W)
    assert rescore_pairs(db_session) == 3

    cve = db_session.get(VmCve, "CVE-2021-44228")
    assert cve.cvss == 8.0 and cve.cvss_source == "nvd_v3"
    assert cve.exploitdb_type == "remote" and cve.exploits_count == 2
    assert cve.msf_rank == "excellent" and cve.msf_modules == 2
    assert cve.description == "log4j"

    bare = db_session.get(VmCve, "CVE-2020-0001")
    assert bare.cvss_source == "none" and bare.cve_factor == 0.5  # только подстановка EPSS

    h1 = db_session.execute(select(VmHost).where(VmHost.hostname == "srv01")).scalar_one()
    assert round(h1.impact, 2) == 0.99
    risks = {
        (p.host_id, p.cve_id): p.risk for p in db_session.execute(select(VmHostCve)).scalars()
    }
    assert risks[(h1.id, "CVE-2021-44228")] == 100
    # хост без критичности и с неразмеченной зоной: None + нет + нет = 0.6
    h2 = db_session.execute(select(VmHost).where(VmHost.hostname == "ws02")).scalar_one()
    assert round(h2.impact, 2) == 0.60
    assert risks[(h2.id, "CVE-2021-44228")] == 67  # 1.1197 × 0.6 = 0.6718


def test_rebuild_subset_and_orphans(app_settings: Any, db_session: Any) -> None:
    _seed(db_session)
    db_session.add(VmRefEpss(cve_id="CVE-2020-0001", epss=0.9, percentile=0.5))
    db_session.commit()
    rebuild_cves(db_session, W, ["CVE-2020-0001"])
    assert db_session.get(VmCve, "CVE-2020-0001").epss == 0.9
    assert db_session.get(VmCve, "CVE-2021-44228").epss is None
    assert drop_orphan_cves(db_session) == 1  # CVE-1999-9999 без пар
    assert db_session.get(VmCve, "CVE-1999-9999") is None
