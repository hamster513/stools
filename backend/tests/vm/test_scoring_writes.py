"""Repeated scoring must preserve tuple versions for unchanged priorities."""
from typing import Any

from sqlalchemy import event, func, insert, select, text

from api.modules.vm.core.weights import Weights
from api.modules.vm.models import VmCve, VmHost, VmHostCve, VmImageCve
from api.modules.vm.services.scoring import rescore_all, rescore_image_pairs
from tests.vm.test_image_scoring import CVE, _image, _pair
from tests.vm.test_import import _upload


def _versions(db: Any, table: str) -> list:
    assert table in {"vm_host_cve", "vm_image_cve", "vm_image"}
    columns = "id" if table == "vm_image" else "cve_id"
    return list(db.execute(text(f"SELECT {columns}, xmin::text FROM {table} ORDER BY {columns} LIMIT 20")))


def test_repeated_full_scoring_preserves_rows_and_processed_count(db_session: Any) -> None:
    db_session.add(VmCve(cve_id=CVE, cvss=8, epss=.5, av_class="network"))
    host = VmHost(hostname="node", ip="192.0.2.1")
    db_session.add(host)
    db_session.flush()
    db_session.add(VmHostCve(host_id=host.id, cve_id=CVE))
    _pair(db_session, _image(db_session))
    _image(db_session, "empty")
    db_session.commit()
    assert rescore_all(db_session, Weights()) == 2
    tables = ("vm_host_cve", "vm_image_cve", "vm_image")
    before = {table: _versions(db_session, table) for table in tables}
    assert rescore_all(db_session, Weights()) == 2
    assert {table: _versions(db_session, table) for table in tables} == before


def test_only_changed_cve_is_rewritten_and_kev_floor_preserved(db_session: Any) -> None:
    second = "CVE-2024-0002"
    db_session.add_all([VmCve(cve_id=CVE, cvss=8, epss=.01, av_class="network"),
                        VmCve(cve_id=second, cvss=8, epss=.01, av_class="network")])
    _pair(db_session, _image(db_session), cve_id=CVE)
    _pair(db_session, _image(db_session, "other"), cve_id=second)
    db_session.commit()
    assert rescore_image_pairs(db_session, Weights()) == 2
    before = dict(_versions(db_session, "vm_image_cve"))
    db_session.get(VmCve, CVE).kev = True
    db_session.commit()
    assert rescore_image_pairs(db_session, Weights()) == 2
    after = dict(_versions(db_session, "vm_image_cve"))
    assert after[CVE] != before[CVE]
    assert after[second] == before[second]
    pair = db_session.scalar(select(VmImageCve).where(VmImageCve.cve_id == CVE).limit(1))
    assert pair.risk >= 80


def test_raw_score_change_is_saved_even_when_rounded_score_stays_same(db_session: Any) -> None:
    db_session.add(VmCve(cve_id=CVE, cvss=8.01, epss=.1, av_class="network"))
    image = _image(db_session)
    _pair(db_session, image)
    db_session.commit()
    rescore_image_pairs(db_session, Weights())
    pair = db_session.scalar(select(VmImageCve).limit(1))
    before = pair.risk, pair.risk_raw
    db_session.get(VmCve, CVE).cvss = 8.02
    db_session.commit()
    rescore_image_pairs(db_session, Weights())
    db_session.expire_all()
    assert pair.risk == before[0]
    assert pair.risk_raw != before[1]


def test_host_import_preserves_scored_images_and_recovers_missing_ones(auth_client: Any, db_session: Any) -> None:
    db_session.add(VmCve(cve_id=CVE, cvss=8, epss=.5, av_class="network"))
    existing = _image(db_session)
    _pair(db_session, existing)
    db_session.commit()
    rescore_image_pairs(db_session, Weights())
    pair_before = dict(_versions(db_session, "vm_image_cve"))[CVE]
    image_before = dict(_versions(db_session, "vm_image"))[existing.id]
    pending = _image(db_session, "pending")
    _pair(db_session, pending)
    db_session.commit()

    assert _upload(auth_client, "hosts.csv")["status"] == "done"
    db_session.expire_all()
    old_pair = db_session.execute(text("SELECT xmin::text FROM vm_image_cve WHERE image_id=:id LIMIT 1"),
                                  {"id": existing.id}).scalar_one()
    assert old_pair == pair_before
    assert dict(_versions(db_session, "vm_image"))[existing.id] == image_before
    assert pending.risk_max is not None and pending.cves_scored == 1


def test_host_import_skips_image_aggregation_when_no_scores_are_missing(auth_client: Any, db_session: Any) -> None:
    db_session.add(VmCve(cve_id=CVE, cvss=8, epss=.5, av_class="network"))
    image = _image(db_session)
    _pair(db_session, image)
    _pair(db_session, image, cve_id="UNKNOWN", package="unmapped")
    db_session.commit()
    rescore_image_pairs(db_session, Weights())
    statements = []

    def capture(_conn, _cursor, statement, _parameters, _context, _many):
        if "image_risk_totals" in statement or "UPDATE vm_image_cve" in statement:
            statements.append(statement)

    engine = db_session.get_bind()
    event.listen(engine, "before_cursor_execute", capture)
    try:
        assert _upload(auth_client, "hosts.csv")["status"] == "done"
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert statements == []


def test_unmapped_findings_reset_across_streamed_batches(db_session: Any) -> None:
    db_session.add(VmCve(cve_id=CVE, cvss=8, epss=.5, av_class="network"))
    image = _image(db_session)
    _pair(db_session, image)
    db_session.execute(insert(VmImageCve), [
        {"image_id": image.id, "cve_id": f"UNKNOWN-{i}", "package": "pkg",
         "installed_version": "1", "trivy_severity": "high", "risk": 99, "risk_raw": .99}
        for i in range(6000)
    ])
    db_session.commit()
    assert rescore_image_pairs(db_session, Weights()) == 1
    db_session.expire_all()
    assert image.cves_scored == 1
    assert db_session.scalar(select(func.count()).select_from(VmImageCve).where(
        VmImageCve.cve_id != CVE,
        VmImageCve.risk.is_not(None) | VmImageCve.risk_raw.is_not(None),
    )) == 0
