"""Correctness and query-work regression for image risk aggregation."""
from types import SimpleNamespace
from typing import Any

from sqlalchemy import select, text

from api.modules.vm.core.weights import Weights
from api.modules.vm.ghsa_models import VmRefGhsa, VmRefGhsaAlias
from api.modules.vm.models import VmCve, VmImage, VmImageCve
from api.modules.vm.services.scoring import rescore_image_pairs


def _summary_statement():
    class Capture:
        def execute(self, statement):
            self.last = statement
            return SimpleNamespace(rowcount=0)

        def commit(self):
            pass

    capture = Capture()
    rescore_image_pairs(capture, Weights())
    return capture.last


def test_summary_does_not_rescan_findings_for_every_image(db_session: Any) -> None:
    images = [VmImage(project="test", repository=str(i), digest=f"sha256:{i}") for i in range(64)]
    db_session.add_all(images)
    db_session.flush()
    db_session.add_all([
        VmImageCve(image_id=image.id, cve_id=f"CVE-2026-{j:05}", package=f"p{j}",
                   installed_version="1", trivy_severity="High", risk=40, risk_raw=0.4)
        for image in images for j in range(32)
    ])
    db_session.flush()
    db_session.execute(text("ANALYZE vm_image"))
    db_session.execute(text("ANALYZE vm_image_cve"))
    db_session.execute(text("SET LOCAL max_parallel_workers_per_gather = 0"))
    sql = str(_summary_statement().compile(
        dialect=db_session.get_bind().dialect, compile_kwargs={"literal_binds": True},
    ))
    plan = db_session.execute(text("EXPLAIN (ANALYZE, FORMAT JSON, TIMING OFF) " + sql)).scalar_one()[0]["Plan"]

    def nodes(node):
        yield node
        for child in node.get("Plans", []):
            yield from nodes(child)

    scans = [node for node in nodes(plan) if node.get("Relation Name") == "vm_image_cve"]
    assert scans
    assert all(node["Actual Loops"] <= 1 for node in scans), [
        (node["Node Type"], node["Actual Loops"]) for node in scans
    ]
    assert all(image.cves_scored == 32 and image.risk_max == 40
               for image in db_session.scalars(select(VmImage).execution_options(populate_existing=True)))


def test_summary_preserves_aliases_packages_versions_and_empty_images(db_session: Any) -> None:
    cve, ghsa = "CVE-2026-10001", "GHSA-test-aaaa-bbbb"
    db_session.add(VmRefGhsa(ghsa_id=ghsa))
    db_session.flush()
    db_session.add(VmRefGhsaAlias(ghsa_id=ghsa, alias=cve))
    db_session.add_all([
        VmCve(cve_id=cve, epss=.5, cvss=8, v3_av="NETWORK", av_class="network"),
        VmCve(cve_id=ghsa, epss=.01, cvss=8, v3_av="NETWORK", av_class="network"),
        VmCve(cve_id="CVE-2026-00000", epss=0, cvss=0, v3_av="NETWORK", av_class="network"),
    ])
    images = [VmImage(project="test", repository=str(i), digest=f"sha256:{i}",
                      risk_max=99, cves_scored=99) for i in range(5)]
    db_session.add_all(images)
    db_session.flush()
    records = [
        (0, cve, "pkg", "1"), (0, ghsa, "pkg", "1"),
        (0, cve, "pkg", "2"), (0, ghsa, "pkg", "2"),
        (0, cve, "other", "1"), (0, "UNKNOWN", "unknown", "1"),
        (1, ghsa, "pkg", "1"), (3, "UNKNOWN", "unknown", "1"),
        (4, "CVE-2026-00000", "zero", "1"),
    ]
    db_session.add_all([
        VmImageCve(image_id=images[i].id, cve_id=identifier, package=package,
                   installed_version=version, trivy_severity="High", risk_raw=0.99, risk=99)
        for i, identifier, package, version in records
    ])
    db_session.commit()
    assert rescore_image_pairs(db_session, Weights()) == 7
    db_session.expire_all()
    assert [image.cves_scored for image in images] == [3, 1, 0, 0, 1]
    assert images[0].risk_max > images[1].risk_max > 0
    assert [image.risk_max for image in images[2:]] == [None, None, 22]
    stored = list(db_session.scalars(select(VmImageCve)))
    assert len(stored) == len(records)
    assert {(p.image_id, p.cve_id, p.package, p.installed_version) for p in stored} == {
        (images[i].id, identifier, package, version) for i, identifier, package, version in records
    }
    assert all(p.risk is None and p.risk_raw is None for p in stored if p.cve_id == "UNKNOWN")
