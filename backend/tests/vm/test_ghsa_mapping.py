"""GHSA aliases are evidence links, never destructive scanner ID rewrites."""
from __future__ import annotations

import datetime as dt
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.modules.vm.core.weights import Weights
from api.modules.vm.ghsa_models import VmRefGhsa, VmRefGhsaAlias
from api.modules.vm.models import VmCve, VmImage, VmImageCve, VmRefEpss, VmRefNvd, VmRefState
from api.modules.vm.services.ghsa_mapping import equivalents, public_advisories, reference_metrics
from api.modules.vm.services.scoring import ensure_cves, rebuild_cves, rescore_image_pairs

GHSA = "GHSA-2345-6789-cfgh"
PEER = "GHSA-jmpq-rvwx-2345"
CVE = "CVE-2026-12345"
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _advisory(db: Any, identifier: str = GHSA, alias: str | None = None,
              withdrawn: bool = False) -> None:
    db.add(VmRefGhsa(ghsa_id=identifier, summary="Package vulnerability", description="Details",
                     cvss=9.8, cvss_version="3.1", cvss_vector=VECTOR, reviewed=True,
                     withdrawn=dt.datetime.now(dt.UTC) if withdrawn else None))
    db.flush()
    if alias:
        db.add(VmRefGhsaAlias(ghsa_id=identifier, alias=alias))
    db.commit()


def test_explicit_aliases_include_peer_ghsa_without_changing_scanner_id(db_session: Any) -> None:
    _advisory(db_session, alias=CVE)
    _advisory(db_session, identifier=PEER, alias=CVE)
    assert equivalents(db_session, GHSA) == {GHSA, PEER, CVE}
    assert equivalents(db_session, CVE) == {GHSA, PEER, CVE}
    assert equivalents(db_session, "CVE-2026-99999") == {"CVE-2026-99999"}


def test_withdrawn_is_visible_but_never_propagates_reference_evidence(db_session: Any) -> None:
    _advisory(db_session, alias=CVE, withdrawn=True)
    db_session.add(VmRefNvd(cve_id=CVE, year=2026, cvss_v3=8.1, v3_av="NETWORK"))
    db_session.commit()
    assert equivalents(db_session, GHSA) == {GHSA}
    assert equivalents(db_session, CVE) == {CVE}
    assert public_advisories(db_session, GHSA)[0].withdrawn is not None
    reference = reference_metrics(db_session, [GHSA])[GHSA]
    assert reference.ghsa is None and reference.nvd is None


def test_alias_scoring_preserves_nvd_priority_and_epss(db_session: Any) -> None:
    _advisory(db_session, alias=CVE)
    db_session.add_all([
        VmRefNvd(cve_id=CVE, year=2026, cvss_v3=7.5, v3_av="LOCAL", description="NVD first"),
        VmRefEpss(cve_id=CVE, epss=0.2, percentile=0.8),
    ])
    db_session.commit()
    ensure_cves(db_session, [CVE, GHSA])
    rebuild_cves(db_session, Weights())
    db_session.expire_all()
    first, second = (db_session.get(VmCve, key) for key in (CVE, GHSA))
    assert second.cve_id == GHSA
    assert first.cvss == second.cvss == 7.5
    assert first.cvss_source == second.cvss_source == "nvd_v3"
    assert first.epss == second.epss == 0.2
    assert first.av_class == second.av_class == "local"


def test_standalone_ghsa_gets_risk_without_fabricated_epss(db_session: Any) -> None:
    _advisory(db_session)
    image = VmImage(project="library", repository="test", digest="sha256:test")
    db_session.add(image)
    db_session.flush()
    db_session.add(VmImageCve(image_id=image.id, cve_id=GHSA, package="test", installed_version="1", trivy_severity="High"))
    db_session.commit()
    # Existing scanner findings must acquire reference risk on import, without another Harbor sync.
    rebuild_cves(db_session, Weights())
    rescore_image_pairs(db_session, Weights())
    db_session.expire_all()
    row = db_session.get(VmCve, GHSA)
    assert row.cvss == 9.8 and row.cvss_source == "ghsa_v3"
    assert row.av_class == "network" and row.epss is None
    assert db_session.get(VmImage, image.id).risk_max is not None
    assert db_session.scalar(select(VmImageCve.risk_raw)) > 0


@pytest.mark.parametrize("scanner_id", [GHSA, GHSA.upper()])
def test_same_package_cve_and_ghsa_finding_are_counted_once(db_session: Any, scanner_id: str) -> None:
    _advisory(db_session, alias=CVE)
    ensure_cves(db_session, [CVE, scanner_id])
    rebuild_cves(db_session, Weights())
    image = VmImage(project="library", repository="test", digest="sha256:test")
    db_session.add(image)
    db_session.flush()
    for identifier in (CVE, scanner_id):
        db_session.add(VmImageCve(image_id=image.id, cve_id=identifier, package="test", installed_version="1", trivy_severity="High"))
    db_session.commit()
    rescore_image_pairs(db_session, Weights())
    db_session.expire_all()
    assert db_session.get(VmImage, image.id).cves_scored == 1
    assert set(db_session.scalars(select(VmImageCve.cve_id))) == {CVE, scanner_id}


def test_harbor_sync_builds_ghsa_risk_and_retains_original_id(db_session: Any) -> None:
    from tests.vm.test_harbor_sync import LIB, _images, _pairs, _sync, fake_harbor

    _advisory(db_session)
    fake = fake_harbor()
    report = fake.routes[f"{LIB}/debian/artifacts/*"]
    first_report = next(iter(report.values()))
    first_report["vulnerabilities"] = [{
        "id": GHSA, "package": "example", "version": "1.0.0", "fix_version": "1.0.1",
        "severity": "High", "description": "Direct scanner finding",
    }]
    assert _sync(fake)[0].status == "done"
    image = _images(db_session)["library/debian"]
    pair = next(pair for pair in _pairs(db_session, image.id) if pair.cve_id == GHSA)
    assert pair.risk is not None and pair.risk_raw > 0
    assert db_session.get(VmCve, GHSA).cvss_source == "ghsa_v3"


def test_peer_alias_component_counts_all_original_findings_once(db_session: Any) -> None:
    high, low = "CVE-2026-22222", "CVE-2026-11111"
    _advisory(db_session, alias=high)
    _advisory(db_session, identifier=PEER, alias=high)
    db_session.add(VmRefGhsaAlias(ghsa_id=PEER, alias=low))
    image = VmImage(project="library", repository="peers", digest="sha256:peers")
    db_session.add(image)
    db_session.flush()
    ids = {GHSA, PEER, high, low}
    for identifier in ids:
        db_session.add(VmImageCve(image_id=image.id, cve_id=identifier, package="test", installed_version="1", trivy_severity="High"))
    db_session.commit()
    ensure_cves(db_session, ids)
    rebuild_cves(db_session, Weights())
    rescore_image_pairs(db_session, Weights())
    db_session.expire_all()
    assert all(equivalents(db_session, identifier) == ids for identifier in ids)
    assert db_session.get(VmImage, image.id).cves_scored == 1
    assert set(db_session.scalars(select(VmImageCve.cve_id))) == ids


def test_usable_nvd_alias_precedes_empty_nvd_and_ghsa_score(db_session: Any) -> None:
    empty, scored = "CVE-2026-11111", "CVE-2026-22222"
    _advisory(db_session, alias=empty)
    db_session.add_all([
        VmRefGhsaAlias(ghsa_id=GHSA, alias=scored),
        VmRefNvd(cve_id=empty, year=2026, description="No metrics yet"),
        VmRefNvd(cve_id=scored, year=2026, cvss_v3=7.5, v3_av="NETWORK"),
    ])
    db_session.commit()
    ensure_cves(db_session, [GHSA, empty, scored])
    rebuild_cves(db_session, Weights())
    db_session.expire_all()
    for identifier in (GHSA, empty, scored):
        metrics = reference_metrics(db_session, [identifier])[identifier]
        assert metrics.nvd.cve_id == scored
        row = db_session.get(VmCve, identifier)
        assert row.cvss == 7.5 and row.cvss_source == "nvd_v3"


@pytest.mark.parametrize("scanner_id", [GHSA, GHSA.upper()])
def test_ghsa_image_card_has_factors_source_and_unknown_kev(
    auth_client: TestClient, db_session: Any, scanner_id: str,
) -> None:
    _advisory(db_session)
    db_session.add(VmRefState(name="kev", source="file", records=1))
    image = VmImage(project="library", repository="card", digest="sha256:card")
    db_session.add(image)
    db_session.flush()
    db_session.add(VmImageCve(image_id=image.id, cve_id=scanner_id, package="test", installed_version="1", trivy_severity="High"))
    db_session.commit()
    rebuild_cves(db_session, Weights())
    rescore_image_pairs(db_session, Weights())
    response = auth_client.get(f"/api/vm/images/{image.id}/vulns/{scanner_id}",
                               params={"package": "test", "installed_version": "1"})
    assert response.status_code == 200
    body = response.json()
    assert body["factors"] is not None and body["factors"]["raw"] > 0
    assert body["vuln"]["cve_id"] == scanner_id
    assert body["source_url"] == f"https://github.com/advisories/{GHSA}"
    assert body["nvd_url"] is None and body["known_exploited"] is None
    assert body["factors"]["likelihood_parts"]["kev"]["substituted"] is True
    assert body["factors"]["likelihood_parts"]["kev"]["source"] == "нет CVE для проверки по KEV"


def test_oversized_alias_component_does_not_partially_merge_findings(db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.modules.vm.services import ghsa_mapping

    monkeypatch.setattr(ghsa_mapping, "MAX_EQUIVALENTS", 4)
    _advisory(db_session)
    aliases = {f"CVE-2026-{index:05}" for index in range(4)}
    db_session.add_all(VmRefGhsaAlias(ghsa_id=GHSA, alias=alias) for alias in aliases)
    image = VmImage(project="library", repository="bounded", digest="sha256:bounded")
    db_session.add(image)
    db_session.flush()
    ids = aliases | {GHSA}
    for identifier in ids:
        db_session.add(VmImageCve(image_id=image.id, cve_id=identifier, package="test", installed_version="1", trivy_severity="High"))
    db_session.commit()
    ensure_cves(db_session, ids)
    rebuild_cves(db_session, Weights())
    rescore_image_pairs(db_session, Weights())
    db_session.expire_all()
    assert all(equivalents(db_session, identifier) == {identifier} for identifier in ids)
    assert db_session.get(VmImage, image.id).cves_scored == len(ids)


def test_public_alias_lookup_keeps_withdrawn_metadata_without_propagating_it(db_session: Any) -> None:
    _advisory(db_session, alias=CVE)
    _advisory(db_session, identifier=PEER, alias=CVE, withdrawn=True)
    assert {row.ghsa_id for row in public_advisories(db_session, CVE)} == {GHSA, PEER}
    assert equivalents(db_session, CVE) == {CVE, GHSA}
    assert equivalents(db_session, PEER) == {PEER}
    assert {row.ghsa_id for row in public_advisories(db_session, PEER)} == {PEER}
