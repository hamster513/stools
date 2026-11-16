"""Deployment contract: SQL scores, policy levels and original inputs stay coherent."""
import itertools
import json

import pytest
from sqlalchemy import select

from api.db.models import AppSetting
from api.modules.vm.core.priority import AssetContext, priority_score
from api.modules.vm.core.risk import CveInputs
from api.modules.vm.core.weights import Weights
from api.modules.vm.models import VmCve, VmHost, VmHostCve, VmImage, VmImageCve, VmZone
from api.modules.vm.services.scoring import rescore_all
from api.modules.vm.services.settings import load_settings


def test_live_sql_matches_additive_policy_over_context_grid(db_session):
    db = db_session
    db.add_all([
        VmZone(name="external", internet_access=True, confidential_data=True, marked=True),
        VmZone(name="internal", internet_access=False, confidential_data=False, marked=True),
        VmZone(name="unmarked", internet_access=True, confidential_data=True, marked=False),
    ])
    contexts = [("Critical", "external", True, True), ("High", "external", True, True),
                ("Low", "internal", False, False), ("Critical", "internal", False, False),
                ("", "unmarked", None, None), ("Medium", "missing", None, None)]
    hosts = [VmHost(hostname=f"priority-{i}", ip=f"192.0.2.{i+1}", criticality=c, zone=z)
             for i, (c, z, _, _) in enumerate(contexts)]
    db.add_all(hosts)
    db.flush()
    vectors = {"network": "NETWORK", "adjacent": "ADJACENT_NETWORK", "local": "LOCAL", "none": None}
    inputs = {}
    combinations = itertools.product([None, 0, .001, .01, .1, .5, 1], [None, 0, 9, 9.8, 10],
                                     vectors, [False, True], [None, "normal", "excellent"], [None, "remote"])
    for index, (epss, cvss, vector, kev, msf, exploit) in enumerate(combinations):
        cve_id = f"CVE-2026-{index+1:05d}"
        inputs[cve_id] = CveInputs(epss=epss, cvss=cvss, av=vectors[vector], kev=kev,
                                  msf_rank=msf, exploitdb_type=exploit)
        db.add(VmCve(cve_id=cve_id, epss=epss, cvss=cvss, v3_av=vectors[vector], av_class=vector,
                     kev=kev, msf_rank=msf, exploitdb_type=exploit))
    db.flush()
    db.add_all(VmHostCve(host_id=h.id, cve_id=cve) for h, cve in itertools.product(hosts, inputs))
    image = VmImage(project="calibration", repository="grid", digest="sha256:priority-grid")
    db.add(image)
    db.flush()
    db.add_all(VmImageCve(image_id=image.id, cve_id=cve, package="example", installed_version="1", trivy_severity="High") for cve in inputs)
    db.commit()
    assert rescore_all(db, Weights()) == len(inputs) * (len(hosts)+1)
    by_host = {h.id: AssetContext(c or None, internet, confidential)
               for h, (c, _, internet, confidential) in zip(hosts, contexts, strict=True)}
    host_pairs = db.execute(select(VmHostCve).limit(11000)).scalars().all()
    assert len(host_pairs) == len(inputs)*len(hosts)
    for pair in host_pairs:
        expected = priority_score(inputs[pair.cve_id], by_host[pair.host_id])
        assert pair.risk == expected.score, (pair.host_id, pair.cve_id, expected)
        assert 0 <= pair.risk_raw <= 1
    pairs = db.execute(select(VmImageCve).limit(2000)).scalars().all()
    assert len(pairs) == len(inputs)
    for pair in pairs:
        assert pair.risk == priority_score(inputs[pair.cve_id], AssetContext()).score
    db.refresh(image)
    assert image.risk_max == max(p.risk for p in pairs)
    assert image.cves_scored == len(inputs)


@pytest.mark.parametrize("stored_threshold,expected", [(70, 80), (60, 60)])
def test_legacy_settings_get_new_levels_without_losing_original(db_session, stored_threshold, expected):
    raw = json.dumps({"weights": {"levels": {"medium": 15, "high": 35, "critical": 60}},
                      "threshold": stored_threshold})
    db_session.add(AppSetting(key="vm", value_json=raw))
    db_session.commit()
    settings = load_settings(db_session)
    assert settings.weights.levels.model_dump() == {"medium": 40, "high": 80, "critical": 85}
    assert settings.threshold == expected
    assert db_session.get(AppSetting, "vm").value_json == raw


def test_ready_metasploit_evidence_is_not_hidden_by_legacy_weights(db_session):
    from api.modules.vm.models import VmRefMsf, VmRefMsfCve
    from api.modules.vm.services.scoring import rebuild_cves

    cve = VmCve(cve_id="CVE-2026-99991")
    db_session.add_all([cve, VmRefMsf(fullname="ready", name="ready", rank=600),
                       VmRefMsf(fullname="normal", name="normal", rank=300)])
    db_session.flush()
    db_session.add_all([VmRefMsfCve(cve_id=cve.cve_id, fullname="ready"),
                       VmRefMsfCve(cve_id=cve.cve_id, fullname="normal")])
    db_session.commit()
    weights = Weights()
    weights.p_msf["normal"] = 1
    weights.p_msf["excellent"] = 0
    rebuild_cves(db_session, weights)
    db_session.refresh(cve)
    assert cve.msf_rank == "excellent"


def test_image_only_inventory_schedules_formula_upgrade(db_session, monkeypatch):
    from api.modules.vm.services import scoring

    image = VmImage(project="test", repository="only-image", digest="sha256:only-image")
    db_session.add(image)
    db_session.flush()
    db_session.add(VmImageCve(image_id=image.id, cve_id="CVE-2026-99992", package="pkg",
                             installed_version="1", trivy_severity="High"))
    db_session.commit()
    callbacks = []
    monkeypatch.setattr(scoring, "spawn", callbacks.append)
    assert scoring.ensure_rescored(db_session) is not None
    assert len(callbacks) == 1
    assert scoring.read_formula_version(db_session) == 0  # marker only after successful full recalculation


def test_cve_detail_preserves_ready_exploit_floor_with_legacy_weights(auth_client, db_session):
    from api.modules.vm.models import VmRefEpss, VmRefMsf, VmRefMsfCve, VmRefNvd

    cve_id = "CVE-2026-99993"
    weights = Weights().model_dump()
    weights["p_msf"].update(normal=1, excellent=0)
    db_session.add_all([
        AppSetting(key="vm", value_json=json.dumps({"weights": weights})),
        VmRefNvd(cve_id=cve_id, year=2026, cvss_v3=9, v3_av="LOCAL"),
        VmRefEpss(cve_id=cve_id, epss=0, percentile=0),
        VmRefMsf(fullname="ready", name="ready", rank=600),
        VmRefMsf(fullname="normal", name="normal", rank=300),
    ])
    db_session.flush()
    db_session.add_all([VmRefMsfCve(cve_id=cve_id, fullname="ready"), VmRefMsfCve(cve_id=cve_id, fullname="normal")])
    db_session.commit()
    response = auth_client.get(f"/api/vm/cve/{cve_id}")
    assert response.status_code == 200, response.text
    assert response.json()["msf_rank"] == "excellent"
    assert response.json()["risk"]["max"] == 85


def test_filter_defaults_use_active_model_levels():
    from api.modules.vm.services.images_query import ImageFilters
    from api.modules.vm.services.images_query import VulnFilters as ImageVulnFilters
    from api.modules.vm.services.query import VulnFilters

    for filters in (ImageFilters(), ImageVulnFilters(image_id=1), VulnFilters()):
        assert filters.levels.model_dump() == {"medium": 40, "high": 80, "critical": 85}
