"""«Не проверено: нет данных» — пустая проверка отличается от непроверенной."""
from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient

from api.modules.ad.core.checks.coverage import coverage_gaps
from api.modules.ad.core.export import load_export
from tests.ad.synthetic import build_export


def _gaps(raw: dict[str, Any]) -> dict[str, str]:
    return coverage_gaps(load_export(json.dumps(raw).encode()))


def test_full_export_has_no_gaps() -> None:
    assert _gaps(build_export()) == {}


def test_missing_sysvol_marks_user_rights_unchecked() -> None:
    raw = build_export()
    raw["sysvol"] = {}
    gaps = _gaps(raw)
    assert set(gaps) == {"UserRightsAssignment"} and "SYSVOL" in gaps["UserRightsAssignment"]


def test_collector_note_explains_missing_sysvol() -> None:
    raw = build_export()
    raw["sysvol"] = {}
    raw["collector"]["notes"] = ["SYSVOL недоступен: ConnectionError"]
    assert "ConnectionError" in _gaps(raw)["UserRightsAssignment"]


def test_missing_logon_dates_mark_inactive_users_unchecked() -> None:
    raw = build_export()
    for o in raw["objects"]:
        o.pop("lastLogonTimestamp", None)
    assert set(_gaps(raw)) == {"InactiveUsers"}


def test_missing_templates_mark_adcs_unchecked() -> None:
    raw = build_export()
    raw["objects"] = [o for o in raw["objects"] if o["class"] != "pKICertificateTemplate"]
    assert set(_gaps(raw)) == {"ADCS_ESC"}


def test_domain_without_gpo_is_not_a_gap() -> None:
    raw = build_export()
    raw["sysvol"] = {}
    raw["objects"] = [o for o in raw["objects"] if o["class"] != "groupPolicyContainer"]
    assert "UserRightsAssignment" not in _gaps(raw)


def _upload(client: TestClient, raw: dict[str, Any]) -> dict[str, Any]:
    r = client.post("/api/ad/snapshots/file", files={"file": ("ad.json", json.dumps(raw).encode(), "application/json")})
    assert r.status_code == 202, r.text
    return client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()


def test_overview_reports_unchecked_and_reanalysis_keeps_it(auth_client: TestClient) -> None:
    raw = build_export()
    raw["sysvol"] = {}
    assert _upload(auth_client, raw)["status"] == "done"
    domain_id = auth_client.get("/api/ad/domains").json()[0]["id"]

    def unchecked() -> dict[str, Any]:
        checks = auth_client.get(f"/api/ad/domains/{domain_id}/overview").json()["checks"]
        return {c["code"]: c["unchecked"] for c in checks}

    first = unchecked()
    assert "SYSVOL" in first["UserRightsAssignment"] and first["DCSync"] is None
    snapshot_id = auth_client.get(f"/api/ad/snapshots?domain_id={domain_id}").json()[0]["id"]
    job = auth_client.post(f"/api/ad/snapshots/{snapshot_id}/reanalyze").json()
    assert auth_client.get(f"/api/ad/jobs/{job['job_id']}").json()["status"] == "done"
    assert unchecked() == first
