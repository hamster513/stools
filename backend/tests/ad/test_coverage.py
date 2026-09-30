"""«Не проверено: нет данных» — пустая проверка отличается от непроверенной."""
from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient

from api.modules.ad.core.ca_data import CaData, parse_ca_data
from api.modules.ad.core.checks.coverage import coverage_gaps
from api.modules.ad.core.export import load_export
from tests.ad.synthetic import build_ca_data, build_export

FULL_CA = parse_ca_data(build_ca_data())


def _gaps(raw: dict[str, Any], ca: CaData | None = FULL_CA) -> dict[str, str]:
    return coverage_gaps(load_export(json.dumps(raw).encode()), ca)


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


def test_old_export_without_pki_objects_marks_esc5_unchecked() -> None:
    raw = build_export()
    raw["objects"] = [o for o in raw["objects"] if o["class"] not in ("pkiContainer", "pKIEnrollmentService")]
    gaps = _gaps(raw)
    assert set(gaps) == {"ADCS_CA"} and "ESC5" in gaps["ADCS_CA"]


def test_ca_object_alone_is_enough_for_esc5() -> None:
    raw = build_export()
    raw["objects"] = [o for o in raw["objects"] if o["class"] != "pkiContainer"]
    assert _gaps(raw) == {}


def test_domain_without_gpo_is_not_a_gap() -> None:
    raw = build_export()
    raw["sysvol"] = {}
    raw["objects"] = [o for o in raw["objects"] if o["class"] != "groupPolicyContainer"]
    assert "UserRightsAssignment" not in _gaps(raw)


def test_without_ca_data_ca_checks_are_unchecked() -> None:
    gaps = _gaps(build_export(), None)
    assert set(gaps) == {"ADCS_CA", "ADCS_MAPPING"}
    assert gaps["ADCS_CA"] == (
        "ESC6, 7, 11, 16 не проверены: нужны данные ЦС (сборщик, пункт 5); "
        "ESC8 не проверен: нужна проверка веб-выдачи (сборщик, пункт 7)"
    )
    assert gaps["ADCS_MAPPING"] == "ESC10 не проверен: нужен реестр контроллеров (сборщик, пункт 6)"


def test_only_ca_section_leaves_web_and_dc_unchecked() -> None:
    gaps = _gaps(build_export(), parse_ca_data(build_ca_data(sections=["ca"], dcs=[], web=[])))
    assert "ESC8" in gaps["ADCS_CA"] and "ESC6" not in gaps["ADCS_CA"] and "ESC10" in gaps["ADCS_MAPPING"]


def test_ca_reasons_join_with_esc5_reason() -> None:
    raw = build_export()
    raw["objects"] = [o for o in raw["objects"] if o["class"] not in ("pkiContainer", "pKIEnrollmentService")]
    reasons = _gaps(raw, parse_ca_data(build_ca_data(sections=["ca", "dc"], web=[])))["ADCS_CA"].split("; ")
    assert len(reasons) == 2 and reasons[0].startswith("ESC5") and reasons[1].startswith("ESC8")


def test_unread_ca_is_a_reason() -> None:
    ca = parse_ca_data(build_ca_data(cas=[{"name": "CORP-CA", "host": "ca01.corp.local", "error": "доступ запрещён"}]))
    assert _gaps(build_export(), ca) == {"ADCS_CA": "ЦС CORP-CA: данные не прочитаны (доступ запрещён)"}


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


def test_overview_marks_adcs_ca_unchecked_until_ca_data_upload(auth_client: TestClient) -> None:
    assert _upload(auth_client, build_export())["status"] == "done"
    domain_id = auth_client.get("/api/ad/domains").json()[0]["id"]

    def unchecked(code: str) -> Any:
        checks = auth_client.get(f"/api/ad/domains/{domain_id}/overview").json()["checks"]
        return next(c["unchecked"] for c in checks if c["code"] == code)

    assert "пункт 5" in unchecked("ADCS_CA") and "пункт 6" in unchecked("ADCS_MAPPING")
    assert _upload(auth_client, build_ca_data())["status"] == "done"
    assert unchecked("ADCS_CA") is None and unchecked("ADCS_MAPPING") is None
