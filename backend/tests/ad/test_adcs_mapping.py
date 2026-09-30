"""ADCS_MAPPING по снапшоту: ESC14 — слабые явные сопоставления сертификатов."""
from __future__ import annotations

import json
from typing import Any

from api.modules.ad.core.ca_data import parse_ca_data
from api.modules.ad.core.checks.adcs_mapping import check_adcs_mapping
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex, load_export
from api.modules.ad.core.findings import Finding
from tests.ad.synthetic import NOW, build_ca_data, build_export


def run(**mappings: list[str]) -> list[Finding]:
    raw: dict[str, Any] = build_export()
    for o in raw["objects"]:
        if o.get("sam") in mappings:
            o["altSecurityIdentities"] = mappings[o["sam"]]
    return check_adcs_mapping(ExportIndex(load_export(json.dumps(raw).encode())), AdConfig())


def test_synthetic_has_no_mappings() -> None:
    assert run() == []


def test_esc14_weak_subject_on_admin_is_high() -> None:
    fs = run(admin1=["X509:<I>DC=local,CN=CA<S>CN=admin1"])
    assert [(f.check, f.key_extra, f.target, f.severity, f.identity) for f in fs] == [("ADCS_MAPPING", "ESC14", "CORP\\admin1", "High", "")]
    assert fs[0].details["mappings"] == ["X509:<I>DC=local,CN=CA<S>CN=admin1"]


def test_esc14_rfc822_on_regular_account_is_medium() -> None:
    fs = run(helpdesk=["x509:<rfc822>a@b"])
    assert [(f.target, f.severity) for f in fs] == [("CORP\\helpdesk", "Medium")]


def test_esc14_subject_only_is_weak() -> None:
    assert len(run(helpdesk=["X509:<S>CN=helpdesk"])) == 1


def test_esc14_strong_mappings_are_fine() -> None:
    assert run(helpdesk=["X509:<I>DC=local,CN=CA<SR>0a1b2c", "X509:<SKI>abcdef", "X509:<SHA1-PUKEY>0011"]) == []


def test_esc14_only_weak_entries_listed() -> None:
    fs = run(helpdesk=["X509:<SKI>abcdef", "X509:<S>CN=helpdesk"])
    assert fs[0].details["mappings"] == ["X509:<S>CN=helpdesk"]


def test_esc14_disabled_account_skipped() -> None:
    assert run(**{"user.disabled": ["X509:<S>CN=x"]}) == []


# ---- ESC10 по реестру контроллеров ------------------------------------------------


def run_dc(**dc: Any) -> list[Finding]:
    entry = {"host": "dc01.corp.local", "strong_binding": 2, "mapping_methods": 0x18, "error": "", **dc}
    ca = parse_ca_data(build_ca_data(dcs=[entry]))
    return check_adcs_mapping(ExportIndex(load_export(json.dumps(build_export()).encode()), ca), AdConfig())


def test_esc10_safe_registry_is_clean() -> None:
    assert run_dc() == []


def test_esc10_binding_disabled_is_high() -> None:
    fs = run_dc(strong_binding=0)
    assert [(f.check, f.key_extra, f.target, f.severity, f.right) for f in fs] == [
        ("ADCS_MAPPING", "ESC10", "dc01.corp.local", "High", "StrongCertificateBindingEnforcement")
    ]
    assert "привязка отключена" in fs[0].details["details"]
    assert fs[0].details["ca_data_collected_at"] == NOW.isoformat()


def test_esc10_compatibility_mode_is_medium() -> None:
    fs = run_dc(strong_binding=1)
    assert [(f.key_extra, f.severity) for f in fs] == [("ESC10", "Medium")]
    assert "режим совместимости" in fs[0].details["details"]


def test_esc10_upn_mapping_is_high() -> None:
    fs = run_dc(mapping_methods=0x4)
    assert [(f.key_extra, f.severity, f.right) for f in fs] == [("ESC10", "High", "CertificateMappingMethods")]
    assert "сопоставление по UPN" in fs[0].details["details"]


def test_esc10_two_conditions_are_two_findings() -> None:
    fs = run_dc(strong_binding=1, mapping_methods=0x1F)
    assert sorted(f.right for f in fs) == ["CertificateMappingMethods", "StrongCertificateBindingEnforcement"]
    assert len({f.key for f in fs}) == 2


def test_esc10_missing_values_are_not_findings() -> None:
    assert run_dc(strong_binding=None, mapping_methods=None) == []
