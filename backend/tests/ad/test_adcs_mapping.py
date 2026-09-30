"""ADCS_MAPPING по снапшоту: ESC14 — слабые явные сопоставления сертификатов."""
from __future__ import annotations

import json
from typing import Any

from api.modules.ad.core.checks.adcs_mapping import check_adcs_mapping
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex, load_export
from api.modules.ad.core.findings import Finding
from tests.ad.synthetic import build_export


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
