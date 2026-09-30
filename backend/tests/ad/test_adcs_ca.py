"""ADCS_CA по снапшоту: ESC5 — запись в контейнеры PKI и объект ЦС."""
from __future__ import annotations

import json
from typing import Any

from api.modules.ad.core import sd
from api.modules.ad.core.checks.adcs_ca import check_adcs_ca
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex, load_export
from api.modules.ad.core.findings import Finding
from tests.ad.synthetic import PKI, b64sd, build_export, rid

NTAUTH = f"CN=NTAuthCertificates,{PKI}"
CA_DN = f"CN=CORP-CA,CN=Enrollment Services,{PKI}"


def run(dn: str, aces: list[bytes]) -> list[Finding]:
    raw: dict[str, Any] = build_export()
    obj = next(o for o in raw["objects"] if o["dn"] == dn)
    obj["sd"] = b64sd([*aces, sd.build_ace(rid(512), sd.GENERIC_ALL)])
    return check_adcs_ca(ExportIndex(load_export(json.dumps(raw).encode())), AdConfig())


def test_synthetic_pki_is_clean() -> None:
    assert check_adcs_ca(ExportIndex(load_export(json.dumps(build_export()).encode())), AdConfig()) == []


def test_esc5_other_writer_on_ntauth() -> None:
    fs = run(NTAUTH, [sd.build_ace(rid(1108), sd.WRITE_PROPERTY)])
    assert len(fs) == 1
    f = fs[0]
    assert (f.check, f.key_extra, f.target, f.severity, f.identity) == ("ADCS_CA", "ESC5", NTAUTH, "Medium", "")
    assert f.details["esc"] == "ESC5" and f.details["requesters"] == ["CORP\\helpdesk"] and f.details["requesters_broad"] is False


def test_esc5_broad_writer_on_ca_object_is_high() -> None:
    fs = run(CA_DN, [sd.build_ace("S-1-5-11", sd.GENERIC_ALL)])
    assert [(f.target, f.severity) for f in fs] == [(CA_DN, "High")]


def test_esc5_not_for_admins() -> None:
    assert run(NTAUTH, [sd.build_ace(rid(519), sd.WRITE_DACL), sd.build_ace("S-1-5-18", sd.GENERIC_ALL)]) == []


def test_esc5_ignores_read_and_inherit_only() -> None:
    aces = [sd.build_ace("S-1-5-11", sd.READ_PROPERTY), sd.build_ace(rid(1108), sd.GENERIC_ALL, flags=sd.ACE_FLAG_INHERIT_ONLY)]
    assert run(PKI, aces) == []
