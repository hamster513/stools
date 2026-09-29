from __future__ import annotations

import json
from typing import Any

import pytest

from api.modules.ad.core.checks import run_all
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex, load_export
from api.modules.ad.core.ldap_collector import LdapCollector, LdapResultError
from tests.ad.fake_ldap import FakeLdap
from tests.ad.synthetic import export_bytes


def test_ldap_collector_matches_powershell_export() -> None:
    fake = FakeLdap()
    collector = LdapCollector(fake.search, fake.root_dse(), smb_reader=fake.smb, host="dc01", account="CORP\\auditor")
    raw = collector.collect()
    export = load_export(json.dumps(raw).encode())
    assert export.collector.kind == "ldap" and export.domain.netbios == "CORP" and export.domain.dns_root == "corp.local"
    assert export.domain.machine_account_quota == 10
    assert export.guids.schema_attributes["msDS-KeyCredentialLink"].lower() == "5b47d60f-6090-40b2-9f37-2a4de88f3063"
    assert len(export.sysvol) == 1
    # Имена SID: и объекты домена, и SID из ACE.
    assert export.principals[f"{export.domain.sid}-1108"].name == "CORP\\helpdesk"

    ours = run_all(ExportIndex(export), AdConfig())
    reference = run_all(ExportIndex(load_export(export_bytes())), AdConfig())
    assert {f.key for f in ours} == {f.key for f in reference}
    assert {(f.check, f.severity) for f in ours} == {(f.check, f.severity) for f in reference}


def test_collector_without_computer_sd_and_sysvol() -> None:
    fake = FakeLdap()
    export = load_export(json.dumps(LdapCollector(fake.search, fake.root_dse(), include_computer_sd=False).collect()).encode())
    comps = [o for o in export.objects if o.cls == "computer"]
    assert comps and all(o.sd is None for o in comps) and export.sysvol == {}


def _failing(fake: FakeLdap, base_prefix: str, code: int, description: str) -> Any:
    def search(base: str, flt: str, attrs: list[str], scope: str) -> Any:
        if base.lower().startswith(base_prefix.lower()):
            raise LdapResultError(code, description, flt)
        return fake.search(base, flt, attrs, scope)

    return search


def test_missing_certificate_templates_container_is_tolerated() -> None:
    """Без AD CS контейнера шаблонов нет: noSuchObject — пустой список шаблонов, а не отказ."""
    fake = FakeLdap()
    raw = LdapCollector(_failing(fake, "CN=Certificate Templates,", 32, "noSuchObject"), fake.root_dse()).collect()
    assert raw["objects"] and not [o for o in raw["objects"] if o["class"] == "pKICertificateTemplate"]


def test_missing_default_container_is_an_error() -> None:
    fake = FakeLdap()
    with pytest.raises(LdapResultError):
        LdapCollector(_failing(fake, "CN=Policies,", 32, "noSuchObject"), fake.root_dse()).collect()


def test_busy_on_templates_is_an_error() -> None:
    fake = FakeLdap()
    with pytest.raises(LdapResultError):
        LdapCollector(_failing(fake, "CN=Certificate Templates,", 51, "busy"), fake.root_dse()).collect()


def test_wrong_base_dn_keeps_the_hint() -> None:
    fake = FakeLdap()
    dn = fake.root_dse()["defaultNamingContext"]

    def search(base: str, flt: str, attrs: list[str], scope: str) -> Any:
        if base == dn and scope == "BASE":
            raise LdapResultError(32, "noSuchObject", flt)
        return fake.search(base, flt, attrs, scope)

    with pytest.raises(ValueError, match="проверьте base DN"):
        LdapCollector(search, fake.root_dse()).collect()
