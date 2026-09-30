from __future__ import annotations

import json
from typing import Any

import pytest

from api.modules.ad.core.checks import run_all
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex, load_export
from api.modules.ad.core.ldap_collector import LdapCollector, LdapResultError
from tests.ad.fake_ldap import FakeLdap
from tests.ad.synthetic import OTHER_SID, PKI, export_bytes


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


def test_collector_reads_pki_objects_and_trusts() -> None:
    fake = FakeLdap()
    raw = LdapCollector(fake.search, fake.root_dse(), smb_reader=fake.smb).collect()
    classes = {o["class"] for o in raw["objects"]}
    assert {"pKIEnrollmentService", "pkiContainer", "msPKI-Enterprise-Oid", "trustedDomain"} <= classes
    ca = next(o for o in raw["objects"] if o["class"] == "pKIEnrollmentService")
    assert ca["cn"] == "CORP-CA" and ca["certificateTemplates"] == ["VulnTemplate", "AgentTemplate"] and ca["sd"]
    assert ca["dNSHostName"] == "ca01.corp.local"
    containers = {o["dn"] for o in raw["objects"] if o["class"] == "pkiContainer"}
    assert containers == {PKI, f"CN=NTAuthCertificates,{PKI}"}
    oid = next(o for o in raw["objects"] if o["class"] == "msPKI-Enterprise-Oid")
    assert oid["displayName"] == "Corp Policy" and oid["msPKI-Cert-Template-OID"] == "1.3.6.1.4.1.311.21.8.1.1"
    trust = next(o for o in raw["objects"] if o["class"] == "trustedDomain")
    assert trust["flatName"] == "OTHER" and trust["sid"] == OTHER_SID
    tpl = next(o for o in raw["objects"] if o["class"] == "pKICertificateTemplate")
    assert tpl["cn"] and "msPKI-Certificate-Policy" in tpl and "msPKI-Cert-Template-OID" in tpl


def test_collector_reads_alt_security_identities() -> None:
    fake = FakeLdap()
    user = next(o for o in fake.objects if o.get("sam") == "helpdesk")
    user["altSecurityIdentities"] = ["X509:<I>DC=local,DC=corp,CN=CORP-CA<SR>0a1b"]
    raw = LdapCollector(fake.search, fake.root_dse(), smb_reader=fake.smb).collect()
    by_sam = {o.get("sam"): o for o in raw["objects"]}
    assert by_sam["helpdesk"]["altSecurityIdentities"] == user["altSecurityIdentities"]
    assert by_sam["admin1"]["altSecurityIdentities"] == [] and by_sam["WS01$"]["altSecurityIdentities"] == []


def test_missing_pki_containers_are_tolerated() -> None:
    fake = FakeLdap()
    raw = LdapCollector(_failing(fake, "cn=enrollment services,", 32, "noSuchObject"), fake.root_dse(), smb_reader=fake.smb).collect()
    assert not [o for o in raw["objects"] if o["class"] == "pKIEnrollmentService"]
    assert [o for o in raw["objects"] if o["class"] == "trustedDomain"]


def test_busy_on_pki_container_is_an_error() -> None:
    fake = FakeLdap()
    with pytest.raises(LdapResultError):
        LdapCollector(_failing(fake, "cn=oid,", 51, "busy"), fake.root_dse(), smb_reader=fake.smb).collect()


def test_wrong_base_dn_keeps_the_hint() -> None:
    fake = FakeLdap()
    dn = fake.root_dse()["defaultNamingContext"]

    def search(base: str, flt: str, attrs: list[str], scope: str) -> Any:
        if base == dn and scope == "BASE":
            raise LdapResultError(32, "noSuchObject", flt)
        return fake.search(base, flt, attrs, scope)

    with pytest.raises(ValueError, match="проверьте base DN"):
        LdapCollector(search, fake.root_dse()).collect()


def _with_schema_types(fake: FakeLdap) -> Any:
    """Как отдаёт настоящий ldap3 со схемой AD (get_info=ALL): отметки времени —
    уже `datetime`, исходные байты — в raw_attributes."""
    import datetime as dt

    def as_datetime(filetime: int) -> dt.datetime:
        return dt.datetime(1601, 1, 1, tzinfo=dt.UTC) + dt.timedelta(microseconds=filetime // 10)

    def search(base: str, flt: str, attrs: list[str], scope: str) -> Any:
        for e in fake.search(base, flt, attrs, scope):
            for name in ("lastLogonTimestamp", "pwdLastSet"):
                value = e["attributes"].get(name)
                if value is not None:
                    e["raw_attributes"][name] = [str(value).encode()]
                    e["attributes"][name] = as_datetime(value)
            yield e

    return search


def test_timestamps_survive_schema_formatting() -> None:
    """Регресс: со схемой ldap3 отдаёт lastLogonTimestamp и pwdLastSet датой, сборщик
    писал пусто — «Неактивные пользователи» и возраст пароля krbtgt молчали."""
    fake = FakeLdap()
    plain = LdapCollector(fake.search, fake.root_dse(), smb_reader=fake.smb, host="dc01", account="a").collect()
    typed = LdapCollector(_with_schema_types(fake), fake.root_dse(), smb_reader=fake.smb, host="dc01", account="a").collect()

    def stamps(raw: dict[str, Any]) -> dict[str, tuple[Any, Any]]:
        return {o["dn"]: (o.get("lastLogonTimestamp"), o.get("pwdLastSet")) for o in raw["objects"] if o["class"] in ("user", "computer")}

    assert any(last for last, _ in stamps(plain).values())
    assert stamps(typed) == stamps(plain)


def test_timestamp_without_raw_bytes_is_converted_from_datetime() -> None:
    import datetime as dt

    from api.modules.ad.core.ldap_collector import _filetime

    moment = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.UTC)
    entry = {"dn": "CN=u", "attributes": {"lastLogonTimestamp": moment}, "raw_attributes": {}}
    assert _filetime(entry, "lastLogonTimestamp") == int((moment - dt.datetime(1601, 1, 1, tzinfo=dt.UTC)).total_seconds()) * 10_000_000
    assert _filetime({"dn": "CN=u", "attributes": {}, "raw_attributes": {}}, "lastLogonTimestamp") is None


def test_collector_notes_reach_the_coverage_reason() -> None:
    from api.modules.ad.core.checks.coverage import coverage_gaps

    fake = FakeLdap()
    raw = LdapCollector(fake.search, fake.root_dse(), smb_reader=None, notes=["SYSVOL недоступен по SMB: ConnectionError"]).collect()
    gaps = coverage_gaps(load_export(json.dumps(raw).encode()))
    assert "ConnectionError" in gaps["UserRightsAssignment"]
