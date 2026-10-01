from __future__ import annotations

import json
from typing import Any

import pytest

from api.modules.ad.core import sd
from api.modules.ad.core.checks import run_all
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex, load_export
from api.modules.ad.core.ldap_collector import LdapCollector, LdapResultError
from tests.ad.fake_ldap import FakeLdap
from tests.ad.synthetic import DN, EXT_SID, OTHER_SID, PKI, b64sd, export_bytes, rid, user_dn


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


def test_collector_reads_computer_host_attributes() -> None:
    """Assets сопоставляет компьютер AD с хостами других источников по DNS-имени и показывает ОС."""
    fake = FakeLdap()
    asked: list[list[str]] = []

    def search(base: str, flt: str, attrs: list[str], scope: str) -> Any:
        if flt == "(objectClass=computer)":
            asked.append(attrs)
        return fake.search(base, flt, attrs, scope)

    for with_sd in (True, False):
        asked.clear()
        raw = LdapCollector(search, fake.root_dse(), include_computer_sd=with_sd).collect()
        assert asked and {"dNSHostName", "operatingSystem", "operatingSystemVersion"} <= set(asked[0])
        export = load_export(json.dumps(raw).encode())
        ws01 = next(o for o in export.objects if o.sam == "WS01$")
        assert (ws01.dNSHostName, ws01.operatingSystem, ws01.operatingSystemVersion) == ("ws01.corp.local", "Windows 11 Pro", "10.0 (22631)")
        admin = next(o for o in raw["objects"] if o.get("sam") == "admin1")
        assert "operatingSystem" not in admin  # у пользователей этих полей нет


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
    assert containers == {PKI, f"CN=NTAuthCertificates,{PKI}", f"CN=OID,{PKI}"}
    oid = next(o for o in raw["objects"] if o["class"] == "msPKI-Enterprise-Oid")
    assert oid["displayName"] == "Corp Policy" and oid["msPKI-Cert-Template-OID"] == "1.3.6.1.4.1.311.21.8.1.1"
    trusts = {o["flatName"]: o for o in raw["objects"] if o["class"] == "trustedDomain"}
    assert trusts["OTHER"]["sid"] == OTHER_SID and trusts["OTHER"]["trustAttributes"] == 0x20
    assert trusts["EXT"]["sid"] == EXT_SID and trusts["EXT"]["trustAttributes"] == 0x4
    tpl = next(o for o in raw["objects"] if o["class"] == "pKICertificateTemplate")
    assert tpl["cn"] and "msPKI-Certificate-Policy" in tpl and "msPKI-Cert-Template-OID" in tpl


def test_oid_container_is_recorded_as_container_only() -> None:
    """Контейнер CN=OID сам класса msPKI-Enterprise-Oid: он записан один раз как контейнер PKI,
    а политиками выдачи считаются только его потомки."""
    fake = FakeLdap()
    raw = LdapCollector(fake.search, fake.root_dse(), smb_reader=fake.smb).collect()
    containers = [o["dn"] for o in raw["objects"] if o["class"] == "pkiContainer"]
    assert containers.count(f"CN=OID,{PKI}") == 1
    assert [o["dn"] for o in raw["objects"] if o["class"] == "msPKI-Enterprise-Oid"] == [f"CN=corp-policy,CN=OID,{PKI}"]


def test_trusts_are_searched_one_level_below_system() -> None:
    """Объекты trustedDomain — прямые потомки CN=System; поддерево System не обходится."""
    fake = FakeLdap()
    scopes: list[str] = []

    def search(base: str, flt: str, attrs: list[str], scope: str) -> Any:
        if flt == "(objectClass=trustedDomain)":
            scopes.append(scope)
        return fake.search(base, flt, attrs, scope)

    raw = LdapCollector(search, fake.root_dse(), smb_reader=fake.smb).collect()
    assert scopes == ["LEVEL"]
    assert [o["sid"] for o in raw["objects"] if o["class"] == "trustedDomain"] == [OTHER_SID, EXT_SID]


def test_foreign_security_principal_does_not_hide_trusted_domain_name() -> None:
    """Регресс: поиск по objectSid находит и запись foreignSecurityPrincipal (SID чужого домена
    в локальной группе). У неё нет sAMAccountName — сборщик записывал имя CORP\\S-1-5-21-…,
    и оно заслоняло имя чужого домена."""
    fake = FakeLdap()
    foreign = f"{OTHER_SID}-513"
    fake.objects.append({"dn": f"CN={foreign},CN=ForeignSecurityPrincipals,{DN}", "class": "foreignSecurityPrincipal", "sid": foreign})
    tpl = next(o for o in fake.objects if o.get("cn") == "SafeTemplate")
    tpl["sd"] = b64sd([sd.build_ace(rid(512), sd.GENERIC_ALL), sd.build_ace(foreign, sd.READ_PROPERTY)])
    raw = LdapCollector(fake.search, fake.root_dse(), smb_reader=fake.smb).collect()
    assert foreign not in raw["principals"]
    idx = ExportIndex(load_export(json.dumps(raw).encode()))
    assert idx.principal_name(foreign) == "OTHER\\Domain Users"


def test_pki_fields_reach_the_model() -> None:
    """Ключи сборщика совпадают с псевдонимами полей модели: значения доходят до ExportIndex."""
    fake = FakeLdap()
    tpl = next(o for o in fake.objects if o.get("cn") == "SafeTemplate")
    tpl["msPKI-Certificate-Policy"] = ["1.3.6.1.4.1.311.21.8.1.1"]
    tpl["msPKI-Certificate-Application-Policy"] = ["1.3.6.1.5.5.7.3.2"]
    tpl["msPKI-RA-Application-Policies"] = ["1.3.6.1.4.1.311.20.2.1"]
    tpl["msPKI-Cert-Template-OID"] = "1.3.6.1.4.1.311.21.8.1.2"
    ca = next(o for o in fake.objects if o["class"] == "pKIEnrollmentService")
    ca["msPKI-Enrollment-Servers"] = ["1\n4\n0\nhttps://ca01.corp.local/CES"]
    oid = next(o for o in fake.objects if o["dn"] == f"CN=corp-policy,CN=OID,{PKI}")
    oid["msDS-OIDToGroupLink"] = user_dn("Tier0")
    raw = LdapCollector(fake.search, fake.root_dse(), smb_reader=fake.smb).collect()
    idx = ExportIndex(load_export(json.dumps(raw).encode()))

    safe = next(t for t in idx.objects("pKICertificateTemplate") if t.cn == "SafeTemplate")
    assert safe.issuance_policies == ["1.3.6.1.4.1.311.21.8.1.1"]
    assert safe.application_policies == ["1.3.6.1.5.5.7.3.2"]
    assert safe.ra_application_policies == ["1.3.6.1.4.1.311.20.2.1"]
    assert safe.template_oid == "1.3.6.1.4.1.311.21.8.1.2"
    assert idx.objects("pKIEnrollmentService")[0].enrollment_servers == ["1\n4\n0\nhttps://ca01.corp.local/CES"]
    policy = next(o for o in idx.objects("msPKI-Enterprise-Oid") if o.dn == oid["dn"])
    assert policy.oid_group_link == user_dn("Tier0")


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
