from __future__ import annotations

import datetime as dt
import json
import struct
from typing import Any

import pytest

from api.modules.ad.core import sd
from api.modules.ad.core.checks import run_all
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex, load_export
from api.modules.ad.core.ldap_collector import (
    LdapCollector,
    LdapResultError,
    dns_allow_update,
    last_backup_from_metadata,
)
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


def collect_with(fake: FakeLdap) -> dict[str, Any]:
    return LdapCollector(fake.search, fake.root_dse(), smb_reader=fake.smb, host="dc01", account="CORP\\auditor").collect()


def _prop(prop_id: int, data: bytes) -> bytes:
    return struct.pack("<IIIII", len(data), 0, 0, 1, prop_id) + data + b"\x00"


def test_dns_allow_update_reads_property_two() -> None:
    assert dns_allow_update([_prop(1, struct.pack("<I", 1)), _prop(2, b"\x01")]) == 1
    assert dns_allow_update([_prop(1, struct.pack("<I", 1))]) is None
    assert dns_allow_update([b"\x00\x01"]) is None          # обрезанная запись не роняет сбор


def test_last_backup_from_metadata() -> None:
    item = ("<DS_REPL_ATTR_META_DATA><pszAttributeName>{}</pszAttributeName><dwVersion>3</dwVersion>"
            "<ftimeLastOriginatingChange>{}</ftimeLastOriginatingChange></DS_REPL_ATTR_META_DATA>")
    values = [item.format("whenCreated", "2024-01-01T00:00:00Z"), item.format("dSASignature", "2026-09-01T10:20:30Z")]
    assert last_backup_from_metadata(values) == dt.datetime(2026, 9, 1, 10, 20, 30, tzinfo=dt.UTC)
    assert last_backup_from_metadata(values[:1]) is None


def test_collector_reads_hygiene_data() -> None:
    out = collect_with(FakeLdap())             # существующий помощник теста сборщика
    d = out["domain"]
    assert out["collector"]["version"] == "1.1"
    assert d["min_pwd_length"] == 12 and d["recycle_bin"] is True and d["sysvol_replication"] == "dfsr" and d["backup_read"] is True
    assert out["guids"]["schema_classes"] == {"msDS-DelegatedManagedServiceAccount": ""}
    by_class: dict[str, list[dict[str, Any]]] = {}
    for o in out["objects"]:
        by_class.setdefault(o["class"], []).append(o)
    assert by_class["dnsZone"][0]["allowUpdate"] == 2 and by_class["subnet"][0]["name"] == "10.0.0.0/24"
    assert by_class["trustedDomain"][0]["trustDirection"] == 3
    users = {o["sam"]: o for o in by_class["user"]}
    assert all(u.get("primaryGroupID") for u in users.values())
    assert sum(1 for u in users.values() if u.get("hasUnixPassword")) == 1
    assert not any("userPassword" in u for u in users.values())       # значения паролей не читаются


def test_collector_survives_denied_sections() -> None:
    out = collect_with(FakeLdap(deny=("CN=Password Settings Container", "DC=DomainDnsZones")))
    assert any("PSO" in n for n in out["collector"]["notes"]) and any("DNS" in n for n in out["collector"]["notes"])


def test_new_fields_reach_the_model() -> None:
    """Учётки, RODC, LAPS, PSO, доверия и настройки домена: ключи сборщика совпадают с полями модели."""
    fake = FakeLdap()
    other = "S-1-5-21-777-888-999-1500"
    by_sam = {o.get("sam"): o for o in fake.objects}
    by_sam["helpdesk"].update(sIDHistory=[other], scriptPath="logon.bat")
    by_sam["WS01$"].update(
        creatorSid=rid(1108), lapsNewExpiry=133_000_000_000_000_000, revealedUsers=[user_dn("admin1"), "CN=a:b,CN=Users," + DN], revealOnDemand=[user_dn("Tier0")],
    )
    fake.objects.append(
        {
            "dn": f"CN=Admins PSO,CN=Password Settings Container,CN=System,{DN}", "class": "msDS-PasswordSettings", "name": "Admins PSO",
            "psoMinLength": 15, "psoLockoutThreshold": 0, "psoReversible": False, "psoComplexity": True, "psoPrecedence": 10,
            "psoAppliesTo": [user_dn("Domain Admins")],
        }
    )
    raw = collect_with(fake)
    exp = load_export(json.dumps(raw).encode())
    objs = {o.dn: o for o in exp.objects}
    helpdesk, ws01 = objs[user_dn("helpdesk")], objs[f"CN=WS01,CN=Computers,{DN}"]
    assert helpdesk.sIDHistory == [other] and helpdesk.scriptPath == "logon.bat" and helpdesk.primaryGroupID == 513
    assert helpdesk.whenCreated == dt.datetime(2025, 9, 9, 12, 0, tzinfo=dt.UTC)
    assert ws01.creatorSid == rid(1108) and ws01.lapsNewExpiry == 133_000_000_000_000_000 and ws01.lapsExpiry is None
    # Байты DN-Binary разобраны; по DN одна запись, двоеточие внутри DN сохраняется.
    assert ws01.revealedUsers == [user_dn("admin1"), "CN=a:b,CN=Users," + DN] and ws01.revealOnDemand == [user_dn("Tier0")] and ws01.primaryGroupID == 515
    pso = next(o for o in exp.objects if o.cls == "msDS-PasswordSettings")
    assert (pso.psoMinLength, pso.psoLockoutThreshold, pso.psoReversible, pso.psoComplexity, pso.psoPrecedence) == (15, 0, False, True, 10)
    assert pso.psoAppliesTo == [user_dn("Domain Admins")]
    trust = next(o for o in exp.objects if o.flatName == "OTHER")
    assert (trust.trustType, trust.trustPartner, trust.supportedEncryptionTypes) == (2, "other.local", 24)
    assert trust.whenChanged == dt.datetime(2026, 8, 30, 12, 0, tzinfo=dt.UTC)
    zone = next(o for o in exp.objects if o.cls == "dnsZone")
    assert zone.partition == "DomainDnsZones" and zone.sd
    assert next(o for o in exp.objects if o.cls == "subnet").site == f"CN=Default-First-Site-Name,CN=Sites,CN=Configuration,{DN}"
    d = exp.domain
    assert (d.forest_functional_level, d.lockout_threshold, d.pwd_properties, d.ds_heuristics) == ("7", 5, 1, "")
    assert (d.smartcard_rotation, d.laps_legacy_schema, d.laps_schema, d.schema_poss_superiors) == (True, False, True, {})
    assert d.last_backup == dt.datetime(2026, 9, 8, 12, 0, tzinfo=dt.UTC)
    assert raw["collector"]["notes"] == []  # PSO есть — записи «PSO не найдены» нет


def test_optional_schema_attributes_are_requested_only_when_present() -> None:
    """ldap3 со схемой отвергает запрос с атрибутом, которого в схеме нет: LAPS и атрибут Server 2016
    запрашиваются, только если они есть; без них поля — «нет в схеме», а не «не прочитано»."""
    fake = FakeLdap()
    for name in ("msLAPS-Password", "msLAPS-PasswordExpirationTime", "msDS-ExpirePasswordsOnSmartCardOnlyAccounts"):
        del fake.schema[name]
    fake.schema["msExchStorageGroup"] = {"possSuperiors": ["msExchInformationStore"], "systemPossSuperiors": ["computer"]}
    fake.schema["msDS-DelegatedManagedServiceAccount"] = {"schemaIDGUID": [bytes(range(16))]}
    asked: list[str] = []

    def search(base: str, flt: str, attrs: list[str], scope: str) -> Any:
        asked.extend(attrs)
        return fake.search(base, flt, attrs, scope)

    raw = LdapCollector(search, fake.root_dse(), smb_reader=fake.smb).collect()
    assert not {"msLAPS-PasswordExpirationTime", "ms-Mcs-AdmPwdExpirationTime", "msDS-ExpirePasswordsOnSmartCardOnlyAccounts"} & set(asked)
    assert "userPassword" not in asked and "unixUserPassword" not in asked
    d = raw["domain"]
    assert (d["laps_schema"], d["laps_legacy_schema"], d["smartcard_rotation"]) == (False, False, False)
    assert d["schema_poss_superiors"] == {"msExchStorageGroup": ["msExchInformationStore", "computer"]}
    assert raw["guids"]["schema_classes"] == {"msDS-DelegatedManagedServiceAccount": "03020100-0504-0706-0809-0a0b0c0d0e0f"}


def test_unread_sections_are_none_with_a_note() -> None:
    """Отказ схемы, корзины и метаданных — None («не прочитано») и запись в notes, а не False."""
    fake = FakeLdap(deny=("CN=Recycle Bin Feature,", "CN=Sites,", "CN=Subnets,"))
    del fake.base_entries[f"CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,{DN}"]

    def search(base: str, flt: str, attrs: list[str], scope: str) -> Any:
        if base.startswith("CN=Schema,") and flt.startswith("(|"):  # проверка необязательных имён схемы
            raise LdapResultError(50, "insufficientAccessRights", flt)
        return fake.search(base, flt, attrs, scope)

    raw = LdapCollector(search, fake.root_dse(), smb_reader=fake.smb).collect()
    d, notes = raw["domain"], raw["collector"]["notes"]
    assert d["recycle_bin"] is None and d["laps_schema"] is None and d["smartcard_rotation"] is None and d["schema_poss_superiors"] is None
    assert "schema_classes" in raw["guids"] and raw["guids"]["schema_classes"] == {}
    assert d["sysvol_replication"] == "ntfrs"
    assert any(n.startswith("корзина AD не прочитана: insufficientAccessRights (50)") for n in notes)
    assert any(n.startswith("схема не прочитана") for n in notes) and any(n.startswith("сайты не прочитаны") for n in notes)
    assert any(n.startswith("подсети не прочитаны") for n in notes)
    assert not [o for o in raw["objects"] if o["class"] in ("site", "subnet")]
    load_export(json.dumps(raw).encode())


def test_missing_recycle_bin_object_is_noted() -> None:
    fake = FakeLdap()
    del fake.base_entries[f"CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,{DN}"]
    raw = collect_with(fake)
    assert raw["domain"]["recycle_bin"] is None and any("Recycle Bin Feature" in n for n in raw["collector"]["notes"])


def test_empty_pso_container_is_noted() -> None:
    """Не администратор домена видит контейнер PSO пустым и без ошибки — отсутствие PSO не доказано."""
    notes = collect_with(FakeLdap())["collector"]["notes"]
    assert "PSO не найдены: при сборе не администратором домена они не видны" in notes


def test_dns_zone_partitions_are_labelled() -> None:
    fake = FakeLdap()
    fake.objects.append({"dn": f"DC=legacy.local,CN=MicrosoftDNS,CN=System,{DN}", "class": "dnsZone", "name": "legacy.local", "allowUpdate": 0})
    zones = {o["name"]: o["partition"] for o in collect_with(fake)["objects"] if o["class"] == "dnsZone"}
    assert zones == {"corp.local": "DomainDnsZones", "legacy.local": "System"}


def test_pure_parsers_tolerate_none() -> None:
    assert dns_allow_update(None) is None  # type: ignore[arg-type]
    assert last_backup_from_metadata(None) is None  # type: ignore[arg-type]


class _Ldap3OverFake:
    """Соединение ldap3 (режим SYNC) поверх FakeLdap; для баз с префиксом из `reject` ведёт себя
    как ldap3 со схемой, в которой нет запрошенного имени: исключение до отправки запроса."""

    def __init__(self, fake: FakeLdap, reject: str) -> None:
        self.fake, self.reject = fake, reject.lower()
        self.auto_referrals = True
        self.response: list[dict[str, Any]] = []
        self.result: dict[str, Any] = {}

    def search(self, search_base: str, search_filter: str, search_scope: Any = None, attributes: Any = None, **_: Any) -> bool:
        from ldap3 import BASE, LEVEL
        from ldap3.core.exceptions import LDAPAttributeError

        if search_base.lower().startswith(self.reject):
            raise LDAPAttributeError("invalid attribute type msDS-EnabledFeatureBL")
        scope = "BASE" if search_scope == BASE else "LEVEL" if search_scope == LEVEL else "SUBTREE"
        self.response = [{"type": "searchResEntry", **e} for e in self.fake.search(search_base, search_filter, attributes, scope)]
        self.result = {"result": 0, "controls": {}}
        return True


def test_attribute_unknown_to_schema_is_a_note_not_an_abort() -> None:
    from api.modules.ad.core.ldap_collector import Pacer, ldap3_searcher

    fake = FakeLdap()
    search = ldap3_searcher(_Ldap3OverFake(fake, "CN=Recycle Bin Feature,"), pacer=Pacer(0))
    raw = LdapCollector(search, fake.root_dse()).collect()
    assert raw["domain"]["recycle_bin"] is None
    assert any(n.startswith("корзина AD не прочитана: undefinedAttributeType (17)") for n in raw["collector"]["notes"])
    assert [o for o in raw["objects"] if o["class"] == "user"] and raw["domain"]["min_pwd_length"] == 12
