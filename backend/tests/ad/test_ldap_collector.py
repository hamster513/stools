from __future__ import annotations

import base64
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
from tests.ad.fake_ldap import DC_OU, DDCP_DN, DDP_DN, DDP_PATH, FakeLdap, sysvol_access
from tests.ad.gpo_fixtures import AUDIT_CSV, GROUPS, LSA, WINLOGON, dword, preg, sz
from tests.ad.synthetic import (
    CA_CERT,
    DN,
    EXT_SID,
    NOW,
    OTHER_SID,
    PKI,
    b64sd,
    export_bytes,
    make_cert,
    rid,
    user_dn,
)


def test_ldap_collector_matches_powershell_export() -> None:
    fake = FakeLdap()
    collector = LdapCollector(fake.search, fake.root_dse(), smb_reader=fake.smb, host="dc01", account="CORP\\auditor")
    raw = collector.collect()
    # Сборщик ставит collected_at текущим временем, а даты фальшивого каталога отсчитаны от NOW:
    # без закрепления пороги давности (бэкап, входы) расходятся с эталоном по мере хода времени.
    raw["collected_at"] = NOW.isoformat()
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


def test_collector_reads_upn_and_display_name() -> None:
    """Сборщик 1.4: userPrincipalName и displayName запрашиваются у пользователей и компьютеров и доходят до модели."""
    fake = FakeLdap()
    by_sam = {o.get("sam"): o for o in fake.objects}
    by_sam["helpdesk"].update(userPrincipalName="helpdesk@corp.local", displayName="Helpdesk Operator")
    by_sam["WS01$"].update(displayName="WS01")
    asked: dict[str, list[str]] = {}

    def search(base: str, flt: str, attrs: list[str], scope: str) -> Any:
        if flt in ("(&(objectCategory=person)(objectClass=user))", "(objectClass=computer)"):
            asked[flt] = attrs
        return fake.search(base, flt, attrs, scope)

    raw = LdapCollector(search, fake.root_dse()).collect()
    assert raw["collector"]["version"] == "1.5"
    for attrs in asked.values():
        assert {"userPrincipalName", "displayName"} <= set(attrs)
    assert len(asked) == 2
    exp = load_export(json.dumps(raw).encode())
    objs = {o.sam: o for o in exp.objects if o.sam}
    assert (objs["helpdesk"].userPrincipalName, objs["helpdesk"].displayName) == ("helpdesk@corp.local", "Helpdesk Operator")
    assert (objs["WS01$"].userPrincipalName, objs["WS01$"].displayName) == (None, "WS01")
    assert (objs["admin1"].userPrincipalName, objs["admin1"].displayName) == (None, None)  # не заданы


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


def _with_ca_stores(fake: FakeLdap) -> tuple[str, str, str]:
    """Сертификаты ЦС в каталоге: корневой в CN=Certification Authorities, два в CN=AIA, один в NTAuth."""
    root, sub, weak = (base64.b64encode(make_cert(cn, **kw)).decode() for cn, kw in (("CORP-ROOT", {}), ("CORP-SUB", {"issuer": "CORP-ROOT"}), ("OLD-SUB", {"bits": 1024})))
    next(o for o in fake.objects if o["dn"] == f"CN=NTAuthCertificates,{PKI}")["cACertificate"] = [sub]
    fake.objects += [
        {"dn": f"CN=CORP-ROOT,CN=Certification Authorities,{PKI}", "class": "certificationAuthority", "cn": "CORP-ROOT", "cACertificate": [root]},
        {"dn": f"CN=CORP-SUB,CN=AIA,{PKI}", "class": "certificationAuthority", "cn": "CORP-SUB", "cACertificate": [sub, weak]},
    ]
    return root, sub, weak


def test_collector_reads_ca_certificates() -> None:
    """Сборщик 1.3: cACertificate у ЦС выдачи, NTAuthCertificates и хранилищ CN=Certification Authorities (root), CN=AIA (intermediate)."""
    fake = FakeLdap()
    root, sub, weak = _with_ca_stores(fake)
    raw = LdapCollector(fake.search, fake.root_dse(), smb_reader=fake.smb).collect()
    by_dn = {o["dn"]: o for o in raw["objects"]}
    assert raw["collector"]["version"] == "1.5" and not [n for n in raw["collector"]["notes"] if "сертификаты ЦС" in n]
    assert by_dn[f"CN=CORP-CA,CN=Enrollment Services,{PKI}"]["cACertificate"] == [CA_CERT]
    assert by_dn[f"CN=NTAuthCertificates,{PKI}"]["cACertificate"] == [sub] and "cACertificate" not in by_dn[PKI]
    stores = {o["cn"]: (o["store"], o["cACertificate"]) for o in raw["objects"] if o["class"] == "certificationAuthority"}
    assert stores == {"CORP-ROOT": ("root", [root]), "CORP-SUB": ("intermediate", [sub, weak])}
    raw["collected_at"] = NOW.isoformat()
    export = load_export(json.dumps(raw).encode())
    found = [f for f in run_all(ExportIndex(export), AdConfig()) if f.check == "CertificateStrength"]
    assert [(f.target, f.identity, f.severity) for f in found] == [(f"CN=CORP-SUB,CN=AIA,{PKI}", "CN=OLD-SUB", "Low")]


def test_denied_ca_store_is_a_note() -> None:
    fake = FakeLdap(deny=(f"CN=AIA,{PKI}",))
    _with_ca_stores(fake)
    raw = LdapCollector(fake.search, fake.root_dse(), smb_reader=fake.smb).collect()
    assert [o["cn"] for o in raw["objects"] if o["class"] == "certificationAuthority"] == ["CORP-ROOT"]
    assert [n for n in raw["collector"]["notes"] if "сертификаты ЦС" in n] == ["сертификаты ЦС (CN=AIA) не прочитаны: insufficientAccessRights (50)"]


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


_FAKE_SMB: Any = object()


def collect_with(fake: FakeLdap, *, smb: Any = _FAKE_SMB, lister: Any = None) -> dict[str, Any]:
    reader = fake.smb if smb is _FAKE_SMB else smb
    return LdapCollector(fake.search, fake.root_dse(), smb_reader=reader, smb_lister=lister, host="dc01", account="CORP\\auditor").collect()


def sysvol_reader(files: dict[str, bytes]) -> Any:
    """SYSVOL с файлами Default Domain Policy: путь `<gPCFileSysPath>\\<относительный>` без учёта регистра."""
    return sysvol_access({f"{DDP_PATH}\\{rel}": data for rel, data in files.items()})[0]


GPO_TEST_FILES = {
    "Machine\\Registry.pol": preg((LSA, "NoLMHash", 4, dword(0)), ("Software\\Vendor\\App", "ApiKey", 1, sz("secret")),
                                  (WINLOGON, "DefaultPassword", 1, sz("P@ssw0rd"))),
    "Machine\\Preferences\\Groups\\Groups.xml": GROUPS.encode(),
    "MACHINE\\Microsoft\\Windows NT\\Audit\\audit.csv": AUDIT_CSV.encode("utf-16"),
    "User\\Scripts\\scripts.ini": "[Logon]\r\n0CmdLine=run.bat\r\n0Parameters=\r\n".encode("utf-16"),
    "User\\Registry.pol": b"broken",
}


def test_collector_reads_gpo_files_with_whitelist_and_redaction() -> None:
    out = collect_with(FakeLdap(), smb=sysvol_reader(GPO_TEST_FILES))
    data = next(iter(out["gpo"].values()))
    assert [(r["value"], r["data"]) for r in data["registry"]] == [("NoLMHash", 0), ("DefaultPassword", "")]
    assert data["gpp"][0]["cpassword"] is True and data["audit"][0]["setting"] == 3 and data["scripts"][0]["phase"] == "logon"
    assert data["acl"] is None and any("Registry.pol" in n for n in data["notes"])
    assert "secret" not in json.dumps(out) and "P@ssw0rd" not in json.dumps(out) and "TEST_ONLY_NOT_A_REAL_PASSWORD" not in json.dumps(out)
    root = next(o for o in out["objects"] if o["class"] == "domainDNS")
    assert "gpLink" in root and out["collector"]["version"] == "1.5"
    # Блок доходит до модели: у GPO без файлов — пустая запись, а не «не прочитано».
    export = load_export(json.dumps(out).encode())
    assert export.gpo is not None and export.gpo[DDP_DN].registry[0].scope == "machine" and export.gpo[DDCP_DN].registry == []


def test_collector_without_sysvol_has_no_gpo_block() -> None:
    out = collect_with(FakeLdap(), smb=None)
    assert out.get("gpo") is None


def test_collector_reads_only_listed_gpo_files() -> None:
    fake = FakeLdap()
    fake.sysvol.update({f"{DDP_PATH}\\{rel}": data for rel, data in GPO_TEST_FILES.items()})
    reads: list[str] = []
    lists: list[str] = []

    def read(path: str) -> bytes | None:
        reads.append(path)
        return fake.smb(path)

    def ls(path: str) -> list[str] | None:
        lists.append(path)
        return fake.ls(path)

    out = collect_with(fake, smb=read, lister=ls)
    assert sorted(p.lower() for p in reads) == sorted(p.lower() for p in fake.sysvol)
    assert len(out["sysvol"]) == 1 and out["gpo"][DDP_DN]["gpp"][0]["kind"] == "User"
    # Папки, которых нет в листинге родителя, не перебираются; у GPO без файлов — только Machine и User.
    ddcp = [p for p in lists if not p.startswith(DDP_PATH)]
    assert len(ddcp) == 2 and not any("\\Preferences\\Drives" in p or "Machine\\Scripts" in p for p in lists)
    assert any(p.endswith("Machine\\Preferences\\Groups") for p in lists)
    assert out["gpo"][DDCP_DN]["notes"] == ["папка GPO не прочитана по SMB: нет Machine и User"]


def test_gpo_file_failures_are_notes() -> None:
    from api.modules.ad.core.gpo_files import MAX_GPO_FILE

    fake = FakeLdap()
    fake.sysvol.update({
        f"{DDP_PATH}\\Machine\\Registry.pol": b"PReg" + b"\x00" * MAX_GPO_FILE,
        f"{DDP_PATH}\\User\\Preferences\\Drives\\Drives.xml": b"<Drives>",
        f"{DDP_PATH}\\User\\Scripts\\scripts.ini": b"",
    })
    gone = f"{DDP_PATH}\\User\\Scripts\\scripts.ini".lower()
    out = collect_with(fake, smb=lambda p: None if p.lower() == gone else fake.smb(p), lister=fake.ls)
    notes = out["gpo"][DDP_DN]["notes"]
    assert len(notes) == 3 and len(out["sysvol"]) == 1
    assert any("Machine\\Registry.pol" in n and "4 МБ" in n for n in notes)
    assert any("Drives.xml" in n for n in notes) and any("scripts.ini" in n and "не прочитан" in n for n in notes)


def test_failed_listing_is_a_note_not_an_absent_folder() -> None:
    fake = FakeLdap()
    fake.sysvol.update({f"{DDP_PATH}\\{rel}": data for rel, data in GPO_TEST_FILES.items()})

    def ls(path: str) -> list[str] | None:
        if path.lower() == f"{DDP_PATH}\\Machine".lower():
            raise OSError(0, "Unknown NtStatus error returned 'STATUS_ACCESS_DENIED'")
        return fake.ls(path)

    out = collect_with(fake, lister=ls)
    data = out["gpo"][DDP_DN]
    assert any(n.startswith("Machine: папка не прочитана по SMB (") and "ACCESS_DENIED" in n for n in data["notes"])
    assert not any("нет Machine и User" in n for n in data["notes"])
    # Пропущена только папка Machine: файлы пользователя прочитаны, компьютерных нет.
    assert data["scripts"][0]["phase"] == "logon" and data["registry"] == [] and data["gpp"] == []


def test_unknown_gpo_file_kind_is_a_note(monkeypatch: pytest.MonkeyPatch) -> None:
    from api.modules.ad.core import ldap_collector

    monkeypatch.setattr(ldap_collector, "GPO_FILES", {"machine/odd.txt": "Machine\\odd.txt"})
    fake = FakeLdap()
    fake.sysvol[f"{DDP_PATH}\\Machine\\odd.txt"] = b"<Groups/>"
    out = collect_with(fake, lister=fake.ls)
    assert out["gpo"][DDP_DN]["notes"] == ["Machine\\odd.txt: неизвестный тип файла"] and out["gpo"][DDP_DN]["gpp"] == []

def test_collector_reads_gpo_links_and_flags() -> None:
    asked: dict[str, list[str]] = {}
    fake = FakeLdap()

    def search(base: str, flt: str, attrs: list[str], scope: str) -> Any:
        asked.setdefault(flt if scope != "BASE" or base != DN else "root", attrs)
        return fake.search(base, flt, attrs, scope)

    out = LdapCollector(search, fake.root_dse(), smb_reader=fake.smb).collect()
    for key in ("root", "(objectClass=organizationalUnit)", "(objectClass=site)"):
        assert {"gPLink", "gPOptions"} <= set(asked[key]), key
    assert "flags" in asked["(objectClass=groupPolicyContainer)"]
    by_dn = {o["dn"]: o for o in out["objects"]}
    assert by_dn[DN]["gpLink"] == f"[LDAP://{DDP_DN};0]" and by_dn[DN]["gpOptions"] == 0
    assert by_dn[DC_OU]["gpLink"] == f"[LDAP://{DDCP_DN};0]" and by_dn[DDP_DN]["flags"] == 0
    # Атрибута нет — ссылок нет: пустая строка отличает новый сборщик от старого (None).
    site = next(o for o in out["objects"] if o["class"] == "site")
    assert site["gpLink"] == "" and site["gpOptions"] is None
    idx = ExportIndex(load_export(json.dumps(out).encode()))
    ddp = next(o for o in idx.objects("groupPolicyContainer") if o.dn == DDP_DN)
    assert idx.applies_to_dcs(ddp) is True


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
    assert out["collector"]["version"] == "1.5"
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


def test_collector_reads_critical_object_descriptors() -> None:
    fake = FakeLdap()
    blob = b64sd([sd.build_ace(rid(1108), sd.WRITE_DACL)])
    for o in fake.objects:
        if o["class"] in ("user", "group"):
            o["sd"] = blob
    out = collect_with(fake)
    by_dn = {o["dn"]: o for o in out["objects"]}
    # Domain Admins → admin1, Tier0 → admin2 (Tier0 вложена в Domain Admins и обратно), Administrator и krbtgt по RID.
    for sam in ("Domain Admins", "admin1", "Tier0", "admin2", "krbtgt"):
        assert by_dn[user_dn(sam)]["sd"] == blob, sam
    assert by_dn[user_dn("user.noexpire")].get("sd") is None
    assert out["collector"]["critical_acl"] is True
    assert out["principals"][rid(1108)]["name"] == "CORP\\helpdesk"


def test_critical_members_limit_and_denial_are_noted(monkeypatch: pytest.MonkeyPatch) -> None:
    from api.modules.ad.core import ldap_collector

    monkeypatch.setattr(ldap_collector, "CRITICAL_MEMBERS_LIMIT", 1)
    out = collect_with(FakeLdap())
    assert any("Domain Admins" in n and "больше 1" in n for n in out["collector"]["notes"])

    fake = FakeLdap()
    search = fake.search

    def deny_chain(base: str, flt: str, attrs: list[str], scope: str) -> list[dict[str, Any]]:
        if "1.2.840.113556.1.4.1941" in flt:
            raise LdapResultError(51, "busy", flt)
        return search(base, flt, attrs, scope)

    out = LdapCollector(deny_chain, fake.root_dse()).collect()
    assert any(n.startswith("дескрипторы критичных объектов не прочитаны") and "busy" in n for n in out["collector"]["notes"])


def test_chain_filter_escapes_the_group_dn() -> None:
    from api.modules.ad.core.ldap_collector import filter_value

    assert filter_value("CN=a\\, b (x)*,DC=c") == "CN=a\\5c, b \\28x\\29\\2a,DC=c"


def test_collector_reads_mail_and_manager():
    fake = FakeLdap()
    users = {o.get("sam"): o for o in fake.objects}
    users["helpdesk"].update(mail="helpdesk@example.test", manager=users["admin1"]["dn"])
    requested = []
    def search(base, flt, attrs, scope):
        if flt == "(&(objectCategory=person)(objectClass=user))":
            requested.extend(attrs)
        return fake.search(base, flt, attrs, scope)
    raw = LdapCollector(search, fake.root_dse()).collect()
    assert {"mail", "manager"} <= set(requested)
    export = load_export(json.dumps(raw).encode())
    user = next(o for o in export.objects if o.sam == "helpdesk")
    assert user.mail == "helpdesk@example.test" and user.manager == users["admin1"]["dn"]
