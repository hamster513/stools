"""Сборщик AD 2.1: раздача, поля, которые читают модели, меню и чистые функции скрипта в контейнере PowerShell.

Весь скрипт в контейнере не запустить (нужен модуль ActiveDirectory и домен), поэтому из него
по AST вынимаются отдельные функции без обращений к домену и выполняются сами по себе.
"""
from __future__ import annotations

import base64
import datetime as dt
import gzip
import json
import re
import shutil
import struct
import subprocess
import threading
import uuid
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.modules.ad.core import sd
from api.modules.ad.core.ca_data import parse_ca_data
from api.modules.ad.core.export import ExportIndex, load_export

SCRIPT = Path("api/modules/ad/collector/STools-AD-Collector.ps1")
IMAGE = "mcr.microsoft.com/powershell:lts-alpine-3.20"


def test_script_download_and_bom(auth_client: TestClient) -> None:
    r = auth_client.get("/api/ad/collector.ps1")
    assert r.status_code == 200 and r.content.startswith(b"\xef\xbb\xbf")
    assert "stools-ad/1" in r.text and "stools-ad-ca/1" in r.text


def test_script_writes_the_fields_the_models_read() -> None:
    text = SCRIPT.read_text(encoding="utf-8-sig")
    for name in ("pKIEnrollmentService", "pkiContainer", "msPKI-Enterprise-Oid", "trustedDomain", "certificateTemplates",
                 "dNSHostName", "msPKI-Enrollment-Servers", "msDS-OIDToGroupLink", "msPKI-Cert-Template-OID",
                 "msPKI-Certificate-Policy", "msPKI-Certificate-Application-Policy", "msPKI-RA-Application-Policies",
                 "altSecurityIdentities", "flatName", "trustAttributes",
                 "edit_flags", "interface_flags", "disable_extension_list", "security", "os_build",
                 "strong_binding", "mapping_methods", "StrongCertificateBindingEnforcement", "CertificateMappingMethods"):
        assert name in text, name


def test_script_writes_hygiene_fields() -> None:
    """Те же поля, что дочитывает LDAP-сборщик 1.1: модели и проверки читают обе выгрузки одинаково."""
    text = SCRIPT.read_text(encoding="utf-8-sig")
    for name in ("primaryGroupID", "sIDHistory", "whenCreated", "scriptPath", "hasUnixPassword", "lapsExpiry", "lapsNewExpiry",
                 "creatorSid", "revealOnDemand", "neverReveal", "revealedUsers", "krbTgtLink", "trustDirection", "trustType",
                 "trustPartner", "whenChanged", "dnsZone", "allowUpdate", "subnet", "msDS-PasswordSettings",
                 "forest_functional_level", "min_pwd_length", "lockout_threshold", "pwd_properties", "pwd_history_length",
                 "recycle_bin", "ds_heuristics", "smartcard_rotation", "laps_legacy_schema", "laps_schema", "last_backup",
                 "backup_read", "sysvol_replication", "schema_poss_superiors", "schema_classes",
                 "PSO не найдены: при сборе не администратором домена они не видны"):
        assert name in text, name


def test_script_never_requests_password_values() -> None:
    """Unix-пароли: только наличие по LDAP-фильтру, сами значения не запрашиваются."""
    text = SCRIPT.read_text(encoding="utf-8-sig")
    flt = "(|(userPassword=*)(unixUserPassword=*))"
    assert flt in text
    assert "userpassword" not in text.replace(flt, "").lower()


def test_script_collects_computer_host_attributes() -> None:
    """Те же три свойства компьютера, что у LDAP-сборщика: по ним Assets узнаёт хост."""
    text = SCRIPT.read_text(encoding="utf-8-sig")
    comp_props = next(line for line in text.splitlines() if line.strip().startswith("$compProps ="))
    for name in ("dNSHostName", "operatingSystem", "operatingSystemVersion"):
        assert f'"{name}"' in comp_props, name
        assert f'$rec["{name}"]' in text, name


def test_menu_lists_seven_items() -> None:
    text = SCRIPT.read_text(encoding="utf-8-sig")
    for line in ("1  Всё: выгрузка AD и данные ЦС", "5  Данные ЦС: настройки и права центров сертификации",
                 "6  Данные ЦС: реестр контроллеров домена", "7  Данные ЦС: проверка веб-выдачи"):
        assert line in text


def test_script_keeps_bom_version_and_module_requirement() -> None:
    raw = SCRIPT.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8-sig")
    assert "#requires -Modules ActiveDirectory" in text and '$CollectorVersion = "2.1"' in text


def _image_present() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, check=False).returncode == 0


needs_pwsh = pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")


def _pwsh(tmp_path: Path, body: str, functions: tuple[str, ...] = (), extra: tuple[str, ...] = ()) -> Any:
    """Выполняет `body` в контейнере; перед ним из AST скрипта определяются `functions`. Последняя строка вывода — JSON."""
    names = ", ".join(f'"{n}"' for n in functions)
    probe = f"""
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile("/script/{SCRIPT.name}", [ref]$tokens, [ref]$errors)
$defs = @($ast.FindAll({{ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }}, $true))
foreach ($name in @({names})) {{
  $fn = @($defs | Where-Object {{ $_.Name -eq $name }})
  if ($fn.Count -ne 1) {{ throw "функция $name найдена $($fn.Count) раз" }}
  Invoke-Expression $fn[0].Extent.Text
}}
{body}
"""
    (tmp_path / "probe.ps1").write_text(probe, encoding="utf-8")
    cmd = ["docker", "run", "--rm", *extra, "-v", f"{SCRIPT.resolve().parent}:/script:ro", "-v", f"{tmp_path}:/t:ro",
           IMAGE, "pwsh", "-NoProfile", "-File", "/t/probe.ps1"]
    run = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
    assert run.returncode == 0, run.stdout + run.stderr
    return json.loads(run.stdout.strip().splitlines()[-1])


@needs_pwsh
def test_script_parses_without_errors(tmp_path: Path) -> None:
    out = _pwsh(tmp_path, "ConvertTo-Json -Compress -InputObject @($errors | ForEach-Object { '{0}: {1}' -f $_.Extent.StartLineNumber, $_.Message })")
    assert out == []


CASES = {"1": (True, False, False, ["ca", "dc", "web"]), "3,4": (True, True, True, []), "5, 7": (False, False, False, ["ca", "web"]),
         "2,6": (True, False, False, ["dc"])}
BAD = ["", "2,3", "9", "abc"]


@needs_pwsh
def test_resolve_selection(tmp_path: Path) -> None:
    cases = ", ".join(f'"{c}"' for c in CASES)
    bad = ", ".join(f'"{b}"' for b in BAD)
    body = f"""
$ok = [ordered]@{{}}
foreach ($c in @({cases})) {{
  $r = Resolve-Selection $c
  $ok[$c] = @($r.Ad, $r.SkipComputerAcl, $r.SkipSysvol, [object[]]@($r.Sections))
}}
$bad = [ordered]@{{}}
foreach ($b in @({bad})) {{
  try {{ Resolve-Selection $b | Out-Null; $bad[$b] = "" }} catch {{ $bad[$b] = $_.Exception.Message }}
}}
[ordered]@{{ ok = $ok; bad = $bad }} | ConvertTo-Json -Compress -Depth 5
"""
    out = _pwsh(tmp_path, body, ("Resolve-Selection",))
    assert {k: tuple(v[:3]) + (v[3],) for k, v in out["ok"].items()} == CASES
    for text, message in out["bad"].items():
        assert re.search(r"[а-яё]", message.lower()), (text, message)


@needs_pwsh
def test_auth_schemes_and_certutil_parsers(tmp_path: Path) -> None:
    body = r"""
$certutil = @(
  "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\CORP-CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags:",
  "",
  "  EditFlags REG_DWORD = 11014e (1114446)",
  "    EDITF_REQUESTEXTENSIONLIST -- 2",
  "    EDITF_BASICCONSTRAINTSCRITICAL -- 40 (64)",
  "CertUtil: -getreg command completed successfully.")
$high = @("  InterfaceFlags REG_DWORD = 80000641 (-2147482047)")
$multi = @("  DisableExtensionList REG_MULTI_SZ =", "    0: 1.3.6.1.4.1.311.25.2", "    1: 1.2.3.4", "CertUtil: -getreg command completed successfully.")
$empty = @("  DisableExtensionList REG_MULTI_SZ =", "CertUtil: -getreg command completed successfully.")
$single = @("  DisableExtensionList REG_SZ = 1.3.6.1.4.1.311.25.2")
[ordered]@{
  ntlm = Get-AuthSchemes @("NTLM")
  negotiate = Get-AuthSchemes @('Negotiate')
  basic = Get-AuthSchemes @('Basic realm="x"')
  joined = Get-AuthSchemes @("NTLM, Negotiate")
  two = Get-AuthSchemes @("Negotiate", "NTLM")
  realm_commas = Get-AuthSchemes @('Basic realm="a, b", charset="UTF-8", NTLM')
  none = Get-AuthSchemes $null
  dword = Read-CertutilDword $certutil
  dword_high = Read-CertutilDword $high
  dword_none = Read-CertutilDword $multi
  multi = Read-CertutilList $multi
  multi_empty = Read-CertutilList $empty
  multi_single = Read-CertutilList $single
  reg_int = AsDword ([int]-2147482047)
  reg_null = AsDword $null
} | ConvertTo-Json -Compress
"""
    out = _pwsh(tmp_path, body, ("Get-AuthSchemes", "Read-CertutilDword", "Read-CertutilList", "AsDword"))
    assert out == {
        "ntlm": ["NTLM"], "negotiate": ["Negotiate"], "basic": ["Basic"], "joined": ["NTLM", "Negotiate"],
        "two": ["Negotiate", "NTLM"], "realm_commas": ["Basic", "NTLM"], "none": [],
        "dword": 1114446, "dword_high": 0x80000641, "dword_none": None,
        "multi": ["1.3.6.1.4.1.311.25.2", "1.2.3.4"], "multi_empty": [], "multi_single": ["1.3.6.1.4.1.311.25.2"],
        "reg_int": 0x80000641, "reg_null": None,
    }


def _dns_prop(prop_id: int, data: bytes) -> str:
    """Запись dNSProperty (как в test_ldap_collector) в base64 для передачи в PowerShell."""
    return base64.b64encode(struct.pack("<IIIII", len(data), 0, 0, 1, prop_id) + data + b"\x00").decode()


_META = ("<DS_REPL_ATTR_META_DATA><pszAttributeName>{}</pszAttributeName><dwVersion>3</dwVersion>"
         "<ftimeLastOriginatingChange>{}</ftimeLastOriginatingChange></DS_REPL_ATTR_META_DATA>")


@needs_pwsh
def test_last_backup_dns_allow_update_and_dn_binary(tmp_path: Path) -> None:
    """Те же входы, что у last_backup_from_metadata и dns_allow_update LDAP-сборщика, — те же ответы."""
    when = _META.format("whenCreated", "2024-01-01T00:00:00Z")
    dsa = _META.format("dSASignature", "2026-09-01T10:20:30Z")
    p1, p2 = _dns_prop(1, struct.pack("<I", 1)), _dns_prop(2, b"\x01")
    body = f"""
function B([string]$s) {{ ,[Convert]::FromBase64String($s) }}
$p1 = B "{p1}"; $p2 = B "{p2}"
[ordered]@{{
  backup = Get-LastBackup @('{when}', '{dsa}')
  backup_nul = Get-LastBackup @('{dsa}' + [char]0)
  backup_none = Get-LastBackup @('{when}')
  backup_null = Get-LastBackup $null
  update = Get-DnsAllowUpdate @($p1, $p2)
  update_none = Get-DnsAllowUpdate @(,$p1)
  update_short = Get-DnsAllowUpdate @(,[byte[]](0, 1))
  update_null = Get-DnsAllowUpdate $null
  dn = Get-DnBinaryDn "B:8:00000001:CN=a:b,CN=Users,DC=corp,DC=local"
  dn_plain = Get-DnBinaryDn "CN=alice,CN=Users,DC=corp,DC=local"
}} | ConvertTo-Json -Compress
"""
    out = _pwsh(tmp_path, body, ("Get-LastBackup", "Get-DnsAllowUpdate", "Get-DnBinaryDn"))
    assert out == {
        "backup": "2026-09-01T10:20:30Z", "backup_nul": "2026-09-01T10:20:30Z", "backup_none": None, "backup_null": None,
        "update": 1, "update_none": None, "update_short": None, "update_null": None,
        "dn": "CN=a:b,CN=Users,DC=corp,DC=local", "dn_plain": "CN=alice,CN=Users,DC=corp,DC=local",
    }


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.startswith("/ntlm/"):
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Negotiate")
            self.send_header("WWW-Authenticate", "NTLM")
        elif self.path.startswith("/redirect/"):
            self.send_response(302)
            self.send_header("Location", "/ntlm/")
        elif self.path.startswith("/basic/"):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="certsrv"')
        else:
            self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def web_server() -> Iterator[int]:
    server = ThreadingHTTPServer(("0.0.0.0", 0), _Handler)  # контейнер ходит на хост через host-gateway
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()


@needs_pwsh
def test_web_enrollment_probe_records_status_and_schemes(tmp_path: Path, web_server: int) -> None:
    """Код ответа виден и на ответах, которые HttpWebRequest бросает исключением; перенаправление не выполняется."""
    base = f"http://host.docker.internal:{web_server}"
    body = f"""
$r = [ordered]@{{}}
foreach ($p in @("ntlm", "redirect", "basic", "none")) {{ $r[$p] = Test-WebEnrollment "{base}/$p/" }}
$r["down"] = Test-WebEnrollment "http://127.0.0.1:1/certsrv/"
$r | ConvertTo-Json -Compress -Depth 4
"""
    out = _pwsh(tmp_path, body, ("Get-AuthSchemes", "ErrorText", "Test-WebEnrollment"), ("--add-host=host.docker.internal:host-gateway",))
    assert out["ntlm"] == {"url": f"{base}/ntlm/", "status": 401, "auth": ["Negotiate", "NTLM"], "error": ""}
    assert out["redirect"]["status"] == 302 and out["redirect"]["auth"] == []
    assert out["basic"]["status"] == 401 and out["basic"]["auth"] == ["Basic"]
    assert out["none"]["status"] == 404 and out["none"]["error"] == ""
    assert out["down"]["status"] is None and out["down"]["auth"] == [] and out["down"]["error"]


# Подделка модуля ActiveDirectory: синтетический домен corp.local. Get-ADObject отдаёт все запрошенные
# -Properties (отсутствующие — $null), как настоящий модуль, поэтому обращение сборщика к незапрошенному
# свойству падает в строгом режиме. SecurityIdentifier в Linux не работает: SID — объект со свойством
# Value, двоичный SID доверенного домена приходит из теста.
STUB_AD_MODULE = r'''Set-StrictMode -Version Latest

$Dom = "DC=corp,DC=local"
$Conf = "CN=Configuration,$Dom"
$Pki = "CN=Public Key Services,CN=Services,$Conf"
$Web = $env:STUB_WEB
# SecurityIdentifier в Linux не работает: SID — объект со свойством Value, как его читает сборщик;
# двоичный SID доверенного домена приходит из теста (base64).
function Sid([string]$s) { [pscustomobject]@{ Value = $s } }
$Base = "S-1-5-21-1-2-3"
$trustBytes = [Convert]::FromBase64String($env:STUB_TRUST_SID)
$creatorBytes = [Convert]::FromBase64String($env:STUB_CREATOR_SID)
$Schema = "CN=Schema,$Conf"
$Created = [datetime]::new(2025, 1, 2, 3, 4, 5, [DateTimeKind]::Utc)
# Имена схемы, которых нет в старом лесу (STUB_OLD_SCHEMA): их записи схемы скрыты, а запрос такого
# свойства настоящий модуль отвергает целиком («One or more properties are invalid»).
$OptionalSchema = @("ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-Password", "msLAPS-PasswordExpirationTime",
  "msDS-ExpirePasswordsOnSmartCardOnlyAccounts", "msExchStorageGroup", "msDS-DelegatedManagedServiceAccount")
# Запись dNSProperty: DataLength, NameLength, Flag, Version, Id (по 4 байта), данные и завершающий ноль.
function DnsProp([uint32]$id, [byte[]]$data) {
  $head = [BitConverter]::GetBytes([uint32]$data.Length) + [BitConverter]::GetBytes([uint32]0) + [BitConverter]::GetBytes([uint32]0) +
    [BitConverter]::GetBytes([uint32]1) + [BitConverter]::GetBytes($id)
  ,[byte[]]($head + $data + [byte]0)
}
$Meta = '<DS_REPL_ATTR_META_DATA><pszAttributeName>{0}</pszAttributeName><dwVersion>1</dwVersion><ftimeLastOriginatingChange>{1}</ftimeLastOriginatingChange></DS_REPL_ATTR_META_DATA>'

$Objects = @(
  @{ dn = $Dom; cls = @("domainDNS"); "ms-DS-MachineAccountQuota" = 10; minPwdLength = 12; lockoutThreshold = 5; pwdProperties = 1; pwdHistoryLength = 24
     "msDS-ReplAttributeMetaData" = @(($Meta -f "whenCreated", "2024-01-01T00:00:00Z"), (($Meta -f "dSASignature", "2026-09-01T10:20:30Z") + [char]0))
     "msDS-ExpirePasswordsOnSmartCardOnlyAccounts" = $true }
  @{ dn = "CN=AdminSDHolder,CN=System,$Dom"; cls = @("container") }
  @{ dn = "CN=Certificate-Enrollment,CN=Extended-Rights,$Conf"; cls = @("controlAccessRight"); displayName = "Enroll"; rightsGuid = "0e10c968-78fb-11d2-90d4-00c04f79dc55" }
  @{ dn = "CN=alice,CN=Users,$Dom"; cls = @("person", "user"); sAMAccountName = "alice"; objectSid = (Sid "$Base-1104"); userAccountControl = 512
     altSecurityIdentities = @("X509:<I>DC=local,DC=corp,CN=CORP-CA<S>CN=alice"); primaryGroupID = 513; sIDHistory = @((Sid "S-1-5-21-9-9-9-1104"))
     whenCreated = $Created; scriptPath = "logon.bat"; userPassword = "not-for-export" }
  @{ dn = "CN=bob,CN=Users,$Dom"; cls = @("person", "user"); sAMAccountName = "bob"; objectSid = (Sid "$Base-1106"); userAccountControl = 512; primaryGroupID = 513 }
  @{ dn = "CN=CA01,OU=Servers,$Dom"; cls = @("computer"); sAMAccountName = "CA01$"; objectSid = (Sid "$Base-1105"); userAccountControl = 4096
     dNSHostName = $Web; OperatingSystemVersion = "10.0 (17763)"; primaryGroupID = 515; whenCreated = $Created
     "ms-Mcs-AdmPwdExpirationTime" = [int64]134000000000000000; "msLAPS-PasswordExpirationTime" = [int64]134100000000000000; "ms-DS-CreatorSID" = $creatorBytes }
  @{ dn = "CN=RODC01,OU=Domain Controllers,$Dom"; cls = @("computer"); sAMAccountName = "RODC01$"; objectSid = (Sid "$Base-1107"); userAccountControl = 0x4001000
     primaryGroupID = 521; "msDS-RevealOnDemandGroup" = @("CN=Allowed RODC Password Replication Group,CN=Users,$Dom")
     "msDS-NeverRevealGroup" = @("CN=Denied RODC Password Replication Group,CN=Users,$Dom")
     "msDS-RevealedUsers" = @("B:8:00000001:CN=alice,CN=Users,$Dom", "B:8:00000002:CN=alice,CN=Users,$Dom", "B:8:00000001:CN=a:b,CN=Users,$Dom")
     "msDS-KrbTgtLink" = "CN=krbtgt_10001,CN=Users,$Dom" }
  @{ dn = "CN=Domain Admins,CN=Users,$Dom"; cls = @("group"); sAMAccountName = "Domain Admins"; objectSid = (Sid "$Base-512"); member = @("CN=alice,CN=Users,$Dom") }
  @{ dn = "OU=Servers,$Dom"; cls = @("organizationalUnit") }
  @{ dn = "CN={11111111-2222-3333-4444-555555555555},CN=Policies,CN=System,$Dom"; cls = @("groupPolicyContainer"); displayName = "Default"; gPCFileSysPath = $env:STUB_GPO }
  @{ dn = "CN=VulnTemplate,CN=Certificate Templates,$Pki"; cls = @("pKICertificateTemplate"); cn = "VulnTemplate"; displayName = "Vuln Template"
     pKIExtendedKeyUsage = @("1.3.6.1.5.5.7.3.2"); "msPKI-Certificate-Name-Flag" = 1; "msPKI-Enrollment-Flag" = 0; "msPKI-RA-Signature" = 0
     "msPKI-Template-Schema-Version" = 2; "msPKI-Certificate-Policy" = @("1.3.6.1.4.1.311.21.8.1.1"); "msPKI-Cert-Template-OID" = "1.3.6.1.4.1.311.21.8.9" }
  @{ dn = $Pki; cls = @("container") }
  @{ dn = "CN=Certificate Templates,$Pki"; cls = @("container") }
  @{ dn = "CN=Enrollment Services,$Pki"; cls = @("container") }
  @{ dn = "CN=NTAuthCertificates,$Pki"; cls = @("certificationAuthority") }
  @{ dn = "CN=OID,$Pki"; cls = @("msPKI-Enterprise-Oid") }
  @{ dn = "CN=1.2345,CN=OID,$Pki"; cls = @("msPKI-Enterprise-Oid"); displayName = "Corp Policy"; "msPKI-Cert-Template-OID" = "1.3.6.1.4.1.311.21.8.1.1"
     "msDS-OIDToGroupLink" = "CN=Domain Admins,CN=Users,$Dom" }
  @{ dn = "CN=CORP-CA,CN=Enrollment Services,$Pki"; cls = @("pKIEnrollmentService"); cn = "CORP-CA"; dNSHostName = $Web
     certificateTemplates = @("VulnTemplate"); "msPKI-Enrollment-Servers" = @("1`n4`n0`nhttp://$Web/ntlm/") }
  @{ dn = "CN=other.local,CN=System,$Dom"; cls = @("trustedDomain"); flatName = "OTHER"; securityIdentifier = $trustBytes; trustAttributes = 8
     trustDirection = 3; trustType = 2; trustPartner = "other.local"; whenChanged = $Created; "msDS-SupportedEncryptionTypes" = 24 }
  @{ dn = "CN=Directory Service,CN=Windows NT,CN=Services,$Conf"; cls = @("nTDSService"); dSHeuristics = "0000002" }
  @{ dn = "CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,$Dom"; cls = @("msDFSR-ReplicationGroup"); cn = "Domain System Volume" }
  @{ dn = "CN=Admins PSO,CN=Password Settings Container,CN=System,$Dom"; cls = @("msDS-PasswordSettings"); "msDS-MinimumPasswordLength" = 15
     "msDS-LockoutThreshold" = 3; "msDS-PasswordReversibleEncryptionEnabled" = $false; "msDS-PasswordComplexityEnabled" = $true
     "msDS-PasswordSettingsPrecedence" = 1; "msDS-PSOAppliesTo" = @("CN=Domain Admins,CN=Users,$Dom") }
  @{ dn = "DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,$Dom"; cls = @("dnsZone")
     dNSProperty = @((DnsProp 1 ([BitConverter]::GetBytes([uint32]1))), (DnsProp 2 ([byte[]]@(2)))) }
  @{ dn = "DC=_msdcs.corp.local,CN=MicrosoftDNS,DC=ForestDnsZones,$Dom"; cls = @("dnsZone"); dNSProperty = @(,(DnsProp 2 ([byte[]]@(1)))) }
  @{ dn = "DC=legacy.local,CN=MicrosoftDNS,CN=System,$Dom"; cls = @("dnsZone") }
  @{ dn = "CN=Default-First-Site-Name,CN=Sites,$Conf"; cls = @("site") }
  @{ dn = "CN=10.0.0.0/24,CN=Subnets,CN=Sites,$Conf"; cls = @("subnet"); siteObject = "CN=Default-First-Site-Name,CN=Sites,$Conf" }
  @{ dn = "CN=ms-Mcs-AdmPwd,$Schema"; cls = @("attributeSchema"); lDAPDisplayName = "ms-Mcs-AdmPwd" }
  @{ dn = "CN=ms-Mcs-AdmPwdExpirationTime,$Schema"; cls = @("attributeSchema"); lDAPDisplayName = "ms-Mcs-AdmPwdExpirationTime" }
  @{ dn = "CN=ms-LAPS-Password,$Schema"; cls = @("attributeSchema"); lDAPDisplayName = "msLAPS-Password" }
  @{ dn = "CN=ms-LAPS-Password-Expiration-Time,$Schema"; cls = @("attributeSchema"); lDAPDisplayName = "msLAPS-PasswordExpirationTime" }
  @{ dn = "CN=ms-DS-Expire-Passwords-On-Smart-Card-Only-Accounts,$Schema"; cls = @("attributeSchema"); lDAPDisplayName = "msDS-ExpirePasswordsOnSmartCardOnlyAccounts" }
  @{ dn = "CN=ms-Exch-Storage-Group,$Schema"; cls = @("classSchema"); lDAPDisplayName = "msExchStorageGroup"; possSuperiors = @("msExchInformationStore")
     systemPossSuperiors = @("computer") }
  @{ dn = "CN=ms-DS-Delegated-Managed-Service-Account,$Schema"; cls = @("classSchema"); lDAPDisplayName = "msDS-DelegatedManagedServiceAccount"
     schemaIDGUID = ([Guid]$env:STUB_DMSA_GUID).ToByteArray() }
)

function New-AdEntity($row, [string[]]$props) {
  $o = [ordered]@{ DistinguishedName = $row.dn; Name = ($row.dn -replace '^[A-Za-z]+=([^,]+),.*$', '$1') }
  # Значение кладётся как есть: $(...) развернул бы byte[] и списки, а модуль отдаёт их целиком.
  foreach ($p in $props) { if (-not $o.Contains($p)) { if ($row.ContainsKey($p)) { $o[$p] = $row[$p] } else { $o[$p] = $null } } }
  [pscustomobject]$o
}

function Test-Row($row, [string]$base, [string]$filter, [string]$scope) {
  if ($base) {
    $parent = $row.dn.Substring($row.dn.IndexOf(",") + 1)
    if ($scope -eq "Base" -and $row.dn -ne $base) { return $false }
    if ($scope -eq "OneLevel" -and $parent -ne $base) { return $false }
    if ($scope -eq "Subtree" -and -not $row.dn.EndsWith($base)) { return $false }
  }
  if ($filter -eq "(&(objectCategory=person)(objectClass=user))") { return $row.cls -contains "person" }
  if ($filter -eq "(&(objectCategory=person)(objectClass=user)(|(userPassword=*)(unixUserPassword=*)))") {
    return $row.cls -contains "person" -and ($row.ContainsKey("userPassword") -or $row.ContainsKey("unixUserPassword"))
  }
  if ($filter -match '^\(\|(.*)\)$') {
    foreach ($m in [regex]::Matches($Matches[1], '\(([^=()]+)=([^()]+)\)')) {
      if ($row.ContainsKey($m.Groups[1].Value) -and $row[$m.Groups[1].Value] -eq $m.Groups[2].Value) { return $true }
    }
    return $false
  }
  if ($filter -eq "(objectClass=*)") { return $true }
  if ($filter -match '^\(objectClass=([^)]+)\)$') { return $row.cls -contains $Matches[1] }
  if ($filter -match '^\(([^=]+)=([^)]+)\)$') { return $row.ContainsKey($Matches[1]) -and $row[$Matches[1]] -eq $Matches[2] }
  return $false
}

function Get-ADObject {
  [CmdletBinding()]
  param([string]$Identity, [string]$SearchBase, [string]$LDAPFilter, [object[]]$Properties, [string]$SearchScope = "Subtree", [string]$Server)
  $props = @($Properties | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
  # STUB_DENY — начала баз поиска через «;», чтение которых запрещено (как отказ доступа в настоящем домене).
  foreach ($deny in @(([string]$env:STUB_DENY) -split ';' | Where-Object { $_ })) {
    if ($SearchBase.StartsWith("$deny,")) {
      $err = [System.Management.Automation.ErrorRecord]::new([System.UnauthorizedAccessException]::new("Access is denied"), "AccessDenied", "PermissionDenied", $SearchBase)
      $PSCmdlet.ThrowTerminatingError($err)
    }
  }
  if ($env:STUB_OLD_SCHEMA -and @($props | Where-Object { $OptionalSchema -contains $_ }).Count -gt 0) {
    $err = [System.Management.Automation.ErrorRecord]::new([System.ArgumentException]::new("One or more properties are invalid."), "InvalidProperty", "InvalidArgument", $props)
    $PSCmdlet.ThrowTerminatingError($err)
  }
  foreach ($row in $Objects) {
    if ($env:STUB_OLD_SCHEMA -and $row.ContainsKey("lDAPDisplayName") -and $OptionalSchema -contains $row.lDAPDisplayName) { continue }
    $hit = $(if ($Identity) { $row.dn -eq $Identity } else { Test-Row $row $SearchBase $LDAPFilter $SearchScope })
    if ($hit) { New-AdEntity $row $props }
  }
}

function Get-ADComputer {
  [CmdletBinding()]
  param([string]$Filter, [object[]]$Properties, [string]$Server)
  if ($Filter -match "DNSHostName -eq '([^']+)'") {
    $name = $Matches[1]
    foreach ($row in $Objects) { if ($row.cls -contains "computer" -and $row.dNSHostName -eq $name) { New-AdEntity $row @($Properties) } }
  }
}

function Get-ADRootDSE {
  [CmdletBinding()] param([string]$Server)
  [pscustomobject]@{ configurationNamingContext = $Conf; schemaNamingContext = "CN=Schema,$Conf"; rootDomainNamingContext = $Dom; dnsHostName = "dc01.corp.local" }
}

function Get-ADForest {
  [CmdletBinding()] param([string]$Server)
  [pscustomobject]@{ ForestMode = "Windows2016Forest"; RootDomain = "corp.local" }
}

function Get-ADOptionalFeature {
  [CmdletBinding()] param([Parameter(Position = 0)][string]$Identity, [string]$Server)
  if ($Identity -ne "Recycle Bin Feature") { throw "Cannot find an object with identity: '$Identity'" }
  [pscustomobject]@{ Name = $Identity; EnabledScopes = @("CN=Partitions,$Conf") }
}

function Get-ADDomain {
  [CmdletBinding()] param([string]$Server)
  [pscustomobject]@{ DistinguishedName = $Dom; DNSRoot = "corp.local"; NetBIOSName = "CORP"; DomainSID = (Sid $Base); DomainMode = "Windows2016Domain" }
}

function Get-ADDomainController {
  [CmdletBinding()] param([string]$Filter, [string]$Server)
  [pscustomobject]@{ HostName = "dc01.corp.local" }
}

Export-ModuleMember -Function Get-ADObject, Get-ADComputer, Get-ADRootDSE, Get-ADDomain, Get-ADDomainController, Get-ADForest, Get-ADOptionalFeature
'''
TRUST_SID = "S-1-5-21-111-222-333"
CREATOR_SID = "S-1-5-21-1-2-3-1106"
DMSA_GUID = "0feb936f-47b3-49f2-9386-1dedc2c23765"


def _run_collector(tmp_path: Path, port: int, args: tuple[str, ...], stdin: str | None = None,
                   env_extra: dict[str, str] | None = None, timeout: int = 300) -> tuple[str, Path]:
    """Весь скрипт в контейнере с поддельным модулем ActiveDirectory; отдаёт вывод и каталог результата.
    Не уложился в `timeout` (например, ждёт ввода) — контейнер снимается, тест падает."""
    module = tmp_path / "modules" / "ActiveDirectory"
    module.mkdir(parents=True)
    (module / "ActiveDirectory.psm1").write_text(STUB_AD_MODULE, encoding="utf-8")
    secedit = tmp_path / "modules" / "gpo" / "MACHINE" / "Microsoft" / "Windows NT" / "SecEdit"
    secedit.mkdir(parents=True)
    (secedit / "GptTmpl.inf").write_text("[Privilege Rights]\nSeDebugPrivilege = *S-1-5-32-544\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    env = {"STUB_WEB": f"host.docker.internal:{port}", "STUB_TRUST_SID": base64.b64encode(sd.str_to_sid(TRUST_SID)).decode(),
           "STUB_CREATOR_SID": base64.b64encode(sd.str_to_sid(CREATOR_SID)).decode(), "STUB_DMSA_GUID": DMSA_GUID,
           "STUB_GPO": "/t/modules/gpo", "PSModulePath": "/t/modules", "COMPUTERNAME": "WS01", "USERDOMAIN": "CORP",
           "USERNAME": "auditor", **(env_extra or {})}
    name = f"stools-collector-test-{uuid.uuid4().hex[:12]}"
    cmd = ["docker", "run", "--rm", "-i", "--name", name, "--add-host=host.docker.internal:host-gateway",
           *[a for k, v in env.items() for a in ("-e", f"{k}={v}")],
           "-v", f"{SCRIPT.resolve().parent}:/script:ro", "-v", f"{tmp_path / 'modules'}:/t/modules:ro", "-v", f"{out}:/out", "-w", "/out",
           IMAGE, "pwsh", "-NoProfile", "-File", f"/script/{SCRIPT.name}", *args]
    try:
        run = subprocess.run(cmd, input=stdin or "", capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        tail = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout or ""
        pytest.fail(f"скрипт не завершился за {timeout} с (ждёт ввода?): …{tail[-1500:]}")
    assert run.returncode == 0, run.stdout + run.stderr
    return run.stdout + run.stderr, out


def _gz_json(path: Path) -> Any:
    return json.loads(gzip.decompress(path.read_bytes()))


@needs_pwsh
def test_script_writes_both_files_the_models_read(tmp_path: Path, web_server: int) -> None:
    """-Mode All: выгрузка AD с объектами PKI и данные ЦС; ошибки серверов (нет certutil и удалённого реестра
    в Linux, нет TLS) пишутся в записи, сбор не прерывается."""
    console, out = _run_collector(tmp_path, web_server, ("-Mode", "All", "-OutputPath", "/out/"))
    assert "План сбора" in console and "Продолжить?" not in console and "Сбор прерван" not in console, console
    [ad_file] = list(out.glob("ad-CORP-*.json.gz"))
    [ca_file] = list(out.glob("adca-CORP-*.json.gz"))

    export = load_export(ad_file.read_bytes())
    by_class: dict[str, list[Any]] = {}
    for o in export.objects:
        by_class.setdefault(o.cls, []).append(o)
    [template] = by_class["pKICertificateTemplate"]
    assert template.cn == "VulnTemplate" and template.issuance_policies == ["1.3.6.1.4.1.311.21.8.1.1"]
    assert template.template_oid == "1.3.6.1.4.1.311.21.8.9"
    [ca] = by_class["pKIEnrollmentService"]
    assert ca.cn == "CORP-CA" and ca.certificateTemplates == ["VulnTemplate"] and ca.enrollment_servers
    assert ExportIndex(export).published_on(template) == ["CORP-CA"]
    containers = sorted(o.dn.split(",")[0] for o in by_class["pkiContainer"])
    assert containers == ["CN=Certificate Templates", "CN=Enrollment Services", "CN=NTAuthCertificates", "CN=OID", "CN=Public Key Services"]
    [oid] = by_class["msPKI-Enterprise-Oid"]
    assert oid.dn.startswith("CN=1.2345,CN=OID,") and oid.oid_group_link == "CN=Domain Admins,CN=Users,DC=corp,DC=local"
    [trust] = by_class["trustedDomain"]
    assert trust.flatName == "OTHER" and trust.sid == TRUST_SID
    raw = _gz_json(ad_file)
    assert next(o for o in raw["objects"] if o["class"] == "trustedDomain")["trustAttributes"] == 8
    assert list(export.sysvol) == ["CN={11111111-2222-3333-4444-555555555555},CN=Policies,CN=System,DC=corp,DC=local"]
    assert export.collector.notes == [] and export.collector.version == "2.1"
    users = {u.sam: u for u in by_class["user"]}
    assert users["alice"].altSecurityIdentities == ["X509:<I>DC=local,DC=corp,CN=CORP-CA<S>CN=alice"]
    comps = {c.sam: c for c in by_class["computer"]}
    comp = comps["CA01$"]
    assert comp.dNSHostName == f"host.docker.internal:{web_server}" and comp.operatingSystemVersion == "10.0 (17763)" and comp.operatingSystem == ""

    # Данные гигиены — те же поля и смысл, что у LDAP-сборщика 1.1.
    created = dt.datetime(2025, 1, 2, 3, 4, 5, tzinfo=dt.UTC)
    d = export.domain
    assert (d.min_pwd_length, d.lockout_threshold, d.pwd_properties, d.pwd_history_length) == (12, 5, 1, 24)
    assert d.forest_functional_level == "Windows2016Forest" and d.recycle_bin is True and d.ds_heuristics == "0000002"
    assert d.smartcard_rotation is True and d.laps_legacy_schema is True and d.laps_schema is True
    assert d.last_backup == dt.datetime(2026, 9, 1, 10, 20, 30, tzinfo=dt.UTC) and d.backup_read is True
    assert d.sysvol_replication == "dfsr" and d.schema_poss_superiors == {"msExchStorageGroup": ["msExchInformationStore", "computer"]}
    assert export.guids.schema_classes == {"msDS-DelegatedManagedServiceAccount": DMSA_GUID}
    alice, bob = users["alice"], users["bob"]
    assert alice.primaryGroupID == 513 and alice.sIDHistory == ["S-1-5-21-9-9-9-1104"] and alice.whenCreated == created
    assert alice.scriptPath == "logon.bat" and alice.hasUnixPassword is True
    assert bob.hasUnixPassword is False and bob.sIDHistory == [] and bob.whenCreated is None and bob.scriptPath is None
    assert "not-for-export" not in json.dumps(raw)
    assert comp.primaryGroupID == 515 and comp.lapsExpiry == 134000000000000000 and comp.lapsNewExpiry == 134100000000000000
    assert comp.creatorSid == CREATOR_SID and comp.revealedUsers == [] and comp.krbTgtLink is None
    rodc = comps["RODC01$"]
    assert rodc.revealOnDemand == ["CN=Allowed RODC Password Replication Group,CN=Users,DC=corp,DC=local"]
    assert rodc.neverReveal == ["CN=Denied RODC Password Replication Group,CN=Users,DC=corp,DC=local"]
    assert rodc.revealedUsers == ["CN=alice,CN=Users,DC=corp,DC=local", "CN=a:b,CN=Users,DC=corp,DC=local"]
    assert rodc.krbTgtLink == "CN=krbtgt_10001,CN=Users,DC=corp,DC=local" and rodc.lapsExpiry is None and rodc.creatorSid is None
    assert (trust.trustDirection, trust.trustType, trust.trustPartner, trust.supportedEncryptionTypes) == (3, 2, "other.local", 24)
    assert trust.whenChanged == created
    [pso] = by_class["msDS-PasswordSettings"]
    assert (pso.name, pso.psoMinLength, pso.psoLockoutThreshold, pso.psoReversible, pso.psoComplexity, pso.psoPrecedence) == ("Admins PSO", 15, 3, False, True, 1)
    assert pso.psoAppliesTo == ["CN=Domain Admins,CN=Users,DC=corp,DC=local"]
    zones = {z.name: z for z in by_class["dnsZone"]}
    assert {n: (z.partition, z.allowUpdate) for n, z in zones.items()} == {
        "corp.local": ("DomainDnsZones", 2), "_msdcs.corp.local": ("ForestDnsZones", 1), "legacy.local": ("System", None)}
    [site] = by_class["site"]
    [subnet] = by_class["subnet"]
    assert site.name == "Default-First-Site-Name" and subnet.name == "10.0.0.0/24" and subnet.site == site.dn

    data = parse_ca_data(_gz_json(ca_file))
    assert data.sections == ["ca", "dc", "web"] and data.domain.sid == export.domain.sid and data.collector.version == "2.1"
    [authority] = data.cas
    assert authority.name == "CORP-CA" and authority.os_build == "10.0 (17763)" and authority.error and authority.edit_flags is None
    [dc] = data.dcs
    assert dc.host == "dc01.corp.local" and dc.strong_binding is None and dc.error
    base = f"host.docker.internal:{web_server}"
    web = {w.url: w for w in data.web}
    assert list(web) == [f"http://{base}/certsrv/", f"https://{base}/certsrv/", f"http://{base}/ntlm/"]
    assert web[f"http://{base}/certsrv/"].status == 404
    assert web[f"http://{base}/ntlm/"].status == 401 and web[f"http://{base}/ntlm/"].auth == ["Negotiate", "NTLM"]
    assert web[f"https://{base}/certsrv/"].status is None and web[f"https://{base}/certsrv/"].error


@needs_pwsh
def test_script_menu_rejects_bad_choice_and_waits_for_confirmation(tmp_path: Path, web_server: int) -> None:
    console, out = _run_collector(tmp_path / "no", web_server, (), stdin="9\n2,3\n5,7\nn\n")
    assert "Нет пункта «9»" in console and "не сочетаются" in console and "Продолжить? (y/n)" in console, console
    assert "Отменено" in console and not list(out.iterdir())
    console, out = _run_collector(tmp_path / "yes", web_server, (), stdin="7\ny\n")
    [ca_file] = list(out.glob("adca-CORP-*.json.gz"))
    assert not list(out.glob("ad-CORP-*")), console
    data = parse_ca_data(_gz_json(ca_file))
    assert data.sections == ["web"] and data.cas == [] and data.dcs == [] and len(data.web) == 3


SKIP_SYSVOL_NOTE = "чтение SYSVOL выключено (-SkipSysvol)"


@needs_pwsh
def test_script_old_command_line_collects_ad_without_menu(tmp_path: Path, web_server: int) -> None:
    """Команда сборщика 1.x (без -Mode) не открывает меню: пишет выгрузку AD в указанный файл, учитывает
    -SkipSysvol; пропуск SYSVOL и отказ чтения CN=OID, PSO и зон DomainDnsZones попадают в collector.notes.
    Старая схема (нет LAPS, атрибута смарт-карт, dMSA, Exchange): эти свойства не запрашиваются, сбор не прерывается."""
    console, out = _run_collector(tmp_path, web_server, ("-SkipSysvol", "-OutputPath", "/out/old.json.gz"),
                                  env_extra={"STUB_DENY": "CN=OID;CN=Password Settings Container;DC=DomainDnsZones", "STUB_OLD_SCHEMA": "1"},
                                  timeout=120)
    assert "Выбор" not in console and "Продолжить?" not in console and "Сбор прерван" not in console, console
    assert sorted(p.name for p in out.iterdir()) == ["old.json.gz"]
    export = load_export((out / "old.json.gz").read_bytes())
    assert export.sysvol == {}
    notes = export.collector.notes
    assert notes[0] == SKIP_SYSVOL_NOTE
    assert [n for n in notes if n.startswith("политики выдачи (CN=OID): ")], notes
    assert [n for n in notes if n.startswith("PSO не прочитаны: ")], notes
    assert [n for n in notes if n.startswith("зоны DNS не прочитаны (DomainDnsZones): ")], notes
    assert not [o for o in export.objects if o.cls in ("msPKI-Enterprise-Oid", "msDS-PasswordSettings")]
    assert sorted(o.partition or "" for o in export.objects if o.cls == "dnsZone") == ["ForestDnsZones", "System"]
    d = export.domain
    assert (d.laps_legacy_schema, d.laps_schema, d.smartcard_rotation, d.schema_poss_superiors) == (False, False, False, {})
    assert export.guids.schema_classes == {"msDS-DelegatedManagedServiceAccount": ""}
    assert d.min_pwd_length == 12 and d.last_backup is not None
    comps = [o for o in export.objects if o.cls == "computer"]
    assert comps and all(c.lapsExpiry is None and c.lapsNewExpiry is None for c in comps)


@needs_pwsh
def test_script_sections_without_mode_collects_ca_data(tmp_path: Path, web_server: int) -> None:
    """-Sections без -Mode — только данные ЦС; вместе с -SkipComputerAcl или -SkipSysvol — оба файла."""
    console, out = _run_collector(tmp_path / "ca", web_server, ("-Sections", "ca", "-OutputPath", "/out/"), timeout=120)
    assert "Выбор" not in console and not list(out.glob("ad-CORP-*")), console
    [ca_file] = list(out.glob("adca-CORP-*.json.gz"))
    assert parse_ca_data(_gz_json(ca_file)).sections == ["ca"]
    console, out = _run_collector(tmp_path / "all", web_server, ("-Sections", "dc", "-SkipComputerAcl"), timeout=120)
    assert "Выбор" not in console, console
    assert len(list(out.glob("ad-CORP-*.json.gz"))) == 1 and len(list(out.glob("adca-CORP-*.json.gz"))) == 1, console
