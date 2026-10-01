"""Сборщик AD 2.0: раздача, поля, которые читают модели, меню и чистые функции скрипта в контейнере PowerShell.

Весь скрипт в контейнере не запустить (нужен модуль ActiveDirectory и домен), поэтому из него
по AST вынимаются отдельные функции без обращений к домену и выполняются сами по себе.
"""
from __future__ import annotations

import base64
import gzip
import json
import re
import shutil
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
    assert "#requires -Modules ActiveDirectory" in text and '$CollectorVersion = "2.0"' in text


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

$Objects = @(
  @{ dn = $Dom; cls = @("domainDNS"); "ms-DS-MachineAccountQuota" = 10 }
  @{ dn = "CN=AdminSDHolder,CN=System,$Dom"; cls = @("container") }
  @{ dn = "CN=Certificate-Enrollment,CN=Extended-Rights,$Conf"; cls = @("controlAccessRight"); displayName = "Enroll"; rightsGuid = "0e10c968-78fb-11d2-90d4-00c04f79dc55" }
  @{ dn = "CN=alice,CN=Users,$Dom"; cls = @("person", "user"); sAMAccountName = "alice"; objectSid = (Sid "$Base-1104"); userAccountControl = 512
     altSecurityIdentities = @("X509:<I>DC=local,DC=corp,CN=CORP-CA<S>CN=alice") }
  @{ dn = "CN=CA01,OU=Servers,$Dom"; cls = @("computer"); sAMAccountName = "CA01$"; objectSid = (Sid "$Base-1105"); userAccountControl = 4096
     dNSHostName = $Web; OperatingSystemVersion = "10.0 (17763)" }
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
  @{ dn = "CN=other.local,CN=System,$Dom"; cls = @("trustedDomain"); flatName = "OTHER"; securityIdentifier = $trustBytes; trustAttributes = 8 }
)

function New-AdEntity($row, [string[]]$props) {
  $o = [ordered]@{ DistinguishedName = $row.dn; Name = ($row.dn -replace '^[A-Za-z]+=([^,]+),.*$', '$1') }
  foreach ($p in $props) { if (-not $o.Contains($p)) { $o[$p] = $(if ($row.ContainsKey($p)) { $row[$p] } else { $null }) } }
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
  if ($filter -eq "(objectClass=*)") { return $true }
  if ($filter -match '^\(objectClass=([^)]+)\)$') { return $row.cls -contains $Matches[1] }
  if ($filter -match '^\(([^=]+)=([^)]+)\)$') { return $row.ContainsKey($Matches[1]) -and $row[$Matches[1]] -eq $Matches[2] }
  return $false
}

function Get-ADObject {
  [CmdletBinding()]
  param([string]$Identity, [string]$SearchBase, [string]$LDAPFilter, [object[]]$Properties, [string]$SearchScope = "Subtree", [string]$Server)
  $props = @($Properties | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
  # STUB_DENY — начало базы поиска, чтение которой запрещено (как отказ доступа в настоящем домене).
  if ($env:STUB_DENY -and $SearchBase.StartsWith("$env:STUB_DENY,")) {
    $err = [System.Management.Automation.ErrorRecord]::new([System.UnauthorizedAccessException]::new("Access is denied"), "AccessDenied", "PermissionDenied", $SearchBase)
    $PSCmdlet.ThrowTerminatingError($err)
  }
  foreach ($row in $Objects) {
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
  [pscustomobject]@{ configurationNamingContext = $Conf; schemaNamingContext = "CN=Schema,$Conf"; dnsHostName = "dc01.corp.local" }
}

function Get-ADDomain {
  [CmdletBinding()] param([string]$Server)
  [pscustomobject]@{ DistinguishedName = $Dom; DNSRoot = "corp.local"; NetBIOSName = "CORP"; DomainSID = (Sid $Base); DomainMode = "Windows2016Domain" }
}

function Get-ADDomainController {
  [CmdletBinding()] param([string]$Filter, [string]$Server)
  [pscustomobject]@{ HostName = "dc01.corp.local" }
}

Export-ModuleMember -Function Get-ADObject, Get-ADComputer, Get-ADRootDSE, Get-ADDomain, Get-ADDomainController
'''
TRUST_SID = "S-1-5-21-111-222-333"


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
    assert _gz_json(ad_file)["objects"][-1]["trustAttributes"] == 8
    assert list(export.sysvol) == ["CN={11111111-2222-3333-4444-555555555555},CN=Policies,CN=System,DC=corp,DC=local"]
    assert export.collector.notes == []
    [user] = by_class["user"]
    assert user.altSecurityIdentities == ["X509:<I>DC=local,DC=corp,CN=CORP-CA<S>CN=alice"]
    [comp] = by_class["computer"]
    assert comp.dNSHostName == f"host.docker.internal:{web_server}" and comp.operatingSystemVersion == "10.0 (17763)" and comp.operatingSystem == ""

    data = parse_ca_data(_gz_json(ca_file))
    assert data.sections == ["ca", "dc", "web"] and data.domain.sid == export.domain.sid and data.collector.version == "2.0"
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
    -SkipSysvol; пропуск SYSVOL и отказ чтения CN=OID попадают в collector.notes."""
    console, out = _run_collector(tmp_path, web_server, ("-SkipSysvol", "-OutputPath", "/out/old.json.gz"),
                                  env_extra={"STUB_DENY": "CN=OID"}, timeout=120)
    assert "Выбор" not in console and "Продолжить?" not in console and "Сбор прерван" not in console, console
    assert sorted(p.name for p in out.iterdir()) == ["old.json.gz"]
    export = load_export((out / "old.json.gz").read_bytes())
    assert export.sysvol == {}
    assert export.collector.notes[0] == SKIP_SYSVOL_NOTE
    assert [n for n in export.collector.notes if n.startswith("политики выдачи (CN=OID): ")], export.collector.notes
    assert not [o for o in export.objects if o.cls == "msPKI-Enterprise-Oid"]


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
