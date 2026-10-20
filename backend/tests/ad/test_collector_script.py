"""Сборщик AD 2.4: раздача, поля, которые читают модели, меню и чистые функции скрипта в контейнере PowerShell.

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

from api.modules.ad.core import gpo_files as g
from api.modules.ad.core import sd
from api.modules.ad.core.ca_data import parse_ca_data
from api.modules.ad.core.checks import run_all
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import (
    CRITICAL_ACL_UNREAD,
    CRITICAL_BUILTIN_RIDS,
    CRITICAL_GROUP_NAMES,
    CRITICAL_GROUP_RIDS,
    ExportIndex,
    load_export,
)
from api.modules.ad.core.ldap_collector import CA_STORES
from tests.ad.gpo_fixtures import AUDIT_CSV, GROUPS, LSA, WINLOGON, dword, preg, sz
from tests.ad.synthetic import make_cert

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
                 "strong_binding", "mapping_methods", "StrongCertificateBindingEnforcement", "CertificateMappingMethods",
                 # Сертификаты ЦС (сборщик 2.4) — те же хранилища и поля, что у LDAP-сборщика 1.3.
                 "cACertificate", "certificationAuthority", "store", "function CertList",
                 *(f'"{c}" = "{s}"' for c, s in CA_STORES.items())):
        assert name in text, name


def test_script_writes_dc_state_fields() -> None:
    """Состояние контроллеров (раздел dc сборщика 2.3): поля DcBinding, ключи реестра и классы CIM."""
    text = SCRIPT.read_text(encoding="utf-8-sig")
    for name in ("lm_compatibility", "no_lm_hash", "ldap_integrity", "ldap_channel_binding", "tls", "smb1", "smb_require_signing",
                 "spooler", "webclient", "last_boot", "os_build", "registry_read", "cim_read",
                 "LmCompatibilityLevel", "NoLMHash", "LDAPServerIntegrity", "LdapEnforceChannelBinding",
                 "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols", '"SSL 3.0", "TLS 1.0", "TLS 1.1"',
                 "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuildNumber", "UBR",
                 "MSFT_SmbServerConfiguration", "EnableSMB1Protocol", "RequireSecuritySignature", "Win32_Service",
                 "Win32_OperatingSystem", "LastBootUpTime", "New-CimSessionOption -Protocol Dcom", "Remove-CimSession"):
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
                 "PSO не найдены: при сборе не администратором домена они не видны",
                 "1.2.840.113556.1.4.1941", "critical_acl = $true", "-ResultSetSize ($CriticalMembersLimit + 1)",
                 # Списки критичных объектов и пометка об отказе — те же, что в контракте выгрузки (export.py).
                 f"$CriticalGroupRids = @({', '.join(map(str, CRITICAL_GROUP_RIDS))})",
                 f"$CriticalBuiltinRids = @({', '.join(map(str, CRITICAL_BUILTIN_RIDS))})",
                 f"$CriticalGroupNames = @({', '.join(f'{chr(34)}{n}{chr(34)}' for n in CRITICAL_GROUP_NAMES)})",
                 f'"{CRITICAL_ACL_UNREAD} (участники', f'"{CRITICAL_ACL_UNREAD} у части участников'):
        assert name in text, name


def test_script_never_requests_password_values() -> None:
    """Unix-пароли: только наличие по LDAP-фильтру, сами значения не запрашиваются."""
    text = SCRIPT.read_text(encoding="utf-8-sig")
    flt = "(|(userPassword=*)(unixUserPassword=*))"
    assert flt in text
    assert "userpassword" not in text.replace(flt, "").lower()


def test_script_writes_gpo_fields() -> None:
    """Блок gpo — те же поля, что у LDAP-сборщика 1.2, плюс acl; список файлов и потолок — как в gpo_files."""
    text = SCRIPT.read_text(encoding="utf-8-sig")
    for name in ("gpLink", "gpOptions", "flags", "registry", "gpp", "audit", "scripts", "acl", "writers", "notes",
                 "cpassword", "members", "group_sid", "group_name", "subcategory", "setting", "phase", "command", "parameters",
                 "function Read-RegistryPol", "function Test-KeepRegistry", "function Protect-RegistryValue", "function Read-GppFile",
                 "function Read-AuditCsv", "function Read-ScriptsIni", "function Get-PathWriters",
                 "права SYSVOL не прочитаны", "$MaxGpoFile = 4 * 1024 * 1024"):
        assert name in text, name
    assert g.MAX_GPO_FILE == 4 * 1024 * 1024
    for name, rel in g.GPO_FILES.items():
        assert f'"{name}" = "{rel}"' in text, name


def _script_whitelist() -> dict[str, frozenset[str] | None]:
    """Таблица белого списка из Test-KeepRegistry: ключ (нижний регистр) → имена значений, None — все."""
    text = SCRIPT.read_text(encoding="utf-8-sig")
    fn = text[text.index("function Test-KeepRegistry("):]
    start = fn.index("$keep = @{") + len("$keep = @{")
    table = fn[start:fn.index("\n  }\n", start)]
    out: dict[str, frozenset[str] | None] = {}
    for key, names in re.findall(r'^\s*"([^"]+)" = (\$null|@\([^)]*\))\s*$', table, re.MULTILINE):
        assert key.lower() not in out, key
        out[key.lower()] = None if names == "$null" else frozenset(n.lower() for n in re.findall(r'"([^"]+)"', names))
    assert len(out) == table.count(" = "), table
    return out


def test_script_whitelist_equals_python() -> None:
    """Белый список скрипта и gpo_files._KEEP совпадают в обе стороны: те же ключи и те же имена значений."""
    assert _script_whitelist() == g._KEEP


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
                 "6  Контроллеры домена: реестр, службы, SMB", "7  Данные ЦС: проверка веб-выдачи"):
        assert line in text


def test_script_keeps_bom_version_and_module_requirement() -> None:
    raw = SCRIPT.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8-sig")
    assert "#requires -Modules ActiveDirectory" in text and '$CollectorVersion = "2.4"' in text


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
def test_cert_list_encodes_each_value(tmp_path: Path) -> None:
    """cACertificate: модуль отдаёт byte[] на значение, а одно значение может прийти и самим byte[]."""
    body = """
$a = [byte[]](1, 2, 3); $b = [byte[]](4, 5)
[ordered]@{
  none = CertList $null; one = CertList $a; wrapped = CertList @(,$a); two = CertList @($a, $b)
} | ConvertTo-Json -Compress
"""
    out = _pwsh(tmp_path, body, ("CertList",))
    one, two = base64.b64encode(b"\x01\x02\x03").decode(), base64.b64encode(b"\x04\x05").decode()
    assert out == {"none": [], "one": [one], "wrapped": [one], "two": [one, two]}


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
  filter = Format-LdapFilterValue 'CN=a\\, b (x)*,DC=c'
  filter_empty = Format-LdapFilterValue ""
}} | ConvertTo-Json -Compress
"""
    out = _pwsh(tmp_path, body, ("Get-LastBackup", "Get-DnsAllowUpdate", "Get-DnBinaryDn", "Format-LdapFilterValue"))
    assert out == {
        "backup": "2026-09-01T10:20:30Z", "backup_nul": "2026-09-01T10:20:30Z", "backup_none": None, "backup_null": None,
        "update": 1, "update_none": None, "update_short": None, "update_null": None,
        "dn": "CN=a:b,CN=Users,DC=corp,DC=local", "dn_plain": "CN=alice,CN=Users,DC=corp,DC=local",
        "filter": "CN=a\\5c, b \\28x\\29\\2a,DC=c", "filter_empty": "",
    }


POLICY_X = "Software\\Policies\\X"
#: Случаи Registry.pol: те же, что в test_gpo_files, и края типов данных.
REGISTRY_POL_CASES = {
    "types": preg((LSA, "LmCompatibilityLevel", 4, dword(2)), (WINLOGON, "DefaultUserName", 1, sz("svc;odd]name")),
                  (POLICY_X, "**del.Old", 1, sz(" ")), (POLICY_X, "List", 7, "a\x00b\x00\x00".encode("utf-16-le"))),
    "edges": preg((POLICY_X, "Exp", 2, sz("%SystemRoot%\\x")), (POLICY_X, "Bin", 3, b"\x01\x02"), (POLICY_X, "ShortDword", 4, b"\x01"),
                  (POLICY_X, "One", 7, "solo\x00\x00".encode("utf-16-le")), (POLICY_X, "Empty", 7, b"\x00\x00"),
                  (POLICY_X, "**delvals.", 1, sz(" ")), (WINLOGON, "DefaultPassword", 1, sz("P@ssw0rd"))),
    "header_only": preg(),
}
REGISTRY_POL_BAD = {
    "garbage": b"not a policy file",
    "truncated": preg((LSA, "NoLMHash", 4, dword(1)))[:-6],
    "version": b"PReg" + struct.pack("<I", 2),
    "no_close": preg((LSA, "NoLMHash", 4, dword(1)))[:-2] + "x".encode("utf-16-le"),
}


def _registry_dicts(data: bytes) -> list[dict[str, Any]]:
    return [{"key": v.key, "value": v.value, "type": v.type, "data": v.data} for v in g.parse_registry_pol(data)]


def _keep_cases() -> list[tuple[str, str, bool]]:
    """Пары (ключ, значение) белого списка gpo_files — в разном регистре — и пары вне его."""
    cases: list[tuple[str, str, bool]] = []
    for i, (key, names) in enumerate(g._KEEP.items()):
        shown = key.upper() if i % 2 else f"\\{key}\\"
        if names is None:
            cases.append((shown, "\\\\*\\SYSVOL", True))
            continue
        cases.extend((shown, n.upper() if i % 3 else n, True) for n in sorted(names))
        cases.append((key, "NotListed", False))
    cases += [("Software\\Vendor\\App", "Secret", False), (f"{LSA}\\Sub", "NoLMHash", False)]
    for key, value, want in cases:
        assert g.keep_registry(key, value) is want, (key, value)
    return cases


@needs_pwsh
def test_registry_pol_whitelist_and_redaction_match_python(tmp_path: Path) -> None:
    """Read-RegistryPol, Test-KeepRegistry и Protect-RegistryValue отвечают так же, что parse_registry_pol, keep_registry и redact."""
    cases = _keep_cases()
    (tmp_path / "cases.json").write_text(json.dumps({
        "ok": {k: base64.b64encode(v).decode() for k, v in REGISTRY_POL_CASES.items()},
        "bad": {k: base64.b64encode(v).decode() for k, v in REGISTRY_POL_BAD.items()},
        "keep": [[k, v] for k, v, _ in cases],
    }), encoding="utf-8")
    body = r"""
$c = Get-Content /t/cases.json -Raw | ConvertFrom-Json
$ok = [ordered]@{}
foreach ($p in $c.ok.PSObject.Properties) { $ok[$p.Name] = @(Read-RegistryPol ([Convert]::FromBase64String($p.Value))) }
$bad = [ordered]@{}
foreach ($p in $c.bad.PSObject.Properties) {
  try { Read-RegistryPol ([Convert]::FromBase64String($p.Value)) | Out-Null; $bad[$p.Name] = "" } catch { $bad[$p.Name] = $_.Exception.Message }
}
$keep = @(foreach ($pair in $c.keep) { [bool](Test-KeepRegistry $pair[0] $pair[1]) })
$redacted = New-Object System.Collections.Generic.List[object]
foreach ($v in @(Read-RegistryPol ([Convert]::FromBase64String($c.ok.edges)))) { $redacted.Add((Protect-RegistryValue $v).data) }
[ordered]@{ ok = $ok; bad = $bad; keep = $keep; redacted = $redacted } | ConvertTo-Json -Compress -Depth 6
"""
    out = _pwsh(tmp_path, body, ("Read-RegistryPol", "Test-KeepRegistry", "Protect-RegistryValue"))
    assert out["ok"] == {k: _registry_dicts(v) for k, v in REGISTRY_POL_CASES.items()}
    for name, message in out["bad"].items():
        with pytest.raises(ValueError):
            g.parse_registry_pol(REGISTRY_POL_BAD[name])
        assert re.search(r"[а-яё]", message.lower()), (name, message)
    assert out["keep"] == [want for _, _, want in cases]
    edges = g.parse_registry_pol(REGISTRY_POL_CASES["edges"])
    assert out["redacted"] == [g.redact(v).data for v in edges] and out["redacted"][-1] == ""


GPP_BAD = {
    "doctype": '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><Groups/>',
    "doctype_case": '<?xml version="1.0"?><!doctype x><Groups/>',
    "broken": "<Groups><User>",
}
SCRIPTS_INIS = {
    "task11": "[Logon]\r\n0CmdLine=\\\\fs01.other.local\\share\\run.bat\r\n0Parameters=/q\r\n[Logoff]\r\n",
    "mixed": "﻿; comment\r\n[Startup]\r\n1CmdLine = second.ps1\r\n0cmdline=first.bat\r\n0Parameters = -a=b\r\n2CmdLine=\r\n"
             "[Other]\r\n0CmdLine=skip.bat\r\n[SHUTDOWN]\r\nnoequals\r\n10CmdLine=ten.bat\r\n",
}
AUDIT_CASES = {
    "fixture": AUDIT_CSV,
    "options": "﻿" + AUDIT_CSV + ",System,Option:CrashOnAuditFail,,Disabled,,0\r\n,System,IPsec Driver,{0cce9213-69ae-11d9-bed3-505054503030},No Auditing,,x\r\n",
    "empty": "",
}


@needs_pwsh
def test_gpp_audit_and_scripts_parsers_match_python(tmp_path: Path) -> None:
    """Read-GppFile на GROUPS — те же записи, что parse_gpp, и без значения cpassword; Read-AuditCsv и
    Read-ScriptsIni — те же ответы, что parse_audit_csv и parse_scripts_ini."""
    (tmp_path / "cases.json").write_text(json.dumps({
        "groups": GROUPS, "gpp_bad": GPP_BAD, "audit": AUDIT_CASES, "ini": SCRIPTS_INIS,
        "audit_bad": "Machine Name,Subcategory\r\n,x\r\n",
    }), encoding="utf-8")
    body = r"""
$c = Get-Content /t/cases.json -Raw | ConvertFrom-Json
$gppBad = [ordered]@{}
foreach ($p in $c.gpp_bad.PSObject.Properties) {
  try { Read-GppFile "Groups.xml" "machine" $p.Value | Out-Null; $gppBad[$p.Name] = "" } catch { $gppBad[$p.Name] = $_.Exception.Message }
}
$audit = [ordered]@{}
foreach ($p in $c.audit.PSObject.Properties) { $audit[$p.Name] = @(Read-AuditCsv $p.Value) }
try { Read-AuditCsv $c.audit_bad | Out-Null; $auditBad = "" } catch { $auditBad = $_.Exception.Message }
$ini = [ordered]@{}
foreach ($p in $c.ini.PSObject.Properties) { $ini[$p.Name] = @(Read-ScriptsIni $p.Value "user") }
[ordered]@{
  gpp = @(Read-GppFile "Groups.xml" "machine" $c.groups); gpp_bad = $gppBad; audit = $audit; audit_bad = $auditBad; ini = $ini
} | ConvertTo-Json -Compress -Depth 8
"""
    out = _pwsh(tmp_path, body, ("Read-GppFile", "Read-AuditCsv", "Read-ScriptsIni"))
    assert out["gpp"] == g.parse_gpp("Groups.xml", "machine", GROUPS)
    assert out["gpp"][0]["cpassword"] is True and "j1Uyj3Vx8TY9" not in json.dumps(out)
    for name, message in out["gpp_bad"].items():
        with pytest.raises(ValueError):
            g.parse_gpp("Groups.xml", "machine", GPP_BAD[name])
        assert message.startswith("Groups.xml: "), (name, message)
    assert out["audit"] == {k: g.parse_audit_csv(v) for k, v in AUDIT_CASES.items()}
    with pytest.raises(ValueError):
        g.parse_audit_csv("Machine Name,Subcategory\r\n,x\r\n")
    assert out["audit_bad"].startswith("audit.csv")
    assert out["ini"] == {k: g.parse_scripts_ini(v, "user") for k, v in SCRIPTS_INIS.items()}


#: Подделка Get-Acl (в Linux командлета нет): владелец — Domain Admins; у файла run.bat ещё и запись
#: Authenticated Users; файл locked.bat не отдаёт права. Правила — как у FileSystemSecurity.GetAccessRules
#: с типом SecurityIdentifier.
FAKE_GET_ACL = r"""
function Get-Acl {
  [CmdletBinding()] param([string]$LiteralPath, [string]$Path)
  if ($LiteralPath -like "*locked.bat") { throw [System.UnauthorizedAccessException]::new("Access is denied") }
  $fsr = [System.Security.AccessControl.FileSystemRights]
  $none = [System.Security.AccessControl.PropagationFlags]::None
  $rules = @(
    @("S-1-5-21-1-2-3-512", $fsr::FullControl, "Allow", $none),
    @("S-1-5-18", $fsr::FullControl, "Allow", $none),
    @("S-1-5-21-1-2-3-1106", $fsr::Modify, "Allow", $none),
    @("S-1-5-21-1-2-3-1106", $fsr::Write, "Allow", $none),
    @("S-1-5-21-1-2-3-1301", [System.Security.AccessControl.FileSystemRights]0x40000, "Allow", $none),
    @("S-1-5-11", $fsr::ReadAndExecute, "Allow", $none),
    @("S-1-1-0", $fsr::Write, "Deny", $none),
    # Общие права (GENERIC_ALL, GENERIC_WRITE) PowerShell в перечисление не приводит — здесь они числом.
    @("S-1-3-0", 0x10000000, "Allow", [System.Security.AccessControl.PropagationFlags]::InheritOnly),
    @("S-1-5-21-1-2-3-1302", 0x40000000, "Allow", $none)
  )
  if ($LiteralPath -like "*run.bat") { $rules += ,@("S-1-5-11", $fsr::Write, "Allow", $none) }
  $acl = [pscustomobject]@{ Rules = @(foreach ($r in $rules) {
    [pscustomobject]@{ IdentityReference = [pscustomobject]@{ Value = $r[0] }; FileSystemRights = $r[1]
      AccessControlType = [System.Security.AccessControl.AccessControlType]$r[2]; PropagationFlags = $r[3] } }) }
  $acl | Add-Member ScriptMethod GetAccessRules { param($explicit, $inherited, $type) $this.Rules }
  $acl | Add-Member ScriptMethod GetOwner { param($type) [pscustomobject]@{ Value = "S-1-5-21-1-2-3-512" } }
  $acl
}
"""
#: Удалённый реестр контроллера dc01.corp.local (в Linux его нет; другие серверы недоступны). Псевдоним
#: сильнее функции сборщика с тем же именем — так подделка подменяет Read-RemoteRegistry во всём скрипте.
FAKE_DC_REGISTRY = r"""
function Read-FakeRegistry([string]$computer, [string]$path, [string[]]$names) {
  if ($computer -ne "dc01.corp.local") { throw [System.IO.IOException]::new("The network path was not found.") }
  $keys = @{
    "SYSTEM\CurrentControlSet\Services\Kdc" = @{ StrongCertificateBindingEnforcement = 1 }
    "SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel" = @{ CertificateMappingMethods = 0x1F }
    "SYSTEM\CurrentControlSet\Control\Lsa" = @{ LmCompatibilityLevel = 3 }
    "SYSTEM\CurrentControlSet\Services\NTDS\Parameters" = @{ LDAPServerIntegrity = 1; LdapEnforceChannelBinding = 0 }
    "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" = @{ Enabled = -1 }
    "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" = @{ Enabled = 0 }
    "SOFTWARE\Microsoft\Windows NT\CurrentVersion" = @{ CurrentBuildNumber = "17763"; UBR = 6189 }
  }
  if (-not $keys.ContainsKey($path)) { return $null }
  $values = @{}
  foreach ($n in $names) { $values[$n] = $keys[$path][$n] }
  return $values
}
Set-Alias -Name Read-RemoteRegistry -Value Read-FakeRegistry
"""
#: CIM контроллера (в Linux командлетов нет): WSMan закрыт, сессия открывается по DCOM.
FAKE_CIM = r"""
function New-CimSessionOption { [CmdletBinding()] param([string]$Protocol) [pscustomobject]@{ Protocol = $Protocol } }
function New-CimSession {
  [CmdletBinding()] param([string[]]$ComputerName, [uint32]$OperationTimeoutSec, $SessionOption)
  if ($null -eq $SessionOption) { throw "WinRM cannot complete the operation." }
  [pscustomobject]@{ ComputerName = $ComputerName[0]; Protocol = $SessionOption.Protocol }
}
function Get-CimInstance {
  [CmdletBinding()] param($CimSession, [string]$Namespace, [string]$ClassName, [string]$Filter)
  if ($CimSession.Protocol -ne "Dcom") { throw "сессия не по DCOM" }
  switch ($ClassName) {
    "MSFT_SmbServerConfiguration" { [pscustomobject]@{ EnableSMB1Protocol = $true; RequireSecuritySignature = $false } }
    "Win32_Service" { [pscustomobject]@{ Name = "Spooler"; StartMode = "Auto"; State = "Running" } }
    "Win32_OperatingSystem" { [pscustomobject]@{ LastBootUpTime = [datetime]::new(2026, 3, 1, 4, 5, 6, [DateTimeKind]::Utc) } }
    default { throw "Invalid class $ClassName" }
  }
}
function Remove-CimSession { [CmdletBinding()] param($CimSession) }
"""
#: Кто, кроме владельца, может писать по FAKE_GET_ACL: SYSTEM, bob (Modify), S-1-5-21-1-2-3-1301 (смена прав)
#: и S-1-5-21-1-2-3-1302 (GENERIC_WRITE).
FAKE_WRITERS = ["S-1-5-18", "S-1-5-21-1-2-3-1106", "S-1-5-21-1-2-3-1301", "S-1-5-21-1-2-3-1302"]


@needs_pwsh
def test_path_writers_from_acl(tmp_path: Path) -> None:
    """Get-PathWriters: разрешающие записи с правом записи (Write, Modify, FullControl, смена прав или владельца,
    общие права), без запрещающих, без только наследуемых, без владельца, без повторов."""
    body = FAKE_GET_ACL + r"""
[ordered]@{ folder = @(Get-PathWriters "/x/gpo"); script = @(Get-PathWriters "/x/gpo/User/Scripts/Logon/run.bat") } | ConvertTo-Json -Compress
"""
    out = _pwsh(tmp_path, body, ("Get-PathWriters",))
    assert out == {"folder": FAKE_WRITERS, "script": [*FAKE_WRITERS, "S-1-5-11"]}


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


@needs_pwsh
def test_convert_to_service_state(tmp_path: Path) -> None:
    body = """
$cases = [ordered]@{
  absent = $null
  disabled = [pscustomobject]@{ Name = "Spooler"; StartMode = "Disabled"; State = "Stopped" }
  running = [pscustomobject]@{ Name = "Spooler"; StartMode = "Auto"; State = "Running" }
  disabled_running = [pscustomobject]@{ Name = "Spooler"; StartMode = "Disabled"; State = "Running" }
  stopped = [pscustomobject]@{ Name = "WebClient"; StartMode = "Manual"; State = "Stopped" }
}
$r = [ordered]@{}
foreach ($k in @($cases.Keys)) { $r[$k] = ConvertTo-ServiceState $cases[$k] }
$r | ConvertTo-Json -Compress
"""
    out = _pwsh(tmp_path, body, ("ConvertTo-ServiceState",))
    # Запуск отключён, а служба работает до перезагрузки — running.
    assert out == {"absent": "absent", "disabled": "disabled", "running": "running", "disabled_running": "running", "stopped": "stopped"}


#: Состояние контроллера без домена: реестр и CIM — подделки в теле пробы (в Linux их нет).
DC_STATE_PROBE = r"""
$global:Removed = 0
function Read-RemoteRegistry([string]$computer, [string]$path, [string[]]$names) {
  if ($computer -eq "dc02.corp.local") { throw [System.UnauthorizedAccessException]::new("Access is denied.") }
  $keys = @{
    "SYSTEM\CurrentControlSet\Services\Kdc" = @{ StrongCertificateBindingEnforcement = 2 }
    "SYSTEM\CurrentControlSet\Control\Lsa" = @{ LmCompatibilityLevel = 5; NoLMHash = 1 }
    "SYSTEM\CurrentControlSet\Services\NTDS\Parameters" = @{ LDAPServerIntegrity = 2 }
    "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" = @{ Enabled = 0 }
    "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" = @{ }
    "SOFTWARE\Microsoft\Windows NT\CurrentVersion" = @{ CurrentBuildNumber = "20348"; UBR = 2340 }
  }
  if (-not $keys.ContainsKey($path)) { return $null }
  $values = @{}
  foreach ($n in $names) { $values[$n] = $keys[$path][$n] }
  return $values
}
function New-CimSessionOption([string]$Protocol) { [pscustomobject]@{ Protocol = $Protocol } }
function New-CimSession([string]$ComputerName, [uint32]$OperationTimeoutSec, $SessionOption) {
  [pscustomobject]@{ ComputerName = $ComputerName }
}
function Get-CimInstance($CimSession, [string]$Namespace, [string]$ClassName, [string]$Filter) {
  if ($ClassName -eq "MSFT_SmbServerConfiguration") { throw "Invalid namespace" }
  if ($ClassName -eq "Win32_Service") {
    return @([pscustomobject]@{ Name = "Spooler"; StartMode = "Auto"; State = "Running" },
             [pscustomobject]@{ Name = "WebClient"; StartMode = "Disabled"; State = "Stopped" })
  }
  [pscustomobject]@{ LastBootUpTime = [datetime]::new(2026, 3, 1, 4, 5, 6, [DateTimeKind]::Utc) }
}
function Remove-CimSession($CimSession) { $global:Removed++ }
$ok = Get-DcState "dc01.corp.local"
$removedAfterOk = $global:Removed
# У второго контроллера реестр отказал, а командлетов CIM нет вовсе (как в Linux).
Remove-Item function:New-CimSession, function:New-CimSessionOption, function:Get-CimInstance, function:Remove-CimSession
$denied = Get-DcState "dc02.corp.local"
[ordered]@{ ok = $ok; denied = $denied; removed = $removedAfterOk } | ConvertTo-Json -Compress -Depth 4
"""


@needs_pwsh
def test_dc_state_reads_registry_and_cim_and_names_failures(tmp_path: Path) -> None:
    out = _pwsh(tmp_path, DC_STATE_PROBE, ("Get-DcState", "ConvertTo-ServiceState", "AsDword", "AsBool", "ErrorText", "IsoTime"))
    ok, denied = out["ok"], out["denied"]
    # Реестр прочитан: значения, которых нет, — null (раздела Schannel и SSL 3.0 нет, у TLS 1.1 нет Enabled).
    assert (ok["strong_binding"], ok["mapping_methods"], ok["lm_compatibility"], ok["no_lm_hash"]) == (2, None, 5, 1)
    assert (ok["ldap_integrity"], ok["ldap_channel_binding"], ok["os_build"]) == (2, None, "20348.2340")
    assert ok["tls"] == {"SSL 3.0": None, "TLS 1.0": 0, "TLS 1.1": None}
    # CIM: сессия открыта; класс SMB не прочитан — его поля null, причина в error; сессия закрыта.
    assert (ok["registry_read"], ok["cim_read"], ok["smb1"], ok["smb_require_signing"]) == (True, True, None, None)
    assert (ok["spooler"], ok["webclient"], ok["last_boot"]) == ("running", "disabled", "2026-03-01T04:05:06Z")
    assert ok["error"].startswith("SMB: ") and "Invalid namespace" in ok["error"] and out["removed"] == 1
    assert (denied["registry_read"], denied["cim_read"], denied["tls"], denied["os_build"], denied["spooler"]) == (False, False, None, None, None)
    reasons = denied["error"].split("; ")
    assert reasons[0] == "реестр: Access is denied." and reasons[1].startswith("CIM: "), denied["error"]
    assert parse_ca_data({"format": "stools-ad-ca/1", "collected_at": "2026-10-01T00:00:00Z", "domain": {"sid": "S-1-5-21-1-2-3"},
                          "sections": ["dc"], "dcs": [ok, denied]}).dcs[0].tls == ok["tls"]


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
# Дескриптор безопасности — байты: ToBase64Sd сборщика принимает и их.
$sdBytes = [Convert]::FromBase64String($env:STUB_SD)
$certBytes = [Convert]::FromBase64String($env:STUB_CERT)
$weakBytes = [Convert]::FromBase64String($env:STUB_WEAK_CERT)
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
     "msDS-ExpirePasswordsOnSmartCardOnlyAccounts" = $true; gPLink = "[LDAP://CN={11111111-2222-3333-4444-555555555555},CN=Policies,CN=System,$Dom;0]"; gPOptions = 0 }
  @{ dn = "CN=AdminSDHolder,CN=System,$Dom"; cls = @("container") }
  @{ dn = "CN=Certificate-Enrollment,CN=Extended-Rights,$Conf"; cls = @("controlAccessRight"); displayName = "Enroll"; rightsGuid = "0e10c968-78fb-11d2-90d4-00c04f79dc55" }
  @{ dn = "CN=alice,CN=Users,$Dom"; cls = @("person", "user"); sAMAccountName = "alice"; objectSid = (Sid "$Base-1104"); userAccountControl = 512
     altSecurityIdentities = @("X509:<I>DC=local,DC=corp,CN=CORP-CA<S>CN=alice"); primaryGroupID = 513; sIDHistory = @((Sid "S-1-5-21-9-9-9-1104"))
     whenCreated = $Created; scriptPath = "logon.bat"; userPassword = "not-for-export"; nTSecurityDescriptor = $sdBytes }
  @{ dn = "CN=bob,CN=Users,$Dom"; cls = @("person", "user"); sAMAccountName = "bob"; objectSid = (Sid "$Base-1106"); userAccountControl = 512; primaryGroupID = 513
     nTSecurityDescriptor = $sdBytes }
  @{ dn = "CN=CA01,OU=Servers,$Dom"; cls = @("computer"); sAMAccountName = "CA01$"; objectSid = (Sid "$Base-1105"); userAccountControl = 4096
     dNSHostName = $Web; OperatingSystemVersion = "10.0 (17763)"; primaryGroupID = 515; whenCreated = $Created
     "ms-Mcs-AdmPwdExpirationTime" = [int64]134000000000000000; "msLAPS-PasswordExpirationTime" = [int64]134100000000000000; "ms-DS-CreatorSID" = $creatorBytes }
  @{ dn = "CN=RODC01,OU=Domain Controllers,$Dom"; cls = @("computer"); sAMAccountName = "RODC01$"; objectSid = (Sid "$Base-1107"); userAccountControl = 0x4001000
     primaryGroupID = 521; "msDS-RevealOnDemandGroup" = @("CN=Allowed RODC Password Replication Group,CN=Users,$Dom")
     "msDS-NeverRevealGroup" = @("CN=Denied RODC Password Replication Group,CN=Users,$Dom")
     "msDS-RevealedUsers" = @("B:8:00000001:CN=alice,CN=Users,$Dom", "B:8:00000002:CN=alice,CN=Users,$Dom", "B:8:00000001:CN=a:b,CN=Users,$Dom")
     "msDS-KrbTgtLink" = "CN=krbtgt_10001,CN=Users,$Dom" }
  @{ dn = "CN=Domain Admins,CN=Users,$Dom"; cls = @("group"); sAMAccountName = "Domain Admins"; objectSid = (Sid "$Base-512"); member = @("CN=Tier0,CN=Users,$Dom")
     nTSecurityDescriptor = $sdBytes }
  @{ dn = "CN=Tier0,CN=Users,$Dom"; cls = @("group"); sAMAccountName = "Tier0"; objectSid = (Sid "$Base-1301"); member = @("CN=alice,CN=Users,$Dom")
     nTSecurityDescriptor = $sdBytes }
  @{ dn = "OU=Servers,$Dom"; cls = @("organizationalUnit"); gPLink = "[LDAP://CN={11111111-2222-3333-4444-555555555555},CN=Policies,CN=System,$Dom;2]"; gPOptions = 1 }
  @{ dn = "CN={11111111-2222-3333-4444-555555555555},CN=Policies,CN=System,$Dom"; cls = @("groupPolicyContainer"); displayName = "Default"; gPCFileSysPath = $env:STUB_GPO; flags = 0 }
  # Папки второй GPO в SYSVOL нет.
  @{ dn = "CN={22222222-2222-3333-4444-555555555555},CN=Policies,CN=System,$Dom"; cls = @("groupPolicyContainer"); displayName = "Gone"
     gPCFileSysPath = ($env:STUB_GPO + "-missing"); flags = 2 }
  @{ dn = "CN=VulnTemplate,CN=Certificate Templates,$Pki"; cls = @("pKICertificateTemplate"); cn = "VulnTemplate"; displayName = "Vuln Template"
     pKIExtendedKeyUsage = @("1.3.6.1.5.5.7.3.2"); "msPKI-Certificate-Name-Flag" = 1; "msPKI-Enrollment-Flag" = 0; "msPKI-RA-Signature" = 0
     "msPKI-Template-Schema-Version" = 2; "msPKI-Certificate-Policy" = @("1.3.6.1.4.1.311.21.8.1.1"); "msPKI-Cert-Template-OID" = "1.3.6.1.4.1.311.21.8.9" }
  @{ dn = $Pki; cls = @("container") }
  @{ dn = "CN=Certificate Templates,$Pki"; cls = @("container") }
  @{ dn = "CN=Enrollment Services,$Pki"; cls = @("container") }
  @{ dn = "CN=NTAuthCertificates,$Pki"; cls = @("certificationAuthority"); cACertificate = @(,$certBytes) }
  @{ dn = "CN=CORP-ROOT,CN=Certification Authorities,$Pki"; cls = @("certificationAuthority"); cn = "CORP-ROOT"; cACertificate = @(,$certBytes) }
  @{ dn = "CN=CORP-SUB,CN=AIA,$Pki"; cls = @("certificationAuthority"); cn = "CORP-SUB"; cACertificate = @($certBytes, $weakBytes) }
  @{ dn = "CN=OID,$Pki"; cls = @("msPKI-Enterprise-Oid") }
  @{ dn = "CN=1.2345,CN=OID,$Pki"; cls = @("msPKI-Enterprise-Oid"); displayName = "Corp Policy"; "msPKI-Cert-Template-OID" = "1.3.6.1.4.1.311.21.8.1.1"
     "msDS-OIDToGroupLink" = "CN=Domain Admins,CN=Users,$Dom" }
  @{ dn = "CN=CORP-CA,CN=Enrollment Services,$Pki"; cls = @("pKIEnrollmentService"); cn = "CORP-CA"; dNSHostName = $Web
     certificateTemplates = @("VulnTemplate"); "msPKI-Enrollment-Servers" = @("1`n4`n0`nhttp://$Web/ntlm/"); cACertificate = $certBytes }
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
  # Разделы каталога: STUB_NO_PARTITION — раздела DNS с таким именем нет (DNS не интегрирован с AD).
  @{ dn = "CN=CORP,CN=Partitions,$Conf"; cls = @("crossRef"); nCName = $Dom }
  @{ dn = "CN=d1,CN=Partitions,$Conf"; cls = @("crossRef"); nCName = "DC=DomainDnsZones,$Dom" }
  @{ dn = "CN=f1,CN=Partitions,$Conf"; cls = @("crossRef"); nCName = "DC=ForestDnsZones,$Dom" }
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
# STUB_EVIL_GPO — ещё одна GPO, папка которой указывает на сервер вне домена.
if ($env:STUB_EVIL_GPO) {
  $Objects += @{ dn = "CN={33333333-2222-3333-4444-555555555555},CN=Policies,CN=System,$Dom"; cls = @("groupPolicyContainer"); displayName = "Evil"
                 gPCFileSysPath = $env:STUB_EVIL_GPO; flags = 0 }
}
# STUB_NO_CROSSREF — список разделов пуст (crossRef не видны).
if ($env:STUB_NO_CROSSREF) { $Objects = @($Objects | Where-Object { $_.cls -notcontains "crossRef" }) }
if ($env:STUB_NO_PARTITION) {
  $gone = "DC=$($env:STUB_NO_PARTITION),"
  $Objects = @($Objects | Where-Object { -not $_.dn.Contains($gone) -and -not ($_.ContainsKey("nCName") -and $_.nCName.StartsWith($gone)) })
}

function New-AdEntity($row, [string[]]$props) {
  $o = [ordered]@{ DistinguishedName = $row.dn; Name = ($row.dn -replace '^[A-Za-z]+=([^,]+),.*$', '$1') }
  # Значение кладётся как есть: $(...) развернул бы byte[] и списки, а модуль отдаёт их целиком.
  foreach ($p in $props) { if (-not $o.Contains($p)) { if ($row.ContainsKey($p)) { $o[$p] = $row[$p] } else { $o[$p] = $null } } }
  [pscustomobject]$o
}

# Правило LDAP_MATCHING_RULE_IN_CHAIN: строка — прямой или вложенный член группы.
function Test-InChain($row, [string]$group) {
  $seen = @{}
  $stack = New-Object System.Collections.Stack
  $stack.Push($group)
  while ($stack.Count) {
    $dn = $stack.Pop()
    if ($seen.ContainsKey($dn)) { continue }
    $seen[$dn] = $true
    $g = @($Objects | Where-Object { $_.dn -eq $dn })
    if (-not $g -or -not $g[0].ContainsKey("member")) { continue }
    foreach ($m in $g[0].member) { if ($m -eq $row.dn) { return $true }; $stack.Push($m) }
  }
  return $false
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
  if ($filter -match '^\(memberOf:1\.2\.840\.113556\.1\.4\.1941:=(.+)\)$') {
    return Test-InChain $row ([regex]::Replace($Matches[1], '\\([0-9a-f]{2})', { param($m) [string][char][Convert]::ToInt32($m.Groups[1].Value, 16) }))
  }
  if ($filter -eq "(objectClass=*)") { return $true }
  if ($filter -match '^\(objectClass=([^)]+)\)$') { return $row.cls -contains $Matches[1] }
  if ($filter -match '^\(([^=]+)=([^)]+)\)$') { return $row.ContainsKey($Matches[1]) -and $row[$Matches[1]] -eq $Matches[2] }
  return $false
}

function Get-ADObject {
  [CmdletBinding()]
  param([string]$Identity, [string]$SearchBase, [string]$LDAPFilter, [object[]]$Properties, [string]$SearchScope = "Subtree", [string]$Server,
        [int]$ResultSetSize = 0)
  $props = @($Properties | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
  # STUB_DENY — начала баз поиска через «;», чтение которых запрещено (как отказ доступа в настоящем домене).
  foreach ($deny in @(([string]$env:STUB_DENY) -split ';' | Where-Object { $_ })) {
    if ($SearchBase.StartsWith("$deny,")) {
      $err = [System.Management.Automation.ErrorRecord]::new([System.UnauthorizedAccessException]::new("Access is denied"), "AccessDenied", "PermissionDenied", $SearchBase)
      $PSCmdlet.ThrowTerminatingError($err)
    }
  }
  # Базы поиска в несуществующем разделе настоящий модуль отвергает: «Directory object not found».
  if ($env:STUB_NO_PARTITION -and ($SearchBase.Contains("DC=$($env:STUB_NO_PARTITION),") -or $Identity.Contains("DC=$($env:STUB_NO_PARTITION),"))) {
    $err = [System.Management.Automation.ErrorRecord]::new([System.ArgumentException]::new("Directory object not found"), "NotFound", "ObjectNotFound", $SearchBase)
    $PSCmdlet.ThrowTerminatingError($err)
  }
  if ($env:STUB_OLD_SCHEMA -and @($props | Where-Object { $OptionalSchema -contains $_ }).Count -gt 0) {
    $err = [System.Management.Automation.ErrorRecord]::new([System.ArgumentException]::new("One or more properties are invalid."), "InvalidProperty", "InvalidArgument", $props)
    $PSCmdlet.ThrowTerminatingError($err)
  }
  $found = 0
  foreach ($row in $Objects) {
    if ($env:STUB_OLD_SCHEMA -and $row.ContainsKey("lDAPDisplayName") -and $OptionalSchema -contains $row.lDAPDisplayName) { continue }
    $hit = $(if ($Identity) { $row.dn -eq $Identity } else { Test-Row $row $SearchBase $LDAPFilter $SearchScope })
    if ($hit) { New-AdEntity $row $props; $found++ }
    if ($ResultSetSize -and $found -ge $ResultSetSize) { return }
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

$Exported = @("Get-ADObject", "Get-ADComputer", "Get-ADRootDSE", "Get-ADDomain", "Get-ADDomainController", "Get-ADForest", "Get-ADOptionalFeature")
# STUB_ACL — подделка Get-Acl (в Linux командлета нет); без неё права SYSVOL не читаются.
if ($env:STUB_ACL) {
''' + FAKE_GET_ACL + r'''
  $Exported += "Get-Acl"
}
$Aliases = @()
# STUB_DC — подделки удалённого реестра и CIM контроллера dc01; без них раздел dc не прочитан.
if ($env:STUB_DC) {
''' + FAKE_DC_REGISTRY + FAKE_CIM + r'''
  $Exported += @("Read-FakeRegistry", "New-CimSessionOption", "New-CimSession", "Get-CimInstance", "Remove-CimSession")
  $Aliases += "Read-RemoteRegistry"
}
Export-ModuleMember -Function $Exported -Alias $Aliases
'''
TRUST_SID = "S-1-5-21-111-222-333"
CREATOR_SID = "S-1-5-21-1-2-3-1106"
DMSA_GUID = "0feb936f-47b3-49f2-9386-1dedc2c23765"
STUB_SD = base64.b64encode(sd.build_sd([sd.build_ace("S-1-5-21-1-2-3-1106", sd.WRITE_DACL)])).decode()
STUB_CERT = base64.b64encode(make_cert("CORP-ROOT")).decode()
STUB_WEAK_CERT = base64.b64encode(make_cert("OLD-SUB", bits=1024)).decode()
PKI_DN = "CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
GPO_ROOT = "/corp.local/SysVol/corp.local/Policies/{11111111-2222-3333-4444-555555555555}"
GPO_UNC = "\\" + GPO_ROOT.replace("/", "\\")
EVIL_ROOT = "/evil.example/share"


def _run_collector(tmp_path: Path, port: int, args: tuple[str, ...], stdin: str | None = None,
                   env_extra: dict[str, str] | None = None, timeout: int = 300,
                   gpo_files: dict[str, bytes] | None = None) -> tuple[str, Path]:
    """Весь скрипт в контейнере с поддельным модулем ActiveDirectory; отдаёт вывод и каталог результата.
    `gpo_files` — файлы папки первой GPO (путь относительно неё, через «\\»).
    Не уложился в `timeout` (например, ждёт ввода) — контейнер снимается, тест падает."""
    module = tmp_path / "modules" / "ActiveDirectory"
    module.mkdir(parents=True)
    (module / "ActiveDirectory.psm1").write_text(STUB_AD_MODULE, encoding="utf-8")
    secedit = tmp_path / "modules" / "gpo" / "MACHINE" / "Microsoft" / "Windows NT" / "SecEdit"
    secedit.mkdir(parents=True)
    (secedit / "GptTmpl.inf").write_text("[Privilege Rights]\nSeDebugPrivilege = *S-1-5-32-544\n", encoding="utf-8")
    for rel, content in (gpo_files or {}).items():
        target = tmp_path / "modules" / "gpo" / rel.replace("\\", "/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    out = tmp_path / "out"
    out.mkdir()
    env = {"STUB_WEB": f"host.docker.internal:{port}", "STUB_TRUST_SID": base64.b64encode(sd.str_to_sid(TRUST_SID)).decode(),
           "STUB_CREATOR_SID": base64.b64encode(sd.str_to_sid(CREATOR_SID)).decode(), "STUB_DMSA_GUID": DMSA_GUID, "STUB_SD": STUB_SD,
           "STUB_CERT": STUB_CERT, "STUB_WEAK_CERT": STUB_WEAK_CERT,
           "STUB_GPO": GPO_UNC, "PSModulePath": "/t/modules", "COMPUTERNAME": "WS01", "USERDOMAIN": "CORP",
           "USERNAME": "auditor", **(env_extra or {})}
    name = f"stools-collector-test-{uuid.uuid4().hex[:12]}"
    cmd = ["docker", "run", "--rm", "-i", "--name", name, "--add-host=host.docker.internal:host-gateway",
           *[a for k, v in env.items() for a in ("-e", f"{k}={v}")],
           "-v", f"{SCRIPT.resolve().parent}:/script:ro", "-v", f"{tmp_path / 'modules'}:/t/modules:ro", "-v", f"{out}:/out", "-w", "/out",
           # pwsh в Linux открывает \\host\share как /host/share: папка GPO видна по UNC-пути домена и чужого сервера.
           *[a for root in (GPO_ROOT, EVIL_ROOT) for a in ("-v", f"{tmp_path / 'modules' / 'gpo'}:{root}:ro")],
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
    у ЦС, нет TLS) пишутся в записи, сбор не прерывается. Реестр и CIM контроллера — подделки (STUB_DC)."""
    console, out = _run_collector(tmp_path, web_server, ("-Mode", "All", "-OutputPath", "/out/"), env_extra={"STUB_DC": "1"})
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
    assert list(export.sysvol) == [GPO_DN]
    assert export.collector.notes == [] and export.collector.version == "2.4"
    # Сертификаты ЦС: одно значение (byte[]) у ЦС выдачи, список у NTAuth и хранилищ.
    assert ca.cACertificate == [STUB_CERT]
    [ntauth] = [o for o in by_class["pkiContainer"] if o.dn.startswith("CN=NTAuthCertificates,")]
    assert ntauth.cACertificate == [STUB_CERT]
    assert all(o.cACertificate == [] for o in by_class["pkiContainer"] if o is not ntauth)
    stores = {o.cn: (o.store, o.cACertificate) for o in by_class["certificationAuthority"]}
    assert stores == {"CORP-ROOT": ("root", [STUB_CERT]), "CORP-SUB": ("intermediate", [STUB_CERT, STUB_WEAK_CERT])}
    found = [f for f in run_all(ExportIndex(export), AdConfig()) if f.check == "CertificateStrength"]
    assert [(f.target, f.identity, f.severity) for f in found] == [(f"CN=CORP-SUB,CN=AIA,{PKI_DN}", "CN=OLD-SUB", "Low")]
    # Блок gpo — у каждой GPO; Get-Acl в Linux нет: права не прочитаны, причина в notes записи GPO.
    assert export.gpo is not None and set(export.gpo) == {GPO_DN, GONE_DN}
    assert export.gpo[GPO_DN].registry == [] and export.gpo[GPO_DN].acl is None
    assert [n for n in export.gpo[GPO_DN].notes if n.startswith("права SYSVOL не прочитаны (")], export.gpo[GPO_DN].notes
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
    # Дескрипторы критичных объектов: Domain Admins, вложенная Tier0 и её участник alice; bob вне групп — без sd.
    groups = {g.sam: g for g in by_class["group"]}
    assert export.collector.critical_acl is True
    assert alice.sd == groups["Domain Admins"].sd == groups["Tier0"].sd == STUB_SD and bob.sd is None
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
    assert data.sections == ["ca", "dc", "web"] and data.domain.sid == export.domain.sid and data.collector.version == "2.4"
    [authority] = data.cas
    assert authority.name == "CORP-CA" and authority.os_build == "10.0 (17763)" and authority.error and authority.edit_flags is None
    [dc] = data.dcs
    # Реестр: значений NoLMHash и SSL 3.0 нет — null; Enabled = 0xFFFFFFFF пишется без знака.
    assert (dc.host, dc.strong_binding, dc.mapping_methods, dc.registry_read) == ("dc01.corp.local", 1, 0x1F, True)
    assert (dc.lm_compatibility, dc.no_lm_hash, dc.ldap_integrity, dc.ldap_channel_binding) == (3, None, 1, 0)
    assert dc.tls == {"SSL 3.0": None, "TLS 1.0": 0xFFFFFFFF, "TLS 1.1": 0} and dc.os_build == "17763.6189"
    # CIM: WSMan закрыт — сессия по DCOM; службы WebClient нет.
    assert (dc.cim_read, dc.smb1, dc.smb_require_signing, dc.spooler, dc.webclient) == (True, True, False, "running", "absent")
    assert dc.last_boot == dt.datetime(2026, 3, 1, 4, 5, 6, tzinfo=dt.UTC) and dc.error == ""
    assert "  dc01.corp.local: привязка 1, NTLM 3, подпись LDAP 1, SMB1 да" in console, console
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
    Список разделов пуст (нет crossRef своего домена) — он считается непрочитанным: зоны читаются из всех баз.
    Старая схема (нет LAPS, атрибута смарт-карт, dMSA, Exchange): эти свойства не запрашиваются, сбор не прерывается."""
    console, out = _run_collector(tmp_path, web_server, ("-SkipSysvol", "-OutputPath", "/out/old.json.gz"),
                                  env_extra={"STUB_DENY": "CN=OID;CN=Password Settings Container;DC=DomainDnsZones", "STUB_OLD_SCHEMA": "1",
                                             "STUB_NO_CROSSREF": "1"},
                                  timeout=120)
    assert "Выбор" not in console and "Продолжить?" not in console and "Сбор прерван" not in console, console
    assert sorted(p.name for p in out.iterdir()) == ["old.json.gz"]
    export = load_export((out / "old.json.gz").read_bytes())
    assert export.sysvol == {} and export.gpo is None and "gpo" not in _gz_json(out / "old.json.gz")
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


GPO_DN = "CN={11111111-2222-3333-4444-555555555555},CN=Policies,CN=System,DC=corp,DC=local"
GONE_DN = "CN={22222222-2222-3333-4444-555555555555},CN=Policies,CN=System,DC=corp,DC=local"
EVIL_DN = "CN={33333333-2222-3333-4444-555555555555},CN=Policies,CN=System,DC=corp,DC=local"
HARDENED = "Software\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths"
DRIVES = ('<?xml version="1.0" encoding="utf-16"?><Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">'
          '<Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="S:"><Properties action="U" path="\\\\fs01.corp.local\\share" '
          'userName="CORP\\svc" cpassword="Zm9vYmFyMTIz"/></Drive></Drives>')
#: Папка GPO: разные кодировки (UTF-8 без BOM, UTF-16 LE и BE с BOM, UTF-8 с BOM), папки MACHINE и Machine,
#: битый Registry.pol, файл больше потолка, скрипты внутри папки GPO (по имени и полным путём) и снаружи.
GPO_TREE = {
    "Machine\\Registry.pol": preg((LSA, "NoLMHash", 4, dword(0)), ("Software\\Vendor\\App", "ApiKey", 1, sz("secret")),
                                  (WINLOGON, "DefaultPassword", 1, sz("P@ssw0rd")), (HARDENED, "\\\\*\\SYSVOL", 1, sz("RequireMutualAuthentication=1"))),
    "Machine\\Preferences\\Groups\\Groups.xml": GROUPS.encode(),
    "Machine\\Preferences\\Services\\Services.xml": b" " * (g.MAX_GPO_FILE + 1),
    "MACHINE\\Microsoft\\Windows NT\\Audit\\audit.csv": AUDIT_CSV.encode("utf-16"),
    "Machine\\Scripts\\psscripts.ini": ("﻿[Startup]\r\n0CmdLine=" + GPO_ROOT + "/Machine/Scripts/Startup/s.ps1\r\n"
                                        "1CmdLine=\\\\fs01.corp.local\\share\\x.ps1\r\n").encode(),
    "Machine\\Scripts\\Startup\\s.ps1": b"Write-Host 1\r\n",
    "User\\Registry.pol": b"broken",
    "User\\Preferences\\Drives\\Drives.xml": b"\xfe\xff" + DRIVES.encode("utf-16-be"),
    "User\\Scripts\\scripts.ini": ("[Logon]\r\n0CmdLine=run.bat\r\n0Parameters=/user:svc S3cretParam\r\n1CmdLine=\"run two.bat\"\r\n2CmdLine=locked.bat\r\n"
                                    "3CmdLine=\"\\\\corp.local\\NETLOGON\\my script.bat\"\r\n").encode("utf-16"),
    "User\\Scripts\\Logon\\run.bat": b"@echo off\r\n",
    "User\\Scripts\\Logon\\run two.bat": b"@echo off\r\n",
    "User\\Scripts\\Logon\\locked.bat": b"@echo off\r\n",
}


@needs_pwsh
def test_script_reads_gpo_files_acl_and_links(tmp_path: Path, web_server: int) -> None:
    """Сборщик 2.2 читает те же файлы GPO, что LDAP-сборщик 1.2 (белый список Registry.pol, GPP без паролей,
    аудит, скрипты), права на папку GPO и файлы её скриптов, gPLink и flags. Раздела ForestDnsZones нет —
    зоны из него не читаются и это не отказ."""
    console, out = _run_collector(tmp_path, web_server, ("-Mode", "AD", "-OutputPath", "/out/"), timeout=180,
                                  env_extra={"STUB_ACL": "1", "STUB_NO_PARTITION": "ForestDnsZones", "STUB_EVIL_GPO": "\\\\evil.example\\share"},
                                  gpo_files=GPO_TREE)
    assert "Сбор прерван" not in console, console
    [ad_file] = list(out.glob("ad-CORP-*.json.gz"))
    text = gzip.decompress(ad_file.read_bytes()).decode()
    for secret in ("P@ssw0rd", "j1Uyj3Vx8TY9", "secret", "Zm9vYmFyMTIz", "S3cretParam"):
        assert secret not in text, secret
    export = load_export(ad_file.read_bytes())
    assert export.gpo is not None and list(export.sysvol) == [GPO_DN]
    data = export.gpo[GPO_DN]
    assert [r.model_dump() for r in data.registry] == [
        {"scope": "machine", "key": LSA, "value": "NoLMHash", "type": 4, "data": 0},
        {"scope": "machine", "key": WINLOGON, "value": "DefaultPassword", "type": 1, "data": ""},
        {"scope": "machine", "key": HARDENED, "value": "\\\\*\\SYSVOL", "type": 1, "data": "RequireMutualAuthentication=1"}]
    assert [i.model_dump() for i in data.gpp] == g.parse_gpp("Groups.xml", "machine", GROUPS) + g.parse_gpp("Drives.xml", "user", DRIVES)
    assert [a.model_dump() for a in data.audit] == g.parse_audit_csv(AUDIT_CSV)
    assert [sc.model_dump() for sc in data.scripts] == [
        {"scope": "machine", "phase": "startup", "command": GPO_ROOT + "/Machine/Scripts/Startup/s.ps1", "parameters": ""},
        {"scope": "machine", "phase": "startup", "command": "\\\\fs01.corp.local\\share\\x.ps1", "parameters": ""},
        {"scope": "user", "phase": "logon", "command": "run.bat", "parameters": ""},
        {"scope": "user", "phase": "logon", "command": '"run two.bat"', "parameters": ""},
        {"scope": "user", "phase": "logon", "command": "locked.bat", "parameters": ""},
        {"scope": "user", "phase": "logon", "command": '"\\\\corp.local\\NETLOGON\\my script.bat"', "parameters": ""}]
    # Путь — как на диске: в macOS (и в Windows) Machine и MACHINE — одна папка, в Linux — две.
    assert data.acl is not None and [(a.path.lower(), a.writers) for a in data.acl] == [
        ("", FAKE_WRITERS),
        ("machine\\scripts\\startup\\s.ps1", FAKE_WRITERS),
        ("user\\scripts\\logon\\run.bat", [*FAKE_WRITERS, "S-1-5-11"]),
        # Команда в кавычках — тот же файл; отказ прав по locked.bat пропускает только его.
        ("user\\scripts\\logon\\run two.bat", FAKE_WRITERS)]
    assert len(data.notes) == 3, data.notes
    assert data.notes[2].lower().startswith("user\\scripts\\logon\\locked.bat: права не прочитаны (") and "denied" in data.notes[2]
    assert data.notes[0].startswith("User\\Registry.pol: ") and "Registry.pol" in data.notes[0][len("User\\Registry.pol: "):]
    assert data.notes[1] == "Machine\\Preferences\\Services\\Services.xml: файл больше 4 МБ, не разобран"
    gone = export.gpo[GONE_DN]
    assert gone.acl is None and len(gone.notes) == 1 and gone.notes[0].startswith("папка GPO не прочитана ("), gone.notes
    assert (gone.registry, gone.gpp, gone.audit, gone.scripts) == ([], [], [], [])
    # Папка GPO на чужом сервере не открывается вовсе (там те же файлы, что у первой GPO), остаётся пометка.
    evil = export.gpo[EVIL_DN]
    assert evil.notes == ["путь GPO вне домена (evil.example) — не читается"]
    assert (evil.registry, evil.gpp, evil.audit, evil.scripts, evil.acl) == ([], [], [], [], None)

    by_dn = {o.dn: o for o in export.objects}
    root = by_dn["DC=corp,DC=local"]
    assert root.gpLink == f"[LDAP://{GPO_DN};0]" and root.gpOptions == 0
    assert by_dn["OU=Servers,DC=corp,DC=local"].gpLink == f"[LDAP://{GPO_DN};2]" and by_dn["OU=Servers,DC=corp,DC=local"].gpOptions == 1
    [site] = [o for o in export.objects if o.cls == "site"]
    assert site.gpLink == "" and site.gpOptions is None
    assert (by_dn[GPO_DN].flags, by_dn[GONE_DN].flags) == (0, 2)
    assert len(ExportIndex(export).gpo_links(by_dn[GPO_DN]) or []) == 2
    assert sorted(o.partition or "" for o in export.objects if o.cls == "dnsZone") == ["DomainDnsZones", "System"]
    assert not [n for n in export.collector.notes if "зоны DNS" in n], export.collector.notes


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
