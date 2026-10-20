from api.modules.ad.core.checks.coverage import coverage_gaps
from api.modules.ad.core.checks.gpo_files_checks import DC_AUDIT_SUBCATEGORIES
from tests.ad.mini import DN, dc, gpo, link, mini_export, rid, run, user

POL = "Software\\Policies\\Microsoft\\Windows"


def reg(key, value, data, rtype=4):
    return {"scope": "machine", "key": key, "value": value, "type": rtype, "data": data}


def setup(data, *, objects=(), linked=True):
    g = gpo("Baseline")
    ou = {"dn": f"OU=Domain Controllers,{DN}", "class": "organizationalUnit", "gpLink": link(g["dn"]) if linked else ""}
    return mini_export([g, ou, dc("DC01", 1001, dNSHostName="dc01.corp.local"), *objects], gpo={g["dn"]: data}, sysvol={})


def kinds(findings):
    return {f.key_extra: f.severity for f in findings}


def test_registry_settings():
    bad = {"registry": [reg(f"{POL} NT\\DNSClient", "EnableMultiCast", 1),
                        reg(f"{POL}\\NetworkProvider\\HardenedPaths", "\\\\*\\SYSVOL", "RequireMutualAuthentication=0, RequireIntegrity=1", 1),
                        reg(f"{POL}\\WindowsUpdate", "WUServer", "http://wsus.corp.local:8530", 1),
                        reg(f"{POL}\\WindowsUpdate", "SetProxyBehaviorForUpdateDetection", 1),
                        reg(f"{POL}\\WindowsUpdate", "DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection", 1)]}
    assert kinds(run("GpoRegistrySettings", setup(bad))) == {"llmnr": "Low", "hardened_paths": "Medium", "wsus_http": "Medium",
                                                           "wsus_user_proxy": "Low", "wsus_no_pinning": "Low", "ps_logging": "Low"}
    good = {"registry": [reg(f"{POL} NT\\DNSClient", "EnableMultiCast", 0), reg(f"{POL}\\PowerShell\\ScriptBlockLogging", "EnableScriptBlockLogging", 1),
                         reg(f"{POL}\\WindowsUpdate", "WUServer", "https://wsus.corp.local:8531", 1)]}
    assert run("GpoRegistrySettings", setup(good)) == []


def test_dc_audit_policy_reports_missing_subcategories():
    assert len(DC_AUDIT_SUBCATEGORIES) == 15
    guids = list(DC_AUDIT_SUBCATEGORIES)
    audit = [{"subcategory": g, "setting": 3} for g in guids[:13]] + [{"subcategory": guids[13], "setting": 2}]   # одна — только отказы, одной нет
    got = run("DcAuditPolicy", setup({"audit": audit}))
    assert {f.key_extra for f in got} == set(guids[13:]) and {f.severity for f in got} == {"Medium"}
    # Старая политика аудита ([Event Audit] в GptTmpl.inf) не читается — в тексте находки это сказано.
    assert all("только расширенная политика аудита (audit.csv)" in f.details["details"] and "[Event Audit]" in f.details["details"] for f in got)
    assert len(run("DcAuditPolicy", setup({"audit": audit}, linked=False))) == 15      # GPO не применяется к контроллерам


def test_external_scripts_and_files():
    data = {"scripts": [{"scope": "user", "phase": "logon", "command": "\\\\fs01.other.local\\share\\run.bat", "parameters": ""},
                        {"scope": "user", "phase": "logon", "command": "\\\\corp.local\\NETLOGON\\ok.bat", "parameters": ""},
                        {"scope": "machine", "phase": "startup", "command": "\\\\dc01.corp.local\\NETLOGON\\ok.ps1", "parameters": ""},
                        {"scope": "machine", "phase": "startup", "command": "local.cmd", "parameters": ""}],
            "gpp": [{"scope": "machine", "file": "Files.xml", "kind": "File", "name": "tool.exe", "path": "\\\\nas\\dist\\tool.exe"}]}
    objects = [user("u1", 1101, scriptPath="\\\\legacy\\scripts\\login.bat"), user("u2", 1102, scriptPath="login.bat")]
    got = {f.key_extra for f in run("GpoExternalFiles", setup(data, objects=objects))}
    assert got == {"\\\\fs01.other.local\\share\\run.bat", "\\\\nas\\dist\\tool.exe", "\\\\legacy\\scripts\\login.bat"}


def test_sysvol_acl():
    data = {"acl": [{"path": "", "writers": ["S-1-5-32-544", rid(512), "S-1-5-18", rid(1101)]},
                    {"path": "User\\Scripts\\Logon\\run.bat", "writers": ["S-1-5-11"]}]}
    got = {(f.identity, f.key_extra): f.severity for f in run("SysvolAcl", setup(data, objects=[user("helpdesk", 1101)]))}
    assert got == {("CORP\\helpdesk", ""): "High", ("NT AUTHORITY\\Authenticated Users", "User\\Scripts\\Logon\\run.bat"): "Critical"}


def test_gaps():
    assert {"GpoRegistrySettings", "DcAuditPolicy", "GpoExternalFiles", "SysvolAcl", "GppPasswords"} <= set(coverage_gaps(mini_export([gpo("X")])))
    only_ldap = setup({"registry": []})
    assert "SysvolAcl" in coverage_gaps(only_ldap) and "GpoRegistrySettings" not in coverage_gaps(only_ldap)


def test_domain_level_kinds_need_gpo_block():
    export = mini_export([gpo("X"), dc("DC01", 1001)])
    assert run("GpoRegistrySettings", export) == [] and run("DcAuditPolicy", export) == []


def test_internal_hosts_and_disabled_parts():
    data = {"scripts": [{"scope": "user", "phase": "logon", "command": '"\\\\CORP\\NETLOGON\\a.bat"', "parameters": ""},
                        {"scope": "user", "phase": "logon", "command": "\\\\DC01\\NETLOGON\\b.bat", "parameters": ""},
                        {"scope": "machine", "phase": "startup", "command": "\\\\fs01\\share\\c.bat", "parameters": ""},
                        {"scope": "user", "phase": "logoff", "command": "\\\\fs01\\share\\d.bat", "parameters": ""}]}
    g = gpo("Logon", flags=2)   # компьютерная часть выключена: сценарий входа пользователя всё равно применяется
    got = run("GpoExternalFiles", mini_export([g, dc("DC01", 1001)], gpo={g["dn"]: data}, sysvol={}))
    assert [f.key_extra for f in got] == ["\\\\fs01\\share\\d.bat"]


def test_gpo_path_outside_domain_is_high():
    evil = gpo("Evil", guid="{22222222-2222-2222-2222-222222222222}", gpcFileSysPath="\\\\evil.example\\share")
    ok = gpo("Ok", gpcFileSysPath="\\\\DC01\\SysVol\\corp.local\\Policies\\{11111111-1111-1111-1111-111111111111}")
    # Путь GPO читается из LDAP: находка не зависит от того, собран ли блок gpo.
    for export in (mini_export([evil, ok, dc("DC01", 1001)]), mini_export([evil, ok, dc("DC01", 1001)], gpo={evil["dn"]: {}}, sysvol={})):
        [f] = run("GpoExternalFiles", export)
        assert (f.key_extra, f.severity, f.target) == ("gpc_path|\\\\evil.example\\share", "High", "Evil")
