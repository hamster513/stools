from tests.ad.mini import DN, dc, gpo, link, mini_export, rid, run

DC_OU = {"dn": f"OU=Domain Controllers,{DN}", "class": "organizationalUnit"}


def setup(inf="", data=None, linked_to_dcs=True, **gpo_extra):
    g = gpo("Hardening", **gpo_extra)
    ou = {**DC_OU, "gpLink": link(g["dn"]) if linked_to_dcs else ""}
    top = {"sysvol": {g["dn"]: {"GptTmpl.inf": inf}}, "gpo": {g["dn"]: data or {}}}
    return mini_export([g, ou, dc("DC01", 1001)], **top)


def kinds(findings):
    return {f.key_extra: f.severity for f in findings}


def test_gpp_passwords_and_autologon():
    data = {"gpp": [{"scope": "machine", "file": "Groups.xml", "kind": "User", "name": "localadm", "user": "localadm", "cpassword": True},
                    {"scope": "machine", "file": "Drives.xml", "kind": "Drive", "name": "S:", "user": "", "cpassword": False}],
            "registry": [{"scope": "machine", "key": "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "value": "DefaultPassword", "type": 1, "data": ""}]}
    assert kinds(run("GppPasswords", setup(data=data))) == {"machine|Groups.xml|localadm": "High", "autologon": "High"}


def test_security_options_from_inf_and_registry_pol():
    inf = ("[System Access]\nClearTextPassword = 1\n[Registry Values]\n"
           "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,1\n"
           "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash=4,0\n"
           "MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity=4,1\n")
    data = {"registry": [{"scope": "machine", "key": "System\\CurrentControlSet\\Control\\Lsa", "value": "EveryoneIncludesAnonymous", "type": 4, "data": 1}]}
    assert kinds(run("GpoSecurityOptions", setup(inf, data))) == {
        "ntlm_level": "High", "ntlm_level_missing": "Medium", "lm_hash": "Medium", "ldap_signing": "Medium", "anonymous": "Medium", "cleartext_password": "High"}


def test_other_security_option_kinds():
    inf = ("[Registry Values]\n"
           f"MACHINE\\{LSA}\\LmCompatibilityLevel=4,5\n"
           f"MACHINE\\{LSA}\\LimitBlankPasswordUse=4,0\n"
           f"MACHINE\\{LSA}\\RestrictAnonymous=4,0\n"
           "MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\RefusePasswordChange=4,1\n"
           "MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole\\SecurityLevel=4,1\n")
    assert kinds(run("GpoSecurityOptions", setup(inf))) == {
        "blank_password": "Medium", "anonymous": "Medium", "refuse_pwd_change": "Low", "recovery_console": "Medium"}


def test_ntlm_level_five_on_dcs_is_clean_and_unlinked_gpo_does_not_count():
    good = "[Registry Values]\nMACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,5\n"
    assert run("GpoSecurityOptions", setup(good)) == []
    assert kinds(run("GpoSecurityOptions", setup(good, linked_to_dcs=False))) == {"ntlm_level_missing": "Medium"}


def test_dc_logon_rights_and_tiering():
    inf = f"[Privilege Rights]\nSeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-11\nSeDenyInteractiveLogonRight = *{rid(512)}\n"
    got = run("DcLogonRights", setup(inf))
    assert [(f.identity, f.right, f.severity) for f in got] == [("NT AUTHORITY\\Authenticated Users", "SeInteractiveLogonRight", "High")]
    assert run("DcLogonRights", setup(inf, linked_to_dcs=False)) == []
    assert run("TieringLogonDeny", setup(inf)) == []
    assert [f.severity for f in run("TieringLogonDeny", setup("[Privilege Rights]\nSeDebugPrivilege = *S-1-5-32-544\n"))] == ["Low"]


def test_dc_logon_rights_by_name_and_batch_logon():
    inf = "[Privilege Rights]\nSeRemoteInteractiveLogonRight = Authenticated Users\nSeBatchLogonRight = *S-1-1-0,*S-1-5-32-551\n"
    got = {(f.identity, f.identity_sid, f.right) for f in run("DcLogonRights", setup(inf))}
    assert got == {("Authenticated Users", "", "SeRemoteInteractiveLogonRight"), ("Everyone", "S-1-1-0", "SeBatchLogonRight")}


def test_restricted_groups_memberof():
    inf = "[Group Membership]\n*S-1-5-11__Memberof = *S-1-5-32-544,*S-1-5-32-555\n*S-1-5-32-551__Memberof = *S-1-5-32-544\n"
    got = {(f.identity, f.details["group"], f.key_extra): f.severity for f in run("RestrictedGroups", setup(inf))}
    assert got == {("NT AUTHORITY\\Authenticated Users", "S-1-5-32-544", "inf|S-1-5-32-544"): "High",
                   ("NT AUTHORITY\\Authenticated Users", "S-1-5-32-555", "inf|S-1-5-32-555"): "Medium"}


def test_restricted_groups_from_inf_and_gpp():
    inf = "[Group Membership]\n*S-1-5-32-544__Members = *S-1-5-11\n*S-1-5-32-555__Members = *S-1-5-21-1000-2000-3000-513\n"
    data = {"gpp": [{"scope": "machine", "file": "Groups.xml", "kind": "Group", "name": "Administrators (built-in)", "group_sid": "S-1-5-32-544",
                     "members": [{"name": "CORP\\Domain Users", "sid": f"{rid(513)}", "action": "ADD"}, {"name": "CORP\\x", "sid": f"{rid(513)}", "action": "REMOVE"}]}]}
    got = {(f.identity, f.details["group"]): f.severity for f in run("RestrictedGroups", setup(inf, data))}
    assert got == {("NT AUTHORITY\\Authenticated Users", "S-1-5-32-544"): "High", ("CORP\\Domain Users", "S-1-5-32-555"): "Medium",
                   ("CORP\\Domain Users", "S-1-5-32-544"): "High"}


# ---- Помощники, выключенная компьютерная часть, неизвестная привязка ----------

LSA = "System\\CurrentControlSet\\Control\\Lsa"


def _index(export):
    from api.modules.ad.core.export import ExportIndex
    idx = ExportIndex(export)
    return idx, idx.objects("groupPolicyContainer")[0]


def test_gpo_setting_reads_inf_first_then_registry_pol():
    from api.modules.ad.core.checks.gpo_settings import gpo_setting
    inf = f"[Registry Values]\nMACHINE\\{LSA}\\NoLMHash=4,1\n"
    data = {"registry": [{"scope": "machine", "key": LSA.lower(), "value": "NoLMHash", "type": 4, "data": 0},
                         {"scope": "machine", "key": LSA, "value": "LmCompatibilityLevel", "type": 4, "data": 5}]}
    idx, g = _index(setup(inf, data))
    assert gpo_setting(idx, g, f"{LSA}\\NoLMHash") == 1
    assert gpo_setting(idx, g, "SYSTEM\\currentcontrolset\\control\\lsa\\lmcompatibilitylevel") == 5
    assert gpo_setting(idx, g, f"{LSA}\\RestrictAnonymous") is None


def test_linked_text():
    from api.modules.ad.core.checks.gpo_settings import linked_text
    assert linked_text(*_index(setup())) == f"применяется к: OU=Domain Controllers,{DN}"
    assert linked_text(*_index(setup(linked_to_dcs=False))) == "не привязана"
    g = gpo("Hardening")
    old = mini_export([g, DC_OU, dc("DC01", 1001)], sysvol={g["dn"]: {"GptTmpl.inf": ""}}, gpo={g["dn"]: {}})
    assert linked_text(*_index(old)) == "привязка GPO неизвестна (сборщик старой версии)"


BAD_INF = ("[System Access]\nClearTextPassword = 1\n[Privilege Rights]\nSeInteractiveLogonRight = *S-1-5-11\n"
           "[Group Membership]\n*S-1-5-32-544__Members = *S-1-5-11\n")
BAD_DATA = {"gpp": [{"scope": "machine", "file": "Groups.xml", "kind": "User", "name": "localadm", "user": "localadm", "cpassword": True}]}


def test_machine_disabled_gpo_is_skipped_except_gpp_passwords():
    export = setup(BAD_INF, BAD_DATA, flags=2)
    for code in ("DcLogonRights", "RestrictedGroups"):
        assert run(code, export) == []
    assert kinds(run("GpoSecurityOptions", export)) == {"ntlm_level_missing": "Medium"}
    assert [f.key_extra for f in run("TieringLogonDeny", setup("[Privilege Rights]\nSeDenyInteractiveLogonRight = Domain Admins\n", flags=2))] == [""]
    # Файл с паролем читается из SYSVOL, применяется GPO или нет.
    assert kinds(run("GppPasswords", export)) == {"machine|Groups.xml|localadm": "High"}


def test_gpp_password_of_allowlisted_account_stays_high():
    data = {"gpp": [{"scope": "user", "file": "Drives.xml", "kind": "Drive", "name": "S:", "user": "Administrator", "cpassword": True}]}
    got = run("GppPasswords", setup(data=data, flags=2))
    assert [(f.identity, f.severity, f.allowlisted, f.key_extra) for f in got] == [("Administrator", "High", False, "user|Drives.xml|S:")]


def test_unknown_links_count_gpo_as_applicable_with_note():
    g = gpo("Hardening")
    old = mini_export([g, DC_OU, dc("DC01", 1001)], sysvol={g["dn"]: {"GptTmpl.inf": BAD_INF}}, gpo={g["dn"]: {}})
    got = run("DcLogonRights", old)
    assert len(got) == 1 and "привязка GPO неизвестна" in got[0].details["details"]
    assert got[0].target == "Hardening" and got[0].details["gpo_dn"] == g["dn"]


def test_without_gpo_files_domain_level_findings_are_not_raised():
    """Нет ни SYSVOL, ни блока gpo: отсутствие настройки не доказано — это пробел покрытия, а не находка."""
    export = mini_export([gpo("Hardening"), dc("DC01", 1001)])
    assert run("GpoSecurityOptions", export) == [] and run("TieringLogonDeny", export) == []


def test_restricted_groups_resolves_group_name_and_ignores_safe_members_and_deleted_items():
    inf = "[Group Membership]\nAdministrators__Members = *S-1-5-32-544,Domain Users\n"
    data = {"gpp": [{"scope": "machine", "file": "Groups.xml", "kind": "Group", "name": "Users", "group_sid": "S-1-5-32-545", "action": "D",
                     "members": [{"name": "Everyone", "sid": "S-1-1-0", "action": "ADD"}]}]}
    got = run("RestrictedGroups", setup(inf, data))
    assert [(f.identity, f.details["group"], f.key_extra, f.severity) for f in got] == [("Domain Users", "S-1-5-32-544", "inf|S-1-5-32-544", "High")]


# ---- Миграция сохранённых настроек ----------------------------------------------

def _settings_migration():
    import importlib.util
    from pathlib import Path
    versions = Path(__file__).resolve().parents[2] / "api" / "db" / "migrations" / "versions"
    path = next(versions.glob("*_ad_право_trustedcredman.py"))
    spec = importlib.util.spec_from_file_location("ad_trusted_cred_man_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_settings_migration_adds_trusted_cred_man_to_old_default_only():
    from api.modules.ad.core.config import AdConfig
    m = _settings_migration()
    new = [r.model_dump() for r in AdConfig().user_rights]
    assert {"right": "SeTrustedCredManAccessPrivilege", "severity": "Medium"} in new
    old = [r for r in new if r["right"] != "SeTrustedCredManAccessPrivilege"]
    assert m.upgrade_settings({"user_rights": list(old), "user_inactivity_days": 30}) == {"user_rights": new, "user_inactivity_days": 30}
    # Порядок прежнего умолчания не важен.
    assert m.upgrade_settings({"user_rights": old[::-1]})["user_rights"][-1]["right"] == "SeTrustedCredManAccessPrivilege"
    custom = {"user_rights": [{"right": "SeDebugPrivilege", "severity": "Critical"}]}
    assert m.upgrade_settings(dict(custom)) == custom
    assert m.upgrade_settings({}) == {}
