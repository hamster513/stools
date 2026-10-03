from tests.ad.mini import DN, computer, ft, mini_export, rid, run, user


def sev(findings):
    return {f.identity: f.severity for f in findings}


def test_password_not_required():
    exp = mini_export([user("u1", 1101, uac=512 | 0x20), user("u2", 1102), user("off", 1103, uac=514 | 0x20),
                       user("adm", 1104, uac=512 | 0x20), computer("PC1", 1105, uac=4096 | 0x20)], admins=["adm"])
    assert sev(run("PasswordNotRequired", exp)) == {"CORP\\u1": "Medium", "CORP\\adm": "High", "CORP\\PC1$": "Medium"}


def test_reversible_password():
    exp = mini_export([user("u1", 1101, uac=512 | 0x80), user("u2", 1102), user("off", 1103, uac=514 | 0x80)])
    assert sev(run("ReversiblePassword", exp)) == {"CORP\\u1": "Medium"}


def test_admin_delegable_respects_flag_and_protected_users():
    objects = [user("a1", 1101), user("a2", 1102, uac=512 | 0x100000), user("a3", 1103), user("plain", 1104)]
    exp = mini_export(objects, admins=["a1", "a2", "a3"])
    next(o for o in exp.objects if o.sid == rid(525)).member.append(f"CN=a3,CN=Users,{DN}")
    got = sev(run("AdminDelegable", exp))
    assert "CORP\\a1" in got and not {"CORP\\a2", "CORP\\a3", "CORP\\plain"} & set(got)


def test_admin_password_age():
    exp = mini_export([user("old", 1101, pwdLastSet=ft(1200)), user("new", 1102, pwdLastSet=ft(100)), user("plain", 1103, pwdLastSet=ft(2000))], admins=["old", "new"])
    assert set(sev(run("AdminPasswordAge", exp))) == {"CORP\\old"}


def test_builtin_admin_used_recently():
    exp = mini_export()
    assert run("BuiltinAdminUsed", exp) == []          # вход 60 дней назад
    next(o for o in exp.objects if o.sid == rid(500)).lastLogonTimestamp = ft(2)
    assert [f.severity for f in run("BuiltinAdminUsed", exp)] == ["Medium"]


def test_guest_enabled():
    assert run("GuestEnabled", mini_export([user("Guest", 501, uac=514)])) == []
    assert [f.severity for f in run("GuestEnabled", mini_export([user("Guest", 501, uac=512)]))] == ["High"]


def test_azure_sso_key_age():
    exp = mini_export([computer("AZUREADSSOACC", 1101, pwdLastSet=ft(400)), computer("PC1", 1102, pwdLastSet=ft(400))])
    assert sev(run("AzureSsoKeyAge", exp)) == {"CORP\\AZUREADSSOACC$": "Medium"}
    assert run("AzureSsoKeyAge", mini_export([computer("AZUREADSSOACC", 1101, pwdLastSet=ft(10))])) == []


def test_duplicate_objects():
    cnf = user("dup", 1101)
    cnf["dn"] = f"CN=dup\\0ACNF:1f3c,CN=Users,{DN}"
    exp = mini_export([cnf, user("$DUPLICATE-4f1", 1102), user("ok", 1103)])
    assert len(run("DuplicateObjects", exp)) == 2
