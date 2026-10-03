import base64
import importlib.util
from pathlib import Path
from types import ModuleType

from api.modules.ad.core import sd
from tests.ad.mini import DN, computer, dc, ft, group, mini_export, rid, run, user

UNCONSTRAINED = 0x80000


def sev(findings):
    return {f.identity: f.severity for f in findings}


def test_delegation_skips_domain_controllers():
    exp = mini_export([dc("DC01", 1001, uac=0x82000), computer("SRV1", 1002, uac=4096 | UNCONSTRAINED)])
    assert sev(run("Delegation", exp)) == {"CORP\\SRV1$": "High"}


def test_rbcd_on_domain_controller_is_critical():
    acl = base64.b64encode(sd.build_sd([sd.build_ace(rid(1101), sd.GENERIC_ALL)])).decode()
    exp = mini_export([user("u1", 1101), dc("DC01", 1001, allowedToActOnBehalf=acl), computer("SRV1", 1002, allowedToActOnBehalf=acl)])
    got = {f.target: f.severity for f in run("RBCD", exp)}
    assert got == {"DC01$": "Critical", "SRV1$": "High"}


def test_admin_count_only_outside_protected_groups():
    exp = mini_export([user("alice", 1101, adminCount=1), user("former", 1102, adminCount=1)], admins=["alice"])
    assert set(sev(run("AdminCount", exp))) == {"CORP\\former"}


def test_password_never_expires_low_and_high_for_admin():
    flag = 512 | 0x10000
    exp = mini_export([user("svc", 1101, uac=flag), user("adm", 1102, uac=flag)], admins=["adm"])
    assert sev(run("PasswordNeverExpires", exp)) == {"CORP\\svc": "Low", "CORP\\adm": "High"}


def test_kerberoast_asrep_inactive_escalate_for_admin():
    spn = ["http/app.corp.local"]
    exp = mini_export(
        [user("svc", 1101, spn=spn), user("adm", 1102, spn=spn, uac=512 | 0x400000, lastLogonTimestamp=ft(200)),
         user("u", 1103, uac=512 | 0x400000)],
        admins=["adm"],
    )
    assert sev(run("Kerberoast", exp)) == {"CORP\\svc": "Medium", "CORP\\adm": "High"}
    assert sev(run("ASREP", exp)) == {"CORP\\u": "High", "CORP\\adm": "Critical"}
    assert sev(run("InactiveUsers", exp)) == {"CORP\\adm": "High"}


def test_des_only_flag_is_weak_encryption():
    exp = mini_export([user("old", 1101, uac=512 | 0x200000), user("ok", 1102)])
    assert sev(run("WeakEncryption", exp)) == {"CORP\\old": "High"}


def test_privileged_groups_include_builtin_and_domain_rids():
    objects = [user("p", 1101), user("k", 1102), user("d", 1103),
               group("Print Operators", "S-1-5-32-550", [f"CN=p,CN=Users,{DN}"]),
               group("Key Admins", rid(526), [f"CN=k,CN=Users,{DN}"]),
               group("DnsAdmins", rid(1150), [f"CN=d,CN=Users,{DN}"])]
    got = {(f.target, f.identity) for f in run("PrivilegedGroups", mini_export(objects))}
    assert {("Print Operators", "CORP\\p"), ("Key Admins", "CORP\\k"), ("DnsAdmins", "CORP\\d")} <= got


def test_preauth_disabled_check_is_gone():
    from api.modules.ad.core.checks import CHECK_BY_CODE
    assert "PreauthDisabled" not in CHECK_BY_CODE and "ASREP" in CHECK_BY_CODE


def _settings_migration() -> ModuleType:
    versions = Path(__file__).resolve().parents[2] / "api" / "db" / "migrations" / "versions"
    path = next(versions.glob("*_ad_привилегированные_группы.py"))
    spec = importlib.util.spec_from_file_location("ad_privileged_groups_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_settings_migration_replaces_old_defaults_only():
    from api.modules.ad.core.config import AdConfig
    m = _settings_migration()
    new = AdConfig()
    old = {"privileged_rids": [512, 519, 518, 544, 548, 551, 549], "privileged_groups": list(m.OLD_PRIVILEGED_GROUPS), "user_inactivity_days": 30}
    got = m.upgrade_settings(old)
    assert got["privileged_rids"] == new.privileged_rids
    assert got["privileged_groups"] == new.privileged_groups and "DnsAdmins" in got["privileged_groups"]
    assert got["user_inactivity_days"] == 30
    # Порядок прежнего умолчания не важен — сравнение как множеств.
    assert m.upgrade_settings({"privileged_rids": [549, 512, 519, 518, 544, 548, 551]})["privileged_rids"] == new.privileged_rids

    custom = {"privileged_rids": [512, 519], "privileged_groups": ["Domain Admins", "Наши админы"]}
    assert m.upgrade_settings(dict(custom)) == custom
    assert m.upgrade_settings({}) == {}
