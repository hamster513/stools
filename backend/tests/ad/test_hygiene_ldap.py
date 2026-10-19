import datetime as dt

from api.modules.ad.core.checks.coverage import coverage_gaps
from api.modules.ad.core.checks.domain import functional_level_value, heuristic
from tests.ad.mini import DN, DOMAIN_SID, NOW, computer, dc, ft, mini_export, rid, run, user

FULL = {"forest_functional_level": "7", "min_pwd_length": 12, "lockout_threshold": 5, "pwd_properties": 1, "recycle_bin": True,
        "ds_heuristics": "", "smartcard_rotation": True, "laps_legacy_schema": False, "laps_schema": True,
        "last_backup": (NOW - dt.timedelta(days=1)).isoformat(), "backup_read": True, "sysvol_replication": "dfsr", "schema_poss_superiors": {}}


def dom(**over):
    return {**FULL, **over}


def kinds(findings):
    return {f.key_extra: f.severity for f in findings}


def test_primary_group():
    exp = mini_export([user("ok", 1101, primaryGroupID=513), user("hid", 1102, primaryGroupID=512), user("Guest", 501, uac=514, primaryGroupID=514),
                       computer("PC1", 1103, primaryGroupID=515), computer("PC2", 1104, primaryGroupID=512), dc("DC01", 1001, primaryGroupID=516)])
    assert {f.identity for f in run("PrimaryGroup", exp)} == {"CORP\\hid", "CORP\\PC2$"}


def test_sid_history_kinds():
    other = {"dn": f"CN=other.local,CN=System,{DN}", "class": "trustedDomain", "flatName": "OTHER", "sid": "S-1-5-21-111-222-333"}
    exp = mini_export([other, user("u", 1101, sIDHistory=[f"{DOMAIN_SID}-512", "S-1-5-21-111-222-333-519", "S-1-5-21-9-9-9-1500", "S-1-5-21-111-222-333-2000"])])
    assert kinds(run("SidHistory", exp)) == {f"{DOMAIN_SID}-512": "Critical", "S-1-5-21-111-222-333-519": "High",
                                             "S-1-5-21-9-9-9-1500": "Medium", "S-1-5-21-111-222-333-2000": "Low"}


def test_password_policy_domain_and_pso():
    pso = {"dn": f"CN=svc,CN=Password Settings Container,CN=System,{DN}", "class": "msDS-PasswordSettings", "name": "svc",
           "psoMinLength": 6, "psoLockoutThreshold": 5, "psoReversible": False, "psoComplexity": True}
    exp = mini_export([pso], domain=dom(min_pwd_length=7, lockout_threshold=0, pwd_properties=0x10))
    got = {(f.target, f.key_extra): f.severity for f in run("PasswordPolicy", exp)}
    assert got == {(DN, "min_length"): "Medium", (DN, "no_lockout"): "Medium", (DN, "reversible"): "High", (DN, "no_complexity"): "Low",
                   (pso["dn"], "min_length"): "Medium"}
    assert run("PasswordPolicy", mini_export(domain=dom())) == []


def test_laps_not_installed_and_coverage():
    assert kinds(run("LapsDeployment", mini_export([computer("PC1", 1101)], domain=dom(laps_schema=False)))) == {"not_installed": "Medium"}
    pcs = [computer(f"PC{i}", 1100 + i, operatingSystem="Windows 11 Enterprise", lapsNewExpiry=ft(-10)) for i in range(9)]
    pcs.append(computer("BARE", 1150, operatingSystem="Windows 11 Enterprise"))
    pcs += [dc("DC01", 1001), computer("NIX", 1151, operatingSystem="Ubuntu"), computer("OFF", 1152, uac=4098)]
    got = run("LapsDeployment", mini_export(pcs, domain=dom()))
    assert kinds(got) == {"coverage": "Low"} and got[0].details["without_laps"] == 1 and got[0].details["eligible"] == 10
    assert run("LapsDeployment", mini_export(pcs[:9], domain=dom())) == []


def test_computer_creators_grouped_by_creator():
    exp = mini_export([user("joiner", 1101), computer("PC1", 1102, creatorSid=rid(1101)), computer("PC2", 1103, creatorSid=rid(1101)),
                       computer("PC3", 1104, creatorSid=rid(500)), computer("PC4", 1105)])
    got = run("ComputerCreators", exp)
    assert [(f.identity, f.severity, f.details["count"]) for f in got] == [("CORP\\joiner", "Low", 2)]


def test_domain_switches():
    assert [f.severity for f in run("RecycleBin", mini_export(domain=dom(recycle_bin=False)))] == ["Low"]
    assert run("RecycleBin", mini_export(domain=dom())) == []
    assert [f.severity for f in run("NtfrsSysvol", mini_export(domain=dom(sysvol_replication="ntfrs")))] == ["Low"]
    old = (NOW - dt.timedelta(days=20)).isoformat()
    assert [f.severity for f in run("BackupAge", mini_export(domain=dom(last_backup=old)))] == ["Medium"]
    assert [f.severity for f in run("BackupAge", mini_export(domain=dom(last_backup=None)))] == ["Medium"]
    assert run("BackupAge", mini_export(domain=dom())) == []
    vuln = dom(schema_poss_superiors={"msExchStorageGroup": ["computer", "msExchServer"]})
    assert [f.severity for f in run("SchemaVulnerableClass", mini_export(domain=vuln))] == ["Medium"]


def test_ds_heuristics_positions():
    assert heuristic("0000002", 7) == "2" and heuristic("00", 7) == "0"
    value = "0010002" + "1" + "0" * 7 + "1" + "0000" + "1" + "000000" + "22"   # позиции 3, 7, 8, 16, 21, 28, 29
    assert len(value) == 29
    assert kinds(run("DsHeuristics", mini_export(domain=dom(ds_heuristics=value)))) == {
        "list_object": "Info", "anonymous": "High", "anon_nspi": "Medium", "adminsdex": "Medium", "uniqueness": "Medium", "ldap_authz": "Medium"}
    assert run("DsHeuristics", mini_export(domain=dom())) == []


def test_smartcard_password_only_without_rotation():
    objects = [user("card", 1101, uac=512 | 0x40000, pwdLastSet=ft(400)), user("adm", 1102, uac=512 | 0x40000, pwdLastSet=ft(400)),
               user("fresh", 1103, uac=512 | 0x40000, pwdLastSet=ft(10))]
    exp = mini_export(objects, admins=["adm"], domain=dom(smartcard_rotation=False))
    assert {f.identity: f.severity for f in run("SmartcardPassword", exp)} == {"CORP\\card": "Medium", "CORP\\adm": "High"}
    assert run("SmartcardPassword", mini_export(objects, admins=["adm"], domain=dom())) == []


def test_unix_passwords_and_never_logged_on_users():
    year_ago = (NOW - dt.timedelta(days=365)).isoformat()
    exp = mini_export([user("nix", 1101, hasUnixPassword=True), user("ghost", 1102, lastLogonTimestamp=None, whenCreated=year_ago),
                       user("newbie", 1103, lastLogonTimestamp=None, whenCreated=(NOW - dt.timedelta(days=5)).isoformat())])
    assert {f.identity for f in run("UnixPasswords", exp)} == {"CORP\\nix"}
    assert {f.identity for f in run("InactiveUsers", exp)} == {"CORP\\ghost"}


def test_forest_functional_level():
    assert [f.key_extra for f in run("FunctionalLevel", mini_export(domain=dom(forest_functional_level="3")))] == ["forest"]


def test_gaps_when_domain_settings_missing():
    gaps = coverage_gaps(mini_export([user("u", 1101)]))
    for code in ("PasswordPolicy", "RecycleBin", "DsHeuristics", "BackupAge", "SmartcardPassword", "NtfrsSysvol", "SchemaVulnerableClass", "LapsDeployment", "PrimaryGroup"):
        assert code in gaps, code
    assert not set(coverage_gaps(mini_export([user("u", 1101, primaryGroupID=513)], domain=dom()))) & {"PasswordPolicy", "PrimaryGroup", "BackupAge"}


def test_functional_level_value_accepts_forest_mode():
    assert functional_level_value("Windows2016Forest") == 7 and functional_level_value("windows2003interimforest") == 1


def test_forest_level_finding_text_and_gap():
    got = run("FunctionalLevel", mini_export(domain=dom(forest_functional_level="Windows2008Forest")))
    assert [(f.key_extra, f.severity) for f in got] == [("forest", "Medium")] and "леса" in got[0].details["details"]
    assert run("FunctionalLevel", mini_export(domain=dom(forest_functional_level=None))) == []
    assert "FunctionalLevel" not in coverage_gaps(mini_export([user("u", 1101, primaryGroupID=513)], domain=dom(forest_functional_level=None)))
    gaps = coverage_gaps(mini_export([user("u", 1101, primaryGroupID=513)], domain=dom(forest_functional_level="WindowsThresholdForest")))
    assert "леса" in gaps["FunctionalLevel"]


def test_pso_note_is_partial_gap_of_password_policy():
    exp = mini_export([user("u", 1101, primaryGroupID=513)], domain=dom(), collector={"notes": ["PSO не найдены: при сборе не администратором домена они не видны"]})
    assert "PSO" in coverage_gaps(exp)["PasswordPolicy"]
    assert run("PasswordPolicy", mini_export(domain=dom(min_pwd_length=4), collector={"notes": ["PSO не прочитаны: отказ"]}))[0].key_extra == "min_length"


def test_laps_mixed_schema_flags_are_a_gap():
    exp = mini_export([user("u", 1101, primaryGroupID=513)], domain=dom(laps_legacy_schema=None, laps_schema=False))
    assert coverage_gaps(exp)["LapsDeployment"] == "схема LAPS прочитана не полностью"
    assert run("LapsDeployment", exp) == []


def test_laps_share_compared_before_rounding():
    pcs = [computer(f"PC{i}", 2000 + i, lapsNewExpiry=ft(-10)) for i in range(215)]
    pcs += [computer(f"BARE{i}", 3000 + i) for i in range(24)]   # 24 из 239 = 10,04 % → округляется до 10,0
    got = run("LapsDeployment", mini_export(pcs, domain=dom()))
    assert got[0].details["share"] == 10.0 and got[0].severity == "Medium"


def test_never_logged_on_threshold_matches_inactive_branch():
    exact = (NOW - dt.timedelta(days=90)).isoformat()
    exp = mini_export([user("edge", 1101, lastLogonTimestamp=None, whenCreated=exact), user("old", 1102, lastLogonTimestamp=ft(90))])
    assert {f.identity for f in run("InactiveUsers", exp)} == {"CORP\\edge", "CORP\\old"}
