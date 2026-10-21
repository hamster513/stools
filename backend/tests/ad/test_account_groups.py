from api.modules.ad.core.account_groups import account_groups
from api.modules.ad.core.export import ExportIndex
from tests.ad.mini import DN, computer, group, mini_export, rid, user


def _dn(sam: str) -> str:
    return f"CN={sam},CN=Users,{DN}"


def _groups(objects: list[dict], sid: str) -> list[tuple[str, bool, bool]]:
    got = account_groups(ExportIndex(mini_export(objects))).groups[sid]
    return [(g["name"], g["direct"], g["primary"]) for g in got]


def test_direct_and_nested():
    u1 = user("u1", 1101)
    objs = [u1, group("G1", rid(1201), [u1["dn"]]), group("G2", rid(1202), [_dn("G1")])]
    assert _groups(objs, u1["sid"]) == [("CORP\\G1", True, False), ("CORP\\G2", False, False)]
    got = account_groups(ExportIndex(mini_export(objs))).groups[u1["sid"]]
    assert [g["sid"] for g in got] == [rid(1201), rid(1202)]


def test_cycle_terminates():
    u1 = user("u1", 1101)
    objs = [u1, group("G1", rid(1201), [u1["dn"], _dn("G2")]), group("G2", rid(1202), [_dn("G1")])]
    assert _groups(objs, u1["sid"]) == [("CORP\\G1", True, False), ("CORP\\G2", False, False)]


def test_primary_group_and_its_parents():
    u1 = user("u1", 1101, primaryGroupID=513)
    objs = [u1, group("Domain Users", rid(513)), group("G3", rid(1203), [_dn("Domain Users")])]
    assert _groups(objs, u1["sid"]) == [("CORP\\Domain Users", True, True), ("CORP\\G3", False, False)]


def test_primary_group_also_in_member():
    u1 = user("u1", 1101, primaryGroupID=513)
    objs = [u1, group("Domain Users", rid(513), [u1["dn"]])]
    assert _groups(objs, u1["sid"]) == [("CORP\\Domain Users", True, True)]


def test_direct_wins_over_nested():
    u1 = user("u1", 1101)
    objs = [u1, group("G1", rid(1201), [u1["dn"]]), group("G2", rid(1202), [u1["dn"], _dn("G1")])]
    assert _groups(objs, u1["sid"]) == [("CORP\\G1", True, False), ("CORP\\G2", True, False)]


def test_foreign_member():
    fsp = "CN=S-1-5-21-9-9-9-1105,CN=ForeignSecurityPrincipals,DC=corp,DC=local"
    assert _groups([group("G1", rid(1201), [fsp])], "S-1-5-21-9-9-9-1105") == [("CORP\\G1", True, False)]


def test_disabled_and_computer_included():
    u1 = user("u1", 1101, uac=514)
    pc = computer("PC01", 1102)
    objs = [u1, pc, group("G1", rid(1201), [u1["dn"], pc["dn"]])]
    res = account_groups(ExportIndex(mini_export(objs)))
    assert [g["name"] for g in res.groups[u1["sid"]]] == ["CORP\\G1"]
    assert [g["name"] for g in res.groups[pc["sid"]]] == ["CORP\\G1"]
    assert res.groups[rid(502)] == []          # krbtgt: учётка есть, групп нет


def test_truncation_note():
    big = group("Big", rid(1201), [f"CN=x{i},CN=Users,{DN}" for i in range(1500)])
    notes = account_groups(ExportIndex(mini_export([big, group("Small", rid(1202), [_dn("x1")])]))).notes
    assert len(notes) == 1 and "CORP\\Big" in notes[0] and "1500" in notes[0]


def test_names():
    # Administrator в Domain Admins, Domain Admins в Administrators — базовые объекты mini_export.
    assert _groups([], rid(500)) == [("CORP\\Domain Admins", True, False), ("BUILTIN\\Administrators", False, False)]
