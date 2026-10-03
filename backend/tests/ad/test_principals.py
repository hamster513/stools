from api.modules.ad.core.checks import principals
from api.modules.ad.core.checks.adcs_rules import requester_kind
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex
from tests.ad.mini import DN, computer, dc, group, mini_export, rid, user


def _idx(objects=(), **kw):
    return ExportIndex(mini_export(objects, **kw))


def test_mini_export_is_valid_and_has_base_objects():
    idx = _idx()
    assert idx.group_for_rid(512) is not None and idx.group_for_rid(544) is not None
    assert idx.by_sid[rid(500)].sam == "Administrator"


def test_dc_detection():
    idx = _idx([dc("DC01", 1001), computer("PC01", 1002), dc("RODC1", 1003, uac=0x4000000 | 0x1000)])
    assert {d.name for d in idx.dcs} == {"DC01", "RODC1"}


def test_admins_are_recursive_members_and_rid_500():
    nested = group("Tier0", rid(1200), members=[f"CN=bob,CN=Users,{DN}"])
    objects = [user("alice", 1101), user("bob", 1102), user("carol", 1103), user("off", 1104, uac=514), nested]
    exp = mini_export(objects, admins=["alice", "off"])
    da = next(o for o in exp.objects if o.sid == rid(512))
    da.member.append(nested.get("dn"))
    idx = ExportIndex(exp)
    names = {idx.by_dn[d].sam for d in principals.admin_dns(idx, AdConfig())}
    assert names == {"Administrator", "alice", "bob"}  # выключенный off и посторонняя carol — нет


def test_protected_objects_include_groups_members_and_krbtgt():
    idx = _idx([user("alice", 1101), user("carol", 1103)], admins=["alice"])
    prot = principals.protected_dns(idx)
    assert f"cn=alice,cn=users,{DN}".lower() in prot and idx.by_sid[rid(502)].dn.lower() in prot
    assert f"cn=carol,cn=users,{DN}".lower() not in prot


def test_tier0_kind_uses_tier0_rids_not_adcs():
    idx, cfg = _idx(), AdConfig()
    assert principals.tier0_kind(idx, cfg, rid(512)) == "safe"
    assert principals.tier0_kind(idx, cfg, rid(517)) == "other"   # Cert Publishers безопасны только для AD CS
    assert principals.tier0_kind(idx, cfg, "S-1-5-11") == "broad"


def test_disabled_rid_500_is_not_admin():
    idx = _idx([user("Administrator", 500, uac=514)])
    assert idx.by_sid[rid(500)].dn.lower() not in principals.admin_dns(idx, AdConfig())


def test_ca_admin_names_are_safe_only_for_adcs():
    idx = _idx([group("CA Admins", rid(1300))])
    cfg = AdConfig(adcs_safe_principals=["CORP\\CA Admins"])
    assert requester_kind(idx, cfg, rid(1300)) == "safe"
    assert principals.tier0_kind(idx, cfg, rid(1300)) == "other"


def test_domain_controllers_are_protected_without_membership():
    idx = _idx([dc("DC01", 1001)])
    assert f"cn=dc01,ou=domain controllers,{DN}".lower() in principals.protected_dns(idx)
