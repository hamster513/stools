import base64

import pytest

from api.modules.ad.core import sd
from api.modules.ad.core.checks.domain import functional_level_value
from api.modules.ad.core.config import AdConfig
from tests.ad.mini import DN, b64sd, group, mini_export, rid, run, user


def test_too_many_admins_is_one_domain_finding():
    names = [f"a{i}" for i in range(4)]
    exp = mini_export([user(n, 1101 + i) for i, n in enumerate(names)], admins=names)
    cfg = AdConfig(admins_max=3)
    got = run("TooManyAdmins", exp, cfg)          # 4 + Administrator = 5 > 3
    assert len(got) == 1 and got[0].severity == "Medium" and got[0].details["count"] == 5
    assert run("TooManyAdmins", exp, AdConfig(admins_max=5)) == []


def test_functional_level():
    assert [f.severity for f in run("FunctionalLevel", mini_export(domain={"functional_level": "3"}))] == ["Medium"]
    assert [f.severity for f in run("FunctionalLevel", mini_export(domain={"functional_level": "6"}))] == ["Low"]
    assert run("FunctionalLevel", mini_export(domain={"functional_level": "7"})) == []
    assert run("FunctionalLevel", mini_export(domain={"functional_level": ""})) == []


@pytest.mark.parametrize(("raw", "level"), [("3", 3), ("Windows2008Domain", 3), ("windows2012r2domain", 6), ("2016", 7), ("garbage", None)])
def test_functional_level_value(raw, level):
    assert functional_level_value(raw) == level


def test_functional_level_from_powershell_domain_mode():
    assert [f.severity for f in run("FunctionalLevel", mini_export(domain={"functional_level": "Windows2008Domain"}))] == ["Medium"]


def test_pre_windows_2000_access():
    fsp = lambda s: f"CN={s},CN=ForeignSecurityPrincipals,{DN}"
    grp = group("Pre-Windows 2000 Compatible Access", "S-1-5-32-554", [fsp("S-1-5-7"), fsp("S-1-5-11"), f"CN=u1,CN=Users,{DN}"])
    got = {f.identity: f.severity for f in run("PreWin2000Access", mini_export([grp, user("u1", 1101)]))}
    assert got == {"NT AUTHORITY\\ANONYMOUS LOGON": "High", "NT AUTHORITY\\Authenticated Users": "Low", "CORP\\u1": "Low"}


def test_domain_root_acl():
    exp = mini_export([user("helpdesk", 1101)])
    root = next(o for o in exp.objects if o.cls == "domainDNS")
    root.sd = b64sd([
        sd.build_ace(rid(512), sd.GENERIC_ALL),
        sd.build_ace(rid(1101), sd.WRITE_DACL),
        sd.build_ace("S-1-5-11", sd.GENERIC_ALL),
        sd.build_ace(rid(513), sd.WRITE_OWNER, flags=sd.ACE_FLAG_INHERIT_ONLY),   # только на потомков — не находка
    ])
    got = {f.identity: (f.severity, f.right) for f in run("DomainRootAcl", exp)}
    assert got == {"CORP\\helpdesk": ("High", "WriteDacl"), "NT AUTHORITY\\Authenticated Users": ("Critical", "GenericAll")}


def test_pre_windows_2000_everyone_is_high():
    grp = group("Pre-Windows 2000 Compatible Access", "S-1-5-32-554", [f"CN=S-1-1-0,CN=ForeignSecurityPrincipals,{DN}"])
    assert [f.severity for f in run("PreWin2000Access", mini_export([grp]))] == ["High"]


def test_domain_root_unsafe_owner_and_self_skipped():
    exp = mini_export([user("helpdesk", 1101)])
    root = next(o for o in exp.objects if o.cls == "domainDNS")
    root.sd = base64.b64encode(sd.build_sd([sd.build_ace(rid(512), sd.GENERIC_ALL), sd.build_ace("S-1-5-10", sd.GENERIC_ALL)], owner=rid(1101))).decode()
    assert [(f.identity, f.right) for f in run("DomainRootAcl", exp)] == [("CORP\\helpdesk", "owner")]
