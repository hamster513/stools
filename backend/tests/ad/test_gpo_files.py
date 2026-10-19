import pytest

from api.modules.ad.core import gpo_files as g
from api.modules.ad.core.export import ExportIndex, GpoLink
from tests.ad.gpo_fixtures import AUDIT_CSV, GROUPS, LSA, WINLOGON, dword, preg, sz
from tests.ad.mini import DN, DOMAIN_SID, dc, gpo, link, mini_export


def test_registry_pol_types_and_delete_markers():
    data = preg((LSA, "LmCompatibilityLevel", 4, dword(2)), (WINLOGON, "DefaultUserName", 1, sz("svc;odd]name")),
                ("Software\\Policies\\X", "**del.Old", 1, sz(" ")), ("Software\\Policies\\X", "List", 7, "a\x00b\x00\x00".encode("utf-16-le")))
    got = g.parse_registry_pol(data)
    assert [(v.value, v.data) for v in got] == [("LmCompatibilityLevel", 2), ("DefaultUserName", "svc;odd]name"), ("List", ["a", "b"])]


def test_registry_pol_rejects_garbage():
    with pytest.raises(ValueError):
        g.parse_registry_pol(b"not a policy file")
    with pytest.raises(ValueError):
        g.parse_registry_pol(preg((LSA, "NoLMHash", 4, dword(1)))[:-6])       # обрезан


def test_whitelist_and_redaction():
    assert g.keep_registry(LSA.upper(), "nolmhash") and not g.keep_registry("Software\\Vendor\\App", "Secret")
    assert g.keep_registry("Software\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths", "\\\\*\\SYSVOL")
    pw = g.redact(g.RegistryValue(WINLOGON, "DefaultPassword", 1, "P@ssw0rd"))
    assert pw.data == "" and g.redact(g.RegistryValue(LSA, "NoLMHash", 4, 1)).data == 1


INF = """[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 7
ClearTextPassword = 1
[Registry Values]
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,2
[Group Membership]
*S-1-5-32-544__Members = *S-1-5-11,CORP\\helpdesk
*S-1-5-21-1-2-3-1105__Memberof = *S-1-5-32-544
[Privilege Rights]
SeDebugPrivilege = *S-1-5-32-544
"""


def test_inf_sections():
    s = g.parse_inf(INF)
    assert s["system access"]["ClearTextPassword"] == "1"
    assert g.inf_registry_values(s) == {"machine\\system\\currentcontrolset\\control\\lsa\\lmcompatibilitylevel": (4, "2")}
    assert g.inf_group_membership(s) == [("S-1-5-32-544", "members", ["S-1-5-11", "CORP\\helpdesk"]), ("S-1-5-21-1-2-3-1105", "memberof", ["S-1-5-32-544"])]


def test_gpp_items_never_carry_the_password():
    items = g.parse_gpp("Groups.xml", "machine", GROUPS)
    assert items[0] == {"scope": "machine", "file": "Groups.xml", "kind": "User", "name": "localadm", "user": "localadm", "cpassword": True,
                        "action": "U", "members": [], "group_sid": "", "group_name": "", "path": ""}
    assert items[1]["group_sid"] == "S-1-5-32-544" and items[1]["members"] == [{"name": "CORP\\Domain Users", "sid": "S-1-5-21-1000-2000-3000-513", "action": "ADD"}]
    assert "j1Uyj3Vx8TY9" not in repr(items)


def test_gpp_rejects_doctype():
    with pytest.raises(ValueError):
        g.parse_gpp("Groups.xml", "machine", '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><Groups/>')


def test_gpp_rejects_oversized_and_broken_xml():
    with pytest.raises(ValueError):
        g.parse_gpp("Files.xml", "user", "<Files>" + " " * g.MAX_GPO_FILE + "</Files>")
    with pytest.raises(ValueError):
        g.parse_gpp("Files.xml", "user", "<Files><File>")


def test_audit_scripts_gplink():
    csv = AUDIT_CSV
    assert g.parse_audit_csv(csv) == [{"subcategory": "0cce923f-69ae-11d9-bed3-505054503030", "setting": 3}]
    ini = "[Logon]\r\n0CmdLine=\\\\fs01.other.local\\share\\run.bat\r\n0Parameters=/q\r\n[Logoff]\r\n"
    assert g.parse_scripts_ini(ini, "user") == [{"scope": "user", "phase": "logon", "command": "\\\\fs01.other.local\\share\\run.bat", "parameters": "/q"}]
    link = "[LDAP://cn={A},cn=policies,cn=system,DC=corp,DC=local;0][LDAP://CN={B},CN=Policies,CN=System,DC=corp,DC=local;3]"
    assert g.parse_gplink(link) == [("cn={a},cn=policies,cn=system,dc=corp,dc=local", False, False), ("cn={b},cn=policies,cn=system,dc=corp,dc=local", True, True)]


def test_gpo_files_paths():
    paths = {p.lower() for p in g.GPO_FILES.values()}
    assert {"machine\\registry.pol", "user\\registry.pol", "machine\\preferences\\groups\\groups.xml",
            "machine\\microsoft\\windows nt\\audit\\audit.csv", "user\\scripts\\scripts.ini", "machine\\scripts\\psscripts.ini"} <= paths


# ---- Индекс: привязка GPO -------------------------------------------------

DC_GPO = "{22222222-2222-2222-2222-222222222222}"
ROOT_GPO = "{33333333-3333-3333-3333-333333333333}"
STAFF_GPO = "{44444444-4444-4444-4444-444444444444}"
OFF_GPO = "{55555555-5555-5555-5555-555555555555}"
USER_ONLY_GPO = "{66666666-6666-6666-6666-666666666666}"


def _dn(guid: str) -> str:
    return f"CN={guid},CN=Policies,CN=System,{DN}"


def _linked_index() -> ExportIndex:
    exp = mini_export([
        {"dn": DN, "class": "domainDNS", "sid": DOMAIN_SID, "gpLink": link(_dn(ROOT_GPO), _dn(USER_ONLY_GPO))},
        {"dn": f"OU=Domain Controllers,{DN}", "class": "organizationalUnit", "gpLink": link(_dn(DC_GPO)) + f"[LDAP://{_dn(OFF_GPO)};1]"},
        {"dn": f"OU=Staff,{DN}", "class": "organizationalUnit", "gpLink": link(_dn(STAFF_GPO)), "gpOptions": 0},
        dc("DC01", 1000),
        gpo("DC policy", DC_GPO), gpo("Root policy", ROOT_GPO), gpo("Staff policy", STAFF_GPO),
        gpo("Disabled link", OFF_GPO), gpo("Users only", USER_ONLY_GPO, flags=2),
    ])
    return ExportIndex(exp)


def test_applies_to_dcs():
    idx = _linked_index()
    by_guid = {o.cn: o for o in idx.objects("groupPolicyContainer")}
    assert idx.applies_to_dcs(by_guid[DC_GPO]) is True
    assert idx.applies_to_dcs(by_guid[ROOT_GPO]) is True
    assert idx.applies_to_dcs(by_guid[STAFF_GPO]) is False
    assert idx.applies_to_dcs(by_guid[OFF_GPO]) is False
    assert idx.applies_to_dcs(by_guid[USER_ONLY_GPO]) is False


def test_gpo_links_list_only_enabled_links():
    idx = _linked_index()
    by_guid = {o.cn: o for o in idx.objects("groupPolicyContainer")}
    assert idx.gpo_links(by_guid[STAFF_GPO]) == [GpoLink(f"OU=Staff,{DN}", enforced=False, disabled=False)]
    assert idx.gpo_links(by_guid[OFF_GPO]) == []
    assert idx.gpo_link_map is not None and idx.gpo_link_map[_dn(OFF_GPO).lower()][0].disabled is True


def test_link_unknown_without_any_gplink():
    idx = ExportIndex(mini_export([dc("DC01", 1000), gpo("DC policy", DC_GPO)]))
    pol = idx.objects("groupPolicyContainer")[0]
    assert idx.gpo_link_map is None and idx.gpo_links(pol) is None and idx.applies_to_dcs(pol) is None


def test_gpo_block_and_inf_sections():
    dn = _dn(DC_GPO)
    exp = mini_export([gpo("DC policy", DC_GPO)], sysvol={dn: {"GptTmpl.inf": INF}}, gpo={dn.lower(): {
        "registry": [{"scope": "machine", "key": LSA, "value": "NoLMHash", "type": 4, "data": 0}],
        "gpp": [{"scope": "machine", "file": "Groups.xml", "kind": "User", "name": "localadm", "cpassword": True}],
        "audit": [{"subcategory": "0cce923f-69ae-11d9-bed3-505054503030", "setting": 3}],
        "scripts": [{"scope": "user", "phase": "logon", "command": "run.bat"}],
        "notes": "Registry.pol: файл повреждён",
    }})
    idx = ExportIndex(exp)
    pol = idx.objects("groupPolicyContainer")[0]
    data = idx.gpo_data(pol)
    assert data is not None and data.registry[0].data == 0 and data.gpp[0].cpassword is True and data.acl is None
    assert data.audit[0].setting == 3 and data.scripts[0].parameters == "" and data.notes == ["Registry.pol: файл повреждён"]
    assert idx.inf_sections(pol)["system access"]["ClearTextPassword"] == "1"
    assert idx.inf_sections(pol) is idx.inf_sections(pol)
    assert ExportIndex(mini_export([gpo("DC policy", DC_GPO)])).gpo_data(pol) is None
