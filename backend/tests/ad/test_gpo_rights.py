from api.modules.ad.core.export import AdObject, ExportIndex
from api.modules.ad.core.gpo_rights import gpo_rights, host_id
from tests.ad.mini import DN, DOMAIN_SID, computer, gpo, group, link, mini_export, rid

WS = f"OU=Ws,{DN}"
LAB = f"OU=Lab,{WS}"
G1 = rid(1201)
G2 = rid(1202)


def _ou(dn: str, **extra):
    return {"dn": dn, "class": "organizationalUnit", **extra}


def _pc(name: str, r: int, parent: str, **extra):
    return computer(name, r, dn=f"CN={name},{parent}", **extra)


def _run(objects, g, inf=None, gpp=None, **top):
    sysvol = {g["dn"]: {"GptTmpl.inf": inf}} if inf is not None else {}
    data = {g["dn"]: {"gpp": gpp}} if gpp is not None else None
    export = mini_export([g, group("G1", G1), group("G2", G2), *objects], sysvol=sysvol, gpo=data, **top)
    return gpo_rights(ExportIndex(export))


def _inf(*lines: str) -> str:
    return "[Group Membership]\n" + "\n".join(lines) + "\n"


def _gpp(members, **extra):
    item = {"scope": "machine", "file": "Groups.xml", "kind": "Group", "name": "Administrators (built-in)", "group_sid": "S-1-5-32-544",
            "members": members, **extra}
    return [item]


def test_restricted_members_on_ou():
    g = gpo("Admins")
    objs = [_ou(WS, gpLink=link(g["dn"])), _pc("PC1", 1101, WS), computer("PC2", 1102)]
    got = _run(objs, g, _inf(f"*S-1-5-32-544__Members = *{G1}"))
    assert got["links_known"] is True and got["files_known"] is True
    assert got["notes"] == []
    assert got["rights"] == [{
        "group_sid": G1, "group_name": "CORP\\G1", "subject_class": "group",
        "local_group": "Administrators", "local_group_sid": "S-1-5-32-544",
        "via": "restricted_groups", "gpo": {"name": "Admins", "dn": g["dn"]},
        "action": "member", "filtered": False,
        "scope": [{"dn": WS, "enforced": False}],
        "hosts": ["pc1.corp.local"], "hosts_total": 1, "notes": [],
    }]


def test_memberof():
    g = gpo("Rdp")
    got = _run([_ou(WS, gpLink=link(g["dn"])), _pc("PC1", 1101, WS)], g, _inf(f"*{G1}__Memberof = *S-1-5-32-555"))
    [r] = got["rights"]
    assert (r["group_sid"], r["local_group"], r["local_group_sid"], r["action"]) == (G1, "Remote Desktop Users", "S-1-5-32-555", "memberof")


def test_block_inheritance():
    g = gpo("Root")
    inf = _inf(f"*S-1-5-32-544__Members = *{G1}")
    objs = [_ou(WS), _ou(LAB, gpOptions=1), _pc("PC1", 1101, WS), _pc("PC3", 1103, LAB)]
    root = {"dn": DN, "class": "domainDNS", "sid": DOMAIN_SID}
    plain = _run([{**root, "gpLink": link(g["dn"])}, *objs], g, inf)
    assert plain["rights"][0]["hosts"] == ["pc1.corp.local"]
    enforced = _run([{**root, "gpLink": f"[LDAP://{g['dn']};2]"}, *objs], g, inf)
    [r] = enforced["rights"]
    assert r["hosts"] == ["pc1.corp.local", "pc3.corp.local"] and r["hosts_total"] == 2
    assert r["scope"] == [{"dn": DN, "enforced": True}]
    # Ссылка на саму OU с блокировкой наследования: блокировка её компьютеров не касается.
    own = _run([_ou(WS), _ou(LAB, gpOptions=1, gpLink=link(g["dn"])), _pc("PC3", 1103, LAB)], g, inf)
    assert own["rights"][0]["hosts"] == ["pc3.corp.local"]


def test_site_link():
    g = gpo("Site")
    site = {"dn": "CN=Moscow,CN=Sites,CN=Configuration,DC=corp,DC=local", "class": "site", "gpLink": link(g["dn"])}
    got = _run([site, _pc("PC1", 1101, WS), _ou(WS)], g, _inf(f"*S-1-5-32-544__Members = *{G1}"))
    [r] = got["rights"]
    assert r["scope"] == [{"dn": site["dn"], "enforced": False}]
    assert r["hosts"] == [] and r["hosts_total"] == 0
    assert any("сайт" in n for n in r["notes"])


def test_gpp_actions():
    g = gpo("Gpp")
    objs = [_ou(WS, gpLink=link(g["dn"])), _pc("PC1", 1101, WS)]
    members = [{"name": "CORP\\G1", "sid": G1, "action": "ADD"}, {"name": "CORP\\G2", "sid": G2, "action": "REMOVE"}]
    got = _run(objs, g, gpp=_gpp(members, filtered=True))
    assert [(r["group_name"], r["action"], r["filtered"], r["via"], r["local_group"]) for r in got["rights"]] == [
        ("CORP\\G1", "add", True, "gpp", "Administrators"), ("CORP\\G2", "delete", True, "gpp", "Administrators")]
    got = _run(objs, g, gpp=_gpp(members, delete_all=True))
    assert [(r["action"], r["filtered"]) for r in got["rights"]] == [("replace", None), ("delete", None)]
    assert got["rights"][0]["hosts"] == ["pc1.corp.local"]


def test_gpp_delete_all_without_members_note():
    g = gpo("Gpp")
    got = _run([_ou(WS, gpLink=link(g["dn"]))], g, gpp=_gpp([], delete_all=True))
    assert got["rights"] == []
    assert any("Gpp" in n and "очищает" in n and "Administrators" in n for n in got["notes"])


def test_gpp_user_scope_and_delete_item_skipped():
    g = gpo("Gpp")
    members = [{"name": "CORP\\G1", "sid": G1, "action": "ADD"}]
    gpp = [*_gpp(members, scope="user"), *_gpp(members, action="D")]
    got = _run([_ou(WS, gpLink=link(g["dn"]))], g, gpp=gpp)
    assert got["rights"] == []
    assert len(got["notes"]) == 1 and "1" in got["notes"][0] and "пользовательск" in got["notes"][0]


def test_domain_group_target_skipped():
    g = gpo("Dom")
    got = _run([_ou(WS, gpLink=link(g["dn"]))], g, _inf(f"*{G2}__Members = *{G1}", f"CORP\\G2__Members = *{G1}"))
    assert got["rights"] == []
    assert got["notes"] == ["GPO «Dom»: цель CORP\\G2 — доменная группа, не локальная"]


def test_target_names_resolved():
    g = gpo("Names")
    inf = _inf(f"BUILTIN\\Administrators__Members = *{G1}", f"Remote Desktop Users (built-in)__Members = *{G1}",
               f"LocalCustom__Members = *{G1}", f"*S-1-5-32-599__Members = *{G1}")
    got = _run([_ou(WS, gpLink=link(g["dn"]))], g, inf)
    assert sorted((r["local_group"], r["local_group_sid"]) for r in got["rights"]) == [
        ("Administrators", "S-1-5-32-544"), ("LocalCustom", ""), ("RID-599", "S-1-5-32-599"), ("Remote Desktop Users", "S-1-5-32-555")]


def test_name_subject_resolved():
    g = gpo("Names")
    got = _run([_ou(WS, gpLink=link(g["dn"]))], g, _inf("*S-1-5-32-544__Members = CORP\\G1,OTHER\\x,*S-1-5-11"))
    got_map = {r["group_name"]: (r["group_sid"], r["subject_class"]) for r in got["rights"]}
    assert got_map == {"CORP\\G1": (G1, "group"), "OTHER\\x": ("", ""), "NT AUTHORITY\\Authenticated Users": ("S-1-5-11", "well_known")}


def test_machine_part_disabled_and_unlinked():
    g = gpo("Off", flags=2)
    inf = _inf(f"*S-1-5-32-544__Members = *{G1}")
    got = _run([_ou(WS, gpLink=link(g["dn"]))], g, inf)
    assert got["rights"] == [] and got["notes"] == []
    u = gpo("Unlinked")
    got = _run([_ou(WS, gpLink="")], u, inf)
    assert got["rights"] == []
    assert len(got["notes"]) == 1 and "1" in got["notes"][0]
    # Выключенная ссылка — тоже не привязана.
    got = _run([_ou(WS, gpLink=f"[LDAP://{u['dn']};1]")], u, inf)
    assert got["rights"] == [] and len(got["notes"]) == 1


def test_links_unknown():
    g = gpo("Old")
    got = _run([_ou(WS), _pc("PC1", 1101, WS)], g, _inf(f"*S-1-5-32-544__Members = *{G1}"))
    assert got["links_known"] is False
    [r] = got["rights"]
    assert (r["scope"], r["hosts"], r["hosts_total"]) == ([], [], 0)


def test_files_unknown():
    g = gpo("Nofiles")
    got = _run([_ou(WS, gpLink=link(g["dn"]))], g)
    assert got == {"links_known": True, "files_known": False, "notes": [], "rights": []}


def test_host_id_fallback():
    assert host_id(AdObject.model_validate(computer("PC9", 1109, dNSHostName=""))) == "PC9"
    assert host_id(AdObject.model_validate(computer("PC8", 1108))) == "pc8.corp.local"


def test_host_list_shared_and_order():
    g = gpo("B-policy")
    a = gpo("A-policy", "{22222222-2222-2222-2222-222222222222}")
    objs = [a, _ou(WS, gpLink=link(g["dn"], a["dn"])), _pc("PC2", 1102, WS), _pc("PC1", 1101, WS)]
    sysvol = {g["dn"]: {"GptTmpl.inf": _inf(f"*S-1-5-32-555__Members = *{G2},*{G1}")},
              a["dn"]: {"GptTmpl.inf": _inf(f"*S-1-5-32-544__Members = *{G1}")}}
    export = mini_export([g, group("G1", G1), group("G2", G2), *objs], sysvol=sysvol)
    got = gpo_rights(ExportIndex(export))
    assert [(r["gpo"]["name"], r["local_group"], r["group_name"]) for r in got["rights"]] == [
        ("A-policy", "Administrators", "CORP\\G1"), ("B-policy", "Remote Desktop Users", "CORP\\G1"),
        ("B-policy", "Remote Desktop Users", "CORP\\G2")]
    assert got["rights"][0]["hosts"] == ["pc1.corp.local", "pc2.corp.local"]
    assert got["rights"][1]["hosts"] is got["rights"][2]["hosts"]


def test_empty_members_note():
    g = gpo("Clear")
    got = _run([_ou(WS, gpLink=link(g["dn"]))], g, _inf("*S-1-5-32-544__Members ="))
    assert got["rights"] == []
    assert got["notes"] == ["GPO «Clear»: Restricted Groups очищает группу Administrators"]


def test_localized_builtin_target():
    g = gpo("Local")
    adm = {"dn": f"CN=Администраторы,CN=Builtin,{DN}", "class": "group", "sid": "S-1-5-32-544", "sam": "Администраторы", "name": "Администраторы"}
    rdp = {"dn": f"CN=Пользователи удаленного рабочего стола,CN=Builtin,{DN}", "class": "group", "sid": "S-1-5-32-555",
           "sam": "Пользователи удаленного рабочего стола", "name": "Пользователи удаленного рабочего стола"}
    inf = _inf(f"Администраторы__Members = *{G1}", f"BUILTIN\\Пользователи удаленного рабочего стола__Members = *{G2}")
    # GPP без groupSid: имя с префиксом BUILTIN\.
    gpp = _gpp([{"name": "CORP\\G2", "sid": G2, "action": "ADD"}], group_sid="", name="BUILTIN\\Администраторы", group_name="BUILTIN\\Администраторы")
    got = _run([adm, rdp, _ou(WS, gpLink=link(g["dn"]))], g, inf, gpp=gpp)
    assert got["notes"] == []
    assert sorted((r["via"], r["local_group"], r["local_group_sid"], r["group_sid"]) for r in got["rights"]) == [
        ("gpp", "Administrators", "S-1-5-32-544", G2),
        ("restricted_groups", "Administrators", "S-1-5-32-544", G1),
        ("restricted_groups", "Remote Desktop Users", "S-1-5-32-555", G2)]


def test_dn_matching():
    g = gpo("Ws")
    old_ws = f"OU=OldWs,{DN}"
    objs = [_ou(WS, gpLink=link(g["dn"])), _ou(old_ws), _pc("PC1", 1101, old_ws),
            computer("PC2", 1102, dn="CN=PC2,ou=ws,dc=CORP,dc=local")]
    got = _run(objs, g, _inf(f"*S-1-5-32-544__Members = *{G1}"))
    assert got["rights"][0]["hosts"] == ["pc2.corp.local"]


def test_well_known_subject():
    g = gpo("Wk")
    got = _run([_ou(WS, gpLink=link(g["dn"]))], g, _inf("*S-1-5-32-544__Members = *S-1-5-11,*S-1-1-0,*S-1-5-32-545,*S-1-5-21-9-9-9-1105"))
    got_map = {r["group_sid"]: r["subject_class"] for r in got["rights"]}
    # BUILTIN Users нет в выгрузке, чужой доменный SID — тоже: не well_known.
    assert got_map == {"S-1-5-11": "well_known", "S-1-1-0": "well_known", "S-1-5-32-545": "", "S-1-5-21-9-9-9-1105": ""}
    # BUILTIN-группа из выгрузки — group.
    got = _run([_ou(WS, gpLink=link(g["dn"]))], g, _inf("*S-1-5-32-555__Members = *S-1-5-32-544"))
    assert [(r["group_sid"], r["subject_class"]) for r in got["rights"]] == [("S-1-5-32-544", "group")]


def test_gpp_disabled_item_skipped():
    g = gpo("Gpp")
    members = [{"name": "CORP\\G1", "sid": G1, "action": "ADD"}]
    got = _run([_ou(WS, gpLink=link(g["dn"]))], g, gpp=_gpp(members, disabled=True, delete_all=True))
    assert got["rights"] == [] and got["notes"] == []
    # Выгрузка старого сборщика (disabled нет) — как включённый.
    got = _run([_ou(WS, gpLink=link(g["dn"]))], g, gpp=_gpp(members))
    assert [r["group_sid"] for r in got["rights"]] == [G1]


def test_gpp_replace_action():
    g = gpo("Gpp")
    objs = [_ou(WS, gpLink=link(g["dn"]))]
    members = [{"name": "CORP\\G1", "sid": G1, "action": "ADD"}, {"name": "CORP\\G2", "sid": G2, "action": "REMOVE"}]
    got = _run(objs, g, gpp=_gpp(members, action="r", delete_all=False))
    assert [(r["group_sid"], r["action"]) for r in got["rights"]] == [(G1, "replace"), (G2, "delete")]
    got = _run(objs, g, gpp=_gpp([], action="R"))
    assert got["rights"] == [] and got["notes"] == ["GPO «Gpp»: GPP очищает группу Administrators"]


def test_gpp_local_group_named_like_domain_group():
    g = gpo("Gpp")
    helpdesk = group("Helpdesk", rid(1210))
    gpp = _gpp([{"name": "CORP\\G1", "sid": G1, "action": "ADD"}], group_sid="", name="Helpdesk", group_name="Helpdesk")
    got = _run([helpdesk, _ou(WS, gpLink=link(g["dn"]))], g, gpp=gpp)
    assert got["notes"] == []
    assert [(r["local_group"], r["local_group_sid"], r["via"]) for r in got["rights"]] == [("Helpdesk", "", "gpp")]


def test_bare_local_account_name():
    g = gpo("Adm")
    got = _run([_ou(WS, gpLink=link(g["dn"]))], g, _inf("*S-1-5-32-544__Members = Administrator,CORP\\Administrator"))
    assert sorted((r["group_name"], r["group_sid"], r["subject_class"]) for r in got["rights"]) == [
        ("Administrator", "", ""), ("CORP\\Administrator", rid(500), "user")]


def test_gpp_bad_sid_resolved_by_name():
    g = gpo("Gpp")
    gpp = _gpp([{"name": "CORP\\G1", "sid": "S-1-5-21-1-2-3-abc", "action": "ADD"}], group_sid="S-1-5-32-abc")
    got = _run([_ou(WS, gpLink=link(g["dn"]))], g, gpp=gpp)
    assert [(r["group_sid"], r["group_name"], r["local_group"], r["local_group_sid"]) for r in got["rights"]] == [
        (G1, "CORP\\G1", "Administrators", "S-1-5-32-544")]


def test_files_read_incompletely_note():
    g = gpo("Partial")
    rel = "Machine\\Preferences\\Groups\\Groups.xml"
    for note in (f"{rel}: не прочитан по SMB", f"{rel}: не прочитан (Access is denied.)",
                 "MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf: не прочитан по SMB",
                 "Machine: папка не прочитана по SMB (STATUS_ACCESS_DENIED)", "папка GPO не прочитана (Access is denied.)",
                 "путь GPO вне домена (fs01.other.local) — не читается"):
        export = mini_export([g, _ou(WS, gpLink=link(g["dn"]))], gpo={g["dn"]: {"notes": [note]}})
        got = gpo_rights(ExportIndex(export))
        assert got["notes"] == ["GPO «Partial»: файлы прочитаны не полностью — назначения групп могут быть неполными"], note
    # Отказ, не касающийся групп, — без оговорки.
    export = mini_export([g, _ou(WS, gpLink=link(g["dn"]))], gpo={g["dn"]: {"notes": ["Machine\\Registry.pol: не прочитан по SMB"]}})
    assert gpo_rights(ExportIndex(export))["notes"] == []
