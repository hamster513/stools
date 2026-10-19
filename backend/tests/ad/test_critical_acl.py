import uuid

from api.modules.ad.core import sd
from api.modules.ad.core.checks.coverage import coverage_gaps
from api.modules.ad.core.config import AdConfig
from tests.ad.mini import DN, b64sd, dc, group, mini_export, rid, run, user

MEMBER = uuid.UUID("bf9679c0-0de6-11d0-a285-00aa003049e2")
RESET = uuid.UUID("00299570-246d-11d0-a768-00aa006e0529")
DMSA = "0feb936f-47b3-49f2-9386-1dedc2c23765"
NEW = {"collector": {"kind": "ldap", "version": "1.1", "critical_acl": True}}


def test_critical_object_acl_rights_and_kinds():
    dns_admins = group("DnsAdmins", rid(1150), [f"CN=dnsadm,CN=Users,{DN}"], sd=b64sd([
        sd.build_ace(rid(512), sd.GENERIC_ALL),
        sd.build_ace(rid(1101), sd.WRITE_PROPERTY, object_type=MEMBER),
        sd.build_ace("S-1-5-11", sd.SELF_WRITE, object_type=MEMBER),
        sd.build_ace(rid(1102), sd.WRITE_PROPERTY, object_type=uuid.UUID("bf967a7f-0de6-11d0-a285-00aa003049e2")),  # userCertificate — не опасно
    ]))
    target = user("dnsadm", 1103, sd=b64sd([sd.build_ace(rid(1101), sd.EXTENDED_RIGHT, object_type=RESET), sd.build_ace("S-1-5-10", sd.GENERIC_ALL)]))
    outsider = user("plain", 1104, sd=b64sd([sd.build_ace(rid(1101), sd.GENERIC_ALL)]))      # не критичный объект
    exp = mini_export([user("helpdesk", 1101), user("certsvc", 1102), dns_admins, target, outsider], **NEW)
    got = {(f.target.split(",")[0], f.identity): (f.severity, f.right) for f in run("CriticalObjectAcl", exp)}
    assert got == {("CN=DnsAdmins", "CORP\\helpdesk"): ("High", "WriteMember"),
                   ("CN=DnsAdmins", "NT AUTHORITY\\Authenticated Users"): ("Critical", "AddSelf"),
                   ("CN=dnsadm", "CORP\\helpdesk"): ("High", "ResetPassword")}


def test_big_group_counts_as_broad_and_adminsdholder_aces_are_skipped():
    staff = [user(f"s{i}", 2000 + i) for i in range(4)]
    big = group("Staff", rid(1300), [s["dn"] for s in staff])
    holder_ace = sd.build_ace(rid(1300), sd.WRITE_DACL)
    holder = {"dn": f"CN=AdminSDHolder,CN=System,{DN}", "class": "container", "sd": b64sd([holder_ace])}
    adm = user("adm", 1101, adminCount=1, sd=b64sd([holder_ace, sd.build_ace(rid(1300), sd.WRITE_OWNER)]))
    exp = mini_export([*staff, big, holder, adm], admins=["adm"], **NEW)
    got = run("CriticalObjectAcl", exp, AdConfig(control_path_many=3))
    assert [(f.identity, f.severity, f.right, f.details["effective_principals"]) for f in got] == [("CORP\\Staff", "Critical", "WriteOwner", 4)]


def ou(name, aces):
    return {"dn": f"OU={name},{DN}", "class": "organizationalUnit", "sd": b64sd(aces)}


def test_bad_successor():
    objects = [user("helpdesk", 1101),
               ou("Servers", [sd.build_ace(rid(1101), sd.CREATE_CHILD), sd.build_ace(rid(512), sd.GENERIC_ALL)]),
               ou("Apps", [sd.build_ace("S-1-5-11", sd.CREATE_CHILD, object_type=uuid.UUID(DMSA))]),
               ou("Inherited", [sd.build_ace(rid(1101), sd.CREATE_CHILD, flags=sd.ACE_FLAG_INHERITED)]),
               ou("Other", [sd.build_ace(rid(1101), sd.CREATE_CHILD, object_type=uuid.UUID("bf967aba-0de6-11d0-a285-00aa003049e2"))])]
    guids = {"schema_classes": {"msDS-DelegatedManagedServiceAccount": DMSA}}
    with_2025 = mini_export([*objects, dc("DC25", 1001, operatingSystem="Windows Server 2025 Standard")], guids=guids)
    assert {(f.target.split(",")[0], f.severity) for f in run("BadSuccessor", with_2025)} == {("OU=Servers", "Medium"), ("OU=Apps", "High")}
    assert {f.severity for f in run("BadSuccessor", mini_export(objects, guids=guids))} == {"Low"}
    assert run("BadSuccessor", mini_export(objects, guids={"schema_classes": {"msDS-DelegatedManagedServiceAccount": ""}})) == []


def test_gaps_for_old_collector():
    gaps = coverage_gaps(mini_export([user("u", 1101)]))
    assert "CriticalObjectAcl" in gaps and "BadSuccessor" in gaps


def test_gap_reasons_for_new_collector():
    dmsa_absent = {"schema_classes": {"msDS-DelegatedManagedServiceAccount": ""}}
    assert {"CriticalObjectAcl", "BadSuccessor"}.isdisjoint(coverage_gaps(mini_export([user("u", 1101)], guids=dmsa_absent, **NEW)))
    old = coverage_gaps(mini_export([user("u", 1101)]))
    assert "сборщик старой версии" in old["CriticalObjectAcl"] and "старого сборщика" in old["BadSuccessor"]
    notes = ["схема не прочитана: busy (51)", "дескрипторы критичных объектов не прочитаны (участники Domain Admins): busy (51)"]
    gaps = coverage_gaps(mini_export([user("u", 1101)], collector={**NEW["collector"], "notes": notes}))
    assert gaps["CriticalObjectAcl"] == notes[1] and "схема не прочитана: busy (51)" in gaps["BadSuccessor"]


def test_owner_full_extended_rights_and_key_credential_link():
    kcl = uuid.UUID("5b47d60f-6090-40b2-9f37-2a4de88f3063")
    adm = user("adm", 1101, sd=b64sd([
        sd.build_ace(rid(1102), sd.WRITE_PROPERTY, object_type=kcl),
        sd.build_ace(rid(1102), sd.EXTENDED_RIGHT),
        sd.build_ace(rid(1103), sd.GENERIC_WRITE | sd.WRITE_PROPERTY, flags=sd.ACE_FLAG_INHERIT_ONLY),     # только на потомков
        sd.build_ace(rid(1103), sd.WRITE_PROPERTY, object_type=MEMBER),                                   # member у пользователя — не право
    ]))
    exp = mini_export([user("svc", 1102), user("ops", 1103), adm], admins=["adm"],
                      guids={"schema_attributes": {"msDS-KeyCredentialLink": str(kcl)}}, **NEW)
    got = {f.identity: f.right for f in run("CriticalObjectAcl", exp)}
    assert got == {"CORP\\svc": "WriteKeyCredentialLink, AllExtendedRights"}


def test_unsafe_owner_of_krbtgt():
    import base64

    krbtgt = user("krbtgt", 502, uac=514, sd=base64.b64encode(sd.build_sd([], owner=rid(1104))).decode())
    got = run("CriticalObjectAcl", mini_export([user("ops", 1104), krbtgt], **NEW))
    assert [(f.target.split(",")[0], f.identity, f.right, f.severity) for f in got] == [("CN=krbtgt", "CORP\\ops", "owner", "High")]


def test_critical_groups_as_subjects_are_skipped_and_full_control_is_one_name():
    acct_ops = group("Account Operators", "S-1-5-32-548")
    full = 0xF01FF
    dns_admins = group("DnsAdmins", rid(1150), sd=b64sd([sd.build_ace("S-1-5-32-548", full), sd.build_ace(rid(1101), full)]))
    got = run("CriticalObjectAcl", mini_export([acct_ops, user("helpdesk", 1101), dns_admins], **NEW))
    assert [(f.identity, f.right) for f in got] == [("CORP\\helpdesk", "GenericAll")]


def test_key_credential_link_counts_only_on_accounts():
    kcl = uuid.UUID("5b47d60f-6090-40b2-9f37-2a4de88f3063")
    ace = lambda s: sd.build_ace(s, sd.WRITE_PROPERTY, object_type=kcl)
    dns_admins = group("DnsAdmins", rid(1150), [f"CN=dnsadm,CN=Users,{DN}"], sd=b64sd([ace(rid(526)), ace(rid(1101))]))
    target = user("dnsadm", 1103, sd=b64sd([ace(rid(1101))]))
    exp = mini_export([group("Key Admins", rid(526)), user("helpdesk", 1101), dns_admins, target],
                      guids={"schema_attributes": {"msDS-KeyCredentialLink": str(kcl)}}, **NEW)
    got = [(f.target.split(",")[0], f.identity, f.right) for f in run("CriticalObjectAcl", exp)]
    assert got == [("CN=dnsadm", "CORP\\helpdesk", "WriteKeyCredentialLink")]


def test_critical_object_acl_goes_through_allowlist():
    dns_admins = group("DnsAdmins", rid(1150), sd=b64sd([sd.build_ace(rid(1101), sd.WRITE_DACL)]))
    [f] = run("CriticalObjectAcl", mini_export([user("helpdesk", 1101), dns_admins], **NEW), AdConfig(allowlist_short=["HELPDESK"]))
    assert f.allowlisted and f.severity == "Low" and f.severity_original == "High"


def test_bad_successor_inherit_only_needs_ou_or_container_children():
    user_class = uuid.UUID("bf967aba-0de6-11d0-a285-00aa003049e2")
    ou_class = uuid.UUID("bf967aa5-0de6-11d0-a285-00aa003049e2")
    io = sd.ACE_FLAG_INHERIT_ONLY
    objects = [user("helpdesk", 1101),
               ou("Users", [sd.build_ace(rid(1101), sd.CREATE_CHILD, flags=io, inherited_object_type=user_class)]),
               ou("Branches", [sd.build_ace(rid(1101), sd.CREATE_CHILD, flags=io, inherited_object_type=ou_class)]),
               ou("Full", [sd.build_ace(rid(1101), 0xF01FF)])]
    guids = {"schema_classes": {"msDS-DelegatedManagedServiceAccount": DMSA}}
    got = {(f.target.split(",")[0], f.right) for f in run("BadSuccessor", mini_export(objects, guids=guids))}
    assert got == {("OU=Branches", "CreateChild"), ("OU=Full", "GenericAll")}
