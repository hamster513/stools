import datetime as dt

from api.modules.ad.core import sd
from api.modules.ad.core.checks.coverage import coverage_gaps
from api.modules.ad.core.config import AdConfig
from tests.ad.mini import DN, NOW, b64sd, computer, group, mini_export, rid, run, user


def trust(name, attrs, *, direction=3, ttype=2, enc=24, changed_days=5):
    return {"dn": f"CN={name},CN=System,{DN}", "class": "trustedDomain", "flatName": name.split(".")[0].upper(), "sid": "S-1-5-21-111-222-333",
            "trustAttributes": attrs, "trustDirection": direction, "trustType": ttype, "trustPartner": name,
            "supportedEncryptionTypes": enc, "whenChanged": (NOW - dt.timedelta(days=changed_days)).isoformat()}


def kinds(findings):
    return {(f.identity, f.key_extra): f.severity for f in findings}


def test_trust_kinds():
    exp = mini_export([
        trust("ext.local", 0x0),                         # внешнее без карантина
        trust("quar.local", 0x4),                        # внешнее с карантином — чисто
        trust("forest.local", 0x8 | 0x40 | 0x800),       # лесное «как внешнее» + делегирование TGT
        trust("child.corp.local", 0x20),                 # свой лес — фильтрация не проверяется
        trust("in.local", 0x0, direction=1),             # только входящее
        trust("nt4.local", 0x4, ttype=1),
        trust("stale.local", 0x4, changed_days=90),
        trust("rc4.local", 0x4, enc=4),
    ])
    assert kinds(run("TrustSecurity", exp)) == {
        ("ext.local", "sid_filtering"): "High", ("forest.local", "sid_filtering"): "High", ("forest.local", "tgt_delegation"): "Medium",
        ("nt4.local", "downlevel"): "High", ("stale.local", "inactive"): "Medium", ("rc4.local", "no_aes"): "Low"}


def zone(name, allow, aces=()):
    return {"dn": f"DC={name},CN=MicrosoftDNS,DC=DomainDnsZones,{DN}", "class": "dnsZone", "name": name, "partition": "DomainDnsZones",
            "allowUpdate": allow, "sd": b64sd([sd.build_ace(rid(512), sd.GENERIC_ALL), *aces])}


def test_dns_zones():
    exp = mini_export([zone("corp.local", 1), zone("_msdcs.corp.local", 2, [sd.build_ace("S-1-5-11", sd.CREATE_CHILD)]),
                       zone("lab.example", 1), zone("RootDNSServers", 1)])
    got = {(f.target.split(",")[0], f.key_extra): f.severity for f in run("DnsZones", exp)}
    assert got == {("DC=corp.local", "insecure_update"): "High", ("DC=lab.example", "insecure_update"): "Medium",
                   ("DC=_msdcs.corp.local", "au_create"): "Info"}


def test_rodc_rules_only_with_rodc():
    da = f"CN=Domain Admins,CN=Users,{DN}"
    denied = group("Denied RODC Password Replication Group", rid(572), [da])
    allowed = group("Allowed RODC Password Replication Group", rid(571), [f"CN=u1,CN=Users,{DN}"])
    rodc = computer("RODC1", 1201, uac=0x4000000 | 0x1000, revealOnDemand=[da], neverReveal=[],
                    revealedUsers=[f"CN=adm,CN=Users,{DN}"], krbTgtLink=f"CN=krbtgt_1111,CN=Users,{DN}")
    objects = [user("u1", 1101), user("adm", 1102), user("krbtgt_1111", 1301, uac=514), user("krbtgt_2222", 1302, uac=514), denied, allowed, rodc]
    got = {f.key_extra for f in run("RodcPasswordReplication", mini_export(objects, admins=["adm"]))}
    assert got == {"reveal_privileged", "never_reveal_missing", "admin_revealed", "krbtgt_orphan", "allowed_group_not_empty", "denied_group_incomplete"}
    no_rodc = [o for o in objects if o is not rodc and o.get("sam") != "krbtgt_1111"]
    assert {f.key_extra for f in run("RodcPasswordReplication", mini_export(no_rodc, admins=["adm"]))} == {"krbtgt_orphan"}


def test_trust_inactive_threshold_from_config():
    exp = mini_export([trust("stale.local", 0x4, changed_days=20)])
    assert run("TrustSecurity", exp) == []
    assert kinds(run("TrustSecurity", exp, AdConfig(trust_inactive_days=10))) == {("stale.local", "inactive"): "Medium"}


def test_trust_gap_only_when_no_trust_has_direction():
    old = {"dn": f"CN=old.local,CN=System,{DN}", "class": "trustedDomain", "flatName": "OLD", "sid": "S-1-5-21-7-8-9", "trustAttributes": 0}
    assert coverage_gaps(mini_export([old]))["TrustSecurity"] == "доверия собраны старым сборщиком"
    assert "TrustSecurity" not in coverage_gaps(mini_export([old, trust("ext.local", 0x4)]))
    assert "TrustSecurity" not in coverage_gaps(mini_export())


def test_dns_gap_without_zones_names_collector_note():
    assert coverage_gaps(mini_export())["DnsZones"] == "зоны DNS не собраны (сборщик старой версии)"
    note = "зоны DNS не прочитаны (DomainDnsZones): отказ в доступе"
    assert coverage_gaps(mini_export(collector={"notes": [note]}))["DnsZones"] == f"зоны DNS не собраны: {note}"
    assert "DnsZones" not in coverage_gaps(mini_export([zone("corp.local", 2)]))


def test_rodc_complete_denied_group_and_policy_are_clean():
    da, ea, sa, dcs = (f"CN={n},CN=Users,{DN}" for n in ("Domain Admins", "Enterprise Admins", "Schema Admins", "Domain Controllers"))
    nested = group("Tier0", rid(1400), [ea, sa])
    denied = group("Denied RODC Password Replication Group", rid(572), [da, nested["dn"], dcs, f"CN=krbtgt,CN=Users,{DN}"])
    rodc = computer("RODC1", 1201, uac=0x4000000 | 0x1000, revealOnDemand=[f"CN=u1,CN=Users,{DN}"], neverReveal=[denied["dn"]],
                    krbTgtLink=f"CN=krbtgt_1111,CN=Users,{DN}")
    objects = [user("u1", 1101), user("krbtgt_1111", 1301, uac=514), denied, nested, rodc,
               group("Enterprise Admins", rid(519)), group("Schema Admins", rid(518)), group("Domain Controllers", rid(516)),
               group("Allowed RODC Password Replication Group", rid(571))]
    assert run("RodcPasswordReplication", mini_export(objects)) == []
