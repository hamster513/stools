"""Native diagnostic KSC slices retain ordinary parser semantics without identities."""
import base64
import copy
import fnmatch
import ipaddress
import json
import uuid

import pytest

from api.modules.ksc.core.export import ExportIndex, load_export
from api.modules.ksc.core.extractors.kes_windows import extract_kes
from api.modules.ksc.core.firewall.match import Tri, _address
from api.modules.ksc.core.policy_index import policy_rows, profile_rows, scope_rows
from api.modules.ksc.core.profile_activation import evaluate, parse_condition
from api.platform.diagnostics.schema import BundleError
from tests.ksc.kes11 import exclusion, octets, packet_rule
from tests.ksc.synthetic import activation, condition_group, tag_condition


def fixture():
    policy = {"KLPOL_ID": 41, "KLPOL_DN": "PRIVATE-POLICY", "KLPOL_PRODUCT": "KES", "KLPOL_VERSION": "12.0.0.0",
              "KLPOL_GROUP_ID": 0, "KLPOL_ACTIVE": True, "KLPOL_ACCEPT_PARENT": True, "KLPOL_FORCE_DISTRIB2CHILDREN": True}
    def leaf(value):
        return {"KLPRSS_Val": value, "KLPRSS_Mnd": True, "KLPRSS_ValLck": True,
                "KLPRSS_ValLckPolicy": "PRIVATE-POLICY", "KLPRSS_ValLckGroup": "PRIVATE-ROOT"}
    sections = {
        "cf9370d5": {"firewall": {"enabled": leaf(True), "notifyOnly": leaf(False), "networkPacketRules": leaf([
            packet_rule("PRIVATE-RULE", action=0, direction=0, remote=[{"octets": octets("10.26.9.0"), "mask": 24}],
                        local=[{"hostName": "private-workstation.private.test", "hostNameIPs": []}])]),
            "availableNetworks": leaf([{"name": "PRIVATE-NET", "type": 2, "address": {"octets": octets("10.26.9.0"), "mask": 24}}])},
            "hips": {"enabled": leaf(True), "appGroups": leaf([]), "defaultAppGroupId": leaf(1)}},
        "852d0287": {"scanExclusionsAndTrustedZone": {"scanExclusions": leaf([
            exclusion(r"C:\PRIVATE-DIR\*.exe", comment="PRIVATE-COMMENT", recursive=True)]), "trustedApplications": leaf([])}},
        "KLPRSS_Basic": {"AdminPassword": leaf("PRIVATE-SECRET"), "ReportsMaxSize": leaf(2048)},
    }
    profile = {"name": "PRIVATE-PROFILE", "attrs": {"KLSSPOL_PRF_ENABLED": True,
        "EXPRESSION": activation(condition_group(tag_condition("PRIVATE-TAG"), name="PRIVATE-CONDITION"))},
        "sections": {"cf9370d5": {"firewall": {"enabled": leaf(False)}}}, "errors": []}
    return {
        "format": "stools-ksc/1", "server": {"name": "PRIVATE-SERVER", "collected_at": "2026-01-02T00:00:00Z", "version": "15.1"},
        "groups": [{"id": 0, "parentId": -1, "name": "PRIVATE-ROOT"}, {"id": 7, "parentId": 0, "name": "PRIVATE-GROUP"},
                   {"id": 8, "parentId": 0, "name": "UNRELATED-GROUP"}],
        "hosts": [{"KLHST_WKS_HOSTNAME": "PRIVATE-HOST-ID", "KLHST_WKS_DN": "private-workstation",
                   "KLHST_WKS_WINHOSTNAME": "private-workstation", "KLHST_WKS_FQDN": "private-workstation.private.test",
                   "KLHST_WKS_DNSDOMAIN": "private.test", "KLHST_WKS_GROUPID": 7,
                   "KLHST_WKS_IP_LONG": int(ipaddress.ip_address("10.26.9.20")), "KLHST_WKS_STATUS": 29, "KLHST_WKS_RTP_STATE": 7,
                   "KLHST_WKS_OWNER_ID": {"type": "binary", "value": "PRIVATE-OWNER"}},
                  {"KLHST_WKS_HOSTNAME": "UNRELATED-HOST", "KLHST_WKS_GROUPID": 8}],
        "host_products": {"PRIVATE-HOST-ID": {"KES": {"12.0.0.0": {"DisplayName": "PRIVATE-PRODUCT", "ProdVersion": "12.0.0.0"}}}},
        "host_components": {"PRIVATE-HOST-ID": {"KES/12.0.0.0": [{"KLHST_PRCST_COMPONENT_DN": "Firewall", "KLHST_PRCST_COMPONENT_STATUS": 4}]}},
        "host_tags": {"PRIVATE-HOST-ID": ["private-tag"], "UNRELATED-HOST": ["UNRELATED-TAG"]},
        "host_users": {"PRIVATE-HOST-ID": [{"sid": "S-1-5-21-11-22-33-1001", "sam": "PRIVATE-USER", "upn": "PRIVATE-USER@private.test",
            "display_name": "PRIVATE-PERSON", "domain": "private.test", "local": False, "active": True, "group": False, "bin_id": "PRIVATE-OWNER"}]},
        "policies": [policy, {**policy, "KLPOL_ID": 99, "KLPOL_GROUP_ID": 8, "KLPOL_DN": "UNRELATED-POLICY"}],
        "effective_policies": {"0": [policy], "7": [{**policy, "KLPOL_INHERITED": True}], "8": []},
        "policy_contents": {"41": {"product": "KES", "version": "12.0.0.0", "sections": sections, "errors": []}},
        "policy_profiles": {"41": {"profiles": [profile], "priorities": ["PRIVATE-PROFILE"], "errors": []}},
        "tasks": [{"password": "PRIVATE-TASK-SECRET"}], "licenses": [{"owner": "PRIVATE-LICENSE"}],
        "internal_users": [{"login": "PRIVATE-ACCOUNT"}], "connections": {"password": "PRIVATE-CONNECTION"},
    }


def test_native_slice_preserves_policy_profile_firewall_and_identity_relations():
    from api.platform.diagnostics.ksc_payload import build_ksc_payload, validate_ksc_payload
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    raw = fixture()
    original = copy.deepcopy(raw)
    anon = ModuleAnonymizer()
    clean = build_ksc_payload(raw, {"PRIVATE-HOST-ID"}, anon, 83)
    assert raw == original
    validate_ksc_payload(clean)
    parsed = load_export(json.dumps(clean).encode())
    idx = ExportIndex(parsed)
    assert len(idx.hosts) == 1 and len(parsed.groups) == 2 and len(parsed.policies) == 1
    host = idx.hosts[0]
    assert host.host_id == anon.token("PRIVATE-HOST-ID") and host.group_id == anon.identifier("group_id:83", 7)
    assert host.fqdn == anon.fqdn("private-workstation.private.test") and host.ip == anon.ip("10.26.9.20")
    assert host.product == "KES" and host.components == [("Firewall", 4)]
    assert host.owner["sid"] == host.users[0].sid == anon.sid("S-1-5-21-11-22-33-1001")
    [policy] = policy_rows(idx)
    assert policy.policy_id == anon.identifier("policy_id:83", 41) and policy.active and policy.accept_parent
    assert {(s.own, s.hosts) for s in scope_rows(idx)} == {(True, 0), (False, 1)}
    [profile] = profile_rows(parsed)
    assert profile.priority == 0 and profile.enabled
    assert evaluate(parse_condition(profile.condition), host.tags).active is True
    old = extract_kes(raw["policy_contents"]["41"]["sections"])
    new = extract_kes(parsed.policy_contents[str(policy.policy_id)]["sections"])
    assert len(new.exclusions) == len(old.exclusions) == 1 and len(new.net_rules) == len(old.net_rules) == 1
    assert new.exclusions[0].components == old.exclusions[0].components
    assert new.exclusions[0].kind == old.exclusions[0].kind
    assert new.firewall.enabled == old.firewall.enabled and new.firewall.locks == old.firewall.locks
    rule = new.net_rules[0]
    assert _address("remote", rule.scope.remote[0], host.ip, "", "host").result == Tri.YES
    assert _address("local", rule.scope.local[0], None, host.fqdn, "host").result == Tri.YES
    assert _address("remote", rule.scope.remote[0], anon.ip("10.26.10.20"), "", "host").result == Tri.NO
    wire = json.dumps(clean).casefold()
    assert "private" not in wire and "unrelated" not in wire and "10.26.9" not in wire
    assert not ({"tasks", "licenses", "internal_users", "connections"} & clean.keys())


def test_address_mapping_preserves_network_and_range_membership():
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    anon = ModuleAnonymizer()
    anon.prepare_addresses({"remoteAddress": "10.26.9.10-10.26.9.40"})
    low, high = map(ipaddress.ip_address, anon.ip_range("10.26.9.10", "10.26.9.40"))
    for source in ("10.26.9.9", "10.26.9.10", "10.26.9.20", "10.26.9.40", "10.26.9.41", "10.26.10.20"):
        mapped = ipaddress.ip_address(anon.ip(source))
        assert (ipaddress.ip_address("10.26.9.10") <= ipaddress.ip_address(source) <= ipaddress.ip_address("10.26.9.40")) == (low <= mapped <= high)
        assert (ipaddress.ip_address(source) in ipaddress.ip_network("10.26.9.0/24")) == (mapped in ipaddress.ip_network(anon.network("10.26.9.0/24")))
        assert str(mapped) != source
    assert ipaddress.ip_address(anon.ip("2001:db8:42::7")) in ipaddress.ip_network(anon.network("2001:db8:42::/64"))


def test_guid_sid_and_wildcard_semantics():
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    anon = ModuleAnonymizer()
    guid = "{11111111-2222-3333-4444-555555555555}"
    assert str(uuid.UUID(anon.guid(guid).strip("{}")))
    assert anon.guid(guid).strip("{}").lower() in anon.dn(f"CN={guid},CN=Policies,DC=private,DC=test").lower()
    assert anon.sid("S-1-5-7") == "S-1-5-7"
    assert anon.sid("S-1-5-21-11-22-33-513").endswith("-513")
    assert fnmatch.fnmatchcase(anon.pattern(r"C:\PRIVATE-DIR\tool.exe"), anon.pattern(r"C:\PRIVATE-DIR\*.exe"))
    assert "private" not in anon.pattern(r"C:\PRIVATE-DIR\tool.exe").lower()


@pytest.mark.parametrize("value", ["PRIVATE-OPAQUE-XML", {"type": "binary", "value": base64.b64encode(b"PRIVATE-BLOB").decode()}])
def test_opaque_policy_content_fails_without_silent_loss(value):
    from api.platform.diagnostics.ksc_payload import build_ksc_payload
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    raw = fixture()
    raw["policy_contents"]["41"]["sections"]["KLPRSS_Opaque"] = value
    with pytest.raises(BundleError, match="(?i)opaque|unsupported"):
        build_ksc_payload(raw, {"PRIVATE-HOST-ID"}, ModuleAnonymizer(), 83)


def test_native_validator_rejects_dangling_and_external_sections():
    from api.platform.diagnostics.ksc_payload import build_ksc_payload, validate_ksc_payload
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    clean = build_ksc_payload(fixture(), {"PRIVATE-HOST-ID"}, ModuleAnonymizer(), 83)
    clean["hosts"][0]["KLHST_WKS_GROUPID"] = 999
    with pytest.raises(BundleError):
        validate_ksc_payload(clean)
    clean = build_ksc_payload(fixture(), {"PRIVATE-HOST-ID"}, ModuleAnonymizer(), 83)
    clean["tasks"] = [{"password": "PRIVATE-SECRET"}]
    with pytest.raises(BundleError):
        validate_ksc_payload(clean)



@pytest.mark.parametrize("target", ["host", "secret", "opaque", "server"])
def test_native_validator_rejects_injected_plaintext(target):
    from api.platform.diagnostics.ksc_payload import build_ksc_payload, validate_ksc_payload
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    clean = build_ksc_payload(fixture(), {"PRIVATE-HOST-ID"}, ModuleAnonymizer(), 83)
    if target == "host":
        clean["hosts"][0]["KLHST_WKS_DN"] = "PRIVATE-HOST"
    elif target == "server":
        clean["server"]["user"] = "PRIVATE-LOGIN"
    else:
        sections = next(iter(clean["policy_contents"].values()))["sections"]
        if target == "secret":
            sections["KLPRSS_Basic"]["AdminPassword"]["KLPRSS_Val"] = "PRIVATE-SECRET"
        else:
            sections["KLPRSS_Opaque"] = "PRIVATE-CONTENT"
    with pytest.raises(BundleError):
        validate_ksc_payload(clean)


@pytest.mark.parametrize("container", ["leaf", "top", "section", "mixed"])
def test_complete_kes_sections_reproduce_ordinary_checks(container):
    from collections import Counter

    from api.modules.ksc.core.checks import run_all
    from api.modules.ksc.core.config import KscConfig
    from api.modules.ksc.core.exclusion_risks import exclusion_risks
    from api.platform.diagnostics.ksc_payload import build_ksc_payload
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer
    from tests.ksc.kes11 import kes11_sections

    raw = fixture()
    raw["hosts"] = raw["hosts"][:1]
    raw["groups"] = raw["groups"][:2]
    raw["policies"] = raw["policies"][:1]
    raw["effective_policies"].pop("8")
    raw["host_tags"].pop("UNRELATED-HOST")
    for key in ("tasks", "licenses", "internal_users", "connections"):
        raw.pop(key)
    raw["policy_contents"]["41"]["sections"] = kes11_sections(container)
    anon = ModuleAnonymizer()
    clean = build_ksc_payload(raw, {"PRIVATE-HOST-ID"}, anon, 83)
    original = load_export(json.dumps(raw).encode())
    copied = load_export(json.dumps(clean).encode())
    cfg = KscConfig()
    assert Counter((f.check, f.severity) for f in run_all(ExportIndex(original), cfg)) == Counter(
        (f.check, f.severity) for f in run_all(ExportIndex(copied), cfg))
    old = extract_kes(original.policy_contents["41"]["sections"])
    new = extract_kes(next(iter(copied.policy_contents.values()))["sections"])
    assert [exclusion_risks(e, cfg) for e in old.exclusions] == [exclusion_risks(e, cfg) for e in new.exclusions]
    assert old.firewall.locks == new.firewall.locks
    assert [(r.action, r.enabled, r.scope.protocol, r.scope.unread) for r in old.net_rules] == [
        (r.action, r.enabled, r.scope.protocol, r.scope.unread) for r in new.net_rules]



def test_server_timestamp_preserves_instant_precision_and_relative_host_age():
    from api.platform.diagnostics.ksc_payload import build_ksc_payload
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    raw = fixture()
    raw["server"]["collected_at"] = "2026-01-02T03:00:00.125000+03:00"
    raw["hosts"][0]["KLHST_WKS_LAST_NAGENT_CONNECTED"] = {"type": "datetime", "value": "2026-01-01T00:00:00Z"}
    anon = ModuleAnonymizer()
    copied = ExportIndex(load_export(json.dumps(build_ksc_payload(raw, {"PRIVATE-HOST-ID"}, anon, 83)).encode()))
    original = ExportIndex(load_export(json.dumps(raw).encode()))
    assert copied.now - copied.hosts[0].last_seen_at == original.now - original.hosts[0].last_seen_at


def test_policy_base_closure_and_unspecified_profile_priorities():
    from api.platform.diagnostics.ksc_payload import build_ksc_payload
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    raw = fixture()
    raw["policies"][0]["KLPOL_BASE_ID"] = 45
    raw["groups"].append({"id": 9, "parentId": 0, "name": "PRIVATE-BASE-GROUP"})
    raw["policies"].append({**raw["policies"][1], "KLPOL_ID": 45, "KLPOL_GROUP_ID": 9, "KLPOL_DN": "PRIVATE-BASE-POLICY"})
    entry = raw["policy_profiles"]["41"]
    entry["profiles"].extend([{**entry["profiles"][0], "name": name} for name in ("PRIVATE-ZETA", "PRIVATE-ALPHA")])
    original = profile_rows(load_export(json.dumps(raw).encode()))
    anon = ModuleAnonymizer()
    clean = build_ksc_payload(raw, {"PRIVATE-HOST-ID"}, anon, 83)
    assert len(clean["policies"]) == 2 and len(clean["groups"]) == 3
    assert clean["policies"][0]["KLPOL_BASE_ID"] == anon.identifier("policy_id:83", 45)
    copied = profile_rows(load_export(json.dumps(clean).encode()))
    assert [row.name for row in copied] == [anon.token(row.name) for row in original]


def test_address_range_registration_is_not_allowed_to_change_prior_cached_ips():
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    anon = ModuleAnonymizer()
    anon.secret = b"deterministic-test-secret"
    before = anon.ip("10.26.9.20")
    with pytest.raises(BundleError, match="Register"):
        anon.prepare_addresses({"remoteAddress": "10.26.9.1-10.26.9.254"})
    assert anon.ip("10.26.9.20") == before
    with pytest.raises(BundleError, match="range"):
        ModuleAnonymizer().ip_range("1.0.0.0", "200.0.0.0")
    for rid in (0, 4096, 8192, 8448, 12288, 16384, 20480):
        assert anon.sid(f"S-1-16-{rid}") == f"S-1-16-{rid}"



@pytest.mark.parametrize("secret", [987654321, [98765, 43210], {"type": "long", "value": 987654321}])
def test_numeric_credential_payloads_are_redacted_without_dropping_policy_numbers(secret):
    from api.platform.diagnostics.ksc_payload import build_ksc_payload
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    raw = fixture()
    settings = raw["policy_contents"]["41"]["sections"]["KLPRSS_Basic"]
    settings["AdminPassword"]["KLPRSS_Val"] = secret
    settings["PasswordProtection"] = {"KLPRSS_Val": {"Enabled": True, "Attempts": 3}}
    clean = build_ksc_payload(raw, {"PRIVATE-HOST-ID"}, ModuleAnonymizer(), 83)
    saved = next(iter(clean["policy_contents"].values()))["sections"]["KLPRSS_Basic"]
    from api.modules.ksc.core.secrets import HIDDEN
    value = saved["AdminPassword"]["KLPRSS_Val"]
    expected = [HIDDEN, HIDDEN] if isinstance(secret, list) else {"type": "long", "value": HIDDEN} if isinstance(secret, dict) else HIDDEN
    assert value == expected
    assert saved["ReportsMaxSize"]["KLPRSS_Val"] == 2048
    assert saved["PasswordProtection"]["KLPRSS_Val"] == {"Enabled": True, "Attempts": 3}


def test_tag_labels_preserve_native_unicode_lower_equality():
    from api.platform.diagnostics.ksc_payload import build_ksc_payload
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    raw = fixture()
    raw["host_tags"]["PRIVATE-HOST-ID"] = ["Straße"]
    raw["policy_profiles"]["41"]["profiles"][0]["attrs"]["EXPRESSION"] = activation(condition_group(tag_condition("Strasse")))
    original = load_export(json.dumps(raw).encode())
    assert evaluate(parse_condition(profile_rows(original)[0].condition), ExportIndex(original).hosts[0].tags).active is False
    clean = build_ksc_payload(raw, {"PRIVATE-HOST-ID"}, ModuleAnonymizer(), 83)
    parsed = load_export(json.dumps(clean).encode())
    assert evaluate(parse_condition(profile_rows(parsed)[0].condition), ExportIndex(parsed).hosts[0].tags).active is False


def test_unknown_host_tag_collection_and_unsupported_single_character_globs():
    from api.platform.diagnostics.ksc_payload import build_ksc_payload
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    raw = fixture()
    raw["host_tags"] = None
    clean = build_ksc_payload(raw, {"PRIVATE-HOST-ID"}, ModuleAnonymizer(), 83)
    assert ExportIndex(load_export(json.dumps(clean).encode())).hosts[0].tags_collected is False
    raw["host_tags"] = {"PRIVATE-HOST-ID": None}
    with pytest.raises(BundleError, match="structure"):
        build_ksc_payload(raw, {"PRIVATE-HOST-ID"}, ModuleAnonymizer(), 83)
    with pytest.raises(BundleError, match="wildcard"):
        ModuleAnonymizer().pattern(r"C:\?.exe")



def test_selected_address_prepass_ignores_unrelated_and_secret_ranges():
    from api.platform.diagnostics.ksc_payload import build_ksc_payload, prepare_ksc_addresses
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    raw = fixture()
    raw["policy_contents"]["99"] = {"sections": {"KLPRSS_Opaque": "1.0.0.0-200.0.0.0"}}
    settings = raw["policy_contents"]["41"]["sections"]["KLPRSS_Basic"]
    settings["remoteAddress"] = "10.26.9.10-10.26.9.40"
    settings["AdminPassword"]["KLPRSS_Val"] = "1.0.0.0-200.0.0.0"
    anon = ModuleAnonymizer()
    prepare_ksc_addresses(raw, {"PRIVATE-HOST-ID"}, anon)
    cached_ip = anon.ip("10.26.9.20")
    clean = build_ksc_payload(raw, {"PRIVATE-HOST-ID"}, anon, 83)
    parsed = ExportIndex(load_export(json.dumps(clean).encode()))
    assert parsed.hosts[0].ip == cached_ip
    assert len(clean["policy_contents"]) == 1



def test_netbios_only_host_matches_shared_directory_domain_label():
    from api.modules.ksc.services.coverage import _domains_of
    from api.platform.diagnostics.ksc_payload import build_ksc_payload
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    raw = fixture()
    raw["hosts"][0]["KLHST_WKS_DNSDOMAIN"] = ""
    raw["hosts"][0]["KLHST_WKS_WINDOMAIN"] = "PRIVATE-NETBIOS"
    anon = ModuleAnonymizer()
    parsed = load_export(json.dumps(build_ksc_payload(raw, {"PRIVATE-HOST-ID"}, anon, 83)).encode())
    assert _domains_of(parsed) == (set(), {anon.name("PRIVATE-NETBIOS").upper()})


@pytest.mark.parametrize("sam", [r"PRIVATE-NETBIOS\PRIVATE-USER", r"PRIVATE-NETBIOS\PRIVATE-USER@NAME"])
def test_qualified_sam_reproduces_native_and_cached_observation_key(sam):
    from dataclasses import asdict

    from api.modules.assets.services.users import _ksc_seen
    from api.platform.diagnostics.ksc_payload import build_ksc_payload
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    raw = fixture()
    user = raw["host_users"]["PRIVATE-HOST-ID"][0]
    user["sid"] = ""
    user["sam"] = sam
    user["domain"] = "private.test"
    anon = ModuleAnonymizer()
    idx = ExportIndex(load_export(json.dumps(build_ksc_payload(raw, {"PRIVATE-HOST-ID"}, anon, 83)).encode()))
    host = idx.hosts[0]
    seen = _ksc_seen(12, host.host_id, 5, asdict(host.users[0]), idx.now)
    assert seen.source_key == "12:" + anon.principal(sam, directory=True)



def test_cached_group_path_uses_native_group_labels_and_stale_path_structure():
    from api.platform.diagnostics.ksc_payload import build_ksc_payload
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    raw = fixture()
    raw["groups"][1]["grp_full_name"] = "PRIVATE-ROOT/PRIVATE-GROUP"
    anon = ModuleAnonymizer()
    idx = ExportIndex(load_export(json.dumps(build_ksc_payload(raw, {"PRIVATE-HOST-ID"}, anon, 83)).encode()))
    assert anon.group_path("PRIVATE-ROOT/PRIVATE-GROUP") == idx.hosts[0].group_path
    assert anon.group_path("PRIVATE-ROOT/PRIVATE-OLD-GROUP") == (
        anon.name("PRIVATE-ROOT") + "/" + anon.name("PRIVATE-OLD-GROUP"))



def test_sidless_netbios_sam_keeps_dns_canonical_user_key():
    from dataclasses import asdict

    from api.modules.assets.core.users import user_key
    from api.modules.assets.services.users import _ksc_seen
    from api.platform.diagnostics.ksc_payload import build_ksc_payload
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    raw = fixture()
    user = raw["host_users"]["PRIVATE-HOST-ID"][0]
    user.update(sid="", sam=r"PRIVATE-NETBIOS\PRIVATE-USER", domain="private.test")
    anon = ModuleAnonymizer()
    anon.register_directory_domain("private.test", "PRIVATE-NETBIOS")
    idx = ExportIndex(load_export(json.dumps(build_ksc_payload(raw, {"PRIVATE-HOST-ID"}, anon, 83)).encode()))
    host = idx.hosts[0]
    seen = _ksc_seen(12, host.host_id, 5, asdict(host.users[0]), idx.now)
    aliases = {anon.name("PRIVATE-NETBIOS").lower(): anon.domain("private.test")}
    assert user_key(seen, aliases) == ("", anon.domain("private.test") + "\\" + anon.name("PRIVATE-USER"))
    assert seen.source_key == "12:" + anon.principal(user["sam"], directory=True)


def test_service_account_sam_remains_excluded_by_normal_user_parser():
    from dataclasses import asdict

    from api.modules.assets.core.users import user_key
    from api.modules.assets.services.users import _ksc_seen
    from api.platform.diagnostics.ksc_payload import build_ksc_payload
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    raw = fixture()
    raw["host_users"]["PRIVATE-HOST-ID"][0].update(sid="", sam="PRIVATE-SERVICE$")
    idx = ExportIndex(load_export(json.dumps(build_ksc_payload(raw, {"PRIVATE-HOST-ID"}, ModuleAnonymizer(), 83)).encode()))
    host = idx.hosts[0]
    assert user_key(_ksc_seen(12, host.host_id, 5, asdict(host.users[0]), idx.now), {}) is None



@pytest.mark.parametrize("sid", ["S-1-5-90-0", "S-1-5-96-0", "S-1-5-80-123-456-789-111-222", "S-1-15-2-123-456"])
def test_non_account_sid_stays_outside_account_namespace(sid):
    from dataclasses import asdict

    from api.modules.assets.core.users import user_key
    from api.modules.assets.services.users import _ksc_seen
    from api.platform.diagnostics.ksc_payload import build_ksc_payload
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    raw = fixture()
    raw["host_users"]["PRIVATE-HOST-ID"][0]["sid"] = sid
    anon = ModuleAnonymizer()
    idx = ExportIndex(load_export(json.dumps(build_ksc_payload(raw, {"PRIVATE-HOST-ID"}, anon, 83)).encode()))
    host = idx.hosts[0]
    assert anon.sid(sid).split("-")[:4] == sid.split("-")[:4]
    assert user_key(_ksc_seen(12, host.host_id, 5, asdict(host.users[0]), idx.now), {}) is None



@pytest.mark.parametrize("field", ["hostname", "account", "path"])
def test_unsupported_unicode_matching_never_changes_policy_predicates(field):
    from api.platform.diagnostics.ksc_payload import build_ksc_payload
    from api.platform.diagnostics.module_privacy import ModuleAnonymizer

    raw = fixture()
    if field == "hostname":
        raw["hosts"][0]["KLHST_WKS_FQDN"] = "straße.private.test"
    elif field == "account":
        raw["host_users"]["PRIVATE-HOST-ID"][0]["sam"] = "Straße"
    else:
        rule = raw["policy_contents"]["41"]["sections"]["852d0287"]["scanExclusionsAndTrustedZone"]["scanExclusions"]["KLPRSS_Val"][0]
        rule["objectMask"]["objectPath"] = r"C:\Straße\*.exe"
    with pytest.raises(BundleError, match="Unicode"):
        build_ksc_payload(raw, {"PRIVATE-HOST-ID"}, ModuleAnonymizer(), 83)
