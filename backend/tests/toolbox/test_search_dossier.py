"""Cross-source dossier keeps identity, provenance and source access boundaries."""

import datetime as dt

import pytest

from api.modules.assets.models import (
    Asset,
    AssetGroup,
    AssetGroupMember,
    AssetObservation,
    AssetUser,
    AssetUserGroup,
    AssetUserHost,
)

NOW = dt.datetime(2026, 11, 11, tzinfo=dt.UTC)
API = "/api/search"


@pytest.fixture
def people(db_session):
    h = Asset(
        name="pc01", name_key="pc01", fqdn="pc01.corp.test", domain="corp.test", ip="10.0.0.1"
    )
    u = AssetUser(
        sid="S-1-5-21-1-1001",
        name_key="corp.test\\alice",
        sam="alice",
        upn="alice@corp.test",
        display_name="Алиса Иванова",
        domain="corp.test",
        last_seen=NOW,
    )
    g = AssetGroup(
        group_key="corp.test:s-1-5-21-1-2001",
        sid="S-1-5-21-1-2001",
        name="Domain Users",
        domain="corp.test",
        sources=["ad"],
        in_ad=True,
    )
    db_session.add_all([h, u, g])
    db_session.flush()
    db_session.add_all(
        [
            AssetUserHost(
                user_id=u.id, asset_id=h.id, source="ksc", kind="session", active=True, seen_at=NOW
            ),
            AssetUserHost(user_id=u.id, asset_id=h.id, source="ksc", kind="owner", seen_at=NOW),
            AssetUserGroup(
                user_id=u.id, group_sid=g.sid, group_name=g.name, direct=False, source="ad"
            ),
            AssetGroupMember(
                group_id=g.id,
                member_kind="computer",
                asset_id=h.id,
                member_name=h.name,
                source="ad",
            ),
            AssetGroupMember(
                group_id=g.id, member_kind="user", user_id=u.id, member_name=u.sam, source="ad"
            ),
            AssetObservation(
                asset_id=h.id, source="ksc", source_key="1:test", seen_at=NOW, name=h.name
            ),
        ]
    )
    db_session.commit()
    return h, u, g


def section(body, key):
    return next(s for s in body["dossier"]["sections"] if s["id"] == key)


def test_search_requires_session_but_not_toolbox(client, client_as):
    assert client.post(API, json={"query": "nothing"}).status_code == 401
    r = client_as({"assets": "read"}).post(API, json={"query": "nothing"})
    assert r.status_code == 200


@pytest.mark.parametrize(
    "query", ["alice", "alice@corp.test", "corp.test\\alice", "S-1-5-21-1-1001", "Алиса Иванова"]
)
def test_user_identifiers_and_relations(auth_client, people, query):
    _h, u, g = people
    r = auth_client.post(API, json={"query": query, "kind": "user"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dossier"]["entity"]["id"] == f"user:{u.id}"
    hosts = section(body, "hosts")["items"]
    assert len(hosts) == 1
    assert "сеанс" in str(hosts).lower() and "владелец" in str(hosts).lower()
    assert section(body, "groups")["items"][0]["target"]["id"] == f"group:{g.id}"


@pytest.mark.parametrize("query", ["Domain Users", "S-1-5-21-1-2001"])
def test_group_members(auth_client, people, query):
    h, u, _g = people
    r = auth_client.post(API, json={"query": query, "kind": "group"})
    assert r.status_code == 200, r.text
    assert {x["target"]["id"] for x in section(r.json(), "members")["items"]} == {
        f"host:{h.id}",
        f"user:{u.id}",
    }


def test_host_has_groups_and_deduplicated_users(auth_client, people):
    h, _u, g = people
    r = auth_client.post(API, json={"query": h.fqdn})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dossier"]["entity"]["id"] == f"host:{h.id}"
    assert len(section(body, "users")["items"]) == 1
    assert section(body, "groups")["items"][0]["target"]["id"] == f"group:{g.id}"


def test_each_relation_source_is_gated(client_as, people):
    _h, u, _g = people
    r = client_as({"assets": "read"}).post(API, json={"query": u.sam, "kind": "user"})
    assert r.status_code == 200
    assert not section(r.json(), "groups")["items"]
    assert not section(r.json(), "hosts")["items"]
    assert (
        client_as({"ad": "read"}).post(API, json={"query": u.sam, "kind": "user"}).json()["matches"]
        == []
    )


def test_same_name_is_not_merged_and_selection_is_explicit(auth_client, db_session, people):
    _h, u, _g = people
    other = AssetUser(name_key="other.test\\alice", sam="alice", domain="other.test")
    db_session.add(other)
    db_session.commit()
    r = auth_client.post(API, json={"query": "alice", "kind": "user"}).json()
    assert len(r["matches"]) == 2 and r["dossier"] is None
    selected = auth_client.post(
        API, json={"query": "alice", "kind": "user", "entity_id": f"user:{u.id}"}
    ).json()
    assert selected["dossier"]["entity"]["id"] == f"user:{u.id}"


def test_direct_object_selection_still_requires_assets_access(client_as, people):
    _h, u, _g = people
    r = client_as({"ksc": "read"}).post(API, json={"query": "alice", "entity_id": f"user:{u.id}"})
    assert r.status_code == 403


def test_shared_ip_keeps_distinct_hosts(auth_client, db_session, people):
    h, _, _ = people
    db_session.add(Asset(name="different", ip=h.ip))
    db_session.commit()
    r = auth_client.post(API, json={"query": h.ip}).json()
    assert len(r["matches"]) == 2 and r["dossier"] is None


def test_ksc_groups_and_inherited_policies_use_latest_snapshot(client_as, db_session, people):
    from api.modules.ksc.models import KscHost, KscPolicy, KscPolicyScope, KscServer, KscSnapshot

    h, _, _ = people
    server = KscServer(name="KSC")
    db_session.add(server)
    db_session.flush()
    snap = KscSnapshot(server_id=server.id, collected_at=NOW, source="file")
    old = KscSnapshot(server_id=server.id, collected_at=NOW - dt.timedelta(days=1), source="file")
    db_session.add_all([snap, old])
    db_session.flush()
    db_session.add_all(
        [
            KscHost(
                snapshot_id=snap.id,
                host_id="test",
                name=h.name,
                group_id=12,
                group_path="Managed/Workstations",
            ),
            KscHost(
                snapshot_id=old.id,
                host_id="old",
                name="stale",
                group_id=14,
                group_path="Managed/Obsolete",
            ),
            KscPolicy(snapshot_id=snap.id, policy_id=3, name="Endpoint Protection", active=True),
            KscPolicyScope(
                snapshot_id=snap.id,
                policy_id=3,
                group_id=12,
                group_path="Managed/Workstations",
                own=False,
            ),
        ]
    )
    db_session.commit()
    client = client_as({"ksc": "read"})
    r = client.post(API, json={"query": "Workstations", "kind": "group"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dossier"]["entity"]["id"] == f"kscgroup:{server.id}:12"
    assert len(section(body, "members")["items"]) == 1
    assert section(body, "antivirus")["items"][0]["reason"] == "Унаследованная"
    assert client.post(API, json={"query": "Obsolete", "kind": "group"}).json()["matches"] == []
    assets_reader = client_as({"assets": "read"})
    assert (
        assets_reader.post(API, json={"query": "Workstations", "kind": "group"}).json()["matches"]
        == []
    )
    denied = assets_reader.post(
        API, json={"query": "Workstations", "entity_id": f"kscgroup:{server.id}:12"}
    )
    assert denied.status_code == 403
    observation = db_session.query(AssetObservation).filter_by(asset_id=h.id, source="ksc").first()
    observation.source_key = f"{server.id}:test"
    db_session.commit()
    both = client_as({"assets": "read", "ksc": "read"})
    host_dossier = both.post(API, json={"query": h.name, "kind": "host"}).json()
    management_group = section(host_dossier, "antivirus")["items"][0]
    assert management_group["target"]["id"] == f"kscgroup:{server.id}:12"
    selected_group = both.post(
        API,
        json={"query": management_group["title"], "entity_id": management_group["target"]["id"]},
    ).json()
    assert section(selected_group, "members")["items"][0]["target"]["id"] == f"host:{h.id}"
    hidden = assets_reader.post(API, json={"query": h.name, "kind": "host"}).json()
    assert section(hidden, "antivirus")["items"] == []


def test_vm_links_do_not_attach_another_host_with_same_ip(auth_client, db_session, people):
    from api.modules.vm.models import VmCve, VmHost, VmHostCve

    h, _, _ = people
    vm = VmHost(hostname=h.fqdn, ip=h.ip)
    other = VmHost(hostname="other.corp.test", ip=h.ip)
    db_session.add_all([vm, other, VmCve(cve_id="CVE-2026-1111"), VmCve(cve_id="CVE-2026-2222")])
    db_session.flush()
    db_session.add_all(
        [
            AssetObservation(
                asset_id=h.id, source="vm", source_key=f"{vm.hostname}|{vm.ip}", seen_at=NOW
            ),
            VmHostCve(host_id=vm.id, cve_id="CVE-2026-1111", risk=90),
            VmHostCve(host_id=other.id, cve_id="CVE-2026-2222", risk=99),
        ]
    )
    db_session.commit()
    r = auth_client.post(API, json={"query": h.fqdn}).json()
    assert [x["title"] for x in section(r, "vulnerabilities")["items"]] == ["CVE-2026-1111"]


@pytest.mark.parametrize("subject_class,disabled_bit", [("user", 1), ("computer", 2)])
def test_ad_scope_honours_inheritance_enforced_links_and_disabled_parts(
    subject_class, disabled_bit
):
    from api.modules.ad.core.export import ExportIndex
    from api.platform.search.policies import applicable_links
    from tests.ad.mini import DN, DOMAIN_SID, gpo, mini_export

    g = gpo("Scope")
    ou = f"OU=Blocked,{DN}"
    dn = f"CN=Subject,{ou}"

    def index(flags=0, enforced=False, blocked=True):
        return ExportIndex(
            mini_export(
                [
                    {**g, "flags": flags},
                    {
                        "dn": DN,
                        "class": "domainDNS",
                        "sid": DOMAIN_SID,
                        "gpLink": f"[LDAP://{g['dn']};{2 if enforced else 0}]",
                    },
                    {"dn": ou, "class": "organizationalUnit", "gpOptions": 1 if blocked else 0},
                    {"dn": dn, "class": subject_class},
                ]
            )
        )

    idx = index()
    assert not applicable_links(idx, idx.get(dn), idx.get(g["dn"]))
    idx = index(enforced=True)
    assert applicable_links(idx, idx.get(dn), idx.get(g["dn"]))
    idx = index(blocked=False)
    assert applicable_links(idx, idx.get(dn), idx.get(g["dn"]))
    idx = index(disabled_bit, enforced=True)
    assert not applicable_links(idx, idx.get(dn), idx.get(g["dn"]))


def test_candidates_are_bounded_and_no_automatic_choice(auth_client, db_session):
    db_session.add_all(
        AssetUser(sam="duplicate", name_key=f"d{i}.test\\duplicate", domain=f"d{i}.test")
        for i in range(23)
    )
    db_session.commit()
    r = auth_client.post(API, json={"query": "duplicate", "kind": "user"}).json()
    assert r["has_more"] and len(r["matches"]) == 20 and r["dossier"] is None


def test_nested_host_groups_and_cycles(auth_client, db_session, people):
    h, _, g = people
    parent = AssetGroup(
        group_key="corp:parent",
        sid="S-1-5-21-1-2002",
        name="Parent",
        domain="corp.test",
        sources=["ad"],
    )
    db_session.add(parent)
    db_session.flush()
    db_session.add_all(
        [
            AssetGroupMember(
                group_id=parent.id,
                member_kind="group",
                member_group_id=g.id,
                member_name=g.name,
                source="ad",
            ),
            AssetGroupMember(
                group_id=g.id,
                member_kind="group",
                member_group_id=parent.id,
                member_name=parent.name,
                source="ad",
            ),
        ]
    )
    db_session.commit()
    rows = section(auth_client.post(API, json={"query": h.fqdn}).json(), "groups")["items"]
    assert {r["target"]["id"] for r in rows} == {f"group:{g.id}", f"group:{parent.id}"}
    assert len(rows) == 2 and rows[1]["reason"] == "Вложенное членство"


def test_secondary_ip_finds_canonical_host(auth_client, db_session, people):
    h, _, _ = people
    db_session.add(
        AssetObservation(
            asset_id=h.id, source="vm", source_key="secondary", seen_at=NOW, ips=["10.99.0.2"]
        )
    )
    db_session.commit()
    response = auth_client.post(API, json={"query": "10.99.0.2"})
    assert response.status_code == 200
    assert response.json()["dossier"]["entity"]["id"] == f"host:{h.id}"


def test_user_gpo_dossier_uses_latest_ad_export(auth_client, db_session, people, monkeypatch):
    from api.modules.ad.models import AdDomain, AdSnapshot
    from api.modules.assets.models import AssetUserObservation
    from tests.ad.mini import DN, DOMAIN_SID, gpo, mini_export, user

    _, u, _ = people
    g = gpo("User settings")
    account = user("alice", 1001)
    export = mini_export(
        [
            g,
            account,
            {"dn": DN, "class": "domainDNS", "sid": DOMAIN_SID, "gpLink": f"[LDAP://{g['dn']};0]"},
        ]
    )
    domain = AdDomain(sid=DOMAIN_SID, dns_root="corp.local", netbios="CORP")
    db_session.add(domain)
    db_session.flush()
    snap = AdSnapshot(domain_id=domain.id, collected_at=NOW, source="file")
    db_session.add(snap)
    db_session.flush()
    db_session.add(
        AssetUserObservation(
            user_id=u.id,
            source="ad",
            source_key=account["sid"],
            seen_at=NOW,
            data={"domain_id": domain.id},
        )
    )
    db_session.commit()
    monkeypatch.setattr("api.platform.search.policies.read_ad_export", lambda *args: export)
    r = auth_client.post(API, json={"query": "alice", "kind": "user"})
    assert r.status_code == 200, r.text
    section_ = section(r.json(), "ad_policies")
    assert len(section_["items"]) == 1 and "пользовательской" in section_["items"][0]["reason"]
    assert "не RSoP" in section_["note"]


def test_group_member_evidence_from_two_sources_is_one_row(auth_client, db_session, people):
    _, u, g = people
    db_session.add(
        AssetGroupMember(
            group_id=g.id, member_kind="user", user_id=u.id, member_name=u.sam, source="vm"
        )
    )
    db_session.commit()
    r = auth_client.post(API, json={"query": g.name, "kind": "group"}).json()
    rows = [
        x
        for x in section(r, "members")["items"]
        if x["target"] and x["target"]["id"] == f"user:{u.id}"
    ]
    assert len(rows) == 1 and "AD" in rows[0]["source"] and "VM" in rows[0]["source"]
