"""Lookup is local evidence, respects source permissions, and never merges host identities."""

import datetime as dt

import pytest

from api.modules.ad.models import AdDomain
from api.modules.assets.models import Asset, AssetObservation
from api.modules.ksc.models import KscHost, KscServer, KscSnapshot
from api.modules.vm.models import VmCve, VmHost, VmHostCve, VmImage, VmImageCve, VmRefNvd
from api.modules.vm.trend_models import (
    VmTrendCard,
    VmTrendEvidence,
    VmTrendIngestState,
    VmTrendPublication,
)

API = "/api/toolbox/lookup"
NOW = dt.datetime(2026, 11, 7, tzinfo=dt.UTC)
CVE = "CVE-2026-12345"


def group(response, id_):
    assert response.status_code == 200, response.text
    return next(g for g in response.json()["groups"] if g["id"] == id_)


@pytest.fixture
def inventory(db_session):
    db = db_session
    asset = Asset(
        name="web01",
        name_key="web01",
        fqdn="web01.corp.test",
        domain="corp.test",
        ip="10.1.2.3",
        last_seen=NOW,
    )
    domain = AdDomain(sid="S-1-5-21-1", dns_root="corp.test", netbios="CORP")
    server = KscServer(name="AV one")
    host = VmHost(hostname="web01.corp.test", ip="10.1.2.3")
    db.add_all([asset, domain, server, host, VmCve(cve_id=CVE, cvss=9.8, kev=True)])
    db.flush()
    db.add(
        AssetObservation(
            asset_id=asset.id,
            source="ad",
            source_key="S-1-5-21-1-1000",
            name="web01",
            fqdn=asset.fqdn,
            domain="corp.test",
            seen_at=NOW,
            extra={"domain_id": domain.id, "enabled": True},
        )
    )
    recent = KscSnapshot(server_id=server.id, collected_at=NOW, source="file")
    db.add(recent)
    db.flush()
    old = KscSnapshot(server_id=server.id, collected_at=NOW - dt.timedelta(days=10), source="file")
    db.add(old)
    db.flush()
    db.add_all(
        [
            KscHost(
                snapshot_id=recent.id,
                host_id="current",
                name="web01",
                fqdn=asset.fqdn,
                domain="corp.test",
                ip=asset.ip,
                protection="on",
            ),
            KscHost(snapshot_id=old.id, host_id="obsolete", name="web01", ip=asset.ip),
            VmHostCve(host_id=host.id, cve_id=CVE, risk=80),
        ]
    )
    db.commit()
    return asset, domain, host


def test_lookup_requires_login_and_toolbox_read(client, client_as):
    assert client.post(API, json={"query": "web01"}).status_code == 401
    assert client_as({"assets": "read"}).post(API, json={"query": "web01"}).status_code == 403
    r = client_as({"toolbox": "read"}).post(API, json={"query": "web01"})
    assert r.status_code == 200
    assert all(g["status"] == "denied" and not g["items"] for g in r.json()["groups"])


@pytest.mark.parametrize(
    "area,allowed",
    [
        ("assets", {"assets"}),
        ("ad", {"ad_domains", "ad_hosts"}),
        ("ksc", {"antivirus"}),
        ("vm", {"vm_hosts", "vulnerabilities", "cve", "images", "publications"}),
    ],
)
def test_lookup_checks_each_source_permission(inventory, client_as, area, allowed):
    r = client_as({"toolbox": "read", area: "read"}).post(API, json={"query": "web01"})
    assert r.status_code == 200
    for g in r.json()["groups"]:
        if g["id"] not in allowed:
            assert g["status"] == "denied" and not g["items"] and not g["has_more"]
    assert any(g["items"] for g in r.json()["groups"])


def test_exact_name_latest_av_and_evidence(inventory, auth_client, db_session):
    db_session.add(Asset(name="web010", name_key="web010", fqdn="web010.corp.test"))
    db_session.commit()
    r = auth_client.post(API, json={"query": " WEB01.CORP.TEST. "})
    assert r.json()["query"] == "web01.corp.test"
    for id_ in ("assets", "ad_hosts", "antivirus", "vm_hosts", "vulnerabilities"):
        g = group(r, id_)
        assert len(g["items"]) == 1
        assert g["items"][0]["reason"]
        assert g["items"][0]["href"].startswith("/")
    av = group(r, "antivirus")["items"][0]
    assert "current" in av["href"] and "obsolete" not in str(av)
    assert av["observed_at"].startswith("2026-11-07")
    assert len(group(auth_client.post(API, json={"query": "web01"}), "assets")["items"]) == 1


def test_shared_ip_is_not_merged_and_domain_can_be_selected(inventory, db_session, auth_client):
    db_session.add(
        Asset(
            name="web02",
            name_key="web02",
            fqdn="web02.other.test",
            domain="other.test",
            ip="10.1.2.3",
        )
    )
    db_session.commit()
    assert len(group(auth_client.post(API, json={"query": "10.1.2.3"}), "assets")["items"]) == 2
    r = auth_client.post(API, json={"query": "CORP.TEST.", "kind": "domain"})
    assert len(group(r, "assets")["items"]) == 1
    assert len(group(r, "ad_domains")["items"]) == 1
    assert not group(auth_client.post(API, json={"query": "corp.test", "kind": "host"}), "assets")[
        "items"
    ]


def test_deleted_observations_and_merged_assets_are_excluded(inventory, db_session, auth_client):
    a, _, _ = inventory
    replacement = Asset(name="replacement")
    db_session.add(replacement)
    db_session.flush()
    a.merged_into = replacement.id
    obs = db_session.query(AssetObservation).filter_by(source="ad").first()
    obs.gone_at = NOW
    db_session.commit()
    r = auth_client.post(API, json={"query": "web01"})
    assert not group(r, "assets")["items"]
    assert not group(r, "ad_hosts")["items"]


def test_cve_has_hosts_images_and_only_current_publications(inventory, db_session, auth_client):
    image = VmImage(
        project="prod",
        repository="api",
        digest="sha256:test",
        scan_status="success",
        scanned_at=NOW,
    )
    db_session.add(image)
    db_session.flush()
    db_session.add(
        VmImageCve(
            image_id=image.id,
            cve_id=CVE,
            package="lib-test",
            installed_version="1",
            trivy_severity="critical",
        )
    )
    db_session.add(
        VmTrendIngestState(
            id=1, collector_id="test", epoch="1", generation="new", active_generation="new"
        )
    )
    db_session.add(VmTrendCard(id=CVE, title="Test threat"))
    db_session.flush()
    for gen, retracted, title in [
        ("new", False, "Current evidence"),
        ("old", False, "Old evidence"),
        ("new", True, "Retracted evidence"),
    ]:
        pub = VmTrendPublication(
            generation=gen,
            external_id=title,
            source_id="test",
            revision=1,
            data={"title": title, "published_at": NOW.isoformat()},
            retracted=retracted,
        )
        db_session.add(pub)
        db_session.flush()
        db_session.add(VmTrendEvidence(card_id=CVE, publication_id=pub.id))
    db_session.commit()
    r = auth_client.post(API, json={"query": CVE.lower()})
    assert r.json()["kind"] == "cve"
    for id_ in ("vm_hosts", "vulnerabilities", "cve", "images", "publications"):
        assert len(group(r, id_)["items"]) == 1
    assert group(r, "publications")["items"][0]["title"] == "Current evidence"


def test_cve_known_only_to_local_reference(db_session, auth_client):
    db_session.add(VmRefNvd(cve_id=CVE, year=2026, cvss_v3=7.5, description="Reference only"))
    db_session.commit()
    r = auth_client.post(API, json={"query": CVE})
    assert len(group(r, "cve")["items"]) == 1
    assert not group(r, "vm_hosts")["items"]


@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        "%",
        "10.300.1.1",
        "https://corp.test/a",
        "CVE-2026-x",
        "a" * 254,
        "foo bar",
        "10.1.2.0/24",
    ],
)
def test_invalid_input(auth_client, value):
    assert auth_client.post(API, json={"query": value}).status_code == 422


def test_empty_and_bounded_results(auth_client, db_session):
    r = auth_client.post(API, json={"query": "unknown.test"})
    assert r.status_code == 200 and all(not g["items"] for g in r.json()["groups"])
    db_session.add_all(
        [Asset(name=f"host{i}", name_key=f"host{i}", domain="corp.test") for i in range(25)]
    )
    db_session.commit()
    g = group(auth_client.post(API, json={"query": "corp.test", "kind": "domain"}), "assets")
    assert len(g["items"]) == 20 and g["has_more"]


def test_equivalent_ipv6_and_malformed_stored_ip(auth_client, db_session):
    db_session.add_all(
        [
            Asset(name="ipv6-host", ip="2001:0DB8:0:0::0001"),
            Asset(name="bad-import", ip="not-an-address"),
        ]
    )
    db_session.commit()
    r = auth_client.post(API, json={"query": "2001:db8::1"})
    assert [i["title"] for i in group(r, "assets")["items"]] == ["ipv6-host"]


def test_vm_host_link_includes_all_imported_states(inventory, auth_client):
    from urllib.parse import parse_qs, urlparse

    r = auth_client.post(API, json={"query": CVE})
    link = group(r, "vm_hosts")["items"][0]["href"]
    assert parse_qs(urlparse(link).query)["status"] == ["all"]
