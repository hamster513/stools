"""IRP session and service boundaries against the actual STools app."""
from datetime import timedelta

import pytest
from sqlalchemy import select

from api.crypto import hash_token
from api.db.models import AppUser, SessionRow
from api.main import app
from api.modules.assets.models import Asset, AssetUser
from api.modules.ksc.models import KscHost, KscServer, KscSnapshot
from api.modules.vm.models import VmCve, VmHost, VmHostCve, VmRefAttack
from api.timeutil import utcnow

PREFIX = "/api/integrations/irp/v1"
TOKEN = "test-irp-service-token"
BEARER = {"Authorization": f"Bearer {TOKEN}"}
ENTITY = {"kind": "host", "value": " APP-07 "}


def test_irp_session_checks_cookie_and_returns_denied_level(client_as, db_session, monkeypatch):
    monkeypatch.setenv("STOOLS_SESSION_COOKIE_NAME", "test_shared_cookie")
    auditor = client_as("auditor")
    response = auditor.get(f"{PREFIX}/session")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    data = response.json()
    assert data["contract_version"] == "1.0"
    assert data["user"] == {
        "id": str(db_session.scalar(select(AppUser.id).where(AppUser.login == "user-auditor"))),
        "login": "user-auditor", "display_name": None, "theme": "dark",
    }
    assert data["access"] == {"irp": "deny"}

    token = auditor.cookies["test_shared_cookie"]
    row = db_session.get(SessionRow, hash_token(token))
    row.expires_at = utcnow() - timedelta(seconds=1)
    db_session.commit()
    response = auditor.get(f"{PREFIX}/session")
    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"


def test_irp_session_rejects_blocked_user(client_as, db_session):
    analyst = client_as("analyst")
    user = db_session.scalar(select(AppUser).where(AppUser.login == "user-analyst"))
    user.is_active = False
    db_session.commit()
    assert analyst.get(f"{PREFIX}/session").status_code == 401


def test_irp_directory_filters_active_assignable_users(client_as, make_user, db_session):
    reader = client_as({"irp": "read"})
    writer = client_as({"irp": "write"})
    admin = client_as("admin")
    make_user("a-disabled", {"irp": "write"}).is_active = False
    make_user("a-analyst", "analyst")
    db_session.commit()

    assert reader.get(f"{PREFIX}/users").status_code == 403
    assert writer.get(f"{PREFIX}/session").json()["access"] == {"irp": "write"}
    assert admin.get(f"{PREFIX}/session").json()["access"] == {"irp": "admin"}
    response = writer.get(f"{PREFIX}/users", params={"limit": 1})
    assert response.status_code == 200
    first = response.json()
    assert first["truncated"] is True
    assert [item["login"] for item in first["items"]] == ["user-admin"]
    assert set(first["items"][0]) == {"id", "login", "display_name"}
    full = admin.get(f"{PREFIX}/users").json()
    assert full["truncated"] is False
    assert [item["login"] for item in full["items"]] == ["user-admin", "user-irp-write"]
    assert writer.get(f"{PREFIX}/users", params={"limit": 101}).status_code == 422


def test_irp_service_auth_and_default_scopes(client, client_as, db_session, monkeypatch):
    db_session.add(Asset(name="APP-07", name_key="app-07"))
    db_session.commit()
    monkeypatch.setenv("STOOLS_IRP_SERVICE_TOKEN", "")
    monkeypatch.setenv("STOOLS_IRP_ENRICHMENT_SCOPES", "")
    payload = {"entities": [ENTITY]}
    assert client.post(f"{PREFIX}/enrichment", json=payload).status_code == 401
    assert client.post(f"{PREFIX}/enrichment", json=payload, headers=BEARER).status_code == 503
    monkeypatch.setenv("STOOLS_IRP_SERVICE_TOKEN", TOKEN)
    assert client_as("admin").post(f"{PREFIX}/enrichment", json=payload).status_code == 401
    assert client.post(f"{PREFIX}/enrichment", json=payload, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get(f"{PREFIX}/session", headers=BEARER).status_code == 401
    assert client.get(f"{PREFIX}/users", headers=BEARER).status_code == 401
    assert client.post(f"{PREFIX}/enrichment", json=payload, headers={**BEARER, "Origin": "https://other.test"}).status_code == 403
    response = client.post(f"{PREFIX}/enrichment", json=payload, headers=BEARER)
    assert response.status_code == 200
    results = response.json()["results"]
    assert len(results) == 5
    assert all(r["status"] == "not_configured" and not r["data"] for r in results)
    assert {r["entity"]["value"] for r in results} == {"APP-07"}
    assert client.post(f"{PREFIX}/enrichment", json={"entities": [ENTITY] * 21}, headers=BEARER).status_code == 422


def test_irp_service_auth_precedes_json_decoding(client, monkeypatch):
    monkeypatch.setenv("STOOLS_IRP_SERVICE_TOKEN", "")
    path = f"{PREFIX}/enrichment"
    malformed = {"content": b"{", "headers": {"Content-Type": "application/json"}}
    assert client.post(path, **malformed).status_code == 401
    malformed["headers"].update(BEARER)
    assert client.post(path, **malformed).status_code == 503

    monkeypatch.setenv("STOOLS_IRP_SERVICE_TOKEN", TOKEN)
    assert client.post(path, **malformed).status_code == 422
    malformed["headers"]["Authorization"] = "Bearer wrong"
    assert client.post(path, **malformed).status_code == 401


def test_irp_enrichment_openapi_keeps_typed_body_and_bearer():
    operation = app.openapi()["paths"][f"{PREFIX}/enrichment"]["post"]
    assert operation["requestBody"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/EnrichmentRequest",
    }
    assert {"HTTPBearer": []} in operation["security"]


@pytest.fixture
def enrich(client, monkeypatch):
    monkeypatch.setenv("STOOLS_IRP_SERVICE_TOKEN", TOKEN)
    monkeypatch.setenv("STOOLS_IRP_ENRICHMENT_SCOPES", "assets,accounts,av,vm,attack")

    def call(*entities, sources=None):
        payload = {"entities": entities}
        if sources is not None:
            payload["sources"] = sources
        response = client.post(f"{PREFIX}/enrichment", json=payload, headers=BEARER)
        assert response.status_code == 200
        return response.json()["results"]

    return call


def test_irp_enrichment_when_inventory_unavailable(enrich):
    results = enrich(ENTITY)
    assert len(results) == 5
    assert all(r["status"] == "not_configured" and not r["data"] for r in results)


def test_irp_asset_allowlist_normalization_and_ambiguity(db_session, enrich):
    db_session.add(Asset(
        name="APP-07", name_key="app-07", ip="2001:db8::7", note="sensitive asset note",
        last_seen=utcnow(),
    ))
    db_session.commit()
    result, = enrich({"kind": "ip", "value": " 2001:0DB8::0007 "}, sources=["assets"])
    assert result["entity"] == {"kind": "ip", "value": "2001:db8::7"}
    assert result["status"] == "ok"
    assert result["observed_at"].endswith("Z")
    assert "note" not in result["data"]["matches"][0]

    db_session.add_all([Asset(name="APP-07", name_key="app-07", ip=f"192.0.2.{i}") for i in range(1, 23)])
    db_session.commit()
    result, = enrich(ENTITY, sources=["assets"])
    assert result["status"] == "ambiguous"
    assert len(result["data"]["matches"]) == 20
    assert result["data"]["truncated"] is True


def test_irp_reads_local_accounts_av_vm_and_attack(db_session, enrich):
    db_session.add(AssetUser(sam="alice", name_key="corp.test\\alice", note="sensitive account note"))
    vm = VmHost(hostname="app-07", ip="192.0.2.7")
    cve = VmCve(cve_id="CVE-2026-0001", description="raw vulnerability description")
    ksc = KscServer(name="test-ksc")
    db_session.add_all([vm, cve, ksc])
    db_session.flush()
    snap = KscSnapshot(server_id=ksc.id, source="file", collected_at=utcnow())
    db_session.add(snap)
    db_session.flush()
    db_session.add_all([
        KscHost(snapshot_id=snap.id, host_id="1", name="APP-07", extra_json='{"token":"sensitive"}'),
        VmHostCve(host_id=vm.id, cve_id=cve.cve_id, risk=8),
        VmRefAttack(cve_id=cve.cve_id, technique_id="T1190", mapping_type="exploitation_technique"),
    ])
    db_session.commit()

    account, = enrich({"kind": "user", "value": "ALICE"}, sources=["accounts"])
    assert account["status"] == "ok"
    assert account["data"]["matches"][0]["sam"] == "alice"
    assert "note" not in account["data"]["matches"][0]
    av, vm_result, attack = enrich(ENTITY, sources=["av", "vm", "attack"])
    assert [r["status"] for r in (av, vm_result, attack)] == ["ok", "ok", "ok"]
    assert av["data"]["matches"][0]["name"] == "APP-07"
    assert "extra_json" not in av["data"]["matches"][0]
    assert vm_result["data"]["vulnerabilities"][0] == {"cve_id": cve.cve_id, "risk": 8}
    assert attack["data"]["matches"][0]["technique_id"] == "T1190"



def test_irp_vm_and_attack_match_imported_ipv6_spellings(db_session, enrich):
    host = VmHost(hostname="app-07", ip="2001:0DB8:0:0:0:0:0:7")
    cve = VmCve(cve_id="CVE-2026-0001")
    db_session.add_all([host, cve, VmHost(hostname="invalid", ip="2001:db8:::7")])
    db_session.flush()
    db_session.add_all([
        VmHostCve(host_id=host.id, cve_id=cve.cve_id, risk=8),
        VmRefAttack(cve_id=cve.cve_id, technique_id="T1190", mapping_type="exploitation_technique"),
    ])
    db_session.commit()

    entity = {"kind": "ip", "value": "2001:db8::7"}
    vm, attack = enrich(entity, sources=["vm", "attack"])
    assert [vm["status"], attack["status"]] == ["ok", "ok"]
    assert vm["data"]["matches"][0]["hostname"] == "app-07"
    assert attack["data"]["matches"][0]["technique_id"] == "T1190"

    db_session.add(VmHost(hostname="another-host", ip="2001:db8::7"))
    db_session.commit()
    vm, attack = enrich(entity, sources=["vm", "attack"])
    assert [vm["status"], attack["status"]] == ["ambiguous", "ambiguous"]
    assert {host["hostname"] for host in vm["data"]["matches"]} == {"app-07", "another-host"}
    assert attack["data"] == {}
