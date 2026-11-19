"""Online KSC MFA and secret boundary regressions."""
import pytest
import httpx

from api.modules.ksc.core import client as client_mod
from api.modules.ksc.core.client import KscClient, KscError
from tests.ksc.fake_ksc import FakeKsc, MFA_SECRET, PASSWORD, USER, http_factory_for


def test_online_mfa_login(monkeypatch):
    fake = FakeKsc(variant="mfa")
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(fake))
    with KscClient("https://ksc01:13299", USER, PASSWORD, totp_secret=MFA_SECRET) as client:
        assert client.call("HostGroup.GetStaticInfo", {"pValues": []})
    assert fake.calls.count("Session.StartSession") == 2
    assert fake.calls[-1] == "Session.EndSession"


def test_mfa_requires_secret(monkeypatch):
    fake = FakeKsc(variant="mfa")
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(fake))
    with pytest.raises(KscError) as error:
        with KscClient("https://ksc01:13299", USER, PASSWORD):
            pass
    assert error.value.kind == "mfa_required"
    assert fake.calls == ["Session.StartSession"]


def test_totp_vector_and_normalization():
    from api.modules.ksc.core.totp import normalize_secret, totp_code

    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert totp_code(secret, at=59) == "287082"
    assert totp_code(secret, at=1111111109) == "081804"
    assert normalize_secret("  " + secret.lower()[:16] + " \n" + secret.lower()[16:] + "  ") == secret


@pytest.mark.parametrize("secret", ["123456", "not-a-base32-secret", "otpauth://totp/secret", "A" * 513])
def test_invalid_secret_is_not_reflected(secret):
    from api.modules.ksc.core.totp import normalize_secret
    with pytest.raises(ValueError) as error:
        normalize_secret(secret)
    assert secret not in str(error.value)


@pytest.mark.parametrize("scenario", ["missing_session", "rejected_code", "server_echo"])
def test_mfa_failures_do_not_leak_secret_or_session(monkeypatch, scenario):
    calls = []
    def respond(request):
        calls.append(request)
        if len(calls) == 1:
            headers = {"WWW-Authenticate": 'KSCMFA realm="KSC"'}
            if scenario != "missing_session":
                headers["X-KSC-Session"] = "sensitive-pending-token"
            return httpx.Response(401, headers=headers)
        if scenario == "server_echo":
            return httpx.Response(200, json={"PxgError": {"code": 1, "message": MFA_SECRET + " " + request.headers["Authorization"]}})
        return httpx.Response(403)
    monkeypatch.setattr(client_mod, "http_factory", lambda verify: httpx.Client(transport=httpx.MockTransport(respond)))
    with pytest.raises(KscError) as error:
        with KscClient("https://ksc01", USER, PASSWORD, totp_secret=MFA_SECRET):
            pass
    assert error.value.kind in ("mfa_challenge", "mfa_invalid")
    assert all(value not in str(error.value) for value in (MFA_SECRET, "sensitive-pending-token"))
    assert len(calls) == (1 if scenario == "missing_session" else 2)


def test_forbidden_method_does_not_repeat_mfa(monkeypatch):
    fake = FakeKsc(variant="mfa", deny={"HostGroup.GetStaticInfo"})
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(fake))
    with KscClient("https://ksc01:13299", USER, PASSWORD, totp_secret=MFA_SECRET) as client:
        with pytest.raises(KscError) as error:
            client.call("HostGroup.GetStaticInfo", {})
        assert error.value.kind == "forbidden"
    assert fake.calls.count("Session.StartSession") == 2


BASE = {"host": "ksc01.corp.local", "username": USER, "password": PASSWORD}


def test_secret_encrypted_preserved_and_cleared(auth_client, db_session):
    from api.crypto import decrypt
    from api.modules.ksc.models import KscConnection

    response = auth_client.post("/api/ksc/connections", json={**BASE, "totp_secret": MFA_SECRET.lower()})
    assert response.status_code == 201
    cid = response.json()["id"]
    assert response.json()["totp_secret_set"] is True and "totp_secret" not in response.json()
    conn = db_session.get(KscConnection, cid)
    ciphertext = conn.totp_secret
    assert ciphertext.startswith("enc:v1:") and MFA_SECRET not in ciphertext
    assert decrypt(ciphertext) == MFA_SECRET
    response = auth_client.put(f"/api/ksc/connections/{cid}", json={**BASE, "password": "", "title": "renamed", "totp_secret": ""})
    assert response.status_code == 200 and response.json()["totp_secret_set"]
    db_session.expire_all()
    assert db_session.get(KscConnection, cid).totp_secret == ciphertext
    listing = auth_client.get("/api/ksc/connections")
    assert MFA_SECRET not in listing.text and ciphertext not in listing.text
    response = auth_client.put(f"/api/ksc/connections/{cid}", json={**BASE, "clear_totp_secret": True})
    assert response.status_code == 200 and response.json()["totp_secret_set"] is False
    db_session.expire_all()
    assert db_session.get(KscConnection, cid).totp_secret == ""


@pytest.mark.parametrize("change", [{"host": "other.ksc"}, {"port": 443}, {"username": "other"}, {"internal": False}, {"domain": "OTHER"}, {"verify_tls": False}])
def test_saved_totp_cannot_be_redirected(auth_client, db_session, change):
    from api.modules.ksc.models import KscConnection
    cid = auth_client.post("/api/ksc/connections", json={**BASE, "totp_secret": MFA_SECRET}).json()["id"]
    response = auth_client.put(f"/api/ksc/connections/{cid}", json={**BASE, **change})
    assert response.status_code == 422 and MFA_SECRET not in response.text
    db_session.expire_all()
    conn = db_session.get(KscConnection, cid)
    assert conn.host == BASE["host"] and conn.username == USER and conn.verify_tls
    response = auth_client.put(f"/api/ksc/connections/{cid}", json={**BASE, **change, "totp_secret": MFA_SECRET})
    assert response.status_code == 200


@pytest.mark.parametrize("value", ["private-invalid-secret", ["private-invalid-secret"], {"private-invalid-secret": True}, "A" * 513])
def test_connection_validation_hides_secret_input(auth_client, value):
    response = auth_client.post("/api/ksc/connections", json={**BASE, "totp_secret": value})
    assert response.status_code == 422
    assert "private-invalid-secret" not in response.text and "A" * 30 not in response.text and PASSWORD not in response.text


def test_cannot_set_and_clear_secret_together(auth_client):
    response = auth_client.post("/api/ksc/connections", json={**BASE, "totp_secret": MFA_SECRET, "clear_totp_secret": True})
    assert response.status_code == 422 and MFA_SECRET not in response.text


def test_totp_fails_closed_without_encryption(auth_client, monkeypatch):
    from api.modules.ksc.routers import connections
    monkeypatch.setattr(connections, "encrypt", lambda value: value)
    response = auth_client.post("/api/ksc/connections", json={**BASE, "totp_secret": MFA_SECRET})
    assert response.status_code == 422 and MFA_SECRET not in response.text
    assert auth_client.get("/api/ksc/connections").json() == []


def test_manual_and_scheduled_collection_with_mfa(auth_client, db_session, monkeypatch):
    import datetime as dt
    from sqlalchemy import select
    from api import collector_routes
    from api.modules.ksc.models import KscJob, KscSnapshot
    from api.platform.scheduler import tick
    from api.platform.sync_queue.worker import dispatch

    fake = FakeKsc(variant="mfa")
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(fake))
    monkeypatch.setattr(collector_routes, "spawn", lambda fn: fn())
    cid = auth_client.post("/api/ksc/connections", json={**BASE, "totp_secret": MFA_SECRET}).json()["id"]
    assert auth_client.post(f"/api/ksc/connections/{cid}/test").json()["ok"]
    response = auth_client.post(f"/api/ksc/connections/{cid}/collect")
    assert auth_client.get(f"/api/ksc/jobs/{response.json()['job_id']}").json()["status"] == "done"
    schedule = auth_client.put(f"/api/ksc/connections/{cid}/schedule", json={"interval_hours": 1, "window_from": None, "window_to": None, "enabled": True})
    assert schedule.status_code == 200
    assert len(tick(db_session, dt.datetime.now(dt.UTC) + dt.timedelta(hours=2))) == 1
    dispatch(db_session)
    db_session.expire_all()
    jobs = db_session.scalars(select(KscJob).order_by(KscJob.id).limit(3)).all()
    assert len(jobs) == 2 and all(job.status == "done" for job in jobs)
    assert jobs[-1].started_by == collector_routes.SCHEDULE_STARTED_BY
    assert len(db_session.scalars(select(KscSnapshot).limit(3)).all()) == 2
    assert fake.calls.count("Session.StartSession") == 6
    assert MFA_SECRET not in auth_client.get("/api/ksc/jobs").text


@pytest.mark.parametrize("secret", ["", MFA_SECRET])
def test_mfa_diagnostic_is_visible_without_echo(auth_client, monkeypatch, secret):
    fake = FakeKsc(variant="mfa")
    fake._mfa_ok = lambda headers: False
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(fake))
    cid = auth_client.post("/api/ksc/connections", json={**BASE, "totp_secret": secret}).json()["id"]
    response = auth_client.post(f"/api/ksc/connections/{cid}/test")
    assert response.json()["ok"] is False and "TOTP" in response.json()["message"]
    assert MFA_SECRET not in response.text and PASSWORD not in response.text
    response = auth_client.post(f"/api/ksc/connections/{cid}/collect")
    job = auth_client.get(f"/api/ksc/jobs/{response.json()['job_id']}")
    assert job.json()["status"] == "failed" and "TOTP" in job.json()["error"]
    assert MFA_SECRET not in job.text and PASSWORD not in job.text
    assert auth_client.get("/api/ksc/snapshots").json() == []


def test_replace_secret_and_explicitly_clear_on_new_address(auth_client, db_session):
    from api.crypto import decrypt
    from api.modules.ksc.models import KscConnection
    cid = auth_client.post("/api/ksc/connections", json={**BASE, "totp_secret": MFA_SECRET}).json()["id"]
    new_secret = "JBSWY3DPEHPK3PXP"
    response = auth_client.put(f"/api/ksc/connections/{cid}", json={**BASE, "totp_secret": new_secret})
    assert response.status_code == 200 and response.json()["totp_secret_set"]
    db_session.expire_all()
    assert decrypt(db_session.get(KscConnection, cid).totp_secret) == new_secret
    response = auth_client.put(f"/api/ksc/connections/{cid}", json={**BASE, "host": "replacement.ksc", "clear_totp_secret": True})
    assert response.status_code == 200 and response.json()["totp_secret_set"] is False
    db_session.expire_all()
    assert db_session.get(KscConnection, cid).totp_secret == ""
