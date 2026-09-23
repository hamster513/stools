from __future__ import annotations

from typing import Any, ClassVar

from fastapi.testclient import TestClient

from api.modules.ad.services import connections as svc
from tests.ad.fake_ldap import FakeLdap


class _FakeConn:
    def __init__(self) -> None:
        self.fake = FakeLdap()

        class Info:
            other: ClassVar[dict[str, list[str]]] = {"defaultNamingContext": ["DC=corp,DC=local"], "configurationNamingContext": ["CN=Configuration,DC=corp,DC=local"], "schemaNamingContext": ["CN=Schema,CN=Configuration,DC=corp,DC=local"]}

        class Server:
            info = Info()

        self.server = Server()

    def unbind(self) -> None:
        pass


def test_connection_crud_hides_password(auth_client: TestClient) -> None:
    r = auth_client.post("/api/ad/connections", json={"title": "CORP", "host": "dc01.corp.local", "username": "CORP\\auditor", "password": "secret"})
    assert r.status_code == 201
    body = r.json()
    assert body["password_set"] is True and "password" not in body
    cid = body["id"]
    r = auth_client.put(f"/api/ad/connections/{cid}", json={"title": "CORP-2", "host": "dc01.corp.local", "username": "CORP\\auditor", "password": ""})
    assert r.json()["title"] == "CORP-2" and r.json()["password_set"] is True
    assert len(auth_client.get("/api/ad/connections").json()) == 1
    assert auth_client.delete(f"/api/ad/connections/{cid}").status_code == 204
    assert auth_client.get("/api/ad/connections").json() == []


def test_collect_via_fake_ldap(auth_client: TestClient, monkeypatch: Any) -> None:
    fake_conn = _FakeConn()
    monkeypatch.setattr(svc, "ldap3_connection", lambda conn: fake_conn)
    monkeypatch.setattr(svc, "ldap3_searcher", lambda c: fake_conn.fake.search)
    monkeypatch.setattr(svc, "smb_reader", lambda host, u, p: fake_conn.fake.smb)
    r = auth_client.post("/api/ad/connections", json={"host": "dc01.corp.local", "username": "CORP\\auditor", "password": "secret"})
    cid = r.json()["id"]
    test = auth_client.post(f"/api/ad/connections/{cid}/test").json()
    assert test["ok"] and "DC=corp,DC=local" in test["message"]
    r = auth_client.post(f"/api/ad/connections/{cid}/collect")
    assert r.status_code == 202, r.text
    job = auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "done", job
    snaps = auth_client.get("/api/ad/snapshots").json()
    assert len(snaps) == 1 and snaps[0]["source"] == "ldap" and snaps[0]["findings"] > 20
    assert auth_client.get("/api/ad/connections").json()[0]["domain_id"] == snaps[0]["domain_id"]
    assert auth_client.post(f"/api/ad/connections/{cid}/collect").status_code == 202


def test_collector_script_download(auth_client: TestClient) -> None:
    r = auth_client.get("/api/ad/collector.ps1")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert "stools-ad/1" in r.text and "Get-ADRootDSE" in r.text


def test_collector_script_has_utf8_bom(auth_client: TestClient) -> None:
    # Windows PowerShell 5.1 без BOM читает файл в ANSI и ломает кириллицу в строках.
    r = auth_client.get("/api/ad/collector.ps1")
    assert r.content.startswith(b"\xef\xbb\xbf")


def _create(auth_client: TestClient, **extra: Any) -> int:
    body = {"title": "CORP", "host": "dc01.corp.local", "username": "CORP\\auditor", "password": "secret", **extra}
    r = auth_client.post("/api/ad/connections", json=body)
    assert r.status_code == 201, r.text
    return int(r.json()["id"])


def _stored_password(db_session: Any, cid: int) -> str:
    from api.crypto import decrypt
    from api.modules.ad.models import AdConnection

    db_session.expire_all()
    return decrypt(db_session.get(AdConnection, cid).password)


def _raw_password(db_session: Any, cid: int) -> str:
    from api.modules.ad.models import AdConnection

    db_session.expire_all()
    return str(db_session.get(AdConnection, cid).password)


def test_password_is_encrypted_at_rest(auth_client: TestClient, db_session: Any) -> None:
    cid = _create(auth_client)
    raw = _raw_password(db_session, cid)
    assert raw.startswith("enc:v1:") and "secret" not in raw
    assert auth_client.get("/api/ad/connections").json()[0]["password_set"] is True


def test_legacy_plaintext_password_is_used_and_reencrypted(auth_client: TestClient, db_session: Any, monkeypatch: Any) -> None:
    """Пароль, сохранённый до шифрования, уходит на контроллер как есть и
    шифруется при следующем сохранении подключения."""
    import ldap3
    from ldap3.core.exceptions import LDAPBindError

    from api.modules.ad.models import AdConnection

    sent: list[str] = []

    def bind(*args: Any, **kwargs: Any) -> Any:
        sent.append(kwargs["password"])
        raise LDAPBindError("invalid credentials")

    monkeypatch.setattr(ldap3, "Connection", bind)
    cid = _create(auth_client)
    db_session.get(AdConnection, cid).password = "secret"
    db_session.commit()
    assert auth_client.post(f"/api/ad/connections/{cid}/test").json() == {"ok": False, "message": "вход отклонён"}
    r = auth_client.put(f"/api/ad/connections/{cid}", json={"title": "другое", "host": "dc01.corp.local", "username": "CORP\\auditor", "password": ""})
    assert r.status_code == 200
    assert _raw_password(db_session, cid).startswith("enc:v1:")
    assert auth_client.post(f"/api/ad/connections/{cid}/test").json()["ok"] is False
    assert sent == ["secret", "secret"]


def test_sysvol_gets_the_decrypted_password(auth_client: TestClient, monkeypatch: Any) -> None:
    fake_conn = _FakeConn()
    seen: list[str] = []
    monkeypatch.setattr(svc, "ldap3_connection", lambda conn: fake_conn)
    monkeypatch.setattr(svc, "ldap3_searcher", lambda c: fake_conn.fake.search)
    monkeypatch.setattr(svc, "smb_reader", lambda host, u, p: seen.append(p) or fake_conn.fake.smb)
    cid = _create(auth_client)
    assert auth_client.post(f"/api/ad/connections/{cid}/collect").status_code == 202
    assert seen == ["secret"]


def test_address_change_requires_password(auth_client: TestClient, db_session: Any) -> None:
    cid = _create(auth_client)
    for change in ({"host": "evil.corp.local"}, {"port": 389}, {"use_ssl": False}, {"verify_tls": False}, {"username": "auditor@corp.local"}):
        r = auth_client.put(f"/api/ad/connections/{cid}", json={"host": "dc01.corp.local", "username": "CORP\\auditor", "password": "", **change})
        assert r.status_code == 422, (change, r.text)
        assert r.json()["detail"] == "при смене адреса или учётной записи пароль нужно ввести заново"
    assert _stored_password(db_session, cid) == "secret"
    assert auth_client.get("/api/ad/connections").json()[0]["host"] == "dc01.corp.local"
    r = auth_client.put(f"/api/ad/connections/{cid}", json={"host": "dc02.corp.local", "username": "CORP\\auditor", "password": "new"})
    assert r.status_code == 200 and r.json()["host"] == "dc02.corp.local"
    assert _stored_password(db_session, cid) == "new"


def test_title_change_keeps_password(auth_client: TestClient, db_session: Any) -> None:
    cid = _create(auth_client)
    r = auth_client.put(f"/api/ad/connections/{cid}", json={"title": "другое", "host": "dc01.corp.local", "username": "CORP\\auditor", "password": ""})
    assert r.status_code == 200 and r.json()["title"] == "другое" and r.json()["password_set"] is True
    assert _stored_password(db_session, cid) == "secret"


def test_host_must_be_name_or_ip(auth_client: TestClient) -> None:
    for bad in ("10.0.0.5/x?y", "https://dc01.corp.local", "dc01.corp.local:636", "u@dc01", "dc 01", ""):
        r = auth_client.post("/api/ad/connections", json={"host": bad})
        assert r.status_code == 422 and "адрес сервера: только имя или IP" in r.text, bad
    cid = _create(auth_client)
    r = auth_client.put(f"/api/ad/connections/{cid}", json={"host": "10.0.0.5/internal/admin?x=", "password": "secret"})
    assert r.status_code == 422
    assert _create(auth_client, host="10.0.0.5") and _create(auth_client, host="fe80::1")


def test_test_error_names_only_the_cause(auth_client: TestClient) -> None:
    cid = _create(auth_client, host="127.0.0.1", port=1, use_ssl=False)
    t = auth_client.post(f"/api/ad/connections/{cid}/test").json()
    assert t == {"ok": False, "message": "нет связи"}


def test_public_error_classes() -> None:
    import ssl

    from ldap3.core.exceptions import (
        LDAPBindError,
        LDAPInsufficientAccessRightsResult,
        LDAPSocketOpenError,
    )

    assert svc.public_error(LDAPBindError("automatic bind not successful - invalidCredentials dc01")) == "вход отклонён"
    assert svc.public_error(LDAPSocketOpenError("socket ssl wrapping error: [SSL: CERTIFICATE_VERIFY_FAILED]")) == "отказ TLS"
    assert svc.public_error(LDAPSocketOpenError("invalid server address")) == "нет связи"
    try:
        raise LDAPSocketOpenError("socket connection error") from ssl.SSLError("handshake")
    except LDAPSocketOpenError as exc:
        assert svc.public_error(exc) == "отказ TLS"
    assert svc.public_error(LDAPInsufficientAccessRightsResult()) == "нет прав"
    assert svc.public_error(RuntimeError("что-то с текстом сервера")) == "ошибка сервера"
    assert "base DN" in svc.public_error(svc.NoNamingContext("rootDSE не отдал defaultNamingContext — укажите base DN"))


def test_third_parallel_test_is_rejected(auth_client: TestClient, monkeypatch: Any) -> None:
    import threading

    entered = threading.Semaphore(0)
    release = threading.Event()

    def slow(conn: Any) -> dict[str, Any]:
        entered.release()
        release.wait(10)
        return {"ok": True, "message": "подключились"}

    monkeypatch.setattr(svc, "test_connection", slow)
    cid = _create(auth_client)
    codes: list[int] = []
    threads = [threading.Thread(target=lambda: codes.append(auth_client.post(f"/api/ad/connections/{cid}/test").status_code)) for _ in range(2)]
    for t in threads:
        t.start()
    assert entered.acquire(timeout=10) and entered.acquire(timeout=10)
    r = auth_client.post(f"/api/ad/connections/{cid}/test")
    assert r.status_code == 429 and r.json()["detail"] == "дождитесь завершения проверки"
    assert auth_client.post(f"/api/ad/connections/{cid}/collect").status_code == 429
    release.set()
    for t in threads:
        t.join(10)
    assert codes == [200, 200]
    assert auth_client.post(f"/api/ad/connections/{cid}/test").status_code == 200


def test_put_summary_lists_changed_fields(auth_client: TestClient, db_session: Any) -> None:
    from api.db.models import AuditEvent

    cid = _create(auth_client)
    auth_client.put(f"/api/ad/connections/{cid}", json={"title": "CORP", "host": "dc02.corp.local", "port": 389, "username": "CORP\\auditor", "password": "new-secret"})
    auth_client.put(f"/api/ad/connections/{cid}", json={"title": "CORP", "host": "dc03.corp.local", "port": 389, "username": "CORP\\auditor", "password": ""})
    db_session.expire_all()
    events = [e for e in db_session.query(AuditEvent).order_by(AuditEvent.id) if e.method == "PUT"]
    assert [(e.status, e.summary) for e in events] == [(200, "изменено: host, port, password"), (422, "изменено: host")]
    assert all("dc0" not in (e.summary or "") and "secret" not in (e.summary or "") for e in events)
