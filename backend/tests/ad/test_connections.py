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
    monkeypatch.setattr(svc, "ldap3_searcher", lambda c, **kw: fake_conn.fake.search)
    monkeypatch.setattr(svc, "smb_access", lambda host, u, p, **kw: (fake_conn.fake.smb, fake_conn.fake.ls))
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
    monkeypatch.setattr(svc, "ldap3_searcher", lambda c, **kw: fake_conn.fake.search)
    monkeypatch.setattr(svc, "smb_access", lambda host, u, p, **kw: seen.append(p) or (fake_conn.fake.smb, fake_conn.fake.ls))
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


# ---- Сбор порциями с паузами -------------------------------------------------

PAGED_OID = "1.2.840.113556.1.4.319"


class _PagedConn(_FakeConn):
    """ldap3-соединение в режиме SYNC поверх FakeLdap: ответ режется страницами по `paged_size`."""

    def __init__(self, on_search: Any = None, fail_on: dict[int, tuple[int, str]] | None = None) -> None:
        super().__init__()
        self.fail_on = fail_on or {}
        self.paged_sizes: list[int | None] = []
        self.returned = 0
        self.auto_referrals = True
        self.on_search = on_search
        self.response: list[dict[str, Any]] = []
        self.result: dict[str, Any] = {}

    def search(self, search_base: str, search_filter: str, search_scope: Any = None, attributes: Any = None,
               controls: Any = None, paged_size: int | None = None, paged_cookie: bytes | None = None, **_: Any) -> bool:
        self.paged_sizes.append(paged_size)
        if self.on_search is not None:
            self.on_search(len(self.paged_sizes))
        if len(self.paged_sizes) in self.fail_on:
            code, description = self.fail_on[len(self.paged_sizes)]
            self.response, self.result = [], {"result": code, "description": description, "controls": {}}
            return False
        assert paged_size
        rows = [{**e, "type": "searchResEntry"} for e in self.fake.search(search_base, search_filter, attributes, search_scope)]
        start = int(paged_cookie or b"0")
        nxt = start + paged_size
        self.response = rows[start:nxt]
        self.returned += len(self.response)
        self.result = {"result": 0, "controls": {PAGED_OID: {"value": {"cookie": str(nxt).encode() if nxt < len(rows) else b""}}}}
        return True


def _real_searcher_with_fake_sleep(monkeypatch: Any, sleeps: list[float], seen: dict[str, Any]) -> None:
    """Настоящие поиск и дозатор; паузы дозатора — в `sleeps`, аргументы — в `seen`."""
    real_searcher, real_pacer = svc.ldap3_searcher, svc.Pacer

    def searcher(c: Any, **kw: Any) -> Any:
        seen.update(kw)
        return real_searcher(c, **kw)

    def pacer(pause_ms: int, *, check_cancel: Any = None) -> Any:
        seen.update(pause_ms=pause_ms, check_cancel=check_cancel)
        return real_pacer(pause_ms, check_cancel=check_cancel, sleep=sleeps.append)

    monkeypatch.setattr(svc, "ldap3_searcher", searcher)
    monkeypatch.setattr(svc, "Pacer", pacer)


def test_paging_defaults_and_ranges(auth_client: TestClient) -> None:
    cid = _create(auth_client)
    body = auth_client.get("/api/ad/connections").json()[0]
    assert (body["page_size"], body["pause_ms"]) == (500, 500)
    base = {"host": "dc01.corp.local", "username": "CORP\\auditor", "password": "secret"}
    for bad, text in (
        ({"page_size": 49}, "размер страницы LDAP: от 50 до 1000"),
        ({"page_size": 1001}, "размер страницы LDAP: от 50 до 1000"),
        ({"pause_ms": -1}, "пауза между запросами к контроллеру: от 0 до 10000 мс"),
        ({"pause_ms": 10001}, "пауза между запросами к контроллеру: от 0 до 10000 мс"),
        # Пустое числовое поле формы приходит как null.
        ({"page_size": None}, "размер страницы LDAP: от 50 до 1000"),
        ({"pause_ms": None}, "пауза между запросами к контроллеру: от 0 до 10000 мс"),
    ):
        r = auth_client.put(f"/api/ad/connections/{cid}", json={**base, **bad})
        assert r.status_code == 422 and text in r.text, (bad, r.text)
        r = auth_client.post("/api/ad/connections", json={**base, **bad})
        assert r.status_code == 422 and text in r.text, (bad, r.text)
    for ok in ({"page_size": 50, "pause_ms": 0}, {"page_size": 1000, "pause_ms": 10000}):
        r = auth_client.put(f"/api/ad/connections/{cid}", json={**base, **ok})
        assert r.status_code == 200 and (r.json()["page_size"], r.json()["pause_ms"]) == (ok["page_size"], ok["pause_ms"])


def test_paging_change_keeps_password(auth_client: TestClient, db_session: Any) -> None:
    """Размер страницы и пауза — не адрес: пароль заново вводить не нужно."""
    cid = _create(auth_client)
    r = auth_client.put(f"/api/ad/connections/{cid}", json={"host": "dc01.corp.local", "username": "CORP\\auditor", "password": "", "page_size": 200, "pause_ms": 2000})
    assert r.status_code == 200, r.text
    assert (r.json()["page_size"], r.json()["pause_ms"]) == (200, 2000)
    assert _stored_password(db_session, cid) == "secret"


def test_put_without_paging_keeps_stored_values(auth_client: TestClient) -> None:
    """PUT без page_size и pause_ms (старая форма, скрипт) не сбрасывает их на умолчания."""
    cid = _create(auth_client, page_size=200, pause_ms=1000)
    r = auth_client.put(f"/api/ad/connections/{cid}", json={"title": "другое", "host": "dc01.corp.local", "username": "CORP\\auditor", "password": ""})
    assert r.status_code == 200, r.text
    assert (r.json()["title"], r.json()["page_size"], r.json()["pause_ms"]) == ("другое", 200, 1000)
    # POST без этих полей по-прежнему получает умолчания.
    other = _create(auth_client)
    body = {c["id"]: c for c in auth_client.get("/api/ad/connections").json()}
    assert (body[other]["page_size"], body[other]["pause_ms"]) == (500, 500)


def test_old_connection_gets_paging_defaults(auth_client: TestClient, db_session: Any) -> None:
    """Строка, записанная без новых колонок (как до миграции), получает умолчания базы."""
    from sqlalchemy import text

    db_session.execute(text(
        "INSERT INTO ad_connection (title, host, port, use_ssl, verify_tls, username, password, base_dn, collect_sysvol) "
        "VALUES ('old', 'dc01.corp.local', 636, true, true, 'CORP\\auditor', '', '', true)"
    ))
    db_session.commit()
    body = auth_client.get("/api/ad/connections").json()[0]
    assert body["title"] == "old" and (body["page_size"], body["pause_ms"]) == (500, 500)


def test_collect_reads_in_pages_with_pauses_and_progress(auth_client: TestClient, monkeypatch: Any) -> None:
    from api import jobs

    fake_conn = _PagedConn()
    sleeps: list[float] = []
    seen: dict[str, Any] = {}
    ticks: list[tuple[int, str | None]] = []
    original_tick = jobs.JobHandle.tick

    def spy(self: jobs.JobHandle, processed: int, message: str | None = None, total: int | None = None) -> None:
        ticks.append((processed, message))
        original_tick(self, processed, message, total)

    monkeypatch.setattr(jobs.JobHandle, "tick", spy)
    monkeypatch.setattr(svc, "ldap3_connection", lambda conn: fake_conn)
    from api.modules.ad.core.ldap_collector import paced_lister, paced_reader

    smb_reads: list[str] = []
    smb_seen: dict[str, Any] = {}

    def smb(host: str, u: str, p: str, *, pacer: Any) -> Any:
        smb_seen["pacer"] = pacer

        def read(path: str) -> bytes | None:
            smb_reads.append(path)
            return fake_conn.fake.smb(path)

        def ls(path: str) -> list[str] | None:
            smb_reads.append(path)  # листинг папки — такой же запрос к контроллеру
            return fake_conn.fake.ls(path)

        return paced_reader(read, pacer), paced_lister(ls, pacer)

    monkeypatch.setattr(svc, "smb_access", smb)
    _real_searcher_with_fake_sleep(monkeypatch, sleeps, seen)
    cid = _create(auth_client, page_size=50, pause_ms=250)
    r = auth_client.post(f"/api/ad/connections/{cid}/collect")
    assert r.status_code == 202, r.text
    job = auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "done", job
    assert seen["page_size"] == 50 and seen["pause_ms"] == 250 and callable(seen["check_cancel"])
    assert set(fake_conn.paged_sizes) == {50}
    # LDAP и SYSVOL идут через один дозатор: пауза между любыми двумя запросами к контроллеру,
    # в том числе на стыке LDAP и SMB; после последнего — нет.
    assert smb_reads and smb_seen["pacer"] is seen["pacer"]
    assert sleeps == [0.25] * (len(fake_conn.paged_sizes) + len(smb_reads) - 1)
    reads = [t for t in ticks if t[1] and t[1].startswith("прочитано объектов")]
    assert len(reads) == len(fake_conn.paged_sizes)
    assert reads[-1] == (fake_conn.returned, f"прочитано объектов {fake_conn.returned}")
    assert fake_conn.returned > 20


def test_cancel_between_pages_stops_collect(auth_client: TestClient, db_session: Any, monkeypatch: Any) -> None:
    from sqlalchemy import func, select, update

    from api.modules.ad.models import AdJob, AdSnapshot

    def cancel_on_third(n: int) -> None:
        if n == 3:
            db_session.execute(update(AdJob).values(cancel_requested=True))
            db_session.commit()

    fake_conn = _PagedConn(on_search=cancel_on_third)
    monkeypatch.setattr(svc, "ldap3_connection", lambda conn: fake_conn)
    monkeypatch.setattr(svc, "smb_access", lambda host, u, p, **kw: (fake_conn.fake.smb, fake_conn.fake.ls))
    _real_searcher_with_fake_sleep(monkeypatch, [], {})
    cid = _create(auth_client)
    r = auth_client.post(f"/api/ad/connections/{cid}/collect")
    assert r.status_code == 202, r.text
    job = auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "cancelled", job
    # Отмена замечена сразу после третьей страницы: четвёртого запроса к контроллеру нет.
    assert len(fake_conn.paged_sizes) == 3
    db_session.expire_all()
    assert db_session.scalar(select(func.count()).select_from(AdSnapshot)) == 0


def test_busy_controller_fails_job_without_snapshot(auth_client: TestClient, db_session: Any, monkeypatch: Any) -> None:
    """Контроллер ответил busy на второй странице: задача failed с понятным текстом, снапшота нет."""
    from sqlalchemy import func, select

    from api.modules.ad.models import AdSnapshot

    fake_conn = _PagedConn(fail_on={2: (51, "busy")})
    monkeypatch.setattr(svc, "ldap3_connection", lambda conn: fake_conn)
    monkeypatch.setattr(svc, "smb_access", lambda host, u, p, **kw: (fake_conn.fake.smb, fake_conn.fake.ls))
    _real_searcher_with_fake_sleep(monkeypatch, [], {})
    cid = _create(auth_client)
    r = auth_client.post(f"/api/ad/connections/{cid}/collect")
    job = auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "failed", job
    assert job["error"].startswith("контроллер ответил busy (51) на поиске"), job["error"]
    assert len(fake_conn.paged_sizes) == 2
    db_session.expire_all()
    assert db_session.scalar(select(func.count()).select_from(AdSnapshot)) == 0


def test_cancel_during_pause_stops_before_next_request(auth_client: TestClient, db_session: Any, monkeypatch: Any) -> None:
    from sqlalchemy import update

    from api.modules.ad.models import AdJob

    fake_conn = _PagedConn()
    monkeypatch.setattr(svc, "ldap3_connection", lambda conn: fake_conn)
    monkeypatch.setattr(svc, "smb_access", lambda host, u, p, **kw: (fake_conn.fake.smb, fake_conn.fake.ls))
    real = svc.Pacer

    def cancel_in_pause(seconds: float) -> None:
        db_session.execute(update(AdJob).values(cancel_requested=True))
        db_session.commit()

    monkeypatch.setattr(svc, "Pacer", lambda pause_ms, *, check_cancel: real(pause_ms, check_cancel=check_cancel, sleep=cancel_in_pause))
    cid = _create(auth_client)
    r = auth_client.post(f"/api/ad/connections/{cid}/collect")
    job = auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "cancelled", job
    # Первый запрос прошёл, отмена пришла в паузе — второго запроса нет.
    assert len(fake_conn.paged_sizes) == 1


# ---- Расписание сбора --------------------------------------------------------


def test_schedule_create_read_and_delete(auth_client: TestClient, db_session: Any) -> None:
    from sqlalchemy import select

    from api.platform.scheduler import PlatformSchedule

    cid = _create(auth_client)
    url = f"/api/ad/connections/{cid}/schedule"
    assert auth_client.get(url).json() is None
    assert auth_client.get("/api/ad/connections").json()[0]["schedule"] is None
    r = auth_client.put(url, json={"interval_hours": 24, "window_from": "02:00", "window_to": "05:00", "enabled": True})
    assert r.status_code == 200, r.text
    assert (r.json()["interval_hours"], r.json()["window_from"], r.json()["enabled"]) == (24, "02:00", True)
    db_session.expire_all()
    sched = db_session.execute(select(PlatformSchedule)).scalar_one()
    assert (sched.module, sched.kind, sched.target_id) == ("ad", "collect", cid)
    assert auth_client.get(url).json()["id"] == sched.id
    assert auth_client.get("/api/ad/connections").json()[0]["schedule"]["id"] == sched.id
    assert auth_client.put(url, json={"interval_hours": 12, "window_from": "02:00", "window_to": None, "enabled": True}).status_code == 422
    assert auth_client.put("/api/ad/connections/999999/schedule", json={"interval_hours": 12, "enabled": True}).status_code == 404
    assert auth_client.delete(url).status_code == 204
    db_session.expire_all()
    assert db_session.execute(select(PlatformSchedule)).scalars().all() == []
    # Удаление подключения уносит и его расписание.
    assert auth_client.put(url, json={"interval_hours": 12, "enabled": True}).status_code == 200
    assert auth_client.delete(f"/api/ad/connections/{cid}").status_code == 204
    db_session.expire_all()
    assert db_session.execute(select(PlatformSchedule)).scalars().all() == []


def test_scheduler_tick_collects_via_fake_ldap(auth_client: TestClient, db_session: Any, monkeypatch: Any) -> None:
    import datetime as dt

    from sqlalchemy import select

    from api import collector_routes
    from api.collector_routes import SCHEDULE_STARTED_BY
    from api.modules.ad.models import AdJob
    from api.platform.scheduler import PlatformSchedule, tick

    monkeypatch.setattr(collector_routes, "spawn", lambda fn: fn())
    fake_conn = _FakeConn()
    monkeypatch.setattr(svc, "ldap3_connection", lambda conn: fake_conn)
    monkeypatch.setattr(svc, "ldap3_searcher", lambda c, **kw: fake_conn.fake.search)
    monkeypatch.setattr(svc, "smb_access", lambda host, u, p, **kw: (fake_conn.fake.smb, fake_conn.fake.ls))
    cid = _create(auth_client)
    assert auth_client.put(f"/api/ad/connections/{cid}/schedule", json={"interval_hours": 1, "enabled": True}).status_code == 200
    now = dt.datetime.now(dt.UTC) + dt.timedelta(hours=2)
    started = tick(db_session, now)
    assert len(started) == 1
    db_session.expire_all()
    job = db_session.get(AdJob, started[0])
    assert job is not None and (job.kind, job.started_by) == ("collect", SCHEDULE_STARTED_BY)
    assert job.status == "done", job.error
    assert job.message.startswith("снапшот #")
    snaps = auth_client.get("/api/ad/snapshots").json()
    assert len(snaps) == 1 and snaps[0]["source"] == "ldap"
    sched = db_session.execute(select(PlatformSchedule)).scalar_one()
    assert sched.last_job_id == job.id and sched.next_run_at == now + dt.timedelta(hours=1)
    # Без пароля расписание выключается на следующем срабатывании.
    from api.modules.ad.models import AdConnection

    db_session.get(AdConnection, cid).password = ""
    db_session.commit()
    assert tick(db_session, now + dt.timedelta(hours=2)) == []
    db_session.expire_all()
    assert db_session.execute(select(PlatformSchedule)).scalar_one().enabled is False
