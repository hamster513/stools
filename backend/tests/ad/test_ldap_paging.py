"""Постраничный поиск ldap3: размер страницы, паузы между запросами, прогресс и отмена.

Поддельное соединение повторяет то, что сборщик берёт у ldap3 в режиме SYNC:
`search(...)` кладёт ответ в `response`, итог с cookie постраничного контрола — в `result`.
"""
from __future__ import annotations

from typing import Any

import pytest

from api.jobs import JobCancelled
from api.modules.ad.core.ldap_collector import (
    PAUSE_MS_DEFAULT,
    LdapResultError,
    Pacer,
    ldap3_searcher,
    paced_reader,
)

PAGED_OID = "1.2.840.113556.1.4.319"
SD_FLAGS_OID = "1.2.840.113556.1.4.801"


def _entry(dn: str) -> dict[str, Any]:
    return {"type": "searchResEntry", "dn": dn, "attributes": {"name": [dn]}, "raw_attributes": {}}


class FakeLdap3:
    """Отдаёт ответ страницами по `paged_size`; cookie — номер следующей страницы."""

    def __init__(self, results: dict[str, list[dict[str, Any]]]) -> None:
        self.results = results
        self.calls: list[dict[str, Any]] = []
        self.auto_referrals = True
        self.response: list[dict[str, Any]] | None = None
        self.result: dict[str, Any] = {}
        #: Номер запроса (с 1) → (код, описание): контроллер отвечает ошибкой без страницы.
        self.fail: dict[int, tuple[int, str]] = {}

    def search(self, search_base: str, search_filter: str, search_scope: Any = None, attributes: Any = None,
               controls: Any = None, paged_size: int | None = None, paged_cookie: bytes | None = None, **_: Any) -> bool:
        self.calls.append({"base": search_base, "filter": search_filter, "scope": search_scope, "attributes": attributes,
                           "controls": controls, "paged_size": paged_size, "paged_cookie": paged_cookie})
        if len(self.calls) in self.fail:
            code, description = self.fail[len(self.calls)]
            self.response = []
            self.result = {"result": code, "description": description, "controls": {}}
            return False
        rows = self.results.get(search_filter, [])
        assert paged_size
        start = int(paged_cookie or b"0")
        page = rows[start : start + paged_size]
        nxt = start + paged_size
        self.response = [*page, {"type": "searchResRef", "uri": ["ldap://other/"]}]
        self.result = {"result": 0, "controls": {PAGED_OID: {"value": {"size": 0, "cookie": str(nxt).encode() if nxt < len(rows) else b""}}}}
        return True


def _rows(n: int, prefix: str = "CN=o") -> list[dict[str, Any]]:
    return [_entry(f"{prefix}{i},DC=corp,DC=local") for i in range(n)]


def _searcher(conn: FakeLdap3, sleeps: list[float], pages: list[int] | None = None, *, pause_ms: int = PAUSE_MS_DEFAULT, **kw: Any) -> Any:
    pacer = Pacer(pause_ms, sleep=sleeps.append)
    return ldap3_searcher(conn, pacer=pacer, on_page=pages.append if pages is not None else None, **kw)


def test_page_size_and_cookie_are_passed() -> None:
    conn = FakeLdap3({"(objectClass=user)": _rows(5)})
    got = list(_searcher(conn, [], page_size=2, pause_ms=0)("DC=corp,DC=local", "(objectClass=user)", ["name"], "SUBTREE"))
    assert [c["paged_size"] for c in conn.calls] == [2, 2, 2]
    assert [c["paged_cookie"] for c in conn.calls] == [None, b"2", b"4"]
    # Ссылки на другие разделы (searchResRef) не выдаются как объекты.
    assert [e["dn"] for e in got] == [f"CN=o{i},DC=corp,DC=local" for i in range(5)]
    assert got[0] == {"dn": "CN=o0,DC=corp,DC=local", "attributes": {"name": ["CN=o0,DC=corp,DC=local"]}, "raw_attributes": {}}
    # Автоматический переход по ссылкам с постраничным поиском несовместим — выключен, как в ldap3.
    assert conn.auto_referrals is False


def test_one_level_scope_is_passed_to_ldap3() -> None:
    from ldap3 import LEVEL

    conn = FakeLdap3({"(objectClass=*)": _rows(1)})
    list(_searcher(conn, [], pause_ms=0)("CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local", "(objectClass=*)", ["name"], "LEVEL"))
    assert conn.calls[0]["scope"] == LEVEL


def test_defaults_page_500_pause_half_second() -> None:
    conn = FakeLdap3({"(objectClass=user)": _rows(1200)})
    sleeps: list[float] = []
    list(ldap3_searcher(conn, pacer=Pacer(sleep=sleeps.append))("DC=corp,DC=local", "(objectClass=user)", ["name"], "SUBTREE"))
    assert [c["paged_size"] for c in conn.calls] == [500, 500, 500]
    assert sleeps == [0.5, 0.5]


def test_pause_between_pages_and_not_after_last() -> None:
    conn = FakeLdap3({"(objectClass=user)": _rows(5)})
    sleeps: list[float] = []
    it = iter(_searcher(conn, sleeps, page_size=2, pause_ms=1500)("DC=corp,DC=local", "(objectClass=user)", ["name"], "SUBTREE"))
    # Первая страница — без паузы.
    next(it), next(it)
    assert sleeps == [] and len(conn.calls) == 1
    # Вторая страница: пауза перед запросом.
    next(it)
    assert sleeps == [1.5] and len(conn.calls) == 2
    rest = list(it)
    assert len(rest) == 2
    # Три запроса — две паузы; после последней страницы паузы нет.
    assert sleeps == [1.5, 1.5] and len(conn.calls) == 3


def test_single_page_has_no_pause() -> None:
    conn = FakeLdap3({"(objectClass=user)": _rows(3)})
    sleeps: list[float] = []
    assert len(list(_searcher(conn, sleeps, page_size=500, pause_ms=500)("DC=corp,DC=local", "(objectClass=user)", ["name"], "SUBTREE"))) == 3
    assert sleeps == []


def test_zero_pause_does_not_sleep() -> None:
    conn = FakeLdap3({"(objectClass=user)": _rows(5)})
    sleeps: list[float] = []
    assert len(list(_searcher(conn, sleeps, page_size=2, pause_ms=0)("DC=corp,DC=local", "(objectClass=user)", ["name"], "SUBTREE"))) == 5
    assert sleeps == []


def test_pause_between_separate_searches() -> None:
    """Дозапросы имён по SID (`_resolve_pending`) идут отдельными поисками — пауза и между ними."""
    conn = FakeLdap3({"(objectSid=S-1)": _rows(1, "CN=a"), "(objectSid=S-2)": _rows(1, "CN=b")})
    sleeps: list[float] = []
    search = _searcher(conn, sleeps, page_size=100, pause_ms=500)
    assert len(list(search("DC=corp,DC=local", "(objectSid=S-1)", ["objectSid"], "SUBTREE"))) == 1
    assert sleeps == []
    assert len(list(search("DC=corp,DC=local", "(objectSid=S-2)", ["objectSid"], "SUBTREE"))) == 1
    assert sleeps == [0.5]


def test_progress_counts_objects_across_searches() -> None:
    conn = FakeLdap3({"(objectClass=user)": _rows(5), "(objectClass=group)": _rows(3, "CN=g")})
    pages: list[int] = []
    search = _searcher(conn, [], pages, page_size=2, pause_ms=0)
    list(search("DC=corp,DC=local", "(objectClass=user)", ["name"], "SUBTREE"))
    list(search("DC=corp,DC=local", "(objectClass=group)", ["name"], "SUBTREE"))
    assert pages == [2, 4, 5, 7, 8]


def test_cancel_between_pages_stops_collection() -> None:
    conn = FakeLdap3({"(objectClass=user)": _rows(5)})
    sleeps: list[float] = []

    def on_page(n: int) -> None:
        raise JobCancelled()

    search = ldap3_searcher(conn, page_size=2, pacer=Pacer(500, sleep=sleeps.append), on_page=on_page)
    with pytest.raises(JobCancelled):
        list(search("DC=corp,DC=local", "(objectClass=user)", ["name"], "SUBTREE"))
    # Следующая страница не запрошена, пауза не выдержана.
    assert len(conn.calls) == 1 and sleeps == []


def test_sd_flags_control_only_for_descriptor() -> None:
    conn = FakeLdap3({"(objectClass=group)": _rows(1)})
    search = _searcher(conn, [], page_size=10, pause_ms=0)
    list(search("DC=corp,DC=local", "(objectClass=group)", ["name"], "SUBTREE"))
    list(search("DC=corp,DC=local", "(objectClass=group)", ["name", "nTSecurityDescriptor"], "SUBTREE"))
    assert conn.calls[0]["controls"] is None
    assert [str(c[0]) for c in conn.calls[1]["controls"]] == [SD_FLAGS_OID]
    # SDFlagsRequestValue ::= SEQUENCE { Flags INTEGER } = 5: OWNER | DACL, без SACL.
    assert bytes(conn.calls[1]["controls"][0][2]) == b"0\x03\x02\x01\x05"


def test_error_result_on_page_two_stops_with_readable_error() -> None:
    """busy/unavailable/timeLimitExceeded приходят без постраничного контрола: раньше
    петля молча заканчивалась, и снапшот выходил без части объектов."""
    conn = FakeLdap3({"(objectClass=user)": _rows(5)})
    conn.fail = {2: (51, "busy")}
    got: list[str] = []
    with pytest.raises(LdapResultError) as err:
        for e in _searcher(conn, [], page_size=2, pause_ms=0)("DC=corp,DC=local", "(objectClass=user)", ["name"], "SUBTREE"):
            got.append(e["dn"])
    assert err.value.code == 51
    assert str(err.value) == "контроллер ответил busy (51) на поиске (objectClass=user) — сбор прерван"
    assert len(got) == 2 and len(conn.calls) == 2


def test_error_text_cuts_long_filter() -> None:
    flt = "(|" + "".join(f"(objectSid=S-1-5-21-{i})" for i in range(20)) + ")"
    conn = FakeLdap3({})
    conn.fail = {1: (3, "timeLimitExceeded")}
    with pytest.raises(LdapResultError) as err:
        list(_searcher(conn, [], pause_ms=0)("DC=corp,DC=local", flt, ["objectSid"], "SUBTREE"))
    text = str(err.value)
    assert text.startswith("контроллер ответил timeLimitExceeded (3) на поиске (|(objectSid=") and len(text) < 140


def test_cancel_checked_after_pause_before_next_request() -> None:
    conn = FakeLdap3({"(objectClass=user)": _rows(5)})
    sleeps: list[float] = []
    checks: list[int] = []

    def check_cancel() -> None:
        checks.append(len(conn.calls))
        if sleeps:
            raise JobCancelled()

    search = ldap3_searcher(conn, page_size=2, pacer=Pacer(500, check_cancel=check_cancel, sleep=sleeps.append))
    with pytest.raises(JobCancelled):
        list(search("DC=corp,DC=local", "(objectClass=user)", ["name"], "SUBTREE"))
    # Отмена, пришедшая во время паузы, замечена до второго запроса.
    assert sleeps == [0.5] and checks == [1] and len(conn.calls) == 1


def test_smb_reads_paused_between_and_not_after_last() -> None:
    sleeps: list[str] = []
    reads: list[str] = []

    def read(unc: str) -> bytes | None:
        reads.append(unc)
        sleeps.append(f"read:{unc}")
        return unc.encode()

    paced = paced_reader(read, Pacer(500, sleep=lambda s: sleeps.append(f"pause:{s}")))
    assert [paced(p) for p in ("a", "b", "c")] == [b"a", b"b", b"c"]
    # Первое чтение — без паузы, дальше пауза перед каждым; после последнего паузы нет.
    assert sleeps == ["read:a", "pause:0.5", "read:b", "pause:0.5", "read:c"]


def test_smb_zero_pause_does_not_sleep() -> None:
    paced = paced_reader(lambda unc: b"x", Pacer(0, sleep=lambda s: pytest.fail("пауза при pause_ms=0")))
    assert [paced("a"), paced("b")] == [b"x", b"x"]


def test_smb_cancel_checked_after_pause_before_next_read() -> None:
    events: list[str] = []

    def check_cancel() -> None:
        events.append("check")
        raise JobCancelled()

    paced = paced_reader(lambda unc: events.append(f"read:{unc}") or b"", Pacer(500, check_cancel=check_cancel, sleep=lambda s: events.append("pause")))
    paced("a")
    with pytest.raises(JobCancelled):
        paced("b")
    # Отмена, пришедшая в паузе, замечена до второго чтения.
    assert events == ["read:a", "pause", "check"]


def test_one_pacer_for_ldap_and_smb() -> None:
    """Один дозатор на сбор: пауза и на стыке LDAP→SMB, и на стыке SMB→LDAP."""
    conn = FakeLdap3({"(objectClass=user)": _rows(1), "(objectClass=group)": _rows(1, "CN=g")})
    events: list[str] = []
    pacer = Pacer(500, sleep=lambda s: events.append(f"pause:{s}"))
    search = ldap3_searcher(conn, page_size=10, pacer=pacer)
    read = paced_reader(lambda unc: events.append(f"read:{unc}") or b"", pacer)
    list(search("DC=corp,DC=local", "(objectClass=user)", ["name"], "SUBTREE"))
    events.append("ldap")
    read("a")
    list(search("DC=corp,DC=local", "(objectClass=group)", ["name"], "SUBTREE"))
    events.append("ldap")
    assert events == ["ldap", "pause:0.5", "read:a", "pause:0.5", "ldap"]


def test_cancel_checked_between_searches_without_pause() -> None:
    """Пауза 0 — отмена всё равно проверяется перед каждым запросом, кроме первого."""
    conn = FakeLdap3({"(objectSid=S-1)": _rows(1, "CN=a"), "(objectSid=S-2)": _rows(1, "CN=b")})
    cancelled: list[bool] = []

    def check_cancel() -> None:
        if cancelled:
            raise JobCancelled()

    search = ldap3_searcher(conn, page_size=100, pacer=Pacer(0, check_cancel=check_cancel, sleep=lambda s: pytest.fail("пауза при pause_ms=0")))
    assert len(list(search("DC=corp,DC=local", "(objectSid=S-1)", ["objectSid"], "SUBTREE"))) == 1
    cancelled.append(True)
    with pytest.raises(JobCancelled):
        list(search("DC=corp,DC=local", "(objectSid=S-2)", ["objectSid"], "SUBTREE"))
    assert len(conn.calls) == 1
