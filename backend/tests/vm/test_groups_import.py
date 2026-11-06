"""Локальные группы из VM (спека 2026-10-23 §2): разбор, PDQL, отдельный снимок после импорта."""
from __future__ import annotations

import datetime as dt
import io
import json
import re
import shutil
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from api.modules.vm.core.groups import GroupsFormatError, iter_group_rows
from api.modules.vm.core.mpvm import build_groups_pdql, build_pdql
from api.modules.vm.models import VmGroupImport, VmHost, VmHostCve, VmHostGroup, VmJob
from api.modules.vm.services import importer
from api.modules.vm.services.jobs import JobHandle
from api.modules.vm.services.settings import Connection, VmSettings

FIXTURES = Path(__file__).parent / "fixtures"
DOM = "S-1-5-21-1111111111-2222222222-3333333333"
MACHINE = "s-1-5-21-4444444444-5555555555-6666666666"

W = "WindowsHost"
WIN_HEADER = ";".join(
    f'"{W}.{c}"'
    for c in (
        "Fqdn", "Hostname", "IpAddress", "OsName", "Groups.Name", "Groups.SID", "Groups.Description",
        "Groups.Members.Name", "Groups.Members.Domain", "Groups.Members.SID", "Groups.Members.Type",
        "Groups.Members.IsLocal", "Groups.Members.IsSystem",
    )
)


def _q(*values: str) -> str:
    return ";".join(f'"{v}"' for v in values)


WIN_CSV = "\n".join([
    WIN_HEADER,
    _q("srv01.corp.local", "srv01", "10.0.0.1", "windows server 2019", "administrators", "s-1-5-32-544",
       "administrators have complete access", "desktop admins", "corp", f"{DOM.lower()}-1105", "group", "false", "false"),
    _q("srv01.corp.local", "srv01", "10.0.0.1", "windows server 2019", "administrators", "s-1-5-32-544",
       "administrators have complete access", "pcadmin", "", f"{MACHINE}-500", "account", "true", "false"),
    _q("srv01.corp.local", "srv01", "10.0.0.1", "windows server 2019", "backup operators", "s-1-5-32-551",
       "", "", "", "", "", "", ""),
    _q("", "", "10.0.0.9", "windows server 2019", "administrators", "s-1-5-32-544", "", "x", "", "", "", "", ""),
]) + "\n"

U = "UnixHost"
LIN_HEADER = ";".join(f'"{U}.{c}"' for c in ("Fqdn", "Hostname", "IpAddress", "OsName", "Groups.GID", "Groups.Name", "Groups.Users"))
LIN_CSV = "\n".join([
    LIN_HEADER,
    _q("srv02.corp.local", "srv02", "10.0.0.2", "astra linux", "10", "wheel", "user01"),
    _q("srv02.corp.local", "srv02", "10.0.0.2", "astra linux", "10", "wheel", "pcadmin"),
    _q("srv02.corp.local", "srv02", "10.0.0.2", "astra linux", "4", "adm", ""),
]) + "\n"

CONN = Connection(host="vm.corp", api_token="pat-test", os_exclude=["Windows 10", "O'Reilly OS"],
                  pdql_extra="Host.UF_Zone = 'DMZ'", limit=0)


# ---- разбор -----------------------------------------------------------------


def test_windows_rows_parsed() -> None:
    rows = list(iter_group_rows(io.StringIO(WIN_CSV), "windows"))
    assert len(rows) == 3  # строка без Fqdn и Hostname пропущена
    dom, local, empty = rows
    assert (dom.os_family, dom.fqdn, dom.hostname, dom.ip) == ("windows", "srv01.corp.local", "srv01", "10.0.0.1")
    assert (dom.group_name, dom.group_sid, dom.group_description) == ("administrators", "S-1-5-32-544", "administrators have complete access")
    assert (dom.member_name, dom.member_domain, dom.member_sid, dom.member_type) == ("desktop admins", "corp", f"{DOM}-1105", "group")
    assert (dom.member_local, dom.member_system) == (False, False)
    assert local.member_sid == f"{MACHINE.upper()}-500" and local.member_local is True and local.member_domain == ""
    assert (empty.group_name, empty.group_sid, empty.member_name, empty.member_sid, empty.member_type) == ("backup operators", "S-1-5-32-551", "", "", "")
    assert (empty.member_local, empty.member_system, empty.group_gid) == (None, None, "")


def test_columns_found_by_name_not_position() -> None:
    lines = WIN_CSV.splitlines()
    cols = list(zip(*(line.split(";") for line in lines[:2]), strict=True))
    shuffled = cols[::-1]
    text = "\n".join(";".join(c[i] for c in shuffled) for i in range(2)) + "\n"
    (row,) = iter_group_rows(io.StringIO(text), "windows")
    assert row.member_name == "desktop admins" and row.group_sid == "S-1-5-32-544"


def test_linux_rows_parsed() -> None:
    rows = list(iter_group_rows(io.StringIO(LIN_CSV), "linux"))
    assert [(r.group_name, r.group_gid, r.member_name) for r in rows] == [("wheel", "10", "user01"), ("wheel", "10", "pcadmin"), ("adm", "4", "")]
    user = rows[0]
    assert (user.os_family, user.fqdn, user.hostname, user.ip) == ("linux", "srv02.corp.local", "srv02", "10.0.0.2")
    assert (user.member_type, user.member_local, user.member_system, user.group_sid) == ("account", True, None, "")
    empty = rows[2]
    assert (empty.member_type, empty.member_local) == ("", None)


# ---- PDQL -------------------------------------------------------------------


def test_groups_pdql_windows() -> None:
    pdql = build_groups_pdql(CONN, "windows")
    head, _, tail = pdql.partition(" | filter(")
    assert head.startswith("select(WindowsHost.Fqdn, WindowsHost.Hostname, WindowsHost.IpAddress, WindowsHost.OsName, WindowsHost.Groups.Name")
    assert "WindowsHost.Groups.Members.IsSystem)" in head and "WindowsHost.OsName" in head
    assert tail.startswith("WindowsHost.OsName != null and WindowsHost.OsName != 'Windows 10' and WindowsHost.OsName != 'O\\'Reilly OS')")
    assert not re.search(r"(?<![A-Za-z])Host\.", pdql)
    assert "UF_Zone" not in pdql and "DMZ" not in pdql
    assert "limit" not in pdql


def test_groups_pdql_linux_and_limit() -> None:
    pdql = build_groups_pdql(CONN, "linux")
    assert pdql.startswith("select(UnixHost.Fqdn, UnixHost.Hostname, UnixHost.IpAddress, UnixHost.OsName, UnixHost.Groups.GID, UnixHost.Groups.Name, UnixHost.Groups.Users) | filter(UnixHost.OsName != null and UnixHost.OsName != 'Windows 10'")
    assert not re.search(r"(?<![A-Za-z])Host\.", pdql)
    assert build_groups_pdql(CONN, "linux", limit=3).endswith("| limit(3)")
    assert build_groups_pdql(CONN.model_copy(update={"limit": 7}), "windows").endswith("| limit(7)")


def test_os_exclude_escapes_backslash_before_quote() -> None:
    """Обратная косая удваивается до экранирования кавычки: `a\\` не съедает закрывающую кавычку."""
    conn = CONN.model_copy(update={"os_exclude": ["Win\\", "O\\'R"]})
    for pdql in (build_groups_pdql(conn, "windows"), build_pdql(conn)):
        assert "!= 'Win\\\\'" in pdql
        assert "!= 'O\\\\\\'R'" in pdql


# ---- импорт -----------------------------------------------------------------


class FakeVm:
    """Три PDQL одного подключения: основной, группы Windows, группы Linux."""

    def __init__(self, fail: set[str] | None = None, bodies: dict[str, bytes] | None = None) -> None:
        self.fail = fail or set()
        self.pdql: list[str] = []
        self.csv = {"main": (FIXTURES / "hosts.csv").read_bytes(), "win": WIN_CSV.encode(), "lin": LIN_CSV.encode(), **(bodies or {})}

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/assets_grid"):
            pdql = json.loads(request.content)["pdql"]
            self.pdql.append(pdql)
            token = "win" if pdql.startswith("select(WindowsHost") else "lin" if pdql.startswith("select(UnixHost") else "main"
            return httpx.Response(200, json={"token": token})
        token = request.url.params["pdqlToken"]
        if token in self.fail:
            return httpx.Response(500)
        return httpx.Response(200, content=self.csv[token])

    def client(self, conn: Any, timeout: float = 60.0) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


def _handle(db: Any, kind: str = "import_vm") -> JobHandle:
    job = VmJob(kind=kind, stage="queued", status="running", started_by="test")
    db.add(job)
    db.commit()
    return JobHandle(db, job)


def _run_vm(db: Any, tmp_path: Path, monkeypatch: Any, fake: FakeVm, conn: Connection = CONN) -> JobHandle:
    monkeypatch.setattr(importer, "make_client", fake.client)
    handle = _handle(db)
    importer.run_import(db, handle, "vm", None, VmSettings(connection=conn), tmp_path)
    return handle


def _message(db: Any, handle: JobHandle) -> str:
    job = db.get(VmJob, handle.id)
    db.refresh(job)
    assert job.stage == "groups"
    return str(job.message)


def _groups(db: Any) -> list[tuple[str, str, str, str]]:
    rows = db.execute(select(VmHostGroup)).scalars().all()
    return sorted((r.os_family, r.fqdn, r.group_name, r.member_name) for r in rows)


def _seed_previous(db: Any) -> dt.datetime:
    when = dt.datetime(2026, 10, 1, tzinfo=dt.UTC)
    db.add_all([
        VmHostGroup(os_family="windows", fqdn="old.corp.local", hostname="old", ip="10.0.0.5", group_name="administrators",
                    group_sid="S-1-5-32-544", group_gid="", group_description="", member_name="user01", member_domain="corp",
                    member_sid=f"{DOM}-1201", member_type="account", member_local=False, member_system=False),
        VmHostGroup(os_family="linux", fqdn="oldlin.corp.local", hostname="oldlin", ip="10.0.0.6", group_name="wheel",
                    group_sid="", group_gid="10", group_description="", member_name="user01", member_domain="",
                    member_sid="", member_type="account", member_local=True, member_system=None),
        VmGroupImport(finished_at=when, hosts=2, rows=2, windows_ok=True, linux_ok=True),
    ])
    db.commit()
    return when


def test_vm_import_writes_groups_of_both_families(db_session: Any, tmp_path: Path, monkeypatch: Any) -> None:
    fake = FakeVm()
    handle = _run_vm(db_session, tmp_path, monkeypatch, fake)
    assert _message(db_session, handle) == "локальные группы: Windows — строк 3, хостов 1; Linux — строк 3, хостов 1"
    assert len(fake.pdql) == 5
    assert fake.pdql[0].startswith("select(@Host") and fake.pdql[3].startswith("select(WindowsHost") and fake.pdql[4].startswith("select(UnixHost")
    assert _groups(db_session) == [
        ("linux", "srv02.corp.local", "adm", ""),
        ("linux", "srv02.corp.local", "wheel", "pcadmin"),
        ("linux", "srv02.corp.local", "wheel", "user01"),
        ("windows", "srv01.corp.local", "administrators", "desktop admins"),
        ("windows", "srv01.corp.local", "administrators", "pcadmin"),
        ("windows", "srv01.corp.local", "backup operators", ""),
    ]
    (snap,) = db_session.execute(select(VmGroupImport)).scalars().all()
    assert snap.finished_at is not None and (snap.hosts, snap.rows, snap.windows_ok, snap.linux_ok) == (2, 6, True, True)
    assert list((tmp_path / "vm").iterdir()) == []  # временные файлы удалены


def test_linux_export_failure_keeps_previous_linux_rows(db_session: Any, tmp_path: Path, monkeypatch: Any) -> None:
    when = _seed_previous(db_session)
    handle = _run_vm(db_session, tmp_path, monkeypatch, FakeVm(fail={"lin"}))
    assert _message(db_session, handle) == (
        "локальные группы: Windows — строк 3, хостов 1; Linux не получены (экспорт не отдан: HTTP 500) — прежний снимок от 01.10 00:00 UTC"
    )
    groups = _groups(db_session)
    assert ("linux", "oldlin.corp.local", "wheel", "user01") in groups
    assert not any(g[1] == "old.corp.local" for g in groups)  # windows заменены
    assert sum(1 for g in groups if g[0] == "windows") == 3 and sum(1 for g in groups if g[0] == "linux") == 1
    snaps = db_session.execute(select(VmGroupImport).order_by(VmGroupImport.finished_at.desc())).scalars().all()
    assert len(snaps) == 2 and snaps[1].finished_at == when
    assert (snaps[0].windows_ok, snaps[0].linux_ok, snaps[0].rows, snaps[0].hosts) == (True, False, 4, 2)
    assert list((tmp_path / "vm").iterdir()) == []


def test_both_group_exports_fail_import_still_succeeds(db_session: Any, tmp_path: Path, monkeypatch: Any) -> None:
    when = _seed_previous(db_session)
    before = _groups(db_session)
    handle = _run_vm(db_session, tmp_path, monkeypatch, FakeVm(fail={"win", "lin"}))
    assert len(db_session.execute(select(VmHost)).scalars().all()) == 3
    assert len(db_session.execute(select(VmHostCve)).scalars().all()) == 4
    assert _groups(db_session) == before
    (snap,) = db_session.execute(select(VmGroupImport)).scalars().all()
    assert snap.finished_at == when
    assert _message(db_session, handle) == (
        "локальные группы: Windows не получены (экспорт не отдан: HTTP 500) — прежний снимок от 01.10 00:00 UTC; "
        "Linux не получены (экспорт не отдан: HTTP 500) — прежний снимок от 01.10 00:00 UTC"
    )
    assert list((tmp_path / "vm").iterdir()) == []


def test_file_import_leaves_groups_alone(db_session: Any, tmp_path: Path, monkeypatch: Any) -> None:
    _seed_previous(db_session)
    before = _groups(db_session)

    def no_vm(conn: Any, timeout: float = 60.0) -> httpx.Client:
        raise AssertionError("импорт из файла не обращается к VM")

    monkeypatch.setattr(importer, "make_client", no_vm)
    path = tmp_path / "upload.csv"
    shutil.copy(FIXTURES / "hosts.csv", path)
    importer.run_import(db_session, _handle(db_session, "import_file"), "file", path, VmSettings(connection=CONN), tmp_path)
    assert len(db_session.execute(select(VmHost)).scalars().all()) == 3
    assert _groups(db_session) == before
    assert len(db_session.execute(select(VmGroupImport)).scalars().all()) == 1


# ---- выгрузка не того формата не стирает снимок семейства -------------------------------------------


@pytest.mark.parametrize("family", ["windows", "linux"])
def test_header_only_export_parses_to_no_rows(family: str) -> None:
    header = WIN_HEADER if family == "windows" else LIN_HEADER
    assert list(iter_group_rows(io.StringIO(header + "\n"), family)) == []


@pytest.mark.parametrize("family", ["windows", "linux"])
@pytest.mark.parametrize("body", ["", "<!DOCTYPE html><html><body>Sign in</body></html>\n", '{"error": "invalidColumn"}\n'])
def test_empty_html_or_json_body_is_rejected(family: str, body: str) -> None:
    with pytest.raises(GroupsFormatError):
        list(iter_group_rows(io.StringIO(body), family))


@pytest.mark.parametrize(("family", "column"), [
    ("windows", "WindowsHost.Groups.Members.SID"), ("windows", "WindowsHost.Fqdn"), ("windows", "WindowsHost.Groups.Members.IsLocal"),
    ("linux", "UnixHost.Groups.Users"), ("linux", "UnixHost.Hostname"), ("linux", "UnixHost.Groups.GID"),
])
def test_missing_required_column_is_rejected(family: str, column: str) -> None:
    text = WIN_CSV if family == "windows" else LIN_CSV
    header, _, rest = text.partition("\n")
    header = ";".join(c for c in header.split(";") if c != f'"{column}"')
    with pytest.raises(GroupsFormatError, match=column):
        list(iter_group_rows(io.StringIO(header + "\n" + rest), family))


@pytest.mark.parametrize(("token", "body", "reason"), [
    ("lin", b"", "пустая выгрузка, нет даже заголовка"),
    ("lin", b"<html><body>login</body></html>\n", "в заголовке нет столбцов"),
    ("lin", (LIN_HEADER + "\n").encode(), "выгрузка пуста, а в прежнем снимке 1 строк"),
    ("win", b'{"error": "x"}', "в заголовке нет столбцов"),
])
def test_bad_family_export_keeps_previous_snapshot(db_session: Any, tmp_path: Path, monkeypatch: Any,
                                                   token: str, body: bytes, reason: str) -> None:
    """Пустое тело, HTML, JSON или 0 строк при непустом прежнем снимке: семейство — как не полученное,
    его строки остаются, флаг False; другое семейство записывается."""
    _seed_previous(db_session)
    handle = _run_vm(db_session, tmp_path, monkeypatch, FakeVm(bodies={token: body}))
    bad, good = ("linux", "windows") if token == "lin" else ("windows", "linux")
    groups = _groups(db_session)
    old_fqdn = "oldlin.corp.local" if bad == "linux" else "old.corp.local"
    assert [g for g in groups if g[0] == bad] == [g for g in groups if g[1] == old_fqdn] != []
    assert sum(1 for g in groups if g[0] == good) == 3
    snap = db_session.execute(select(VmGroupImport).order_by(VmGroupImport.finished_at.desc())).scalars().first()
    assert (snap.windows_ok, snap.linux_ok) == ((False, True) if bad == "windows" else (True, False))
    message = _message(db_session, handle)
    assert f"{importer.FAMILY_TITLE[bad]} не получены ({reason}" in message and "прежний снимок от 01.10 00:00 UTC" in message


def test_empty_family_with_empty_previous_is_a_snapshot(db_session: Any, tmp_path: Path, monkeypatch: Any) -> None:
    """0 строк, и прежде строк семейства не было: это и есть снимок (групп у хостов семейства нет)."""
    handle = _run_vm(db_session, tmp_path, monkeypatch, FakeVm(bodies={"lin": (LIN_HEADER + "\n").encode()}))
    (snap,) = db_session.execute(select(VmGroupImport)).scalars().all()
    assert (snap.windows_ok, snap.linux_ok, snap.rows) == (True, True, 3)
    assert _message(db_session, handle) == "локальные группы: Windows — строк 3, хостов 1; Linux — строк 0, хостов 0"


def test_limited_export_is_partial_snapshot(db_session: Any, tmp_path: Path, monkeypatch: Any) -> None:
    """Лимит подключения: строки пишутся, но снимок неполный — флаги False, пропавшие по нему не судятся."""
    fake = FakeVm()
    handle = _run_vm(db_session, tmp_path, monkeypatch, fake, conn=CONN.model_copy(update={"limit": 5}))
    assert all(p.endswith("| limit(5)") for p in fake.pdql)
    assert len(_groups(db_session)) == 6
    (snap,) = db_session.execute(select(VmGroupImport)).scalars().all()
    assert (snap.windows_ok, snap.linux_ok) == (False, False)
    assert _message(db_session, handle) == (
        "локальные группы: Windows — строк 3, хостов 1 (лимит 5 — снимок неполный, пропавшие не определяются); "
        "Linux — строк 3, хостов 1 (лимит 5 — снимок неполный, пропавшие не определяются)"
    )


def test_long_values_are_cut_to_column_length(db_session: Any, tmp_path: Path, monkeypatch: Any) -> None:
    """Одно длинное значение не роняет снимок: строка обрезается по длине столбца."""
    long_name, long_domain = "u" * 700, "d" * 300
    row = _q("srv03.corp.local", "srv03", "10.0.0.3", "windows server 2019", "g" * 600, "s-1-5-32-544", "x" * 5000,
             long_name, long_domain, "s" * 300, "account" * 5, "false", "false")
    handle = _run_vm(db_session, tmp_path, monkeypatch, FakeVm(bodies={"win": (WIN_CSV + row + "\n").encode()}))
    got = db_session.execute(select(VmHostGroup).where(VmHostGroup.fqdn == "srv03.corp.local")).scalar_one()
    assert (len(got.group_name), len(got.member_name), len(got.member_domain), len(got.member_sid), len(got.member_type)) == (512, 512, 255, 255, 16)
    assert len(got.group_description) == 5000
    assert _message(db_session, handle).startswith("локальные группы: Windows — строк 4, хостов 2;")


def test_group_tables_match_models(db_session: Any) -> None:
    """Таблицы групп VM из миграции совпадают с моделями, включая индексы."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from api.db.models import Base

    ctx = MigrationContext.configure(db_session.connection(), opts={"compare_type": True, "compare_server_default": False})
    assert [d for d in compare_metadata(ctx, Base.metadata) if "vm_host_group" in repr(d) or "vm_group_import" in repr(d)] == []
