from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from api.hosts import LOGIN_REJECTED, NO_LINK, NO_RIGHTS
from api.modules.siem.core import kb as kb_mod
from api.modules.siem.core.kb import (
    ROOT_SET_ID,
    KbClient,
    KbError,
    KbShapeError,
    public_error,
)
from api.modules.siem.services.kb_settings import KbConnection
from tests.api.fake_kb import DB, INSTALL_SET, TOKEN, FakeKb, kb_object

CONN = KbConnection(host="mp.corp.local", api_token=TOKEN)


def _client(fake: FakeKb) -> KbClient:
    return KbClient(CONN, fake.http_factory(CONN))


def test_databases_and_version() -> None:
    client = _client(FakeKb())
    db = client.deployable_database()
    assert db.name == DB and db.parent == "PT" and db.deployable is True
    assert client.version(DB) == "27.1.1234"


def test_deployment_sets_statuses_flatten() -> None:
    sets = _client(FakeKb()).deployment_sets(DB)
    assert [s.kb_id for s in sets] == [ROOT_SET_ID, INSTALL_SET]
    assert sets[0].compilation_status == "Success" and sets[0].deployment_statuses == {"p1": "Installed"}
    assert sets[1].parent_kb_id == ROOT_SET_ID and sets[1].general_status == "Outdated"
    assert sets[1].deployment_statuses == {"p1": "Outdated"}


def test_objects_are_paged_and_folder_path_normalised() -> None:
    fake = FakeKb()
    objs = list(_client(fake).correlation_objects(DB))
    assert len(objs) == 501
    assert objs[0].folder_path == "PT/Windows" and objs[0].installed is False and objs[1].installed is True
    assert objs[0].guid == "00000000-0000-0000-0000-000000000000" and objs[0].short_id == "Rule_0"
    # 500 + 1 + пустая страница: конец листинга определяется только пустой страницей.
    assert [c.url.path for c in fake.calls].count("/api-studio/siem/objects/list") == 3
    fake.calls.clear()
    assert len(list(_client(fake).correlation_objects(DB, group_id=INSTALL_SET))) == 3
    assert [c.url.path for c in fake.calls].count("/api-studio/siem/objects/list") == 2


def test_server_capped_page_size_does_not_truncate() -> None:
    fake = FakeKb()
    fake.page_cap = 100
    assert len(list(_client(fake).correlation_objects(DB))) == 501
    assert [c.url.path for c in fake.calls].count("/api-studio/siem/objects/list") == 7


def test_objects_list_without_rows_is_a_clear_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"Items": []})

    client = KbClient(CONN, httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(KbShapeError, match="нет списка объектов"):
        list(client.correlation_objects(DB))


def test_no_deployable_database_is_a_clear_error() -> None:
    fake = FakeKb()
    fake.databases = [{"Name": "Archive", "IsDeployable": False}]
    with pytest.raises(KbShapeError, match="подключённой к SIEM"):
        _client(fake).deployable_database()


def test_deploy_stats() -> None:
    stats = _client(FakeKb()).deploy_stats(DB)
    assert (stats.installed, stats.not_installed, stats.outdated) == (250, 251, 0)


def test_export_streams_to_file(tmp_path: Path) -> None:
    out = tmp_path / "kb.zip"
    size = _client(FakeKb()).export_all(DB, out)
    assert size == out.stat().st_size == 22


def test_export_over_limit_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kb_mod, "EXPORT_LIMIT", 10)
    with pytest.raises(KbError, match="больше лимита"):
        _client(FakeKb()).export_all(DB, tmp_path / "kb.zip")


def test_non_json_body_is_a_clear_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>login</html>")

    client = KbClient(CONN, httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(KbShapeError, match="не JSON") as exc_info:
        client.databases()
    assert public_error(exc_info.value) == "ответ KB не JSON"


def test_export_failure_leaves_no_partial_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kb_mod, "EXPORT_LIMIT", 10)
    out = tmp_path / "kb.zip"
    with pytest.raises(KbError):
        _client(FakeKb()).export_all(DB, out)
    assert not out.exists()


def test_export_write_failure_is_a_client_error(tmp_path: Path) -> None:
    out = tmp_path / "no-such-dir" / "kb.zip"
    with pytest.raises(KbError, match="не удалось записать экспорт — ") as exc_info:
        _client(FakeKb()).export_all(DB, out)
    assert str(tmp_path) not in str(exc_info.value)
    assert "записать" in public_error(exc_info.value)


def test_guid_lowercased_and_installed_case_insensitive() -> None:
    obj = kb_object("ABCDEF00-0000-0000-0000-000000000ABC", "R", installed=True)
    obj["DeploymentStatus"] = "INSTALLED"
    (got,) = _client(FakeKb(objects=[obj])).correlation_objects(DB)
    assert got.guid == "abcdef00-0000-0000-0000-000000000abc" and got.installed is True


def test_deploy_stats_non_numeric_counters_are_zero() -> None:
    fake = FakeKb()
    original = fake.handler

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api-studio/siem/deploy/stats":
            return httpx.Response(200, json={"Installed": "n/a", "NotInstalled": [1], "Outdated": 7})
        return original(request)

    client = KbClient(CONN, httpx.Client(transport=httpx.MockTransport(handler)))
    stats = client.deploy_stats(DB)
    assert (stats.installed, stats.not_installed, stats.outdated) == (0, 0, 7)


def test_public_error_classes() -> None:
    unauthorized = FakeKb()
    unauthorized.unauthorized = True
    with pytest.raises(KbError) as login_exc:
        _client(unauthorized).databases()
    assert login_exc.value.status == 401 and public_error(login_exc.value) == LOGIN_REJECTED
    with pytest.raises(KbError, match="не задан") as empty_exc:
        KbClient(KbConnection(host="mp.corp.local"), httpx.Client()).token()
    assert public_error(empty_exc.value) == LOGIN_REJECTED

    forbidden = FakeKb()
    forbidden.forbidden = True
    with pytest.raises(KbError) as forbidden_exc:
        _client(forbidden).databases()
    assert public_error(forbidden_exc.value) == NO_RIGHTS

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    with pytest.raises(KbError) as link_exc:
        KbClient(CONN, httpx.Client(transport=httpx.MockTransport(down))).databases()
    assert public_error(link_exc.value) == NO_LINK
    assert "mp.corp.local" not in public_error(link_exc.value)

    assert public_error(KbShapeError("нет БД контента, подключённой к SIEM")) == "нет БД контента, подключённой к SIEM"
