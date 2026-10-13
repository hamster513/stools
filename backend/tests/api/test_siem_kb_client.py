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
    KbLoginError,
    KbShapeError,
    public_error,
)
from api.modules.siem.services.kb_settings import KbConnection
from tests.api.fake_kb import DB, INSTALL_SET, FakeKb

CONN = KbConnection(host="mp.corp.local", username="svc", password="pw", client_secret="sec")


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
    assert [c.url.path for c in fake.calls].count("/api-studio/siem/objects/list") == 2
    assert len(list(_client(fake).correlation_objects(DB, group_id=INSTALL_SET))) == 3


def test_objects_list_without_rows_is_a_clear_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/connect/token":
            return httpx.Response(200, json={"access_token": "tok"})
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


def test_public_error_classes() -> None:
    bad_secret = FakeKb()
    bad_secret.token_status = 400
    with pytest.raises(KbLoginError) as login_exc:
        _client(bad_secret).token()
    assert public_error(login_exc.value) == LOGIN_REJECTED

    forbidden = FakeKb()
    forbidden.forbidden = True
    with pytest.raises(KbError) as forbidden_exc:
        _client(forbidden).databases()
    assert public_error(forbidden_exc.value) == NO_RIGHTS

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    with pytest.raises(KbError) as link_exc:
        KbClient(CONN, httpx.Client(transport=httpx.MockTransport(down))).token()
    assert public_error(link_exc.value) == NO_LINK
    assert "mp.corp.local" not in public_error(link_exc.value)

    assert public_error(KbShapeError("нет БД контента, подключённой к SIEM")) == "нет БД контента, подключённой к SIEM"
