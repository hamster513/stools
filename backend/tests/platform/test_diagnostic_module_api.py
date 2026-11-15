"""Module imports require module write rights and use the live application database."""
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.db.base import get_db
from api.deps import get_current_user
from api.modules.assets.models import AssetUser
from api.platform.diagnostics import router as diagnostic
from api.platform.diagnostics.storage import encode_archive
from api.rbac import current_access
from api.settings import get_settings
from tests.platform.test_diagnostic_export import source  # noqa: F401
from tests.platform.test_diagnostic_module_export import _native_source


def _client(db, directory, permissions):
    app = FastAPI()
    app.include_router(diagnostic.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=7)
    app.dependency_overrides[get_settings] = lambda: SimpleNamespace(data_dir=directory)
    app.dependency_overrides[current_access] = lambda: permissions
    return TestClient(app)


def test_exports_prepare_native_module_archive(source):  # noqa: F811
    from api.platform.diagnostics.storage import decode_archive

    db, directory = _native_source(source)
    request = SimpleNamespace(state=SimpleNamespace())
    settings = SimpleNamespace(data_dir=directory)
    store = diagnostic.package_store(settings)
    prepared = diagnostic.create_export(
        diagnostic.ExportRequest(kind="user", entity_id=1), request, db, settings,
        SimpleNamespace(id=7), store,
    )
    archive = store.download_export(prepared["id"], 7)
    assert decode_archive(archive)["format"] == "stools-diagnostic/2"


@pytest.mark.parametrize("denied", ["ad", "assets", "ksc"])
def test_live_import_requires_write_in_every_target_module(source, db_session, tmp_path, denied):  # noqa: F811
    from api.platform.diagnostics.module_export import build_module_bundle

    source_db, directory = _native_source(source)
    bundle = build_module_bundle(source_db, directory, "user", 1)
    permissions = {"platform": "admin", "ad": "write", "assets": "write", "ksc": "write"}
    permissions[denied] = "read"
    client = _client(db_session, tmp_path / "target", permissions)
    response = client.post("/api/settings/diagnostics/imports", files={"file": ("slice.zip", encode_archive(bundle), "application/zip")})
    assert response.status_code == 403
    assert not db_session.query(AssetUser).count()


def test_live_import_links_to_normal_modules_and_blocks_isolated_search(source, db_session, tmp_path):  # noqa: F811
    from api.platform.diagnostics.module_export import build_module_bundle

    source_db, directory = _native_source(source)
    bundle = build_module_bundle(source_db, directory, "user", 1)
    permissions = {"platform": "admin", "ad": "write", "assets": "write", "ksc": "write"}
    client = _client(db_session, tmp_path / "target", permissions)
    response = client.post("/api/settings/diagnostics/imports", files={"file": ("slice.zip", encode_archive(bundle), "application/zip")})
    assert response.status_code == 200, response.text
    item = response.json()
    assert item["mode"] == "modules"
    assert item["summary"] == bundle["report"]
    assert db_session.get(AssetUser, item["root"]["id"]) is not None
    assert any(link["href"].startswith("/ad/domains/") for link in item["links"])
    assert any(link["href"].startswith("/assets/users?") for link in item["links"])
    assert client.get("/api/settings/diagnostics/imports").json()["items"][0]["id"] == item["id"]
    response = client.post(f"/api/settings/diagnostics/imports/{item['id']}/search", json={"query": item["root"]["title"]})
    assert response.status_code == 409
    permissions["assets"] = "read"
    assert client.delete(f"/api/settings/diagnostics/imports/{item['id']}").status_code == 403
    assert db_session.get(AssetUser, item["root"]["id"]) is not None
