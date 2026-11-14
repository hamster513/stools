"""Untrusted archive boundary and independent offline dossier stores."""
import io
import json
import stat
import sys
import zipfile
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from api.modules.assets.models import Asset
from api.platform.diagnostics import storage, workspace


def bundle():
    return {"format": "stools-diagnostic/1", "created_at": "2026-01-01T00:00:00+00:00",
            "root": {"kind": "host", "id": 1}, "tables": {"asset": [{"id": 1, "name": "host-0001", "name_key": "host-0001"}]},
            "ad_exports": [], "report": {"counts": {"asset": 1}, "limitations": []}}


def archive(value=None, name="dataset.json"):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, json.dumps(value or bundle()))
    return out.getvalue()


@pytest.fixture(autouse=True)
def codec(monkeypatch):
    from types import ModuleType
    exporter = ModuleType("api.platform.diagnostics.exporter")
    exporter.validate_bundle = lambda value: value
    exporter.TABLE_MODELS = {"asset": Asset}
    monkeypatch.setitem(sys.modules, "api.platform.diagnostics.exporter", exporter)
    monkeypatch.setattr(exporter, "validate_bundle", lambda value: value)
    monkeypatch.setattr(exporter, "TABLE_MODELS", {"asset": Asset})


@pytest.mark.parametrize("name", ["../dataset.json", "/dataset.json", "sub/dataset.json", "dataset.json\\extra"])
def test_archive_rejects_arbitrary_paths(name):
    with pytest.raises(ValueError):
        storage.decode_archive(archive(name=name))


def test_archive_rejects_duplicate_member_and_symlink():
    for symlink in (False, True):
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as z:
            item = zipfile.ZipInfo("dataset.json")
            if symlink:
                item.create_system = 3
                item.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(item, "{}")
            if not symlink:
                z.writestr("dataset.json", "{}")
        with pytest.raises(ValueError):
            storage.decode_archive(out.getvalue())


def test_archive_rejects_oversized_and_duplicate_json(codec, monkeypatch):
    monkeypatch.setattr(storage, "MAX_UNCOMPRESSED", 16)
    with pytest.raises(ValueError):
        storage.decode_archive(archive())
    monkeypatch.setattr(storage, "MAX_UNCOMPRESSED", 1000)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("dataset.json", '{"root":1,"root":2}')
    with pytest.raises(ValueError):
        storage.decode_archive(out.getvalue())


def test_imports_have_independent_read_only_sessions_and_delete(tmp_path, codec):
    store = storage.PackageStore(tmp_path)
    first = store.import_archive(archive())
    second_bundle = bundle()
    second_bundle["tables"]["asset"][0]["name"] = "host-0002"
    second = store.import_archive(archive(second_bundle))
    assert first["id"] != second["id"]
    assert first["root"] == {"kind": "host", "id": 1, "title": "host-0001"}
    with workspace.open_dataset(store.import_path(first["id"])) as db:
        assert db.get(Asset, 1).name == "host-0001"
        db.get(Asset, 1).name = "changed"
        with pytest.raises(OperationalError):
            db.commit()
    with workspace.open_dataset(store.import_path(second["id"])) as db:
        assert db.get(Asset, 1).name == "host-0002"
    assert len(store.list_imports()) == 2
    store.delete_import(first["id"])
    assert [item["id"] for item in store.list_imports()] == [second["id"]]
    with pytest.raises(ValueError):
        store.import_path("../outside")


def test_export_is_owner_bound_and_expires(tmp_path, codec, monkeypatch):
    store = storage.PackageStore(tmp_path)
    preview = store.create_export(bundle(), owner_id=7)
    assert storage.decode_archive(store.download_export(preview["id"], 7))["root"]["id"] == 1
    with pytest.raises(FileNotFoundError):
        store.download_export(preview["id"], 8)
    monkeypatch.setattr(storage, "EXPORT_TTL_SECONDS", -1)
    expired = store.create_export(bundle(), owner_id=7)
    with pytest.raises(FileNotFoundError):
        store.download_export(expired["id"], 7)


@pytest.fixture
def api(tmp_path, monkeypatch):
    from api.db.base import get_db
    from api.deps import get_current_user
    from api.platform.diagnostics import router as diagnostic
    from api.rbac import current_access
    from api.settings import get_settings
    app = FastAPI()
    app.include_router(diagnostic.router)
    permissions = {"platform": "admin", "assets": "read", "ad": "read", "ksc": "read"}
    app.dependency_overrides[current_access] = lambda: permissions
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=7)
    app.dependency_overrides[get_settings] = lambda: SimpleNamespace(data_dir=tmp_path)
    app.dependency_overrides[get_db] = lambda: None
    return TestClient(app), permissions, diagnostic


def test_routes_require_platform_admin_and_each_source_read(api):
    client, permissions, _ = api
    for area in ("platform", "assets", "ad", "ksc"):
        saved = permissions[area]
        permissions[area] = "read" if area == "platform" else "deny"
        assert client.get("/api/settings/diagnostics/imports").status_code == 403
        assert client.get("/api/settings/diagnostics/exports/" + "0" * 32 + "/download").status_code == 403
        permissions[area] = saved
    assert client.get("/api/settings/diagnostics/imports").json() == {"items": []}


def test_api_import_search_is_local_and_clears_all_live_links(api, monkeypatch):
    client, _, diagnostic = api
    imported = client.post("/api/settings/diagnostics/imports", files={"file": ("secret-company.zip", archive(), "application/zip")})
    assert imported.status_code == 200, imported.text
    info = imported.json()
    def local_search(db, payload, access, data_dir):
        assert db.get(Asset, 1).name == "host-0001"
        assert access == {"assets": "read", "ad": "read", "ksc": "read"}
        assert data_dir.name == info["id"]
        return SimpleNamespace(model_dump=lambda **kw: {"query": payload.query, "matches": [{"id": "host:1", "kind": "host", "title": "host-0001", "href": "/assets/list?asset=1"}], "dossier": None})
    monkeypatch.setattr(diagnostic, "search", local_search)
    response = client.post(f"/api/settings/diagnostics/imports/{info['id']}/search", json={"query": "host-0001", "entity_id": "host:1"})
    assert response.status_code == 200, response.text
    assert response.json()["matches"][0]["href"] == ""
    assert "secret-company" not in client.get("/api/settings/diagnostics/imports").text
    assert client.delete(f"/api/settings/diagnostics/imports/{info['id']}").status_code == 204
    assert client.post(f"/api/settings/diagnostics/imports/{info['id']}/search", json={"query": "host-0001"}).status_code == 404


def test_api_rejects_bad_archive_without_echoing_filename(api):
    client, _, _ = api
    response = client.post("/api/settings/diagnostics/imports", files={"file": ("secret-company.zip", b"not a zip")})
    assert response.status_code == 422
    assert "secret-company" not in response.text


def test_real_dossier_uses_only_local_tables_and_no_live_links(tmp_path):
    from api.platform.search.models import SearchRequest
    from api.platform.search.service import search
    store = storage.PackageStore(tmp_path)
    info = store.import_archive(archive())
    directory = store.import_path(info["id"])
    with workspace.open_dataset(directory) as db:
        result = search(db, SearchRequest(query="host-0001", entity_id="host:1"), workspace.ACCESS, directory)
        assert result.dossier.entity.title == "host-0001"
        assert {section.id for section in result.dossier.sections} >= {"groups", "vulnerabilities"}
        clean = workspace.without_live_links(result.model_dump(mode="json"))
        assert clean["dossier"]["entity"]["href"] == ""
        unknown = search(db, SearchRequest(query="2001:db8::1", kind="ip"), workspace.ACCESS, directory)
        assert unknown.matches == []


def test_export_snapshot_is_read_only_and_repeatable_in_postgres(db_session):
    from sqlalchemy import text

    from api.platform.diagnostics.router import export_snapshot
    with export_snapshot(db_session) as snapshot:
        assert snapshot is not db_session
        assert snapshot.scalar(text("SHOW transaction_isolation")) == "repeatable read"
        assert snapshot.scalar(text("SHOW transaction_read_only")) == "on"
    assert db_session.scalar(text("SHOW transaction_read_only")) == "off"


def test_routes_registered_in_application_and_reads_need_admin():
    from api.main import create_app
    from api.rbac import needed
    paths = create_app().openapi()["paths"]
    assert "/api/settings/diagnostics/imports/{package_id}/search" in paths
    assert needed("GET", "/api/settings/diagnostics/imports") == ("platform", "admin")


def test_sqlite_preserves_partial_index_for_multiple_users_without_sid(tmp_path, monkeypatch):
    from api.modules.assets.models import AssetUser
    from api.platform.diagnostics.exporter import TABLE_MODELS
    monkeypatch.setitem(TABLE_MODELS, "asset_user", AssetUser)
    value = bundle()
    value["tables"]["asset_user"] = [{"id": 1, "sam": "user-0001", "sid": ""}, {"id": 2, "sam": "user-0002", "sid": ""}]
    store = storage.PackageStore(tmp_path)
    info = store.import_archive(archive(value))
    with workspace.open_dataset(store.import_path(info["id"])) as db:
        assert db.get(AssetUser, 1).sam == "user-0001"
        assert db.get(AssetUser, 2).sam == "user-0002"
    original = next(index for index in AssetUser.__table__.indexes if index.name == "uq_asset_user_sid_live")
    assert original.dialect_options["sqlite"].get("where") is None


def test_import_body_limit_allows_bounded_multipart_only():
    from api.limits import DEFAULT_LIMIT, limit_for
    assert limit_for("POST", "/api/settings/diagnostics/imports") == 21 * 1024 * 1024
    assert limit_for("POST", "/api/settings/diagnostics/exports") == DEFAULT_LIMIT


def test_archive_rejects_extreme_compression_ratio():
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zipped:
        zipped.writestr("dataset.json", json.dumps({"padding": " " * (2 * 1024 * 1024)}))
    with pytest.raises(ValueError):
        storage.decode_archive(out.getvalue())


@pytest.mark.parametrize(("error_kind", "message", "expected"), [
    ("bundle", "Diagnostic record limit exceeded.", "5000"),
    ("bundle", "Diagnostic source size limit exceeded.", "размер"),
    ("bundle", "Selected entity is unavailable.", "объект недоступен"),
    ("bundle", "Latest directory export is unavailable or unsupported.", "снимок AD"),
    ("bundle", "Unsupported directory identity.", "идентификатор AD"),
    ("bundle", "private-db.internal password=secret", "Не удалось подготовить"),
    ("value", "private-db.internal password=secret", "Не удалось подготовить"),
    ("sql", "private-db.internal password=secret", "Не удалось подготовить"),
    ("value", "Diagnostic record limit exceeded.", "Не удалось подготовить"),
])
def test_export_errors_explain_only_known_safe_bundle_failures(api, monkeypatch, error_kind, message, expected):
    from contextlib import nullcontext

    from sqlalchemy.exc import SQLAlchemyError
    client, _, diagnostic = api
    exporter = sys.modules["api.platform.diagnostics.exporter"]
    class SafeBundleError(ValueError):
        pass
    def fail(*args):
        raise {"bundle": SafeBundleError, "value": ValueError, "sql": SQLAlchemyError}[error_kind](message)
    monkeypatch.setattr(exporter, "BundleError", SafeBundleError, raising=False)
    monkeypatch.setattr(exporter, "build_bundle", fail, raising=False)
    monkeypatch.setattr(diagnostic, "export_snapshot", lambda _: nullcontext(None))
    response = client.post("/api/settings/diagnostics/exports", json={"kind": "host", "entity_id": 1})
    assert response.status_code == 422
    assert expected in response.json()["detail"]
    assert "private-db.internal" not in response.text
    assert "password=secret" not in response.text
