"""GET /api/settings/data-status: сводка свежести данных всех модулей."""
from __future__ import annotations

import datetime as dt
import json
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from api.db.models import RuTtpImport
from api.modules import MODULE_ROUTERS
from api.modules.ad.models import AdConnection, AdDomain, AdSnapshot
from api.modules.assets.models import AssetDns, AssetRacktables
from api.modules.ksc.models import KscConnection, KscServer, KscSnapshot
from api.modules.vm.core.refs import REF_NAMES
from api.modules.vm.models import VmRefState
from api.modules.vm.services.refs_view import ref_views
from api.platform import data_status
from api.platform.data_status import DataItem, collect, register_data_status, registered_modules
from tests.api.conftest import upload_and_wait


def test_data_status_returns_items(auth_client: TestClient) -> None:
    response = auth_client.get("/api/settings/data-status")
    assert response.status_code == 200, response.text
    assert isinstance(response.json()["items"], list)


def test_data_status_open_to_auditor(client_as: Callable[[str], TestClient]) -> None:
    assert client_as("auditor").get("/api/settings/data-status").status_code == 200


def test_data_status_serializes_item_and_provider_error(
    auth_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(data_status, "_PROVIDERS", {})
    when = dt.datetime(2026, 10, 1, 12, 0, tzinfo=dt.UTC)

    def broken(db: object) -> list[DataItem]:
        raise RuntimeError("boom")

    register_data_status("siem", lambda db: [DataItem("siem", "k", "Заголовок", "reference", when, "fresh", "src", "d", "#a")])
    register_data_status("vm", broken)
    items = {i["module"]: i for i in auth_client.get("/api/settings/data-status").json()["items"]}
    assert items["siem"] == {
        "module": "siem", "key": "k", "title": "Заголовок", "kind": "reference",
        "updated_at": when.isoformat(), "state": "fresh", "source": "src", "detail": "d", "anchor": "#a",
    }
    assert items["vm"]["state"] == "missing"
    assert items["vm"]["updated_at"] is None and items["vm"]["detail"] == "ошибка: RuntimeError"


def test_data_status_rows_only_of_readable_modules(client_as: Callable[..., TestClient]) -> None:
    """Строки модулей, где у вызывающего нет чтения, в сводку не попадают."""
    items = client_as({"siem": "read", "vm": "deny"}).get("/api/settings/data-status").json()["items"]
    assert items and {i["module"] for i in items} == {"siem"}


def test_collect_survives_db_error_in_provider(db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ошибка SQL в одном провайдере не должна ломать сессию для следующих."""
    monkeypatch.setattr(data_status, "_PROVIDERS", {})

    def broken(db: Any) -> list[DataItem]:
        db.execute(text("SELECT * FROM no_such_table"))
        return []

    def healthy(db: Any) -> list[DataItem]:
        db.execute(text("SELECT 1"))
        return [DataItem("bbb", "k", "T", "source", None, "fresh", None, "", "")]

    register_data_status("aaa", broken)
    register_data_status("bbb", healthy)
    items = collect(db_session)
    assert [(i.module, i.key, i.state, i.detail) for i in items] == [
        ("aaa", "error", "missing", "ошибка: ProgrammingError"),
        ("bbb", "k", "fresh", ""),
    ]


def test_all_modules_registered() -> None:
    assert registered_modules() == {r.prefix.split("/")[2] for r in MODULE_ROUTERS}


def _rows(db: Any, module: str) -> dict[str, DataItem]:
    return {i.key: i for i in collect(db) if i.module == module}


def test_vm_refs_missing_until_loaded(db_session: Any) -> None:
    rows = _rows(db_session, "vm")
    refs = {k: v for k, v in rows.items() if k.startswith("ref:")}
    assert sorted(refs) == sorted(f"ref:{n}" for n in REF_NAMES) and len(refs) == 6
    assert {r.state for r in refs.values()} == {"missing"}
    assert {r.anchor for r in refs.values()} == {"references"}
    assert rows["import"].state == "missing" and rows["import"].kind == "snapshot"
    harbor = rows["harbor"]
    assert (harbor.state, harbor.kind, harbor.anchor) == ("missing", "source", "harbor")
    assert set(rows) == {"import", "harbor", *refs}


def test_vm_ref_loaded_is_fresh(db_session: Any) -> None:
    db_session.add(VmRefState(name="kev", loaded_at=dt.datetime.now(dt.UTC), source="сеть", records=1200, detail=""))
    db_session.commit()
    row = _rows(db_session, "vm")["ref:kev"]
    assert (row.state, row.title, row.source, row.kind) == ("fresh", "CISA KEV", "сеть", "reference")


def test_attack_bundle_present(db_session: Any) -> None:
    rows = _rows(db_session, "attack")
    bundle = rows["bundle"]
    assert bundle.state in {"fresh", "stale"} and bundle.source == "встроенный"
    assert bundle.title == "База MITRE ATT&CK" and bundle.anchor == "bundle"
    assert rows["ru-ttp"].state == "missing" and rows["ru-ttp"].anchor == "ru-ttp"


def test_attack_ru_ttp_uses_latest_import(db_session: Any) -> None:
    old = dt.datetime.now(dt.UTC) - dt.timedelta(days=400)
    db_session.add(RuTtpImport(source="старая", imported_at=old))
    db_session.add(RuTtpImport(source="новая", imported_at=dt.datetime.now(dt.UTC)))
    db_session.commit()
    row = _rows(db_session, "attack")["ru-ttp"]
    assert (row.state, row.source) == ("fresh", "новая")


def test_ad_connection_without_domain_is_missing(db_session: Any) -> None:
    conn = AdConnection(title="Основной", host="dc1.example.test")
    db_session.add(conn)
    db_session.commit()
    row = _rows(db_session, "ad")[f"conn:{conn.id}"]
    assert (row.state, row.detail, row.title, row.kind) == ("missing", "сбора ещё не было", "Основной", "source")
    assert row.anchor == "connections"


def test_ad_file_row_only_when_newer_than_ldap(db_session: Any) -> None:
    domain = AdDomain(sid="S-1-5-21-1", dns_root="example.test")
    db_session.add(domain)
    db_session.flush()
    conn = AdConnection(title="", host="dc1.example.test", domain_id=domain.id)
    db_session.add(conn)
    now = dt.datetime.now(dt.UTC)
    db_session.add(AdSnapshot(domain_id=domain.id, collected_at=now - dt.timedelta(days=1), source="ldap"))
    db_session.add(AdSnapshot(domain_id=domain.id, collected_at=now - dt.timedelta(days=3), source="file"))
    db_session.commit()
    rows = _rows(db_session, "ad")
    assert rows[f"conn:{conn.id}"].state == "fresh" and rows[f"conn:{conn.id}"].title == "dc1.example.test"
    assert "file" not in rows
    db_session.add(AdSnapshot(domain_id=domain.id, collected_at=now, source="file"))
    db_session.commit()
    file_row = _rows(db_session, "ad")["file"]
    assert (file_row.state, file_row.title, file_row.kind, file_row.anchor) == ("fresh", "Выгрузка файлом", "snapshot", "upload")


def test_ksc_connection_and_file_rows(db_session: Any) -> None:
    server = KscServer(name="ksc1")
    db_session.add(server)
    db_session.flush()
    conn = KscConnection(title="KSC", host="ksc1.example.test", server_id=server.id)
    empty = KscConnection(title="Новое", host="ksc2.example.test")
    db_session.add_all([conn, empty])
    stale = dt.datetime.now(dt.UTC) - dt.timedelta(days=30)
    db_session.add(KscSnapshot(server_id=server.id, collected_at=stale, source="online"))
    db_session.add(KscSnapshot(server_id=server.id, collected_at=dt.datetime.now(dt.UTC), source="file"))
    db_session.commit()
    rows = _rows(db_session, "ksc")
    assert rows[f"conn:{conn.id}"].state == "stale"
    assert rows[f"conn:{empty.id}"].state == "missing" and rows[f"conn:{empty.id}"].detail == "сбора ещё не было"
    assert rows["file"].state == "fresh"


def test_siem_file_snapshot_row(auth_client: TestClient, kb_zip_bytes: bytes, db_session: Any) -> None:
    upload_and_wait(auth_client, kb_zip_bytes)
    rows = _rows(db_session, "siem")
    snap = rows["kb-snapshot"]
    assert (snap.state, snap.source, snap.kind, snap.anchor) == ("fresh", "файл", "snapshot", "upload")
    conn = rows["kb-connection"]
    assert (conn.state, conn.detail, conn.anchor) == ("missing", "не настроено", "kb")


def test_siem_empty_snapshot_is_missing(db_session: Any) -> None:
    assert _rows(db_session, "siem")["kb-snapshot"].state == "missing"


def test_assets_rows(db_session: Any) -> None:
    db_session.add(AssetDns(title="", last_run_at=dt.datetime.now(dt.UTC)))
    db_session.add(AssetRacktables(title="Стойки", url="https://rt.example.test", last_run_at=None))
    db_session.commit()
    rows = _rows(db_session, "assets")
    assert rows["sync"].state == "missing" and rows["sync"].anchor == "sync"
    dns = next(r for k, r in rows.items() if k.startswith("dns:"))
    rt = next(r for k, r in rows.items() if k.startswith("racktables:"))
    assert dns.title.startswith("DNS #") and dns.state == "fresh" and dns.anchor == "dns"
    assert (rt.title, rt.state, rt.anchor) == ("Стойки", "missing", "racktables")


def test_toolbox_has_no_rows(db_session: Any) -> None:
    assert _rows(db_session, "toolbox") == {}


def test_refs_router_uses_shared_view(auth_client: TestClient, db_session: Any) -> None:
    body = auth_client.get("/api/vm/refs").json()
    assert [r["name"] for r in body] == list(REF_NAMES)
    assert body == [json.loads(v.model_dump_json()) for v in ref_views(db_session)]
